//! Configuration of the City-G v0.3 server, clients and GUI.
//!
//! Sources, highest priority first:
//! 1. environment variables (`CITYG_<SECTION>_<KEY>`),
//! 2. a configuration file (`cityg.toml` or `cityg.json` in the working
//!    directory, then `config.toml` or `config.json` in the user
//!    configuration directory under `cityg/`),
//! 3. the defaults.
//!
//! Unknown keys are ignored, so a v0.1.4 file with a `[protocol]` section
//! still loads; its protocol settings have no v0.3 equivalent.
//!
//! # Example
//! ```no_run
//! use cityg_config::CityGConfig;
//!
//! let config = CityGConfig::load().unwrap();
//! let config = CityGConfig::from_file("config/production.toml").unwrap();
//!
//! // Explicit overrides (handy for tests).
//! let overrides = [("CITYG_SERVER_ADDRESS", "0.0.0.0:9000")];
//! let config = CityGConfig::default()
//!     .apply_env_overrides_with(|key| {
//!         overrides
//!             .iter()
//!             .find(|(k, _)| k == &key)
//!             .map(|(_, v)| v.to_string())
//!             .ok_or(std::env::VarError::NotPresent)
//!     })
//!     .unwrap();
//! ```

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{
    env::VarError,
    path::{Path, PathBuf},
};
use thiserror::Error;

/// Largest group capacity of the v0.3 profile (`MAX_CAPACITY`).
pub const PROFILE_MAX_GROUP_SIZE: u32 = 8192;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Environment variable error: {0}")]
    EnvVar(#[from] std::env::VarError),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

/// Configuration of City-G.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct CityGConfig {
    /// Delivery service (native server and Worker).
    pub server: ServerConfig,

    /// Clients.
    pub client: ClientConfig,

    /// Desktop GUI.
    pub gui: GuiConfig,
}

/// Delivery-service configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ServerConfig {
    /// Bind address of the native server (e.g. "0.0.0.0:8080").
    pub address: String,

    /// Directory prefix of the room journals; rooms live in memory only
    /// without it.
    pub state_path: Option<PathBuf>,

    /// Capacity of the log-head notification channel.
    pub websocket_capacity: usize,

    /// Largest capacity a new group may declare (at most
    /// [`PROFILE_MAX_GROUP_SIZE`]).
    pub max_group_size: u32,

    /// How long message envelopes stay in a room log (seconds).
    pub message_retention_secs: u64,

    /// How long commits stay in a room log (seconds; the latest commit
    /// always stays).
    pub commit_retention_secs: u64,

    /// Most entries kept in a room log; the oldest messages go first.
    pub max_log_entries: usize,

    /// Lifetime of a member session token (seconds).
    pub session_ttl_secs: u64,

    /// Accepted clock difference of a signed session request (seconds).
    pub auth_skew_secs: u64,

    /// Journal length that triggers a room snapshot.
    pub compact_every: usize,
}

/// Client configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ClientConfig {
    /// Server URL proposed by the join form.
    pub default_server_url: String,

    /// Interval between room log polls (seconds).
    pub fetch_poll_interval_secs: u64,

    /// Delay before retrying a failed sync (seconds).
    pub fetch_retry_interval_secs: u64,

    /// Delay before reconnecting the notification socket (seconds).
    pub websocket_reconnect_delay_secs: u64,
}

/// GUI configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct GuiConfig {
    /// Initial window width (pixels).
    pub default_window_width: f32,

    /// Initial window height (pixels).
    pub default_window_height: f32,

    /// Interval of the maintenance tick: committing other members' leave
    /// requests, periodic re-keying, expiry of previous-epoch keys
    /// (seconds).
    pub maintenance_interval_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:8080".to_string(),
            state_path: None,
            websocket_capacity: 1000,
            max_group_size: 1024,
            message_retention_secs: 7 * 24 * 3600,
            commit_retention_secs: 30 * 24 * 3600,
            max_log_entries: 50_000,
            session_ttl_secs: 3600,
            auth_skew_secs: 300,
            compact_every: 256,
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            default_server_url: String::new(),
            fetch_poll_interval_secs: 3,
            fetch_retry_interval_secs: 10,
            websocket_reconnect_delay_secs: 5,
        }
    }
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            default_window_width: 1160.0,
            default_window_height: 760.0,
            maintenance_interval_secs: 30,
        }
    }
}

fn positive(value: u64, name: &str) -> Result<()> {
    if value == 0 {
        return Err(ConfigError::Validation(format!("{name} must be > 0")));
    }
    Ok(())
}

impl CityGConfig {
    /// Load the configuration from the default locations, then apply the
    /// environment.
    pub fn load() -> Result<Self> {
        for local in ["cityg.toml", "cityg.json"] {
            if let Ok(config) = Self::from_file(local) {
                return config.apply_env_overrides();
            }
        }
        if let Some(config_dir) = dirs::config_dir() {
            for name in ["config.toml", "config.json"] {
                let path = config_dir.join("cityg").join(name);
                if path.exists()
                    && let Ok(config) = Self::from_file(&path)
                {
                    return config.apply_env_overrides();
                }
            }
        }
        Self::default().apply_env_overrides()
    }

    /// Load a TOML file, or a JSON file (`.json` extension).
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)?;
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            Ok(serde_json::from_str(&contents)?)
        } else {
            Ok(toml::from_str(&contents)?)
        }
    }

    /// Save as TOML, or as JSON (`.json` extension).
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        let contents = if path.extension().and_then(|s| s.to_str()) == Some("json") {
            serde_json::to_string_pretty(self)?
        } else {
            toml::to_string_pretty(self).map_err(|e| ConfigError::Validation(e.to_string()))?
        };
        std::fs::write(path, contents)?;
        Ok(())
    }

    fn apply_env_overrides(self) -> Result<Self> {
        self.apply_env_overrides_with(|key| std::env::var(key))
    }

    /// Apply the `CITYG_<SECTION>_<KEY>` variables `get_var` returns.
    pub fn apply_env_overrides_with<F>(mut self, mut get_var: F) -> Result<Self>
    where
        F: for<'a> FnMut(&'a str) -> std::result::Result<String, VarError>,
    {
        macro_rules! env_parse {
            ($env:literal, $field:expr, $name:literal) => {
                if let Ok(val) = get_var($env) {
                    $field = val.parse().map_err(|e| {
                        ConfigError::Validation(format!(concat!("Invalid ", $name, ": {}"), e))
                    })?;
                }
            };
        }

        if let Ok(val) = get_var("CITYG_SERVER_ADDRESS") {
            self.server.address = val;
        }
        if let Ok(val) = get_var("CITYG_SERVER_STATE_PATH") {
            self.server.state_path = Some(PathBuf::from(val));
        }
        env_parse!(
            "CITYG_SERVER_WEBSOCKET_CAPACITY",
            self.server.websocket_capacity,
            "websocket_capacity"
        );
        env_parse!(
            "CITYG_SERVER_MAX_GROUP_SIZE",
            self.server.max_group_size,
            "max_group_size"
        );
        env_parse!(
            "CITYG_SERVER_MESSAGE_RETENTION_SECS",
            self.server.message_retention_secs,
            "message_retention_secs"
        );
        env_parse!(
            "CITYG_SERVER_COMMIT_RETENTION_SECS",
            self.server.commit_retention_secs,
            "commit_retention_secs"
        );
        env_parse!(
            "CITYG_SERVER_MAX_LOG_ENTRIES",
            self.server.max_log_entries,
            "max_log_entries"
        );
        env_parse!(
            "CITYG_SERVER_SESSION_TTL_SECS",
            self.server.session_ttl_secs,
            "session_ttl_secs"
        );
        env_parse!(
            "CITYG_SERVER_AUTH_SKEW_SECS",
            self.server.auth_skew_secs,
            "auth_skew_secs"
        );
        env_parse!(
            "CITYG_SERVER_COMPACT_EVERY",
            self.server.compact_every,
            "compact_every"
        );

        if let Ok(val) = get_var("CITYG_CLIENT_DEFAULT_SERVER_URL") {
            self.client.default_server_url = val;
        }
        env_parse!(
            "CITYG_CLIENT_FETCH_POLL_INTERVAL_SECS",
            self.client.fetch_poll_interval_secs,
            "fetch_poll_interval_secs"
        );
        env_parse!(
            "CITYG_CLIENT_FETCH_RETRY_INTERVAL_SECS",
            self.client.fetch_retry_interval_secs,
            "fetch_retry_interval_secs"
        );
        env_parse!(
            "CITYG_CLIENT_WEBSOCKET_RECONNECT_DELAY_SECS",
            self.client.websocket_reconnect_delay_secs,
            "websocket_reconnect_delay_secs"
        );

        env_parse!(
            "CITYG_GUI_DEFAULT_WINDOW_WIDTH",
            self.gui.default_window_width,
            "default_window_width"
        );
        env_parse!(
            "CITYG_GUI_DEFAULT_WINDOW_HEIGHT",
            self.gui.default_window_height,
            "default_window_height"
        );
        env_parse!(
            "CITYG_GUI_MAINTENANCE_INTERVAL_SECS",
            self.gui.maintenance_interval_secs,
            "maintenance_interval_secs"
        );

        Ok(self)
    }

    /// Check the values.
    pub fn validate(&self) -> Result<()> {
        let server = &self.server;
        positive(server.websocket_capacity as u64, "websocket_capacity")?;
        if server.max_group_size == 0 || server.max_group_size > PROFILE_MAX_GROUP_SIZE {
            return Err(ConfigError::Validation(format!(
                "max_group_size must be in 1..={PROFILE_MAX_GROUP_SIZE}"
            )));
        }
        positive(server.message_retention_secs, "message_retention_secs")?;
        positive(server.commit_retention_secs, "commit_retention_secs")?;
        positive(server.max_log_entries as u64, "max_log_entries")?;
        positive(server.session_ttl_secs, "session_ttl_secs")?;
        positive(server.auth_skew_secs, "auth_skew_secs")?;
        positive(server.compact_every as u64, "compact_every")?;

        positive(
            self.client.fetch_poll_interval_secs,
            "fetch_poll_interval_secs",
        )?;
        positive(
            self.client.fetch_retry_interval_secs,
            "fetch_retry_interval_secs",
        )?;

        if self.gui.default_window_width <= 0.0 {
            return Err(ConfigError::Validation(
                "default_window_width must be > 0".to_string(),
            ));
        }
        if self.gui.default_window_height <= 0.0 {
            return Err(ConfigError::Validation(
                "default_window_height must be > 0".to_string(),
            ));
        }
        positive(
            self.gui.maintenance_interval_secs,
            "maintenance_interval_secs",
        )?;
        Ok(())
    }
}

impl ServerConfig {
    pub fn message_retention(&self) -> Duration {
        Duration::from_secs(self.message_retention_secs)
    }

    pub fn commit_retention(&self) -> Duration {
        Duration::from_secs(self.commit_retention_secs)
    }

    pub fn session_ttl(&self) -> Duration {
        Duration::from_secs(self.session_ttl_secs)
    }
}

impl ClientConfig {
    pub fn fetch_poll_interval(&self) -> Duration {
        Duration::from_secs(self.fetch_poll_interval_secs)
    }

    pub fn fetch_retry_interval(&self) -> Duration {
        Duration::from_secs(self.fetch_retry_interval_secs)
    }

    pub fn websocket_reconnect_delay(&self) -> Duration {
        Duration::from_secs(self.websocket_reconnect_delay_secs)
    }
}

impl GuiConfig {
    pub fn maintenance_interval(&self) -> Duration {
        Duration::from_secs(self.maintenance_interval_secs)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::Mutex;
    use tempfile::{NamedTempFile, TempDir};

    /// Serializes the tests that touch the working directory or the process
    /// environment.
    static PROCESS_LOCK: Mutex<()> = Mutex::new(());

    struct CurrentDirGuard(PathBuf);

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    fn overrides(pairs: &[(&'static str, &str)]) -> HashMap<&'static str, String> {
        pairs
            .iter()
            .map(|(key, value)| (*key, (*value).to_string()))
            .collect()
    }

    fn with_env(pairs: &[(&'static str, &str)]) -> Result<CityGConfig> {
        let vars = overrides(pairs);
        CityGConfig::default()
            .apply_env_overrides_with(|key| vars.get(key).cloned().ok_or(VarError::NotPresent))
    }

    #[test]
    fn defaults_are_valid() {
        let config = CityGConfig::default();
        config.validate().unwrap();
        assert_eq!(config.server.address, "0.0.0.0:8080");
        assert_eq!(config.server.max_group_size, 1024);
        assert!(config.client.default_server_url.is_empty());
        assert_eq!(
            config.server.message_retention(),
            Duration::from_secs(604_800)
        );
        assert_eq!(
            config.server.commit_retention(),
            Duration::from_secs(2_592_000)
        );
        assert_eq!(config.server.session_ttl(), Duration::from_secs(3600));
        assert_eq!(config.client.fetch_poll_interval(), Duration::from_secs(3));
        assert_eq!(
            config.client.fetch_retry_interval(),
            Duration::from_secs(10)
        );
        assert_eq!(
            config.client.websocket_reconnect_delay(),
            Duration::from_secs(5)
        );
        assert_eq!(config.gui.maintenance_interval(), Duration::from_secs(30));
    }

    #[test]
    fn every_variable_overrides_its_field() {
        let config = with_env(&[
            ("CITYG_SERVER_ADDRESS", "127.0.0.1:9000"),
            ("CITYG_SERVER_STATE_PATH", "/var/lib/cityg/rooms"),
            ("CITYG_SERVER_WEBSOCKET_CAPACITY", "10"),
            ("CITYG_SERVER_MAX_GROUP_SIZE", "64"),
            ("CITYG_SERVER_MESSAGE_RETENTION_SECS", "60"),
            ("CITYG_SERVER_COMMIT_RETENTION_SECS", "120"),
            ("CITYG_SERVER_MAX_LOG_ENTRIES", "500"),
            ("CITYG_SERVER_SESSION_TTL_SECS", "30"),
            ("CITYG_SERVER_AUTH_SKEW_SECS", "15"),
            ("CITYG_SERVER_COMPACT_EVERY", "8"),
            ("CITYG_CLIENT_DEFAULT_SERVER_URL", "https://edge.example"),
            ("CITYG_CLIENT_FETCH_POLL_INTERVAL_SECS", "7"),
            ("CITYG_CLIENT_FETCH_RETRY_INTERVAL_SECS", "9"),
            ("CITYG_CLIENT_WEBSOCKET_RECONNECT_DELAY_SECS", "11"),
            ("CITYG_GUI_DEFAULT_WINDOW_WIDTH", "800"),
            ("CITYG_GUI_DEFAULT_WINDOW_HEIGHT", "600"),
            ("CITYG_GUI_MAINTENANCE_INTERVAL_SECS", "13"),
        ])
        .unwrap();
        config.validate().unwrap();
        let server = &config.server;
        assert_eq!(server.address, "127.0.0.1:9000");
        assert_eq!(
            server.state_path.as_deref(),
            Some(Path::new("/var/lib/cityg/rooms"))
        );
        assert_eq!(server.websocket_capacity, 10);
        assert_eq!(server.max_group_size, 64);
        assert_eq!(server.message_retention_secs, 60);
        assert_eq!(server.commit_retention_secs, 120);
        assert_eq!(server.max_log_entries, 500);
        assert_eq!(server.session_ttl_secs, 30);
        assert_eq!(server.auth_skew_secs, 15);
        assert_eq!(server.compact_every, 8);
        assert_eq!(config.client.default_server_url, "https://edge.example");
        assert_eq!(config.client.fetch_poll_interval_secs, 7);
        assert_eq!(config.client.fetch_retry_interval_secs, 9);
        assert_eq!(config.client.websocket_reconnect_delay_secs, 11);
        assert_eq!(config.gui.default_window_width, 800.0);
        assert_eq!(config.gui.default_window_height, 600.0);
        assert_eq!(config.gui.maintenance_interval_secs, 13);
    }

    #[test]
    fn unparsable_variables_are_rejected() {
        for key in [
            "CITYG_SERVER_WEBSOCKET_CAPACITY",
            "CITYG_SERVER_MAX_GROUP_SIZE",
            "CITYG_SERVER_MESSAGE_RETENTION_SECS",
            "CITYG_SERVER_COMMIT_RETENTION_SECS",
            "CITYG_SERVER_MAX_LOG_ENTRIES",
            "CITYG_SERVER_SESSION_TTL_SECS",
            "CITYG_SERVER_AUTH_SKEW_SECS",
            "CITYG_SERVER_COMPACT_EVERY",
            "CITYG_CLIENT_FETCH_POLL_INTERVAL_SECS",
            "CITYG_CLIENT_FETCH_RETRY_INTERVAL_SECS",
            "CITYG_CLIENT_WEBSOCKET_RECONNECT_DELAY_SECS",
            "CITYG_GUI_DEFAULT_WINDOW_WIDTH",
            "CITYG_GUI_DEFAULT_WINDOW_HEIGHT",
            "CITYG_GUI_MAINTENANCE_INTERVAL_SECS",
        ] {
            let error = with_env(&[(key, "not-a-number")]).unwrap_err();
            assert!(error.to_string().contains("Invalid"), "{key}");
        }
    }

    #[test]
    fn validation_rejects_each_bad_value() {
        let cases: Vec<fn(&mut CityGConfig)> = vec![
            |c| c.server.websocket_capacity = 0,
            |c| c.server.max_group_size = 0,
            |c| c.server.max_group_size = PROFILE_MAX_GROUP_SIZE + 1,
            |c| c.server.message_retention_secs = 0,
            |c| c.server.commit_retention_secs = 0,
            |c| c.server.max_log_entries = 0,
            |c| c.server.session_ttl_secs = 0,
            |c| c.server.auth_skew_secs = 0,
            |c| c.server.compact_every = 0,
            |c| c.client.fetch_poll_interval_secs = 0,
            |c| c.client.fetch_retry_interval_secs = 0,
            |c| c.gui.default_window_width = 0.0,
            |c| c.gui.default_window_height = -1.0,
            |c| c.gui.maintenance_interval_secs = 0,
        ];
        for (index, break_it) in cases.into_iter().enumerate() {
            let mut config = CityGConfig::default();
            break_it(&mut config);
            assert!(
                matches!(config.validate(), Err(ConfigError::Validation(_))),
                "case {index}"
            );
        }
        let mut config = CityGConfig::default();
        config.server.max_group_size = PROFILE_MAX_GROUP_SIZE;
        config.validate().unwrap();
    }

    #[test]
    fn files_load_and_save_in_both_formats() {
        let toml = r#"
[server]
address = "0.0.0.0:9000"
max_group_size = 32

[client]
default_server_url = "http://example.com:8080"

[gui]
maintenance_interval_secs = 45

[protocol]
window_duration_secs = 20
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(toml.as_bytes()).unwrap();
        let config = CityGConfig::from_file(file.path()).unwrap();
        assert_eq!(config.server.address, "0.0.0.0:9000");
        assert_eq!(config.server.max_group_size, 32);
        assert_eq!(config.server.message_retention_secs, 604_800);
        assert_eq!(config.client.default_server_url, "http://example.com:8080");
        assert_eq!(config.gui.maintenance_interval_secs, 45);

        let dir = TempDir::new().unwrap();
        for name in ["saved.toml", "saved.json"] {
            let path = dir.path().join(name);
            config.save(&path).unwrap();
            assert_eq!(CityGConfig::from_file(&path).unwrap(), config);
        }

        assert!(matches!(
            CityGConfig::from_file(dir.path().join("missing.toml")),
            Err(ConfigError::Io(_))
        ));
        let bad_toml = dir.path().join("bad.toml");
        std::fs::write(&bad_toml, "[server\n").unwrap();
        assert!(matches!(
            CityGConfig::from_file(&bad_toml),
            Err(ConfigError::TomlParse(_))
        ));
        let bad_json = dir.path().join("bad.json");
        std::fs::write(&bad_json, "{").unwrap();
        assert!(matches!(
            CityGConfig::from_file(&bad_json),
            Err(ConfigError::JsonParse(_))
        ));
        assert_eq!(
            ConfigError::Validation("x".into()).to_string(),
            "Validation error: x"
        );
    }

    #[test]
    fn load_prefers_the_working_directory() {
        let _lock = PROCESS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = TempDir::new().unwrap();
        let _restore = CurrentDirGuard(std::env::current_dir().unwrap());
        std::env::set_current_dir(dir.path()).unwrap();

        std::fs::write("cityg.json", r#"{"server":{"address":"127.0.0.1:7001"}}"#).unwrap();
        let config = CityGConfig::load().unwrap();
        // The environment still applies on top.
        if std::env::var("CITYG_SERVER_ADDRESS").is_err() {
            assert_eq!(config.server.address, "127.0.0.1:7001");
        }
        std::fs::write("cityg.toml", "[server]\naddress = \"127.0.0.1:7002\"\n").unwrap();
        let config = CityGConfig::load().unwrap();
        if std::env::var("CITYG_SERVER_ADDRESS").is_err() {
            assert_eq!(config.server.address, "127.0.0.1:7002");
        }
        std::fs::remove_file("cityg.toml").unwrap();
        std::fs::remove_file("cityg.json").unwrap();
        CityGConfig::load().unwrap();
    }
}
