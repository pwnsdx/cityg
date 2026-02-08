//! Configuration management for CityG
//!
//! This crate provides a centralized configuration system with support for:
//! - TOML and JSON configuration files
//! - Environment variable overrides
//! - Runtime configuration updates
//! - Validation and defaults
//!
//! # Configuration Priority (highest to lowest):
//! 1. Environment variables (CITYG_*)
//! 2. Configuration file (cityg.toml or cityg.json)
//! 3. Default values
//!
//! # Example
//! ```no_run
//! use cityg_config::CityGConfig;
//!
//! // Load configuration from default locations
//! let config = CityGConfig::load().unwrap();
//!
//! // Load from specific file
//! let config = CityGConfig::from_file("config/production.toml").unwrap();
//!
//! // Use explicit overrides (handy for tests)
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

use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{env::VarError, path::Path};
use thiserror::Error;

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

/// Main configuration structure for CityG
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CityGConfig {
    /// Server configuration
    pub server: ServerConfig,

    /// Client configuration
    pub client: ClientConfig,

    /// Protocol configuration
    pub protocol: ProtocolConfig,

    /// GUI configuration
    pub gui: GuiConfig,
}

/// Server/API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Server bind address (e.g., "0.0.0.0:8080")
    pub address: String,

    /// WebSocket broadcast channel capacity
    pub websocket_capacity: usize,

    /// Window TTL in seconds (default: 24 hours)
    pub window_ttl_secs: u64,

    /// Whether to seed the demo room (preloads KBROAD + bootstrap keys)
    pub seed_demo_room: bool,
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientConfig {
    /// Default server URL for connections
    pub default_server_url: String,

    /// Polling interval for fetching updates (seconds)
    pub fetch_poll_interval_secs: u64,

    /// Retry interval for failed fetch operations (seconds)
    pub fetch_retry_interval_secs: u64,

    /// WebSocket reconnection delay (seconds)
    pub websocket_reconnect_delay_secs: u64,

    /// API timeout for requests (seconds)
    pub api_timeout_secs: u64,
}

/// Protocol-level configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtocolConfig {
    /// Time window duration (seconds)
    pub window_duration_secs: u64,

    /// Maximum concurrent heads in multi-head window
    pub max_concurrent_heads: usize,

    /// Epoch rotation interval (seconds)
    pub epoch_rotation_interval_secs: u64,

    /// Default maximum SRX payload size (bytes)
    pub default_srx_max_bytes: usize,

    /// Maximum HP proof size (bytes)
    pub max_hp_proof_bytes: usize,

    /// Maximum VRF proof size (bytes)
    pub max_vrf_proof_bytes: usize,

    /// FS CAPSS maximum size (bytes)
    pub fs_capss_max_bytes: usize,

    /// SRX Smallwood maximum size (bytes)
    pub srx_smallwood_max_bytes: usize,

    /// Maximum HP envelope size (bytes)
    pub max_hp_envelope_bytes: usize,

    /// Minimum SRX maximum size (bytes)
    pub min_srx_max_bytes: usize,

    /// Cache TTL for receiver cache (seconds)
    pub receiver_cache_ttl_secs: u64,

    /// Forward-secrecy policy parameters
    pub fs_policy: FsPolicySettings,

    /// Expected FS policy version label
    pub fs_policy_version: String,
}

/// Forward-secrecy policy parameters (Annex H/J)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FsPolicySettings {
    /// Base window duration `H` (seconds)
    pub h_seconds: u64,

    /// Checkpoint interval (seconds)
    pub checkpoint_interval_seconds: u64,

    /// Number of heads required before checkpoint adoption
    pub checkpoint_head_threshold: u64,

    /// Slack for anchor joins relative to `H`
    pub slack_anchor: u64,

    /// Slack for first device joins
    pub slack_first_device: u64,

    /// Slack for subsequent device joins
    pub slack_device: u64,
}

/// GUI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GuiConfig {
    /// Default window width (pixels)
    pub default_window_width: f32,

    /// Default window height (pixels)
    pub default_window_height: f32,

    /// Members per page for pagination
    pub members_page_limit: u32,

    /// Interval for background member refresh (seconds)
    pub members_refresh_interval_secs: u64,

    /// Minimum card width (pixels)
    pub min_card_width: f32,

    /// Maximum card width (pixels)
    pub max_card_width: f32,

    /// Maximum card height (pixels)
    pub max_card_height: f32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:8080".to_string(),
            websocket_capacity: 1000,
            window_ttl_secs: 120, // 2 minutes default TTL
            seed_demo_room: false,
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            default_server_url: "http://127.0.0.1:8080".to_string(),
            fetch_poll_interval_secs: 3,
            fetch_retry_interval_secs: 10,
            websocket_reconnect_delay_secs: 5,
            api_timeout_secs: 30,
        }
    }
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            window_duration_secs: 120,
            max_concurrent_heads: 16,
            epoch_rotation_interval_secs: 300,  // 5 minutes
            default_srx_max_bytes: 1024 * 1024, // 1 MB
            max_hp_proof_bytes: 512 * 1024,     // 512 KB
            max_vrf_proof_bytes: 6 * 1024,      // 6 KB
            fs_capss_max_bytes: 16 * 1024,      // 16 KB
            srx_smallwood_max_bytes: 16 * 1024, // 16 KB
            max_hp_envelope_bytes: 16 * 1024,   // 16 KB
            min_srx_max_bytes: 256 * 1024,      // 256 KB
            receiver_cache_ttl_secs: 10,
            fs_policy: FsPolicySettings::default(),
            fs_policy_version: "7".to_string(),
        }
    }
}

impl Default for FsPolicySettings {
    fn default() -> Self {
        Self {
            h_seconds: 300,
            checkpoint_interval_seconds: 3600,
            checkpoint_head_threshold: 24,
            slack_anchor: 0,
            slack_first_device: 0,
            slack_device: 4,
        }
    }
}

impl FsPolicySettings {
    pub fn validate(&self) -> Result<()> {
        if self.h_seconds == 0 {
            return Err(ConfigError::Validation(
                "fs_policy.h_seconds must be > 0".to_string(),
            ));
        }
        if self.checkpoint_interval_seconds == 0 {
            return Err(ConfigError::Validation(
                "fs_policy.checkpoint_interval_seconds must be > 0".to_string(),
            ));
        }
        if self.checkpoint_interval_seconds < self.h_seconds {
            return Err(ConfigError::Validation(
                "fs_policy.checkpoint_interval_seconds must be >= h_seconds".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            default_window_width: 1160.0,
            default_window_height: 760.0,
            members_page_limit: 200,
            members_refresh_interval_secs: 30,
            min_card_width: 320.0,
            max_card_width: 960.0,
            max_card_height: 780.0,
        }
    }
}

impl CityGConfig {
    /// Load configuration from default locations
    ///
    /// Searches for configuration in the following order:
    /// 1. ./cityg.toml or ./cityg.json
    /// 2. ~/.config/cityg/config.toml or ~/.config/cityg/config.json
    /// 3. Environment variables (CITYG_*)
    /// 4. Default values
    pub fn load() -> Result<Self> {
        // Try current directory first
        if let Ok(config) = Self::from_file("cityg.toml") {
            return config.apply_env_overrides();
        }

        if let Ok(config) = Self::from_file("cityg.json") {
            return config.apply_env_overrides();
        }

        // Try user config directory
        if let Some(config_dir) = dirs::config_dir() {
            let config_path = config_dir.join("cityg").join("config.toml");
            if config_path.exists()
                && let Ok(config) = Self::from_file(&config_path)
            {
                return config.apply_env_overrides();
            }

            let config_path = config_dir.join("cityg").join("config.json");
            if config_path.exists()
                && let Ok(config) = Self::from_file(&config_path)
            {
                return config.apply_env_overrides();
            }
        }

        // Fall back to defaults with env overrides
        Self::default().apply_env_overrides()
    }

    /// Load configuration from a specific file
    ///
    /// Supports both TOML and JSON formats (detected by file extension)
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)?;

        let config = if path.extension().and_then(|s| s.to_str()) == Some("json") {
            serde_json::from_str(&contents)?
        } else {
            // Default to TOML
            toml::from_str(&contents)?
        };

        Ok(config)
    }

    /// Save configuration to a file
    ///
    /// Format is determined by file extension (.toml or .json)
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

    /// Apply environment variable overrides
    ///
    /// Environment variables follow the pattern: CITYG_<SECTION>_<KEY>
    /// Example: CITYG_SERVER_ADDRESS=0.0.0.0:9000
    fn apply_env_overrides(self) -> Result<Self> {
        self.apply_env_overrides_with(|key| std::env::var(key))
    }

    pub fn apply_env_overrides_with<F>(mut self, mut get_var: F) -> Result<Self>
    where
        F: for<'a> FnMut(&'a str) -> std::result::Result<String, VarError>,
    {
        if let Ok(val) = get_var("CITYG_SERVER_ADDRESS") {
            self.server.address = val;
        }
        if let Ok(val) = get_var("CITYG_SERVER_WEBSOCKET_CAPACITY") {
            self.server.websocket_capacity = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid websocket_capacity: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_SERVER_WINDOW_TTL_SECS") {
            self.server.window_ttl_secs = val
                .parse()
                .map_err(|e| ConfigError::Validation(format!("Invalid window_ttl_secs: {}", e)))?;
        }
        if let Ok(val) = get_var("CITYG_SERVER_SEED_DEMO_ROOM") {
            self.server.seed_demo_room = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid seed_demo_room flag: {}", e))
            })?;
        }

        if let Ok(val) = get_var("CITYG_CLIENT_DEFAULT_SERVER_URL") {
            self.client.default_server_url = val;
        }
        if let Ok(val) = get_var("CITYG_CLIENT_FETCH_POLL_INTERVAL_SECS") {
            self.client.fetch_poll_interval_secs = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid fetch_poll_interval_secs: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_CLIENT_FETCH_RETRY_INTERVAL_SECS") {
            self.client.fetch_retry_interval_secs = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid fetch_retry_interval_secs: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_CLIENT_WEBSOCKET_RECONNECT_DELAY_SECS") {
            self.client.websocket_reconnect_delay_secs = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid websocket_reconnect_delay_secs: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_CLIENT_API_TIMEOUT_SECS") {
            self.client.api_timeout_secs = val
                .parse()
                .map_err(|e| ConfigError::Validation(format!("Invalid api_timeout_secs: {}", e)))?;
        }

        if let Ok(val) = get_var("CITYG_PROTOCOL_WINDOW_DURATION_SECS") {
            self.protocol.window_duration_secs = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid window_duration_secs: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_MAX_CONCURRENT_HEADS") {
            self.protocol.max_concurrent_heads = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid max_concurrent_heads: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_EPOCH_ROTATION_INTERVAL_SECS") {
            self.protocol.epoch_rotation_interval_secs = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid epoch_rotation_interval_secs: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_DEFAULT_SRX_MAX_BYTES") {
            self.protocol.default_srx_max_bytes = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid default_srx_max_bytes: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_MAX_HP_PROOF_BYTES") {
            self.protocol.max_hp_proof_bytes = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid max_hp_proof_bytes: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_MAX_VRF_PROOF_BYTES") {
            self.protocol.max_vrf_proof_bytes = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid max_vrf_proof_bytes: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_FS_CAPSS_MAX_BYTES") {
            self.protocol.fs_capss_max_bytes = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid fs_capss_max_bytes: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_SRX_SMALLWOOD_MAX_BYTES") {
            self.protocol.srx_smallwood_max_bytes = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid srx_smallwood_max_bytes: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_MAX_HP_ENVELOPE_BYTES") {
            self.protocol.max_hp_envelope_bytes = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid max_hp_envelope_bytes: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_MIN_SRX_MAX_BYTES") {
            self.protocol.min_srx_max_bytes = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid min_srx_max_bytes: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_RECEIVER_CACHE_TTL_SECS") {
            self.protocol.receiver_cache_ttl_secs = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid receiver_cache_ttl_secs: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_FS_POLICY_VERSION") {
            self.protocol.fs_policy_version = val;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_FS_POLICY_H_SECONDS") {
            self.protocol.fs_policy.h_seconds = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid fs_policy.h_seconds: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_FS_POLICY_CHECKPOINT_INTERVAL_SECS") {
            self.protocol.fs_policy.checkpoint_interval_seconds = val.parse().map_err(|e| {
                ConfigError::Validation(format!(
                    "Invalid fs_policy.checkpoint_interval_seconds: {}",
                    e
                ))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_FS_POLICY_CHECKPOINT_HEAD_THRESHOLD") {
            self.protocol.fs_policy.checkpoint_head_threshold = val.parse().map_err(|e| {
                ConfigError::Validation(format!(
                    "Invalid fs_policy.checkpoint_head_threshold: {}",
                    e
                ))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_FS_POLICY_SLACK_ANCHOR") {
            self.protocol.fs_policy.slack_anchor = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid fs_policy.slack_anchor: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_FS_POLICY_SLACK_FIRST_DEVICE") {
            self.protocol.fs_policy.slack_first_device = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid fs_policy.slack_first_device: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_PROTOCOL_FS_POLICY_SLACK_DEVICE") {
            self.protocol.fs_policy.slack_device = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid fs_policy.slack_device: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_GUI_DEFAULT_WINDOW_WIDTH") {
            self.gui.default_window_width = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid default_window_width: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_GUI_DEFAULT_WINDOW_HEIGHT") {
            self.gui.default_window_height = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid default_window_height: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_GUI_MEMBERS_PAGE_LIMIT") {
            self.gui.members_page_limit = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid members_page_limit: {}", e))
            })?;
        }
        if let Ok(val) = get_var("CITYG_GUI_MEMBERS_REFRESH_INTERVAL_SECS") {
            self.gui.members_refresh_interval_secs = val.parse().map_err(|e| {
                ConfigError::Validation(format!("Invalid members_refresh_interval_secs: {}", e))
            })?;
        }

        Ok(self)
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<()> {
        // Validate server config
        if self.server.websocket_capacity == 0 {
            return Err(ConfigError::Validation(
                "websocket_capacity must be > 0".to_string(),
            ));
        }
        if self.server.window_ttl_secs == 0 {
            return Err(ConfigError::Validation(
                "window_ttl_secs must be > 0".to_string(),
            ));
        }

        // Validate client config
        if self.client.fetch_poll_interval_secs == 0 {
            return Err(ConfigError::Validation(
                "fetch_poll_interval_secs must be > 0".to_string(),
            ));
        }
        if self.client.fetch_retry_interval_secs == 0 {
            return Err(ConfigError::Validation(
                "fetch_retry_interval_secs must be > 0".to_string(),
            ));
        }

        // Validate protocol config
        if self.protocol.window_duration_secs == 0 {
            return Err(ConfigError::Validation(
                "window_duration_secs must be > 0".to_string(),
            ));
        }
        if self.protocol.max_concurrent_heads == 0 {
            return Err(ConfigError::Validation(
                "max_concurrent_heads must be > 0".to_string(),
            ));
        }
        if self.protocol.epoch_rotation_interval_secs == 0 {
            return Err(ConfigError::Validation(
                "epoch_rotation_interval_secs must be > 0".to_string(),
            ));
        }
        if self.protocol.default_srx_max_bytes < self.protocol.min_srx_max_bytes {
            return Err(ConfigError::Validation(format!(
                "default_srx_max_bytes ({}) must be >= min_srx_max_bytes ({})",
                self.protocol.default_srx_max_bytes, self.protocol.min_srx_max_bytes
            )));
        }
        if self.protocol.fs_policy_version.trim().is_empty() {
            return Err(ConfigError::Validation(
                "fs_policy_version must not be empty".to_string(),
            ));
        }
        self.protocol.fs_policy.validate()?;

        // Validate GUI config
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
        if self.gui.members_page_limit == 0 {
            return Err(ConfigError::Validation(
                "members_page_limit must be > 0".to_string(),
            ));
        }
        if self.gui.members_refresh_interval_secs == 0 {
            return Err(ConfigError::Validation(
                "members_refresh_interval_secs must be > 0".to_string(),
            ));
        }

        Ok(())
    }
}

// Helper methods for converting config values to Duration
impl ServerConfig {
    pub fn window_ttl(&self) -> Duration {
        Duration::from_secs(self.window_ttl_secs)
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

    pub fn api_timeout(&self) -> Duration {
        Duration::from_secs(self.api_timeout_secs)
    }
}

impl ProtocolConfig {
    pub fn window_duration(&self) -> Duration {
        Duration::from_secs(self.window_duration_secs)
    }

    pub fn epoch_rotation_interval(&self) -> Duration {
        Duration::from_secs(self.epoch_rotation_interval_secs)
    }

    pub fn receiver_cache_ttl(&self) -> Duration {
        Duration::from_secs(self.receiver_cache_ttl_secs)
    }
}

impl GuiConfig {
    pub fn members_refresh_interval(&self) -> Duration {
        Duration::from_secs(self.members_refresh_interval_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use tempfile::{NamedTempFile, TempDir};

    static LOAD_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct CurrentDirGuard(PathBuf);

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.original.as_deref() {
                Some(value) => {
                    // SAFETY: test-scoped environment mutation restored by this guard.
                    unsafe { std::env::set_var(self.key, value) };
                }
                None => {
                    // SAFETY: test-scoped environment mutation restored by this guard.
                    unsafe { std::env::remove_var(self.key) };
                }
            }
        }
    }

    fn set_env_guard(key: &'static str, value: &str) -> EnvVarGuard {
        let original = std::env::var(key).ok();
        // SAFETY: test-scoped environment mutation restored by `EnvVarGuard`.
        unsafe { std::env::set_var(key, value) };
        EnvVarGuard { key, original }
    }

    #[test]
    fn test_default_config() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let config = CityGConfig::default();
        assert_eq!(config.server.address, "0.0.0.0:8080");
        assert_eq!(config.client.default_server_url, "http://127.0.0.1:8080");
        assert_eq!(config.protocol.window_duration_secs, 120);
        assert!(!config.server.seed_demo_room);
        assert_eq!(config.protocol.fs_policy_version, "7");
        assert_eq!(config.protocol.fs_policy.h_seconds, 300);
        assert_eq!(config.gui.default_window_width, 1160.0);
        Ok(())
    }

    #[test]
    fn test_load_from_toml() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let toml_content = r#"
[server]
address = "0.0.0.0:9000"
websocket_capacity = 2000

[client]
default_server_url = "http://example.com:8080"
fetch_poll_interval_secs = 5

[protocol]
window_duration_secs = 20
max_concurrent_heads = 32

[gui]
default_window_width = 1920.0
default_window_height = 1080.0
"#;

        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(toml_content.as_bytes())?;
        temp_file.flush()?;

        let config = CityGConfig::from_file(temp_file.path())?;
        assert_eq!(config.server.address, "0.0.0.0:9000");
        assert_eq!(config.server.websocket_capacity, 2000);
        assert_eq!(config.client.default_server_url, "http://example.com:8080");
        assert_eq!(config.protocol.window_duration_secs, 20);
        assert_eq!(config.gui.default_window_width, 1920.0);
        Ok(())
    }

    #[test]
    fn test_load_from_json() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let json_content = r#"{
  "server": {
    "address": "0.0.0.0:9000",
    "websocket_capacity": 2000,
    "window_ttl_secs": 120
  },
  "client": {
    "default_server_url": "http://example.com:8080",
    "fetch_poll_interval_secs": 5,
    "fetch_retry_interval_secs": 10,
    "websocket_reconnect_delay_secs": 5,
    "api_timeout_secs": 30
  }
}"#;

        let mut temp_file = NamedTempFile::with_suffix(".json")?;
        temp_file.write_all(json_content.as_bytes())?;
        temp_file.flush()?;

        let config = CityGConfig::from_file(temp_file.path())?;
        assert_eq!(config.server.address, "0.0.0.0:9000");
        assert_eq!(config.client.default_server_url, "http://example.com:8080");
        Ok(())
    }

    #[test]
    fn test_validation() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut config = CityGConfig::default();
        assert!(config.validate().is_ok());

        config.server.websocket_capacity = 0;
        assert!(config.validate().is_err());

        config = CityGConfig::default();
        config.protocol.default_srx_max_bytes = 100;
        config.protocol.min_srx_max_bytes = 200;
        assert!(config.validate().is_err());
        Ok(())
    }

    #[test]
    fn test_env_overrides() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use ahash::AHashMap;
        let mut overrides = AHashMap::new();
        overrides.insert("CITYG_SERVER_ADDRESS", "0.0.0.0:9999".to_string());
        overrides.insert("CITYG_CLIENT_FETCH_POLL_INTERVAL_SECS", "7".to_string());

        let config = CityGConfig::default().apply_env_overrides_with(|key| {
            overrides.get(key).cloned().ok_or(VarError::NotPresent)
        })?;
        assert_eq!(config.server.address, "0.0.0.0:9999");
        assert_eq!(config.client.fetch_poll_interval_secs, 7);
        Ok(())
    }

    #[test]
    fn test_duration_conversions() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let config = CityGConfig::default();
        assert_eq!(config.client.fetch_poll_interval(), Duration::from_secs(3));
        assert_eq!(config.protocol.window_duration(), Duration::from_secs(120));
        Ok(())
    }

    // Additional comprehensive tests for coverage

    #[test]
    fn test_config_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let err = ConfigError::Validation("test error".to_string());
        assert_eq!(err.to_string(), "Validation error: test error");
        Ok(())
    }

    #[test]
    fn test_server_config_duration_helpers() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let server = ServerConfig::default();
        assert_eq!(server.window_ttl(), Duration::from_secs(120));

        let custom_server = ServerConfig {
            window_ttl_secs: 3600,
            ..Default::default()
        };
        assert_eq!(custom_server.window_ttl(), Duration::from_secs(3600));
        Ok(())
    }

    #[test]
    fn test_client_config_all_duration_helpers()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let client = ClientConfig::default();
        assert_eq!(client.fetch_poll_interval(), Duration::from_secs(3));
        assert_eq!(client.fetch_retry_interval(), Duration::from_secs(10));
        assert_eq!(client.websocket_reconnect_delay(), Duration::from_secs(5));
        assert_eq!(client.api_timeout(), Duration::from_secs(30));
        Ok(())
    }

    #[test]
    fn test_protocol_config_all_duration_helpers()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let protocol = ProtocolConfig::default();
        assert_eq!(protocol.window_duration(), Duration::from_secs(120));
        assert_eq!(protocol.epoch_rotation_interval(), Duration::from_secs(300));
        assert_eq!(protocol.receiver_cache_ttl(), Duration::from_secs(10));
        Ok(())
    }

    #[test]
    fn test_gui_config_duration_helpers() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let gui = GuiConfig::default();
        assert_eq!(gui.members_refresh_interval(), Duration::from_secs(30));
        Ok(())
    }

    #[test]
    fn test_fs_policy_validation_success() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let policy = FsPolicySettings::default();
        assert!(policy.validate().is_ok());
        Ok(())
    }

    #[test]
    fn test_fs_policy_validation_h_seconds_zero()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let policy = FsPolicySettings {
            h_seconds: 0,
            ..Default::default()
        };
        let result = policy.validate();
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(err.to_string().contains("h_seconds must be > 0"));
        }
        Ok(())
    }

    #[test]
    fn test_fs_policy_validation_checkpoint_interval_zero()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let policy = FsPolicySettings {
            checkpoint_interval_seconds: 0,
            ..Default::default()
        };
        let result = policy.validate();
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(
                err.to_string()
                    .contains("checkpoint_interval_seconds must be > 0")
            );
        }
        Ok(())
    }

    #[test]
    fn test_fs_policy_validation_checkpoint_less_than_h()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let policy = FsPolicySettings {
            h_seconds: 1000,
            checkpoint_interval_seconds: 500,
            ..Default::default()
        };
        let result = policy.validate();
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(err.to_string().contains("must be >= h_seconds"));
        }
        Ok(())
    }

    #[test]
    fn test_validation_all_server_fields() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut config = CityGConfig::default();

        config.server.websocket_capacity = 0;
        assert!(config.validate().is_err());

        config = CityGConfig::default();
        config.server.window_ttl_secs = 0;
        assert!(config.validate().is_err());
        Ok(())
    }

    #[test]
    fn test_validation_all_client_fields() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut config = CityGConfig::default();

        config.client.fetch_poll_interval_secs = 0;
        assert!(config.validate().is_err());

        config = CityGConfig::default();
        config.client.fetch_retry_interval_secs = 0;
        assert!(config.validate().is_err());
        Ok(())
    }

    #[test]
    fn test_validation_all_protocol_fields() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let mut config = CityGConfig::default();

        config.protocol.window_duration_secs = 0;
        assert!(config.validate().is_err());

        config = CityGConfig::default();
        config.protocol.max_concurrent_heads = 0;
        assert!(config.validate().is_err());

        config = CityGConfig::default();
        config.protocol.epoch_rotation_interval_secs = 0;
        assert!(config.validate().is_err());

        config = CityGConfig::default();
        config.protocol.fs_policy_version = "".to_string();
        assert!(config.validate().is_err());

        config = CityGConfig::default();
        config.protocol.fs_policy_version = "   ".to_string();
        assert!(config.validate().is_err());
        Ok(())
    }

    #[test]
    fn test_validation_all_gui_fields() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut config = CityGConfig::default();

        config.gui.default_window_width = 0.0;
        assert!(config.validate().is_err());

        config = CityGConfig::default();
        config.gui.default_window_width = -100.0;
        assert!(config.validate().is_err());

        config = CityGConfig::default();
        config.gui.default_window_height = 0.0;
        assert!(config.validate().is_err());

        config = CityGConfig::default();
        config.gui.members_page_limit = 0;
        assert!(config.validate().is_err());

        config = CityGConfig::default();
        config.gui.members_refresh_interval_secs = 0;
        assert!(config.validate().is_err());
        Ok(())
    }

    #[test]
    fn test_save_and_load_toml() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let original = CityGConfig::default();
        let temp_file = NamedTempFile::with_suffix(".toml")?;

        original.save(temp_file.path())?;
        let loaded = CityGConfig::from_file(temp_file.path())?;

        assert_eq!(original.server.address, loaded.server.address);
        assert_eq!(
            original.client.default_server_url,
            loaded.client.default_server_url
        );
        assert_eq!(
            original.protocol.window_duration_secs,
            loaded.protocol.window_duration_secs
        );
        Ok(())
    }

    #[test]
    fn test_save_and_load_json() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let original = CityGConfig::default();
        let temp_file = NamedTempFile::with_suffix(".json")?;

        original.save(temp_file.path())?;
        let loaded = CityGConfig::from_file(temp_file.path())?;

        assert_eq!(original.server.address, loaded.server.address);
        assert_eq!(
            original.client.default_server_url,
            loaded.client.default_server_url
        );
        Ok(())
    }

    #[test]
    fn test_comprehensive_env_overrides() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use ahash::AHashMap;
        let mut overrides = AHashMap::new();

        // Server overrides
        overrides.insert("CITYG_SERVER_ADDRESS", "1.2.3.4:5000".to_string());
        overrides.insert("CITYG_SERVER_WEBSOCKET_CAPACITY", "5000".to_string());
        overrides.insert("CITYG_SERVER_WINDOW_TTL_SECS", "7200".to_string());
        overrides.insert("CITYG_SERVER_SEED_DEMO_ROOM", "false".to_string());

        // Client overrides
        overrides.insert(
            "CITYG_CLIENT_DEFAULT_SERVER_URL",
            "http://test.com".to_string(),
        );
        overrides.insert("CITYG_CLIENT_FETCH_POLL_INTERVAL_SECS", "15".to_string());
        overrides.insert("CITYG_CLIENT_FETCH_RETRY_INTERVAL_SECS", "20".to_string());
        overrides.insert(
            "CITYG_CLIENT_WEBSOCKET_RECONNECT_DELAY_SECS",
            "10".to_string(),
        );
        overrides.insert("CITYG_CLIENT_API_TIMEOUT_SECS", "60".to_string());

        // Protocol overrides
        overrides.insert("CITYG_PROTOCOL_WINDOW_DURATION_SECS", "30".to_string());
        overrides.insert("CITYG_PROTOCOL_MAX_CONCURRENT_HEADS", "64".to_string());
        overrides.insert(
            "CITYG_PROTOCOL_EPOCH_ROTATION_INTERVAL_SECS",
            "600".to_string(),
        );
        overrides.insert(
            "CITYG_PROTOCOL_DEFAULT_SRX_MAX_BYTES",
            "2048576".to_string(),
        );
        overrides.insert("CITYG_PROTOCOL_MAX_HP_PROOF_BYTES", "524288".to_string());
        overrides.insert("CITYG_PROTOCOL_MAX_VRF_PROOF_BYTES", "6144".to_string());
        overrides.insert("CITYG_PROTOCOL_FS_CAPSS_MAX_BYTES", "16384".to_string());
        overrides.insert(
            "CITYG_PROTOCOL_SRX_SMALLWOOD_MAX_BYTES",
            "16384".to_string(),
        );
        overrides.insert("CITYG_PROTOCOL_MAX_HP_ENVELOPE_BYTES", "16384".to_string());
        overrides.insert("CITYG_PROTOCOL_MIN_SRX_MAX_BYTES", "262144".to_string());
        overrides.insert("CITYG_PROTOCOL_RECEIVER_CACHE_TTL_SECS", "20".to_string());
        overrides.insert(
            "CITYG_PROTOCOL_FS_POLICY_VERSION",
            "custom-policy".to_string(),
        );

        // FS Policy overrides
        overrides.insert("CITYG_PROTOCOL_FS_POLICY_H_SECONDS", "600".to_string());
        overrides.insert(
            "CITYG_PROTOCOL_FS_POLICY_CHECKPOINT_INTERVAL_SECS",
            "7200".to_string(),
        );
        overrides.insert(
            "CITYG_PROTOCOL_FS_POLICY_CHECKPOINT_HEAD_THRESHOLD",
            "48".to_string(),
        );
        overrides.insert("CITYG_PROTOCOL_FS_POLICY_SLACK_ANCHOR", "10".to_string());
        overrides.insert(
            "CITYG_PROTOCOL_FS_POLICY_SLACK_FIRST_DEVICE",
            "5".to_string(),
        );
        overrides.insert("CITYG_PROTOCOL_FS_POLICY_SLACK_DEVICE", "8".to_string());

        // GUI overrides
        overrides.insert("CITYG_GUI_DEFAULT_WINDOW_WIDTH", "1920.0".to_string());
        overrides.insert("CITYG_GUI_DEFAULT_WINDOW_HEIGHT", "1080.0".to_string());
        overrides.insert("CITYG_GUI_MEMBERS_PAGE_LIMIT", "500".to_string());
        overrides.insert("CITYG_GUI_MEMBERS_REFRESH_INTERVAL_SECS", "60".to_string());

        let config = CityGConfig::default().apply_env_overrides_with(|key| {
            overrides.get(key).cloned().ok_or(VarError::NotPresent)
        })?;

        // Verify all overrides
        assert_eq!(config.server.address, "1.2.3.4:5000");
        assert_eq!(config.server.websocket_capacity, 5000);
        assert_eq!(config.server.window_ttl_secs, 7200);
        assert!(!config.server.seed_demo_room);

        assert_eq!(config.client.default_server_url, "http://test.com");
        assert_eq!(config.client.fetch_poll_interval_secs, 15);
        assert_eq!(config.client.fetch_retry_interval_secs, 20);
        assert_eq!(config.client.websocket_reconnect_delay_secs, 10);
        assert_eq!(config.client.api_timeout_secs, 60);

        assert_eq!(config.protocol.window_duration_secs, 30);
        assert_eq!(config.protocol.max_concurrent_heads, 64);
        assert_eq!(config.protocol.epoch_rotation_interval_secs, 600);
        assert_eq!(config.protocol.default_srx_max_bytes, 2048576);
        assert_eq!(config.protocol.max_hp_proof_bytes, 524288);
        assert_eq!(config.protocol.max_vrf_proof_bytes, 6144);
        assert_eq!(config.protocol.fs_capss_max_bytes, 16384);
        assert_eq!(config.protocol.srx_smallwood_max_bytes, 16384);
        assert_eq!(config.protocol.max_hp_envelope_bytes, 16384);
        assert_eq!(config.protocol.min_srx_max_bytes, 262144);
        assert_eq!(config.protocol.receiver_cache_ttl_secs, 20);
        assert_eq!(config.protocol.fs_policy_version, "custom-policy");

        assert_eq!(config.protocol.fs_policy.h_seconds, 600);
        assert_eq!(config.protocol.fs_policy.checkpoint_interval_seconds, 7200);
        assert_eq!(config.protocol.fs_policy.checkpoint_head_threshold, 48);
        assert_eq!(config.protocol.fs_policy.slack_anchor, 10);
        assert_eq!(config.protocol.fs_policy.slack_first_device, 5);
        assert_eq!(config.protocol.fs_policy.slack_device, 8);

        assert_eq!(config.gui.default_window_width, 1920.0);
        assert_eq!(config.gui.default_window_height, 1080.0);
        assert_eq!(config.gui.members_page_limit, 500);
        assert_eq!(config.gui.members_refresh_interval_secs, 60);
        Ok(())
    }

    #[test]
    fn test_env_override_parse_errors() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use ahash::AHashMap;
        let cases = [
            (
                "CITYG_SERVER_WEBSOCKET_CAPACITY",
                "not-a-number",
                "Invalid websocket_capacity",
            ),
            (
                "CITYG_SERVER_SEED_DEMO_ROOM",
                "not-bool",
                "Invalid seed_demo_room flag",
            ),
            (
                "CITYG_CLIENT_FETCH_POLL_INTERVAL_SECS",
                "bad",
                "Invalid fetch_poll_interval_secs",
            ),
            (
                "CITYG_CLIENT_FETCH_RETRY_INTERVAL_SECS",
                "bad",
                "Invalid fetch_retry_interval_secs",
            ),
            (
                "CITYG_CLIENT_WEBSOCKET_RECONNECT_DELAY_SECS",
                "bad",
                "Invalid websocket_reconnect_delay_secs",
            ),
            (
                "CITYG_PROTOCOL_WINDOW_DURATION_SECS",
                "bad",
                "Invalid window_duration_secs",
            ),
            (
                "CITYG_PROTOCOL_MAX_CONCURRENT_HEADS",
                "bad",
                "Invalid max_concurrent_heads",
            ),
            (
                "CITYG_PROTOCOL_EPOCH_ROTATION_INTERVAL_SECS",
                "bad",
                "Invalid epoch_rotation_interval_secs",
            ),
            (
                "CITYG_PROTOCOL_DEFAULT_SRX_MAX_BYTES",
                "bad",
                "Invalid default_srx_max_bytes",
            ),
            (
                "CITYG_PROTOCOL_MAX_HP_PROOF_BYTES",
                "bad",
                "Invalid max_hp_proof_bytes",
            ),
            (
                "CITYG_PROTOCOL_MAX_VRF_PROOF_BYTES",
                "bad",
                "Invalid max_vrf_proof_bytes",
            ),
            (
                "CITYG_PROTOCOL_FS_CAPSS_MAX_BYTES",
                "bad",
                "Invalid fs_capss_max_bytes",
            ),
            (
                "CITYG_PROTOCOL_SRX_SMALLWOOD_MAX_BYTES",
                "bad",
                "Invalid srx_smallwood_max_bytes",
            ),
            (
                "CITYG_PROTOCOL_MAX_HP_ENVELOPE_BYTES",
                "bad",
                "Invalid max_hp_envelope_bytes",
            ),
            (
                "CITYG_PROTOCOL_MIN_SRX_MAX_BYTES",
                "bad",
                "Invalid min_srx_max_bytes",
            ),
            (
                "CITYG_PROTOCOL_RECEIVER_CACHE_TTL_SECS",
                "bad",
                "Invalid receiver_cache_ttl_secs",
            ),
            (
                "CITYG_PROTOCOL_FS_POLICY_H_SECONDS",
                "bad",
                "Invalid fs_policy.h_seconds",
            ),
            (
                "CITYG_PROTOCOL_FS_POLICY_CHECKPOINT_INTERVAL_SECS",
                "bad",
                "Invalid fs_policy.checkpoint_interval_seconds",
            ),
            (
                "CITYG_PROTOCOL_FS_POLICY_CHECKPOINT_HEAD_THRESHOLD",
                "bad",
                "Invalid fs_policy.checkpoint_head_threshold",
            ),
            (
                "CITYG_PROTOCOL_FS_POLICY_SLACK_ANCHOR",
                "bad",
                "Invalid fs_policy.slack_anchor",
            ),
            (
                "CITYG_PROTOCOL_FS_POLICY_SLACK_FIRST_DEVICE",
                "bad",
                "Invalid fs_policy.slack_first_device",
            ),
            (
                "CITYG_PROTOCOL_FS_POLICY_SLACK_DEVICE",
                "bad",
                "Invalid fs_policy.slack_device",
            ),
            (
                "CITYG_GUI_DEFAULT_WINDOW_WIDTH",
                "bad",
                "Invalid default_window_width",
            ),
            (
                "CITYG_GUI_DEFAULT_WINDOW_HEIGHT",
                "bad",
                "Invalid default_window_height",
            ),
            (
                "CITYG_GUI_MEMBERS_PAGE_LIMIT",
                "bad",
                "Invalid members_page_limit",
            ),
            (
                "CITYG_GUI_MEMBERS_REFRESH_INTERVAL_SECS",
                "bad",
                "Invalid members_refresh_interval_secs",
            ),
        ];

        for (key, value, expected_msg) in cases {
            let mut overrides = AHashMap::new();
            overrides.insert(key, value.to_string());
            let result = CityGConfig::default().apply_env_overrides_with(|lookup| {
                overrides.get(lookup).cloned().ok_or(VarError::NotPresent)
            });
            assert!(result.is_err(), "{key} should fail parsing");
            let err = result.expect_err("expected parse error");
            assert!(
                err.to_string().contains(expected_msg),
                "unexpected error for {key}: {err}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_load_prefers_cwd_files_before_other_sources()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let _lock = LOAD_ENV_LOCK.lock().expect("lock poisoned");
        let temp_dir = TempDir::new()?;
        let original = std::env::current_dir()?;
        let _cwd_guard = CurrentDirGuard(original);
        std::env::set_current_dir(temp_dir.path())?;

        let cwd_toml = r#"
[server]
address = "10.1.1.1:9001"
websocket_capacity = 2222
window_ttl_secs = 500

[client]
default_server_url = "http://10.1.1.1:9001"
"#;
        std::fs::write(temp_dir.path().join("cityg.toml"), cwd_toml)?;

        let loaded = CityGConfig::load()?;
        assert_eq!(loaded.server.address, "10.1.1.1:9001");
        assert_eq!(loaded.server.websocket_capacity, 2222);

        std::fs::remove_file(temp_dir.path().join("cityg.toml"))?;
        let cwd_json = r#"{
  "server": {
    "address": "10.2.2.2:9002",
    "websocket_capacity": 3333,
    "window_ttl_secs": 600
  },
  "client": {
    "default_server_url": "http://10.2.2.2:9002",
    "fetch_poll_interval_secs": 9,
    "fetch_retry_interval_secs": 11,
    "websocket_reconnect_delay_secs": 7,
    "api_timeout_secs": 45
  }
}"#;
        std::fs::write(temp_dir.path().join("cityg.json"), cwd_json)?;

        let loaded = CityGConfig::load()?;
        assert_eq!(loaded.server.address, "10.2.2.2:9002");
        assert_eq!(loaded.server.websocket_capacity, 3333);
        Ok(())
    }

    #[test]
    fn test_load_reads_user_config_directory_when_cwd_missing()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let _lock = LOAD_ENV_LOCK.lock().expect("lock poisoned");
        let temp_home = TempDir::new()?;
        let temp_xdg = TempDir::new()?;
        let _home_guard = set_env_guard("HOME", temp_home.path().to_string_lossy().as_ref());
        let _xdg_guard = set_env_guard(
            "XDG_CONFIG_HOME",
            temp_xdg.path().to_string_lossy().as_ref(),
        );

        let cwd_temp = TempDir::new()?;
        let original = std::env::current_dir()?;
        let _cwd_guard = CurrentDirGuard(original);
        std::env::set_current_dir(cwd_temp.path())?;

        let cfg_toml = r#"
[server]
address = "10.9.9.9:9090"
websocket_capacity = 4444
window_ttl_secs = 777

[protocol]
window_duration_secs = 123
"#;

        let xdg_path = temp_xdg.path().join("cityg");
        std::fs::create_dir_all(&xdg_path)?;
        std::fs::write(xdg_path.join("config.toml"), cfg_toml)?;

        // Also prepare the macOS-style fallback location for portability.
        let mac_path = temp_home
            .path()
            .join("Library")
            .join("Application Support")
            .join("cityg");
        std::fs::create_dir_all(&mac_path)?;
        std::fs::write(mac_path.join("config.toml"), cfg_toml)?;

        let loaded = CityGConfig::load()?;
        assert_eq!(loaded.server.address, "10.9.9.9:9090");
        assert_eq!(loaded.server.websocket_capacity, 4444);
        assert_eq!(loaded.protocol.window_duration_secs, 123);
        Ok(())
    }

    #[test]
    fn test_from_file_missing_file() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result = CityGConfig::from_file("nonexistent_file.toml");
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_from_file_invalid_toml() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let invalid_toml = "this is not valid toml {{{";
        let mut temp_file = NamedTempFile::with_suffix(".toml")?;
        temp_file.write_all(invalid_toml.as_bytes())?;
        temp_file.flush()?;

        let result = CityGConfig::from_file(temp_file.path());
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_from_file_invalid_json() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let invalid_json = "{ this is not valid json }";
        let mut temp_file = NamedTempFile::with_suffix(".json")?;
        temp_file.write_all(invalid_json.as_bytes())?;
        temp_file.flush()?;

        let result = CityGConfig::from_file(temp_file.path());
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_clone_and_debug() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let config = CityGConfig::default();
        let cloned = config.clone();

        assert_eq!(config.server.address, cloned.server.address);

        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("CityGConfig"));
        Ok(())
    }

    #[test]
    fn test_all_default_impls() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let _server = ServerConfig::default();
        let _client = ClientConfig::default();
        let _protocol = ProtocolConfig::default();
        let _fs_policy = FsPolicySettings::default();
        let _gui = GuiConfig::default();
        let _config = CityGConfig::default();
        Ok(())
    }

    #[test]
    fn test_serde_roundtrip() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let original = CityGConfig::default();

        // JSON roundtrip
        let json = serde_json::to_string(&original)?;
        let from_json: CityGConfig = serde_json::from_str(&json)?;
        assert_eq!(original.server.address, from_json.server.address);

        // TOML roundtrip
        let toml_str = toml::to_string(&original)?;
        let from_toml: CityGConfig = toml::from_str(&toml_str)?;
        assert_eq!(original.server.address, from_toml.server.address);
        Ok(())
    }
}
