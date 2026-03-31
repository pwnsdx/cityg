use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cityg_server::{CityGServer, ServerConfig};
use msphf_orchestrator::{AcceptanceOptions, FsPolicyConfig};

/// Build a `cityg-server` configuration from the shared repository config shape.
#[must_use]
pub fn server_config_from_cityg_config(cfg: &cityg_config::CityGConfig) -> ServerConfig {
    let mut server_cfg = ServerConfig::new();
    server_cfg.enable_global_history_authority();
    server_cfg.h_max = Some(cfg.protocol.max_concurrent_heads);
    server_cfg.window_ttl = Some(Duration::from_secs(cfg.server.window_ttl_secs));
    server_cfg.state_path = cfg.server.state_path.clone();

    let mut acceptance = AcceptanceOptions {
        srx_max_bytes: cfg.protocol.default_srx_max_bytes,
        fs_policy_config: fs_policy_from_settings(&cfg.protocol.fs_policy),
        ..AcceptanceOptions::default()
    };

    apply_demo_seed_acceptance(&mut acceptance, cfg.server.seed_demo_room);

    server_cfg.acceptance_options = Some(acceptance);
    server_cfg
}

/// Build a `CityGServer` from the shared repository configuration shape.
#[must_use]
pub fn server_from_cityg_config(cfg: &cityg_config::CityGConfig) -> CityGServer {
    let mut server = CityGServer::new(server_config_from_cityg_config(cfg));
    let version = cfg.protocol.fs_policy_version.clone();
    {
        let ctx = server.context_mut();
        ctx.set_allowed_fs_policy_version(Some(version.clone()));
        ctx.set_fs_policy_version(Some(version));
    }
    server
}

/// Build a lane-specific `CityGServer` while preserving the shared config shape.
#[must_use]
pub fn server_from_cityg_config_for_lane(
    cfg: &cityg_config::CityGConfig,
    lane_index: usize,
    lane_count: usize,
) -> CityGServer {
    if lane_count <= 1 || cfg.server.state_path.is_none() {
        return server_from_cityg_config(cfg);
    }

    let mut lane_cfg = cfg.clone();
    lane_cfg.server.state_path = cfg
        .server
        .state_path
        .as_ref()
        .map(|path| lane_state_path(path, lane_index, lane_count));
    server_from_cityg_config(&lane_cfg)
}

/// Compute the per-lane journal path used by the native API topology.
#[must_use]
pub fn lane_state_path(base: &Path, lane_index: usize, lane_count: usize) -> PathBuf {
    if lane_count <= 1 {
        return base.to_path_buf();
    }

    let stem = base
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("cityg-server");
    let lane_stem = format!("{stem}.lane-{lane_index:02}");
    match base.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if !ext.is_empty() => base.with_file_name(format!("{lane_stem}.{ext}")),
        _ => base.with_file_name(lane_stem),
    }
}

/// Round a wall-clock timestamp down to the forward-secrecy period boundary.
#[must_use]
pub fn aligned_fs_epoch_base_ts(now: SystemTime, period_seconds: u64) -> u64 {
    let period = period_seconds.max(1);
    let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    now_secs - (now_secs % period)
}

fn fs_policy_from_settings(settings: &cityg_config::FsPolicySettings) -> FsPolicyConfig {
    FsPolicyConfig {
        h: settings.h_seconds,
        checkpoint_interval: settings.checkpoint_interval_seconds,
        checkpoint_head_threshold: settings.checkpoint_head_threshold,
        slack_anchor: settings.slack_anchor,
        slack_first_device: settings.slack_first_device,
        slack_device: settings.slack_device,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn apply_demo_seed_acceptance(acceptance: &mut AcceptanceOptions, seed_demo_room: bool) {
    if !seed_demo_room {
        return;
    }

    acceptance.bootstrap_policy = msphf_orchestrator::BootstrapPolicy::CaMlDsa {
        public_key: cityg_client::demo::bootstrap_public().to_vec(),
    };
    let mut registry = std::collections::BTreeMap::new();
    registry.insert(
        cityg_client::demo::DEMO_GID.to_vec(),
        cityg_client::demo::kbroad_public().to_vec(),
    );
    acceptance.kbroad_registry = Some(registry);
}

#[cfg(target_arch = "wasm32")]
fn apply_demo_seed_acceptance(_acceptance: &mut AcceptanceOptions, _seed_demo_room: bool) {
    // Demo seeding depends on host-only fixtures and local filesystem state.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_fs_epoch_base_ts_rounds_down_to_period() {
        let now = UNIX_EPOCH + Duration::from_secs(1_001);
        assert_eq!(aligned_fs_epoch_base_ts(now, 300), 900);
    }

    #[test]
    fn server_from_cityg_config_leaves_fs_base_ts_unset() {
        let config = cityg_config::CityGConfig::default();
        let server = server_from_cityg_config(&config);
        assert!(server.context().fs_base_ts().is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn server_config_from_cityg_config_seeds_demo_bootstrap_acceptance() {
        let mut config = cityg_config::CityGConfig::default();
        config.server.seed_demo_room = true;

        let server_config = server_config_from_cityg_config(&config);
        let acceptance = server_config
            .acceptance_options
            .expect("acceptance options should be set");

        match acceptance.bootstrap_policy {
            msphf_orchestrator::BootstrapPolicy::CaMlDsa { public_key } => {
                assert_eq!(public_key, cityg_client::demo::bootstrap_public());
            }
            _ => panic!("unexpected bootstrap policy"),
        }
        let registry = acceptance.kbroad_registry.expect("kbroad registry");
        assert_eq!(
            registry.get(cityg_client::demo::DEMO_GID.as_slice()),
            Some(&cityg_client::demo::kbroad_public().to_vec())
        );
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn server_config_from_cityg_config_ignores_demo_bootstrap_on_wasm() {
        let mut config = cityg_config::CityGConfig::default();
        config.server.seed_demo_room = true;

        let server_config = server_config_from_cityg_config(&config);
        let acceptance = server_config
            .acceptance_options
            .expect("acceptance options should be set");

        assert!(matches!(
            acceptance.bootstrap_policy,
            msphf_orchestrator::BootstrapPolicy::Disabled
        ));
        assert!(acceptance.kbroad_registry.is_none());
    }

    #[test]
    fn lane_state_path_suffixes_multi_lane_journals() {
        let path = Path::new("/tmp/cityg-server.journal");
        let lane_path = lane_state_path(path, 3, 8);
        assert_eq!(
            lane_path,
            PathBuf::from("/tmp/cityg-server.lane-03.journal")
        );
    }
}
