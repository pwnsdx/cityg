//! Policy-derived state shared across acceptance flows.

use crate::mhw::FreezeError;

use super::FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceChainState {
    pub last_commit: Option<[u8; 32]>,
    pub last_ec: u64,
    pub last_pcs_refresh_ec: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BarrierGroupState {
    pub barrier_initialized: bool,
    pub barrier_version: u64,
    pub barrier_roots_hash: [u8; 32],
    pub kem_tree_hash_after: [u8; 32],
    pub n_max: u64,
    pub max_barrier_update_bytes: usize,
    pub last_pcs_refresh_ec: Option<u64>,
    pub pcs_refresh_min_delta_device_ec: u64,
    pub pcs_refresh_min_delta_group_ec: u64,
    pub pcs_refresh_slot_width_ec: u64,
}

impl Default for BarrierGroupState {
    fn default() -> Self {
        Self {
            barrier_initialized: false,
            barrier_version: 0,
            barrier_roots_hash: [0u8; 32],
            kem_tree_hash_after: [0u8; 32],
            n_max: 1_024,
            max_barrier_update_bytes: 1_048_576,
            last_pcs_refresh_ec: None,
            pcs_refresh_min_delta_device_ec: 1,
            pcs_refresh_min_delta_group_ec: 1,
            pcs_refresh_slot_width_ec: 1,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsCaps {
    pub window_periods: u64,
    pub anchor_max: u64,
    pub first_device: u64,
    pub device_max: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsPolicyConfig {
    pub h: u64,
    pub checkpoint_interval: u64,
    pub checkpoint_head_threshold: u64,
    pub slack_anchor: u64,
    pub slack_first_device: u64,
    pub slack_device: u64,
}

impl Default for FsPolicyConfig {
    fn default() -> Self {
        Self {
            h: 300,
            checkpoint_interval: 3600,
            checkpoint_head_threshold: 24,
            slack_anchor: 0,
            slack_first_device: 0,
            slack_device: 4,
        }
    }
}

impl FsPolicyConfig {
    pub fn synthesize_caps(&self) -> Result<FsCaps, FreezeError> {
        if self.h == 0 || self.checkpoint_interval == 0 {
            return Err(FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE);
        }
        if self.checkpoint_interval < self.h {
            return Err(FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE);
        }
        let window_periods = self.checkpoint_interval.div_ceil(self.h);
        if window_periods == 0 {
            return Err(FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE);
        }
        let anchor_max = window_periods + self.slack_anchor;
        let first_device = window_periods + self.slack_first_device;
        let device_max = window_periods + self.slack_device;
        if anchor_max < window_periods || first_device < window_periods {
            return Err(FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE);
        }
        Ok(FsCaps {
            window_periods,
            anchor_max,
            first_device,
            device_max,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesize_caps_rejects_zero_and_inverted_windows() {
        let cfg = FsPolicyConfig {
            h: 0,
            ..FsPolicyConfig::default()
        };
        assert_eq!(
            cfg.synthesize_caps().expect_err("h=0 must freeze"),
            FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE
        );

        let cfg = FsPolicyConfig {
            checkpoint_interval: 0,
            ..FsPolicyConfig::default()
        };
        assert_eq!(
            cfg.synthesize_caps()
                .expect_err("checkpoint_interval=0 must freeze"),
            FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE
        );

        let cfg = FsPolicyConfig {
            h: 600,
            checkpoint_interval: 300,
            ..FsPolicyConfig::default()
        };
        assert_eq!(
            cfg.synthesize_caps()
                .expect_err("checkpoint interval below h must freeze"),
            FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE
        );
    }

    #[test]
    fn synthesize_caps_computes_expected_values() {
        let cfg = FsPolicyConfig {
            h: 300,
            checkpoint_interval: 1000,
            checkpoint_head_threshold: 24,
            slack_anchor: 2,
            slack_first_device: 3,
            slack_device: 4,
        };
        let caps = cfg
            .synthesize_caps()
            .unwrap_or_else(|err| panic!("unexpected error: {err:?}"));
        assert_eq!(caps.window_periods, 4);
        assert_eq!(caps.anchor_max, 6);
        assert_eq!(caps.first_device, 7);
        assert_eq!(caps.device_max, 8);
    }

    #[test]
    fn barrier_group_state_defaults_are_profile_compatible() {
        let state = BarrierGroupState::default();
        assert!(!state.barrier_initialized);
        assert_eq!(state.barrier_version, 0);
        assert_eq!(state.n_max, 1_024);
        assert!(state.n_max.is_power_of_two());
        assert!(state.max_barrier_update_bytes > 0);
        assert_eq!(state.pcs_refresh_min_delta_device_ec, 1);
        assert_eq!(state.pcs_refresh_min_delta_group_ec, 1);
        assert_eq!(state.pcs_refresh_slot_width_ec, 1);
        assert_eq!(state.last_pcs_refresh_ec, None);
    }
}
