//! Policy-derived state shared across acceptance flows.

use crate::mhw::FreezeError;

use super::FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE;

pub type DeviceKey = (Vec<u8>, Vec<u8>);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceChainState {
    pub last_commit: Option<[u8; 32]>,
    pub last_ec: u64,
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
    pub h_seconds: u64,
    pub checkpoint_interval_seconds: u64,
    pub checkpoint_head_threshold: u64,
    pub slack_anchor: u64,
    pub slack_first_device: u64,
    pub slack_device: u64,
}

impl Default for FsPolicyConfig {
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

impl FsPolicyConfig {
    pub fn synthesize_caps(&self) -> Result<FsCaps, FreezeError> {
        if self.h_seconds == 0 || self.checkpoint_interval_seconds == 0 {
            return Err(FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE);
        }
        if self.checkpoint_interval_seconds < self.h_seconds {
            return Err(FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE);
        }
        let window_periods = self.checkpoint_interval_seconds.div_ceil(self.h_seconds);
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
            h_seconds: 0,
            ..FsPolicyConfig::default()
        };
        assert_eq!(
            cfg.synthesize_caps().expect_err("h_seconds=0 must freeze"),
            FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE
        );

        let cfg = FsPolicyConfig {
            checkpoint_interval_seconds: 0,
            ..FsPolicyConfig::default()
        };
        assert_eq!(
            cfg.synthesize_caps()
                .expect_err("checkpoint_interval_seconds=0 must freeze"),
            FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE
        );

        let cfg = FsPolicyConfig {
            h_seconds: 600,
            checkpoint_interval_seconds: 300,
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
            h_seconds: 300,
            checkpoint_interval_seconds: 1000,
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
}
