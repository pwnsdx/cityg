use anyhow::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingBarrierRecoveryReason {
    InsufficientAuthenticatedHistory,
    ContradictoryAuthenticatedHistory,
    LegacyPendingLocatorMissing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingBarrierObservation {
    pub observed_barrier_version: u64,
    pub observed_fs_ec: Option<u64>,
    pub observed_barrier_update_reason: Option<u64>,
    pub accepted_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingBarrierLookupStatus {
    Pending,
    Accepted,
    Superseded,
    FinalRejected,
    NotFound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingBarrierHistoryInput {
    pub current_barrier_version: u64,
    pub pending_barrier_version: u64,
    pub pending_we_epoch_id: [u8; 32],
    pub status: PendingBarrierLookupStatus,
    pub accepted_barrier_version: Option<u64>,
    pub accepted_fs_ec: Option<u64>,
    pub accepted_reason: Option<u64>,
    pub accepted_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingBarrierHistoryResolution {
    Unchanged,
    Activate {
        we_epoch_id: [u8; 32],
        observation: PendingBarrierObservation,
    },
    Discard,
    RecoveryRequired(PendingBarrierRecoveryReason),
}

pub fn pending_activation_source_matches<T: Eq>(
    current_source: &T,
    expected_source: Option<&T>,
) -> bool {
    expected_source.is_none_or(|expected| current_source == expected)
}

pub fn pending_barrier_matches_observation(
    pending_barrier_version: u64,
    pending_fs_ec: u64,
    pending_barrier_update_reason: Option<u64>,
    pending_barrier_update_digest: [u8; 32],
    observation: PendingBarrierObservation,
) -> bool {
    observation
        .accepted_digest
        .is_some_and(|digest| digest == pending_barrier_update_digest)
        && observation.observed_barrier_version == pending_barrier_version
        && observation.observed_fs_ec == Some(pending_fs_ec)
        && observation.observed_barrier_update_reason == pending_barrier_update_reason
}

pub fn resolve_pending_barrier_history(
    input: PendingBarrierHistoryInput,
) -> Result<PendingBarrierHistoryResolution> {
    if input.pending_we_epoch_id == [0u8; 32] {
        return Ok(
            if input.current_barrier_version > input.pending_barrier_version {
                PendingBarrierHistoryResolution::RecoveryRequired(
                    PendingBarrierRecoveryReason::LegacyPendingLocatorMissing,
                )
            } else {
                PendingBarrierHistoryResolution::Unchanged
            },
        );
    }

    Ok(match input.status {
        PendingBarrierLookupStatus::Accepted => match input.accepted_barrier_version {
            Some(observed_barrier_version) => PendingBarrierHistoryResolution::Activate {
                we_epoch_id: input.pending_we_epoch_id,
                observation: PendingBarrierObservation {
                    observed_barrier_version,
                    observed_fs_ec: input.accepted_fs_ec,
                    observed_barrier_update_reason: input.accepted_reason,
                    accepted_digest: input.accepted_digest,
                },
            },
            None => PendingBarrierHistoryResolution::RecoveryRequired(
                PendingBarrierRecoveryReason::ContradictoryAuthenticatedHistory,
            ),
        },
        PendingBarrierLookupStatus::Superseded | PendingBarrierLookupStatus::FinalRejected => {
            PendingBarrierHistoryResolution::Discard
        }
        PendingBarrierLookupStatus::Pending | PendingBarrierLookupStatus::NotFound => {
            if input.current_barrier_version > input.pending_barrier_version {
                PendingBarrierHistoryResolution::RecoveryRequired(
                    PendingBarrierRecoveryReason::InsufficientAuthenticatedHistory,
                )
            } else {
                PendingBarrierHistoryResolution::Unchanged
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn pending_barrier_matches_observation_requires_exact_match() {
        let matches = pending_barrier_matches_observation(
            7,
            31,
            Some(2),
            [0x41; 32],
            PendingBarrierObservation {
                observed_barrier_version: 7,
                observed_fs_ec: Some(31),
                observed_barrier_update_reason: Some(2),
                accepted_digest: Some([0x41; 32]),
            },
        );
        assert!(matches);

        let mismatched = pending_barrier_matches_observation(
            7,
            31,
            Some(2),
            [0x41; 32],
            PendingBarrierObservation {
                observed_barrier_version: 8,
                observed_fs_ec: Some(31),
                observed_barrier_update_reason: Some(2),
                accepted_digest: Some([0x41; 32]),
            },
        );
        assert!(!mismatched);
    }

    #[test]
    fn resolve_pending_barrier_history_requires_recovery_for_legacy_locator_after_newer_version()
    -> Result<()> {
        let resolution = resolve_pending_barrier_history(PendingBarrierHistoryInput {
            current_barrier_version: 6,
            pending_barrier_version: 5,
            pending_we_epoch_id: [0u8; 32],
            status: PendingBarrierLookupStatus::Pending,
            accepted_barrier_version: None,
            accepted_fs_ec: None,
            accepted_reason: None,
            accepted_digest: None,
        })?;
        assert_eq!(
            resolution,
            PendingBarrierHistoryResolution::RecoveryRequired(
                PendingBarrierRecoveryReason::LegacyPendingLocatorMissing
            )
        );
        Ok(())
    }

    #[test]
    fn resolve_pending_barrier_history_yields_activation_observation() -> Result<()> {
        let resolution = resolve_pending_barrier_history(PendingBarrierHistoryInput {
            current_barrier_version: 9,
            pending_barrier_version: 9,
            pending_we_epoch_id: [0xAB; 32],
            status: PendingBarrierLookupStatus::Accepted,
            accepted_barrier_version: Some(9),
            accepted_fs_ec: Some(31),
            accepted_reason: Some(1),
            accepted_digest: Some([0xCD; 32]),
        })?;
        assert_eq!(
            resolution,
            PendingBarrierHistoryResolution::Activate {
                we_epoch_id: [0xAB; 32],
                observation: PendingBarrierObservation {
                    observed_barrier_version: 9,
                    observed_fs_ec: Some(31),
                    observed_barrier_update_reason: Some(1),
                    accepted_digest: Some([0xCD; 32]),
                },
            }
        );
        Ok(())
    }
}
