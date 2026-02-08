use std::time::Duration;

use ahash::AHashMap;
use msphf_core::MsphfError;

use crate::{
    AcceptanceKind, AnchorAcceptanceResult, PivotParity, mhw::FreezeError, time::AcceptInstant,
};

pub const FREEZE_MH_PARENT_MISMATCH: FreezeError = FreezeError {
    code: 926,
    reason: "mh_parent_mismatch",
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheEntry {
    parent_root: Vec<u8>,
    wid: [u8; 32],
    pivot_parity: PivotParity,
    accept_time: AcceptInstant,
}

#[derive(Debug)]
pub enum ReceiverError {
    Freeze(FreezeError),
    EpochExpired,
    UnknownHead,
    Msphf(MsphfError),
}

impl std::fmt::Display for ReceiverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiverError::Freeze(code) => write!(f, "Freeze error: {:?}", code),
            ReceiverError::EpochExpired => write!(f, "Epoch expired"),
            ReceiverError::UnknownHead => write!(f, "Unknown head"),
            ReceiverError::Msphf(err) => write!(f, "MSPHF error: {:?}", err),
        }
    }
}

impl std::error::Error for ReceiverError {}

impl From<MsphfError> for ReceiverError {
    fn from(err: MsphfError) -> Self {
        ReceiverError::Msphf(err)
    }
}

#[derive(Clone)]
pub struct ReceiverCache {
    ttl: Duration,
    entries: AHashMap<[u8; 32], CacheEntry>,
}

impl ReceiverCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: AHashMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(Duration::from_secs(10))
    }

    pub fn set_ttl(&mut self, ttl: Duration, now: AcceptInstant) {
        self.ttl = ttl;
        self.prune(now, None);
    }

    fn prune(&mut self, now: AcceptInstant, target: Option<&[u8; 32]>) -> bool {
        let mut target_expired = false;
        self.entries.retain(|we, entry| {
            let expired = now.duration_since(entry.accept_time) > self.ttl;
            if expired && target == Some(we) {
                target_expired = true;
            }
            !expired
        });
        target_expired
    }

    fn insert(&mut self, acceptance: &AnchorAcceptanceResult) {
        let now = acceptance.outcome.accept_time;
        self.entries.insert(
            acceptance.outcome.we_epoch_id,
            CacheEntry {
                parent_root: acceptance.pivot_parity.parent_root.to_vec(),
                wid: acceptance.outcome.wid,
                pivot_parity: acceptance.pivot_parity.clone(),
                accept_time: now,
            },
        );
    }

    pub fn apply_acceptance(&mut self, acceptance: &AnchorAcceptanceResult) {
        let now = acceptance.outcome.accept_time;
        self.prune(now, None);
        match &acceptance.outcome.kind {
            AcceptanceKind::NonMerge => self.insert(acceptance),
            AcceptanceKind::Merge { retired_heads } => {
                for head in retired_heads {
                    self.entries.remove(head);
                }
                self.insert(acceptance);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn parities_for_heads(
        &mut self,
        parent_root: &[u8],
        heads: &[[u8; 32]],
        now: AcceptInstant,
    ) -> Result<Vec<PivotParity>, ReceiverError> {
        self.prune(now, None);
        let mut parities = Vec::with_capacity(heads.len());
        for head in heads {
            let entry = self.entries.get(head).ok_or(ReceiverError::UnknownHead)?;
            if entry.parent_root.as_slice() != parent_root {
                return Err(ReceiverError::Freeze(FREEZE_MH_PARENT_MISMATCH));
            }
            parities.push(entry.pivot_parity.clone());
        }
        Ok(parities)
    }

    pub fn wid_for_head(&mut self, we_epoch_id: &[u8; 32], now: AcceptInstant) -> Option<[u8; 32]> {
        let expired = self.prune(now, Some(we_epoch_id));
        if expired {
            return None;
        }
        self.entries.get(we_epoch_id).map(|entry| entry.wid)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::todo,
        clippy::unimplemented
    )]
    use super::*;
    use crate::{
        AcceptanceOutcome, DEFAULT_POLICY_VERSION, DEFAULT_PROOF_MODE, DEFAULT_VRF_ID, PivotParity,
        TelemetryCounters, TelemetryKey,
    };
    use std::sync::Arc;

    fn acceptance(
        kind: AcceptanceKind,
        _we: u8,
        new_we: u8,
        wid_tag: u8,
    ) -> AnchorAcceptanceResult {
        let we_current = [new_we; 32];
        let outcome = AcceptanceOutcome {
            kind,
            we_epoch_id: we_current,
            wid: [wid_tag; 32],
            seed_ctx_hash: [0xAA; 32],
            seed_commit: [0xBB; 32],
            rho_commit: [0xCC; 32],
            hp_commit: [0xDD; 32],
            xk_hash: [0xEE; 32],
            accept_seq: 0,
            accept_time: AcceptInstant::from_ticks(0),
            mh_note: None,
            fs_epoch_commit: None,
            fs_ec: None,
            fs_dev_commit: None,
        };
        let pivot_parity = PivotParity {
            gid: b"gid".to_vec(),
            cat: b"cat".to_vec(),
            parent_root: [0x10; 32],
            we_epoch_id: we_current,
            rho_commit: outcome.rho_commit,
            seed_ctx_hash: outcome.seed_ctx_hash,
            seed_commit: outcome.seed_commit,
            hp_commit: outcome.hp_commit,
            xk_hash: outcome.xk_hash,
            join_delta_root: [0x00; 32],
            revoked_since_root: [0x00; 32],
            revoked_root: [0x00; 32],
            accept_seq: outcome.accept_seq,
            crs_id: b"crs".to_vec(),
            params_id: vec![0u8; 32],
            policy_version: DEFAULT_POLICY_VERSION.to_string(),
            proof_mode: DEFAULT_PROOF_MODE.to_string(),
            vrf_id: DEFAULT_VRF_ID.to_string(),
            vrf_proof: vec![0x55],
            vrf_public: vec![0x66],
            mask_a: [0xAA; 32],
            mask_b: [0xBB; 32],
            fs_capss: vec![0x33],
            proofs_commit: [0x99; 32],
            srx_commit: None,
            srx_root_sw: None,
            is_join: true,
            hp_envelope: Arc::from([] as [u8; 0]),
            fs_epoch_commit: None,
            fs_ec: None,
            fs_dev_commit: None,
        };
        let telemetry_key = TelemetryKey {
            gid: b"gid".to_vec().into(),
            parent_root: [0x10; 32],
        };
        AnchorAcceptanceResult {
            outcome,
            pivot_parity,
            telemetry_key,
            telemetry_counters: TelemetryCounters::default(),
        }
    }

    #[test]
    fn stores_and_returns_parities() -> Result<(), Box<dyn std::error::Error>> {
        let mut cache = ReceiverCache::with_defaults();
        let acceptance = acceptance(AcceptanceKind::NonMerge, 0x11, 0x01, 0x90);
        cache.apply_acceptance(&acceptance);

        let parities = cache.parities_for_heads(
            &acceptance.pivot_parity.parent_root,
            &[acceptance.outcome.we_epoch_id],
            AcceptInstant::from_ticks(0),
        )?;
        assert_eq!(parities.len(), 1);
        assert_eq!(parities[0].we_epoch_id, acceptance.outcome.we_epoch_id);
        Ok(())
    }

    #[test]
    fn merge_retires_previous_heads() -> Result<(), Box<dyn std::error::Error>> {
        let mut cache = ReceiverCache::with_defaults();
        let parent = [0x10; 32];
        let head_a = acceptance(AcceptanceKind::NonMerge, 0x11, 0x01, 0x80);
        let head_b = acceptance(AcceptanceKind::NonMerge, 0x22, 0x02, 0x80);
        cache.apply_acceptance(&head_a);
        cache.apply_acceptance(&head_b);
        assert_eq!(cache.len(), 2);

        let merge = acceptance(
            AcceptanceKind::Merge {
                retired_heads: vec![head_a.outcome.we_epoch_id, head_b.outcome.we_epoch_id],
            },
            0x33,
            0x03,
            0x81,
        );
        cache.apply_acceptance(&merge);
        assert_eq!(cache.len(), 1);

        let parities = cache.parities_for_heads(
            &parent,
            &[merge.outcome.we_epoch_id],
            AcceptInstant::from_ticks(0),
        )?;
        assert_eq!(parities[0].we_epoch_id, merge.outcome.we_epoch_id);
        Ok(())
    }

    #[test]
    fn wid_lookup_returns_public_id() {
        let mut cache = ReceiverCache::with_defaults();
        let acceptance = acceptance(AcceptanceKind::NonMerge, 0x44, 0x04, 0xF0);
        cache.apply_acceptance(&acceptance);
        let wid = match cache.wid_for_head(
            &acceptance.outcome.we_epoch_id,
            AcceptInstant::from_ticks(0),
        ) {
            Some(wid) => wid,
            None => unreachable!("wid"),
        };
        assert_eq!(wid, [0xF0; 32]);
    }

    #[test]
    fn prune_expires_entries() {
        let mut cache = ReceiverCache::new(Duration::from_secs(1));
        let acceptance = acceptance(AcceptanceKind::NonMerge, 0x55, 0x05, 0x20);
        cache.apply_acceptance(&acceptance);
        assert!(
            cache
                .wid_for_head(
                    &acceptance.outcome.we_epoch_id,
                    AcceptInstant::from_ticks(10)
                )
                .is_none()
        );
        assert!(cache.is_empty());
    }
}
