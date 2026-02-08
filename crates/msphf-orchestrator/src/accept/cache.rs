//! Caches for proof verification (HP and SRX) used during acceptance.

use super::*;
use crate::{proofs::hp_binding, time::AcceptInstant};
use std::time::Duration;

use ahash::AHashMap;

#[derive(Clone)]
pub(super) struct VckCacheEntry {
    hp_proof: Option<hp_binding::HpProof>,
    srx: Option<VckSrxState>,
    verified_at: AcceptInstant,
}

#[derive(Clone)]
pub(super) struct VckSrxState {
    pub(super) join_count: u64,
    pub(super) since_count: u64,
    pub(super) anchor_count: u64,
    pub(super) payload_len: usize,
}

#[derive(Clone)]
pub(super) struct VckCache {
    ttl: Duration,
    entries: AHashMap<[u8; 32], VckCacheEntry>,
}

impl VckCache {
    pub(super) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: AHashMap::new(),
        }
    }

    pub(super) fn set_ttl(&mut self, ttl: Duration, now: AcceptInstant) {
        self.ttl = ttl;
        self.prune(now);
    }

    fn prune(&mut self, now: AcceptInstant) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, entry| now.duration_since(entry.verified_at) <= ttl);
    }

    pub(super) fn should_verify_hp(
        &mut self,
        key: [u8; 32],
        proof: &hp_binding::HpProof,
        now: AcceptInstant,
    ) -> bool {
        self.prune(now);
        match self.entries.get(&key) {
            Some(entry) if entry.hp_proof.as_ref() == Some(proof) => false,
            Some(_) => {
                self.entries.remove(&key);
                true
            }
            None => true,
        }
    }

    pub(super) fn record_hp(
        &mut self,
        key: [u8; 32],
        proof: &hp_binding::HpProof,
        now: AcceptInstant,
    ) {
        self.prune(now);
        let entry = self.entries.entry(key).or_insert_with(|| VckCacheEntry {
            hp_proof: None,
            srx: None,
            verified_at: now,
        });
        entry.hp_proof = Some(proof.clone());
        entry.verified_at = now;
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_skip_srx(
        &mut self,
        key: [u8; 32],
        hint_join_count: u64,
        hint_since_count: u64,
        hint_anchor_count: u64,
        hint_payload_bytes: u64,
        payload_len: usize,
        now: AcceptInstant,
    ) -> Result<bool, AcceptanceError> {
        self.prune(now);
        if let Some(srx) = self.entries.get(&key).and_then(|entry| entry.srx.as_ref()) {
            if hint_join_count < srx.join_count
                || hint_since_count < srx.since_count
                || hint_anchor_count < srx.anchor_count
                || hint_payload_bytes < srx.payload_len as u64
            {
                return Err(AcceptanceError::Freeze(FREEZE_SRX_HINT_UNDER));
            }
            if payload_len != srx.payload_len {
                return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
            }
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn record_srx(
        &mut self,
        key: [u8; 32],
        join_count: u64,
        since_count: u64,
        anchor_count: u64,
        payload_len: usize,
        now: AcceptInstant,
    ) {
        self.prune(now);
        let entry = self.entries.entry(key).or_insert_with(|| VckCacheEntry {
            hp_proof: None,
            srx: None,
            verified_at: now,
        });
        entry.srx = Some(VckSrxState {
            join_count,
            since_count,
            anchor_count,
            payload_len,
        });
        entry.verified_at = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_freeze(err: AcceptanceError, expected: FreezeError) {
        match err {
            AcceptanceError::Freeze(code) => assert_eq!(code, expected),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn set_ttl_prunes_existing_entries() {
        let mut cache = VckCache::new(Duration::from_secs(10));
        let key = [0x11u8; 32];
        let now = AcceptInstant::from_ticks(0);
        cache.record_srx(key, 1, 1, 1, 8, now);

        let skip = cache
            .try_skip_srx(key, 1, 1, 1, 8, 8, AcceptInstant::from_ticks(5))
            .unwrap_or_else(|err| panic!("unexpected error: {err:?}"));
        assert!(skip);

        cache.set_ttl(Duration::from_secs(1), AcceptInstant::from_ticks(2));
        let skip = cache
            .try_skip_srx(key, 1, 1, 1, 8, 8, AcceptInstant::from_ticks(2))
            .unwrap_or_else(|err| panic!("unexpected error: {err:?}"));
        assert!(!skip);
    }

    #[test]
    fn try_skip_srx_rejects_payload_len_mismatch() {
        let mut cache = VckCache::new(Duration::from_secs(60));
        let key = [0x22u8; 32];
        cache.record_srx(key, 2, 2, 2, 16, AcceptInstant::from_ticks(0));

        let err = cache
            .try_skip_srx(key, 2, 2, 2, 16, 15, AcceptInstant::from_ticks(1))
            .expect_err("payload_len mismatch should freeze");
        assert_freeze(err, FREEZE_SRX_INVALID);
    }

    #[test]
    fn try_skip_srx_rejects_hint_undercounts() {
        let mut cache = VckCache::new(Duration::from_secs(60));
        let key = [0x33u8; 32];
        cache.record_srx(key, 3, 2, 1, 24, AcceptInstant::from_ticks(0));

        let err = cache
            .try_skip_srx(key, 2, 2, 1, 24, 24, AcceptInstant::from_ticks(1))
            .expect_err("understated hints should freeze");
        assert_freeze(err, FREEZE_SRX_HINT_UNDER);
    }
}
