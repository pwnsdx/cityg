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
