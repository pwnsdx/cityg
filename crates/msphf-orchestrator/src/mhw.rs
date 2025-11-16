use std::{collections::BTreeMap, time::Duration};

use crate::time::AcceptInstant;

/// Default maximum number of concurrent heads per parent root.
pub const DEFAULT_H_MAX: usize = 16;
/// Default time window during which heads remain active.
/// 120s strikes a balance between client jitter tolerance and bounded state.
pub const DEFAULT_T_WINDOW: Duration = Duration::from_secs(120);

/// Error returned when a head violates the multi-head window policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreezeError {
    pub code: u32,
    pub reason: &'static str,
}

impl FreezeError {
    pub const WINDOW_FULL: Self = Self {
        code: 925,
        reason: "mh_window_full",
    };

    pub const MERGE_INVALID: Self = Self {
        code: 927,
        reason: "mh_merge_invalid",
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadRecord {
    pub we_epoch_id: [u8; 32],
    pub msphf_hp_commit: [u8; 32],
    pub seed_ctx_hash: [u8; 32],
    pub rho_commit: [u8; 32],
    pub seed_commit: [u8; 32],
    pub xk_hash: [u8; 32],
    pub join_delta_root: [u8; 32],
    pub revoked_since_root: [u8; 32],
    pub revoked_root: [u8; 32],
    pub accept_seq: u64,
    accept_time: AcceptInstant,
}

impl HeadRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        we_epoch_id: [u8; 32],
        msphf_hp_commit: [u8; 32],
        seed_ctx_hash: [u8; 32],
        rho_commit: [u8; 32],
        seed_commit: [u8; 32],
        xk_hash: [u8; 32],
        join_delta_root: [u8; 32],
        revoked_since_root: [u8; 32],
        revoked_root: [u8; 32],
        accept_seq: u64,
        accept_time: AcceptInstant,
    ) -> Self {
        Self {
            we_epoch_id,
            msphf_hp_commit,
            seed_ctx_hash,
            rho_commit,
            seed_commit,
            xk_hash,
            join_delta_root,
            revoked_since_root,
            revoked_root,
            accept_seq,
            accept_time,
        }
    }

    pub fn accept_time(&self) -> AcceptInstant {
        self.accept_time
    }
}

#[derive(Clone, Default, Debug)]
pub struct MultiHeadWindow {
    h_max: usize,
    ttl: Duration,
    heads: BTreeMap<Vec<u8>, Vec<HeadRecord>>,
}

impl MultiHeadWindow {
    pub fn new(h_max: usize, ttl: Duration) -> Self {
        Self {
            h_max,
            ttl,
            heads: BTreeMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_H_MAX, DEFAULT_T_WINDOW)
    }

    /// Accepts a non-merge anchor. Returns `FreezeError::WINDOW_FULL` if inserting would
    /// exceed `h_max` after pruning expired heads.
    pub fn accept_head(
        &mut self,
        wid: &[u8],
        mut record: HeadRecord,
        now: AcceptInstant,
    ) -> Result<(), FreezeError> {
        record.accept_time = now;
        let h_max = self.h_max;
        let entry = self.prune(wid, now);
        if entry.len() >= h_max {
            return Err(FreezeError::WINDOW_FULL);
        }
        entry.push(record);
        Ok(())
    }

    /// Accepts a merge anchor listing heads to retire. The `mh_heads` slice MUST be sorted in
    /// ascending lexicographical order and contain no duplicates.
    pub fn accept_merge(
        &mut self,
        wid_old: &[u8],
        wid_new: &[u8],
        mh_heads: &[[u8; 32]],
        mut new_record: HeadRecord,
        now: AcceptInstant,
    ) -> Result<(), FreezeError> {
        if !is_sorted_unique(mh_heads) {
            return Err(FreezeError::MERGE_INVALID);
        }
        new_record.accept_time = now;
        let h_max = self.h_max;
        let wid_old_key = wid_old.to_vec();
        let remove_old_entry = {
            let entry_old = self.prune(wid_old, now);
            for head in mh_heads {
                if let Some(pos) = entry_old.iter().position(|rec| &rec.we_epoch_id == head) {
                    entry_old.remove(pos);
                } else {
                    return Err(FreezeError::MERGE_INVALID);
                }
            }

            if wid_old == wid_new {
                if entry_old.len() >= h_max {
                    return Err(FreezeError::WINDOW_FULL);
                }
                entry_old.push(new_record);
                return Ok(());
            }

            entry_old.is_empty()
        };

        if remove_old_entry {
            self.heads.remove(&wid_old_key);
        }

        let entry_new = self.prune(wid_new, now);
        if entry_new.len() >= h_max {
            return Err(FreezeError::WINDOW_FULL);
        }
        entry_new.push(new_record);
        Ok(())
    }

    pub fn active_heads(&self, wid: &[u8]) -> usize {
        self.heads.get(wid).map(|list| list.len()).unwrap_or(0)
    }

    pub fn iter_heads(&self, wid: &[u8]) -> impl Iterator<Item = &HeadRecord> {
        self.heads.get(wid).into_iter().flat_map(|list| list.iter())
    }

    pub fn find_head(&self, wid: &[u8], we_epoch_id: &[u8; 32]) -> Option<&HeadRecord> {
        self.heads.get(wid).and_then(|list| {
            list.iter()
                .find(|record| &record.we_epoch_id == we_epoch_id)
        })
    }

    pub fn find_head_window(&self, we_epoch_id: &[u8; 32]) -> Option<Vec<u8>> {
        self.heads.iter().find_map(|(wid, records)| {
            if records
                .iter()
                .any(|record| &record.we_epoch_id == we_epoch_id)
            {
                Some(wid.clone())
            } else {
                None
            }
        })
    }

    pub fn h_max(&self) -> usize {
        self.h_max
    }

    pub fn set_h_max(&mut self, h_max: usize) {
        self.h_max = h_max;
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn set_ttl(&mut self, ttl: Duration, now: AcceptInstant) {
        self.ttl = ttl;
        self.prune_all(now);
    }

    pub fn prune_all(&mut self, now: AcceptInstant) {
        let ttl_bound = self.ttl;
        self.heads.retain(|_, records| {
            records.retain(|record| now.duration_since(record.accept_time) <= ttl_bound);
            !records.is_empty()
        });
    }

    pub fn snapshot(&self) -> Vec<(Vec<u8>, Vec<HeadRecord>)> {
        self.heads
            .iter()
            .map(|(wid, records)| (wid.clone(), records.clone()))
            .collect()
    }

    fn prune(&mut self, wid: &[u8], now: AcceptInstant) -> &mut Vec<HeadRecord> {
        let ttl = self.ttl;
        let entry = self.heads.entry(wid.to_vec()).or_default();
        entry.retain(|record| now.duration_since(record.accept_time) <= ttl);
        entry
    }
}

fn is_sorted_unique(list: &[[u8; 32]]) -> bool {
    if list.is_empty() {
        return false;
    }
    for window in list.windows(2) {
        if window[0] >= window[1] {
            return false;
        }
    }
    true
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
    use crate::time::AcceptInstant;
    use rand::seq::SliceRandom;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    fn sample_record(weid: u8) -> HeadRecord {
        HeadRecord::new(
            [weid; 32],
            [0xAA; 32],
            [0xBB; 32],
            [0xCC; 32],
            [0xDD; 32],
            [0xEE; 32],
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            0,
            AcceptInstant::from_ticks(0),
        )
    }

    #[test]
    fn accept_head_under_limit() {
        let mut window = MultiHeadWindow::with_defaults();
        let wid = [0x01; 32];
        let now = AcceptInstant::from_ticks(0);
        assert!(window.accept_head(&wid, sample_record(1), now).is_ok());
        assert_eq!(window.active_heads(&wid), 1);
    }

    #[test]
    fn window_full_rejected() {
        let mut window = MultiHeadWindow::new(1, DEFAULT_T_WINDOW);
        let wid = [0x01; 32];
        window
            .accept_head(&wid, sample_record(1), AcceptInstant::from_ticks(0))
            .unwrap();
        let err = window
            .accept_head(&wid, sample_record(2), AcceptInstant::from_ticks(1))
            .unwrap_err();
        assert_eq!(err, FreezeError::WINDOW_FULL);
    }

    #[test]
    fn merge_requires_sorted_unique() {
        let mut window = MultiHeadWindow::with_defaults();
        let wid = [0x01; 32];
        window
            .accept_head(&wid, sample_record(1), AcceptInstant::from_ticks(0))
            .unwrap();
        let err = window
            .accept_merge(
                &wid,
                &wid,
                &[[0x01; 32], [0x01; 32]],
                sample_record(2),
                AcceptInstant::from_ticks(1),
            )
            .unwrap_err();
        assert_eq!(err, FreezeError::MERGE_INVALID);
    }

    #[test]
    fn merge_retires_listed_heads() {
        let mut window = MultiHeadWindow::new(2, DEFAULT_T_WINDOW);
        let wid = [0x01; 32];
        let now = AcceptInstant::from_ticks(0);
        window.accept_head(&wid, sample_record(10), now).unwrap();
        window.accept_head(&wid, sample_record(11), now).unwrap();
        assert_eq!(window.active_heads(&wid), 2);

        window
            .accept_merge(
                &wid,
                &wid,
                &[[10u8; 32], [11u8; 32]],
                sample_record(20),
                AcceptInstant::from_ticks(1),
            )
            .unwrap();
        let heads: Vec<_> = window
            .iter_heads(&wid)
            .map(|rec| rec.we_epoch_id[0])
            .collect();
        assert_eq!(heads, vec![20]);
    }

    #[test]
    fn prune_expires_old_heads() {
        let mut window = MultiHeadWindow::new(1, Duration::from_secs(1));
        let wid = [0x01; 32];
        let old = AcceptInstant::from_ticks(0);
        let mut record = sample_record(5);
        record.accept_time = old;
        window.heads.insert(wid.to_vec(), vec![record]);

        assert!(
            window
                .accept_head(&wid, sample_record(6), AcceptInstant::from_ticks(2))
                .is_ok()
        );
    }

    #[test]
    fn fuzz_multi_head_window_random_sequences() -> Result<(), Box<dyn std::error::Error>> {
        let ttl = Duration::from_secs(1);
        let mut window = MultiHeadWindow::new(4, ttl);
        let wid = [0xAB; 32];
        let mut rng = StdRng::seed_from_u64(0xC17F_F155_D00D_BEEF);
        let mut naive: Vec<HeadRecord> = Vec::new();

        for step in 0..200 {
            let now = AcceptInstant::from_ticks(step);
            naive.retain(|rec| now.duration_since(rec.accept_time) <= ttl);

            if rng.gen_bool(0.6) || naive.is_empty() {
                let weid = rng.r#gen::<u8>();
                let head = sample_record(weid);
                let mut naive_record = head.clone();
                naive_record.accept_time = now;
                let result = window.accept_head(&wid, head, now);
                if naive.len() < 4 {
                    match result {
                        Ok(()) => naive.push(naive_record),
                        Err(e) => unreachable!("head should be accepted, got: {e:?}"),
                    }
                } else {
                    assert_eq!(result.unwrap_err(), FreezeError::WINDOW_FULL);
                }
            } else {
                let retire_count = rng.gen_range(1..=naive.len());
                let mut retire: Vec<[u8; 32]> = naive
                    .choose_multiple(&mut rng, retire_count)
                    .map(|record| record.we_epoch_id)
                    .collect();
                retire.sort();
                retire.dedup();
                if retire.is_empty() {
                    continue;
                }

                let new_weid = rng.r#gen::<u8>();
                let merge_head = sample_record(new_weid);
                let mut expected = naive.clone();
                let mut valid = true;
                for head in &retire {
                    if let Some(pos) = expected.iter().position(|rec| rec.we_epoch_id == *head) {
                        expected.remove(pos);
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid && expected.len() >= 4 {
                    valid = false;
                }
                let mut naive_merge = merge_head.clone();
                naive_merge.accept_time = now;
                if valid {
                    expected.push(naive_merge);
                }
                let result = window.accept_merge(&wid, &wid, &retire, merge_head, now);
                if valid {
                    match result {
                        Ok(()) => naive = expected,
                        Err(e) => unreachable!("merge should succeed, got: {e:?}"),
                    }
                } else {
                    assert!(result.is_err());
                }
            }

            let mut actual: Vec<[u8; 32]> =
                window.iter_heads(&wid).map(|rec| rec.we_epoch_id).collect();
            actual.sort();
            let mut expected_ids: Vec<[u8; 32]> = naive.iter().map(|rec| rec.we_epoch_id).collect();
            expected_ids.sort();
            assert_eq!(actual, expected_ids);
            assert!(actual.len() <= 4);
        }
        Ok(())
    }
}
