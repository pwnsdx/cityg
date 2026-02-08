//! Annex M telemetry helpers for acceptance events.

use serde::{Serialize, Serializer, ser::SerializeStruct};
use smallvec::SmallVec;
use tracing::info;

pub const ANNEX_M_LOG_TARGET: &str = "cityg.annex_m";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TelemetryKey {
    pub gid: SmallVec<[u8; 32]>,
    pub parent_root: [u8; 32],
}

impl TelemetryKey {
    pub fn from_parts(gid: &[u8], parent_root: &[u8]) -> Self {
        let mut root = [0u8; 32];
        root.copy_from_slice(parent_root);
        Self {
            gid: SmallVec::from_slice(gid),
            parent_root: root,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TelemetryCounters {
    pub head_attempts: u64,
    pub head_insertions: u64,
    pub freeze_rho_replay: u64,
    pub freeze_window_full: u64,
    pub last_active_heads: usize,
}

impl TelemetryCounters {
    pub fn record_attempt(&mut self) {
        self.head_attempts += 1;
    }

    pub fn record_success(&mut self, active_heads: usize) {
        self.head_insertions += 1;
        self.last_active_heads = active_heads;
    }

    pub fn record_rho_freeze(&mut self) {
        self.freeze_rho_replay += 1;
    }

    pub fn record_window_full(&mut self) {
        self.freeze_window_full += 1;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnexMTelemetryRow {
    pub gid: SmallVec<[u8; 32]>,
    pub parent_root: [u8; 32],
    pub head_attempts: u64,
    pub head_insertions: u64,
    pub freeze_rho_replay: u64,
    pub freeze_window_full: u64,
    pub last_active_heads: usize,
}

impl From<(TelemetryKey, TelemetryCounters)> for AnnexMTelemetryRow {
    fn from((key, counters): (TelemetryKey, TelemetryCounters)) -> Self {
        Self {
            gid: key.gid,
            parent_root: key.parent_root,
            head_attempts: counters.head_attempts,
            head_insertions: counters.head_insertions,
            freeze_rho_replay: counters.freeze_rho_replay,
            freeze_window_full: counters.freeze_window_full,
            last_active_heads: counters.last_active_heads,
        }
    }
}

impl Serialize for AnnexMTelemetryRow {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AnnexMTelemetryRow", 7)?;
        state.serialize_field("gid", &serde_bytes::Bytes::new(self.gid.as_slice()))?;
        state.serialize_field("parent_root", &serde_bytes::Bytes::new(&self.parent_root))?;
        state.serialize_field("head_attempts", &self.head_attempts)?;
        state.serialize_field("head_insertions", &self.head_insertions)?;
        state.serialize_field("freeze_rho_replay", &self.freeze_rho_replay)?;
        state.serialize_field("freeze_window_full", &self.freeze_window_full)?;
        state.serialize_field("last_active_heads", &self.last_active_heads)?;
        state.end()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct AnnexMTelemetryReport {
    pub rows: Vec<AnnexMTelemetryRow>,
    pub total_attempts: u64,
    pub total_insertions: u64,
    pub total_freeze_rho_replay: u64,
    pub total_freeze_window_full: u64,
}

impl AnnexMTelemetryReport {
    pub fn log(&self) {
        for row in &self.rows {
            info!(
                target = ANNEX_M_LOG_TARGET,
                gid = hex::encode(row.gid.as_slice()),
                parent_root = hex::encode(row.parent_root),
                head_attempts = row.head_attempts,
                head_insertions = row.head_insertions,
                freeze_rho_replay = row.freeze_rho_replay,
                freeze_window_full = row.freeze_window_full,
                last_active_heads = row.last_active_heads,
                "Annex M telemetry snapshot"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn telemetry_key_from_parts_copies_inputs() {
        let gid = [0xAAu8; 16];
        let parent_root = [0xBBu8; 32];
        let key = TelemetryKey::from_parts(&gid, &parent_root);
        assert_eq!(key.gid.as_slice(), gid.as_slice());
        assert_eq!(key.parent_root, parent_root);
    }

    #[test]
    fn counters_record_events() {
        let mut counters = TelemetryCounters::default();
        counters.record_attempt();
        counters.record_success(2);
        counters.record_rho_freeze();
        counters.record_window_full();
        assert_eq!(counters.head_attempts, 1);
        assert_eq!(counters.head_insertions, 1);
        assert_eq!(counters.freeze_rho_replay, 1);
        assert_eq!(counters.freeze_window_full, 1);
        assert_eq!(counters.last_active_heads, 2);
    }

    #[test]
    fn annex_row_from_key_and_counters() {
        let key = TelemetryKey {
            gid: SmallVec::from_slice(&[0x01, 0x02]),
            parent_root: [0x33; 32],
        };
        let mut counters = TelemetryCounters::default();
        counters.record_attempt();
        counters.record_success(3);
        let row = AnnexMTelemetryRow::from((key.clone(), counters.clone()));
        assert_eq!(row.gid, key.gid);
        assert_eq!(row.parent_root, key.parent_root);
        assert_eq!(row.head_attempts, counters.head_attempts);
        assert_eq!(row.last_active_heads, counters.last_active_heads);
    }

    #[test]
    fn report_aggregates_totals() {
        let row_a = AnnexMTelemetryRow {
            gid: SmallVec::from_slice(&[0x10]),
            parent_root: [0x44; 32],
            head_attempts: 2,
            head_insertions: 1,
            freeze_rho_replay: 1,
            freeze_window_full: 0,
            last_active_heads: 3,
        };
        let row_b = AnnexMTelemetryRow {
            gid: SmallVec::from_slice(&[0x20]),
            parent_root: [0x55; 32],
            head_attempts: 3,
            head_insertions: 2,
            freeze_rho_replay: 0,
            freeze_window_full: 1,
            last_active_heads: 1,
        };
        let report = AnnexMTelemetryReport {
            rows: vec![row_a, row_b],
            total_attempts: 5,
            total_insertions: 3,
            total_freeze_rho_replay: 1,
            total_freeze_window_full: 1,
        };
        assert_eq!(report.rows.len(), 2);
        assert_eq!(report.total_attempts, 5);
        assert_eq!(report.total_insertions, 3);
        assert_eq!(report.total_freeze_rho_replay, 1);
        assert_eq!(report.total_freeze_window_full, 1);
    }

    #[test]
    fn annex_row_serializes_expected_fields() {
        let row = AnnexMTelemetryRow {
            gid: SmallVec::from_slice(&[0xAA, 0xBB]),
            parent_root: [0xCC; 32],
            head_attempts: 7,
            head_insertions: 5,
            freeze_rho_replay: 2,
            freeze_window_full: 1,
            last_active_heads: 4,
        };
        let value: Value = serde_json::to_value(&row).expect("serialize annex row");
        assert!(value.get("gid").is_some());
        assert!(value.get("parent_root").is_some());
        assert_eq!(value.get("head_attempts"), Some(&Value::from(7u64)));
        assert_eq!(value.get("head_insertions"), Some(&Value::from(5u64)));
        assert_eq!(value.get("freeze_rho_replay"), Some(&Value::from(2u64)));
        assert_eq!(value.get("freeze_window_full"), Some(&Value::from(1u64)));
        assert_eq!(value.get("last_active_heads"), Some(&Value::from(4u64)));
    }

    #[test]
    fn report_log_handles_empty_and_populated_rows() {
        AnnexMTelemetryReport::default().log();

        let report = AnnexMTelemetryReport {
            rows: vec![AnnexMTelemetryRow {
                gid: SmallVec::from_slice(&[0x01]),
                parent_root: [0x11; 32],
                head_attempts: 1,
                head_insertions: 1,
                freeze_rho_replay: 0,
                freeze_window_full: 0,
                last_active_heads: 1,
            }],
            total_attempts: 1,
            total_insertions: 1,
            total_freeze_rho_replay: 0,
            total_freeze_window_full: 0,
        };
        report.log();
    }
}
