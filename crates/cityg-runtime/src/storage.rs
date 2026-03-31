use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{EpochScope, MemberMetadata, StoredBundle, StoredMessage};

/// Persisted room snapshot used to rehydrate a room-scoped engine.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomSnapshot {
    pub gid: [u8; 32],
    /// Schema version for the opaque serialized engine payload.
    pub format_version: u32,
    /// Opaque serialized room-engine snapshot.
    pub server_state_bytes: Vec<u8>,
    pub last_parent_root: Option<[u8; 32]>,
    pub last_we_epoch_id: Option<[u8; 32]>,
    pub accepted_bundle_count: u64,
    pub persisted_at_ms: u64,
}

/// Persisted representation of an accepted bundle append.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedBundleRecord {
    pub we_epoch_id: [u8; 32],
    pub parent_root: [u8; 32],
    pub new_root: [u8; 32],
    pub bytes: Vec<u8>,
    pub accepted_at_ms: u64,
}

/// Persisted member metadata row for room-local indexes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberMetadataRecord {
    pub leaf_id: [u8; 32],
    pub metadata: MemberMetadata,
}

/// Persisted reverse index row from accepted epoch to member leaf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochLeafBindingRecord {
    pub we_epoch_id: [u8; 32],
    pub leaf_id: [u8; 32],
}

/// Persisted reverse index row from accepted epoch to room scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochScopeRecord {
    pub we_epoch_id: [u8; 32],
    pub scope: EpochScope,
}

/// Persisted stored-bundle row keyed by `we_epoch_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBundleRecord {
    pub we_epoch_id: [u8; 32],
    pub bundle: StoredBundle,
}

/// Persisted room-local volatile state that can be rehydrated after isolate churn.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomVolatileSnapshot {
    pub member_metadata: Vec<MemberMetadataRecord>,
    pub weid_to_leaf: Vec<EpochLeafBindingRecord>,
    pub epoch_scopes: Vec<EpochScopeRecord>,
    pub messages: Vec<StoredMessage>,
    pub bundles: Vec<StoredBundleRecord>,
    pub message_prune_due_ms: u64,
    pub bundle_prune_due_ms: u64,
}

/// Full persisted room checkpoint suitable for Durable Object rehydration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomStateCheckpoint {
    pub snapshot: RoomSnapshot,
    pub accepted_bundles: Vec<AcceptedBundleRecord>,
    pub volatile: RoomVolatileSnapshot,
}

/// Reverse-routing entry derived from persisted room state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoomRoutingEntry {
    pub gid: [u8; 32],
    pub we_epoch_id: [u8; 32],
}

/// Derive the room-scoped `we_epoch_id -> gid` routing entries that can be
/// reconstructed from a persisted checkpoint.
#[must_use]
pub fn derive_room_routing_entries(checkpoint: &RoomStateCheckpoint) -> Vec<RoomRoutingEntry> {
    let mut entries = BTreeSet::new();
    if let Some(we_epoch_id) = checkpoint.snapshot.last_we_epoch_id {
        entries.insert(RoomRoutingEntry {
            gid: checkpoint.snapshot.gid,
            we_epoch_id,
        });
    }
    for accepted in &checkpoint.accepted_bundles {
        entries.insert(RoomRoutingEntry {
            gid: checkpoint.snapshot.gid,
            we_epoch_id: accepted.we_epoch_id,
        });
    }
    for scope in &checkpoint.volatile.epoch_scopes {
        entries.insert(RoomRoutingEntry {
            gid: scope.scope.gid,
            we_epoch_id: scope.we_epoch_id,
        });
    }
    entries.into_iter().collect()
}

/// Storage contract for room-scoped authoritative state.
///
/// The Cloudflare Durable Object implementation will eventually map this onto
/// SQLite-backed object storage. The native runtime can use this trait for
/// parity testing and incremental migration away from filesystem-only
/// assumptions.
pub trait RoomStateStore {
    type Error;

    fn load_snapshot(&self, gid: &[u8; 32]) -> Result<Option<RoomSnapshot>, Self::Error>;

    fn load_accepted_bundles(
        &self,
        gid: &[u8; 32],
    ) -> Result<Vec<AcceptedBundleRecord>, Self::Error>;

    fn load_volatile_snapshot(
        &self,
        gid: &[u8; 32],
    ) -> Result<Option<RoomVolatileSnapshot>, Self::Error>;

    fn persist_snapshot(&mut self, snapshot: RoomSnapshot) -> Result<(), Self::Error>;

    fn append_accepted_bundle(
        &mut self,
        gid: [u8; 32],
        record: AcceptedBundleRecord,
    ) -> Result<(), Self::Error>;

    fn replace_accepted_bundles(
        &mut self,
        gid: [u8; 32],
        records: Vec<AcceptedBundleRecord>,
    ) -> Result<(), Self::Error>;

    fn persist_volatile_snapshot(
        &mut self,
        gid: [u8; 32],
        snapshot: RoomVolatileSnapshot,
    ) -> Result<(), Self::Error>;

    fn load_checkpoint(&self, gid: &[u8; 32]) -> Result<Option<RoomStateCheckpoint>, Self::Error> {
        let Some(snapshot) = self.load_snapshot(gid)? else {
            return Ok(None);
        };
        Ok(Some(RoomStateCheckpoint {
            accepted_bundles: self.load_accepted_bundles(gid)?,
            volatile: self.load_volatile_snapshot(gid)?.unwrap_or_default(),
            snapshot,
        }))
    }

    fn persist_checkpoint(&mut self, checkpoint: RoomStateCheckpoint) -> Result<(), Self::Error> {
        let gid = checkpoint.snapshot.gid;
        self.persist_snapshot(checkpoint.snapshot)?;
        self.replace_accepted_bundles(gid, checkpoint.accepted_bundles)?;
        self.persist_volatile_snapshot(gid, checkpoint.volatile)
    }
}

/// In-memory implementation useful for tests and local adapter development.
#[derive(Clone, Debug, Default)]
pub struct MemoryRoomStateStore {
    snapshots: BTreeMap<[u8; 32], RoomSnapshot>,
    bundles: BTreeMap<[u8; 32], Vec<AcceptedBundleRecord>>,
    volatile: BTreeMap<[u8; 32], RoomVolatileSnapshot>,
}

impl MemoryRoomStateStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl RoomStateStore for MemoryRoomStateStore {
    type Error = std::convert::Infallible;

    fn load_snapshot(&self, gid: &[u8; 32]) -> Result<Option<RoomSnapshot>, Self::Error> {
        Ok(self.snapshots.get(gid).cloned())
    }

    fn load_accepted_bundles(
        &self,
        gid: &[u8; 32],
    ) -> Result<Vec<AcceptedBundleRecord>, Self::Error> {
        Ok(self.bundles.get(gid).cloned().unwrap_or_default())
    }

    fn load_volatile_snapshot(
        &self,
        gid: &[u8; 32],
    ) -> Result<Option<RoomVolatileSnapshot>, Self::Error> {
        Ok(self.volatile.get(gid).cloned())
    }

    fn persist_snapshot(&mut self, snapshot: RoomSnapshot) -> Result<(), Self::Error> {
        self.snapshots.insert(snapshot.gid, snapshot);
        Ok(())
    }

    fn append_accepted_bundle(
        &mut self,
        gid: [u8; 32],
        record: AcceptedBundleRecord,
    ) -> Result<(), Self::Error> {
        self.bundles.entry(gid).or_default().push(record);
        Ok(())
    }

    fn replace_accepted_bundles(
        &mut self,
        gid: [u8; 32],
        records: Vec<AcceptedBundleRecord>,
    ) -> Result<(), Self::Error> {
        self.bundles.insert(gid, records);
        Ok(())
    }

    fn persist_volatile_snapshot(
        &mut self,
        gid: [u8; 32],
        snapshot: RoomVolatileSnapshot,
    ) -> Result<(), Self::Error> {
        self.volatile.insert(gid, snapshot);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trips_snapshot_and_bundles() {
        let gid = [0x11; 32];
        let mut store = MemoryRoomStateStore::new();
        let snapshot = RoomSnapshot {
            gid,
            format_version: 1,
            server_state_bytes: vec![9, 8, 7],
            last_parent_root: Some([0x22; 32]),
            last_we_epoch_id: Some([0x33; 32]),
            accepted_bundle_count: 1,
            persisted_at_ms: 99,
        };
        store
            .persist_snapshot(snapshot.clone())
            .expect("persist snapshot");
        store
            .append_accepted_bundle(
                gid,
                AcceptedBundleRecord {
                    we_epoch_id: [0x33; 32],
                    parent_root: [0x22; 32],
                    new_root: [0x44; 32],
                    bytes: vec![1, 2, 3],
                    accepted_at_ms: 111,
                },
            )
            .expect("append bundle");
        let volatile = RoomVolatileSnapshot {
            member_metadata: vec![MemberMetadataRecord {
                leaf_id: [0x55; 32],
                metadata: MemberMetadata {
                    join_timestamp_ms: 10,
                    last_seen_timestamp_ms: 11,
                },
            }],
            weid_to_leaf: vec![EpochLeafBindingRecord {
                we_epoch_id: [0x33; 32],
                leaf_id: [0x55; 32],
            }],
            epoch_scopes: vec![EpochScopeRecord {
                we_epoch_id: [0x33; 32],
                scope: EpochScope {
                    gid,
                    membership_root: [0x66; 32],
                },
            }],
            messages: vec![StoredMessage {
                we_epoch_id: [0x33; 32],
                ciphertext: vec![4, 5, 6],
                sender: vec![0xAA; 32],
                timestamp_ms: 12,
            }],
            bundles: vec![StoredBundleRecord {
                we_epoch_id: [0x33; 32],
                bundle: StoredBundle {
                    bytes: vec![7, 8],
                    stored_at_ms: 13,
                },
            }],
            message_prune_due_ms: 14,
            bundle_prune_due_ms: 15,
        };
        store
            .persist_volatile_snapshot(gid, volatile.clone())
            .expect("persist volatile");

        assert_eq!(
            store.load_snapshot(&gid).expect("load snapshot"),
            Some(snapshot)
        );
        assert_eq!(
            store
                .load_accepted_bundles(&gid)
                .expect("load bundles")
                .len(),
            1
        );
        assert_eq!(
            store
                .load_volatile_snapshot(&gid)
                .expect("load volatile snapshot"),
            Some(volatile)
        );
    }

    #[test]
    fn memory_store_round_trips_checkpoint() {
        let gid = [0xAA; 32];
        let mut store = MemoryRoomStateStore::new();
        let checkpoint = RoomStateCheckpoint {
            snapshot: RoomSnapshot {
                gid,
                format_version: 2,
                server_state_bytes: vec![1, 2, 3, 4],
                last_parent_root: Some([0xBB; 32]),
                last_we_epoch_id: Some([0xCC; 32]),
                accepted_bundle_count: 2,
                persisted_at_ms: 1234,
            },
            accepted_bundles: vec![AcceptedBundleRecord {
                we_epoch_id: [0xCC; 32],
                parent_root: [0xBB; 32],
                new_root: [0xDD; 32],
                bytes: vec![9],
                accepted_at_ms: 2222,
            }],
            volatile: RoomVolatileSnapshot {
                message_prune_due_ms: 30,
                bundle_prune_due_ms: 31,
                ..RoomVolatileSnapshot::default()
            },
        };

        store
            .persist_checkpoint(checkpoint.clone())
            .expect("persist checkpoint");

        assert_eq!(
            store.load_checkpoint(&gid).expect("load checkpoint"),
            Some(checkpoint)
        );
    }

    #[test]
    fn derives_routing_entries_from_checkpoint_sources() {
        let gid = [0x10; 32];
        let other_gid = [0x20; 32];
        let checkpoint = RoomStateCheckpoint {
            snapshot: RoomSnapshot {
                gid,
                last_we_epoch_id: Some([0x01; 32]),
                ..RoomSnapshot::default()
            },
            accepted_bundles: vec![
                AcceptedBundleRecord {
                    we_epoch_id: [0x02; 32],
                    parent_root: [0xA0; 32],
                    new_root: [0xB0; 32],
                    bytes: vec![2],
                    accepted_at_ms: 12,
                },
                AcceptedBundleRecord {
                    we_epoch_id: [0x01; 32],
                    parent_root: [0xA1; 32],
                    new_root: [0xB1; 32],
                    bytes: vec![3],
                    accepted_at_ms: 13,
                },
            ],
            volatile: RoomVolatileSnapshot {
                epoch_scopes: vec![
                    EpochScopeRecord {
                        we_epoch_id: [0x03; 32],
                        scope: EpochScope {
                            gid: other_gid,
                            membership_root: [0xC0; 32],
                        },
                    },
                    EpochScopeRecord {
                        we_epoch_id: [0x02; 32],
                        scope: EpochScope {
                            gid,
                            membership_root: [0xC1; 32],
                        },
                    },
                ],
                ..RoomVolatileSnapshot::default()
            },
        };

        assert_eq!(
            derive_room_routing_entries(&checkpoint),
            vec![
                RoomRoutingEntry {
                    gid,
                    we_epoch_id: [0x01; 32],
                },
                RoomRoutingEntry {
                    gid,
                    we_epoch_id: [0x02; 32],
                },
                RoomRoutingEntry {
                    gid: other_gid,
                    we_epoch_id: [0x03; 32],
                },
            ]
        );
    }
}
