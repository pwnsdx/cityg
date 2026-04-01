use std::{collections::BTreeMap, error::Error as StdError, fmt};

use cityg_runtime::{AcceptedBundleRecord, RoomSnapshot, RoomStateStore, RoomVolatileSnapshot};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Minimal Durable Object storage surface needed by the Worker adapter.
///
/// The concrete Cloudflare binding can implement this trait on top of Durable
/// Object SQLite storage while tests can use the in-memory implementation
/// below.
pub trait DurableObjectStorage {
    type Error: StdError + Send + Sync + 'static;

    fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, Self::Error>;

    fn put_bytes(&mut self, key: &str, value: Vec<u8>) -> Result<(), Self::Error>;

    fn delete_bytes(&mut self, key: &str) -> Result<(), Self::Error>;

    fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Self::Error>;
}

/// In-memory Durable Object storage useful for parity tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryDurableObjectStorage {
    entries: BTreeMap<String, Vec<u8>>,
}

impl MemoryDurableObjectStorage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn entries(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.entries
    }
}

impl DurableObjectStorage for MemoryDurableObjectStorage {
    type Error = std::convert::Infallible;

    fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.entries.get(key).cloned())
    }

    fn put_bytes(&mut self, key: &str, value: Vec<u8>) -> Result<(), Self::Error> {
        self.entries.insert(key.to_owned(), value);
        Ok(())
    }

    fn delete_bytes(&mut self, key: &str) -> Result<(), Self::Error> {
        self.entries.remove(key);
        Ok(())
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Self::Error> {
        Ok(self
            .entries
            .range(prefix.to_owned()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }
}

/// Error returned by the Durable Object room-state adapter.
#[derive(Debug, Error)]
pub enum DurableObjectRoomStateStoreError<E>
where
    E: StdError + Send + Sync + 'static,
{
    #[error("durable object storage backend error: {0}")]
    Backend(E),
    #[error("failed to encode {kind} as CBOR: {message}")]
    Encode { kind: &'static str, message: String },
    #[error("failed to decode {kind} from CBOR: {message}")]
    Decode { kind: &'static str, message: String },
}

impl<E> From<E> for DurableObjectRoomStateStoreError<E>
where
    E: StdError + Send + Sync + 'static,
{
    fn from(value: E) -> Self {
        Self::Backend(value)
    }
}

/// `RoomStateStore` adapter backed by Durable Object key-value storage.
#[derive(Clone, Debug)]
pub struct DurableObjectRoomStateStore<S> {
    storage: S,
}

impl<S> DurableObjectRoomStateStore<S> {
    #[must_use]
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    #[must_use]
    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    #[must_use]
    pub fn into_storage(self) -> S {
        self.storage
    }
}

impl<S> RoomStateStore for DurableObjectRoomStateStore<S>
where
    S: DurableObjectStorage,
{
    type Error = DurableObjectRoomStateStoreError<S::Error>;

    fn load_snapshot(&self, gid: &[u8; 32]) -> Result<Option<RoomSnapshot>, Self::Error> {
        load_optional_cbor(&self.storage, &snapshot_key(gid), "room snapshot")
    }

    fn load_accepted_bundles(
        &self,
        gid: &[u8; 32],
    ) -> Result<Vec<AcceptedBundleRecord>, Self::Error> {
        let mut entries = self
            .storage
            .list_prefix(&accepted_bundle_prefix(gid))
            .map_err(Self::Error::from)?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
            .into_iter()
            .map(|(_, bytes)| {
                decode_cbor::<AcceptedBundleRecord, S::Error>(&bytes, "accepted bundle")
            })
            .collect()
    }

    fn load_volatile_snapshot(
        &self,
        gid: &[u8; 32],
    ) -> Result<Option<RoomVolatileSnapshot>, Self::Error> {
        load_optional_cbor(&self.storage, &volatile_key(gid), "room volatile snapshot")
    }

    fn persist_snapshot(&mut self, snapshot: RoomSnapshot) -> Result<(), Self::Error> {
        persist_cbor(
            &mut self.storage,
            &snapshot_key(&snapshot.gid),
            &snapshot,
            "room snapshot",
        )
    }

    fn append_accepted_bundle(
        &mut self,
        gid: [u8; 32],
        record: AcceptedBundleRecord,
    ) -> Result<(), Self::Error> {
        let prefix = accepted_bundle_prefix(&gid);
        let next_index = self
            .storage
            .list_prefix(&prefix)
            .map_err(Self::Error::from)?
            .len() as u64;
        persist_cbor(
            &mut self.storage,
            &accepted_bundle_key(&gid, next_index),
            &record,
            "accepted bundle",
        )
    }

    fn replace_accepted_bundles(
        &mut self,
        gid: [u8; 32],
        records: Vec<AcceptedBundleRecord>,
    ) -> Result<(), Self::Error> {
        let prefix = accepted_bundle_prefix(&gid);
        for (key, _) in self
            .storage
            .list_prefix(&prefix)
            .map_err(Self::Error::from)?
        {
            self.storage.delete_bytes(&key).map_err(Self::Error::from)?;
        }
        for (index, record) in records.iter().enumerate() {
            persist_cbor(
                &mut self.storage,
                &accepted_bundle_key(&gid, index as u64),
                record,
                "accepted bundle",
            )?;
        }
        Ok(())
    }

    fn persist_volatile_snapshot(
        &mut self,
        gid: [u8; 32],
        snapshot: RoomVolatileSnapshot,
    ) -> Result<(), Self::Error> {
        persist_cbor(
            &mut self.storage,
            &volatile_key(&gid),
            &snapshot,
            "room volatile snapshot",
        )
    }
}

fn snapshot_key(gid: &[u8; 32]) -> String {
    format!("{}/snapshot.cbor", room_prefix(gid))
}

fn volatile_key(gid: &[u8; 32]) -> String {
    format!("{}/volatile.cbor", room_prefix(gid))
}

fn accepted_bundle_prefix(gid: &[u8; 32]) -> String {
    format!("{}/accepted/", room_prefix(gid))
}

fn accepted_bundle_key(gid: &[u8; 32], index: u64) -> String {
    format!("{}{index:020}.cbor", accepted_bundle_prefix(gid))
}

fn room_prefix(gid: &[u8; 32]) -> String {
    format!("rooms/{}", hex::encode(gid))
}

fn load_optional_cbor<T, S>(
    storage: &S,
    key: &str,
    kind: &'static str,
) -> Result<Option<T>, DurableObjectRoomStateStoreError<S::Error>>
where
    T: DeserializeOwned,
    S: DurableObjectStorage,
{
    storage
        .get_bytes(key)
        .map_err(DurableObjectRoomStateStoreError::from)?
        .map(|bytes| decode_cbor::<T, S::Error>(&bytes, kind))
        .transpose()
}

fn persist_cbor<T, S>(
    storage: &mut S,
    key: &str,
    value: &T,
    kind: &'static str,
) -> Result<(), DurableObjectRoomStateStoreError<S::Error>>
where
    T: Serialize,
    S: DurableObjectStorage,
{
    storage
        .put_bytes(key, encode_cbor(value, kind)?)
        .map_err(DurableObjectRoomStateStoreError::from)
}

fn encode_cbor<T, E>(
    value: &T,
    kind: &'static str,
) -> Result<Vec<u8>, DurableObjectRoomStateStoreError<E>>
where
    T: Serialize,
    E: StdError + Send + Sync + 'static,
{
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|error| {
        DurableObjectRoomStateStoreError::Encode {
            kind,
            message: error.to_string(),
        }
    })?;
    Ok(bytes)
}

fn decode_cbor<T, E>(
    bytes: &[u8],
    kind: &'static str,
) -> Result<T, DurableObjectRoomStateStoreError<E>>
where
    T: DeserializeOwned,
    E: StdError + Send + Sync + 'static,
{
    ciborium::from_reader(bytes).map_err(|error| DurableObjectRoomStateStoreError::Decode {
        kind,
        message: error.to_string(),
    })
}

impl<S> fmt::Display for DurableObjectRoomStateStore<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableObjectRoomStateStore")
            .field("storage", &self.storage)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use std::{collections::BTreeMap, time::Duration};

    use cityg_client::demo::{
        DEMO_GID, bootstrap_public, demo_bundle, demo_member_leaf, kbroad_public,
    };
    use cityg_runtime::{
        AppliedBundleIndexes, BundleIndexUpdate, EpochLeafBindingRecord, EpochScope,
        EpochScopeRecord, MemberMetadata, MemberMetadataRecord, RoomMessageWrite,
        RoomRetentionPolicy, RoomStateCheckpoint, RoomVolatileState, StoredBundle,
        StoredBundleRecord, StoredMessage, apply_bundle_indexes, derive_room_routing_entries,
        fetch_room_bundle, fetch_room_messages, store_room_message,
    };
    use cityg_server::{CityGServer, ServerOutcome};
    use msphf_orchestrator::{AcceptanceOptions, BootstrapPolicy};

    use super::*;
    use crate::{
        WorkerHistoryAuthority, WorkerRoomBootstrap, rehydrate_runtime_room_from_checkpoint,
    };

    #[test]
    fn checkpoint_round_trips_through_durable_object_store() {
        let gid = [0x11; 32];
        let checkpoint = sample_checkpoint(gid);
        let mut store = DurableObjectRoomStateStore::new(MemoryDurableObjectStorage::new());

        store
            .persist_checkpoint(checkpoint.clone())
            .expect("persist checkpoint");

        let loaded = store.load_checkpoint(&gid).expect("load checkpoint");
        assert_eq!(loaded, Some(checkpoint));
    }

    #[test]
    fn accepted_bundle_ordering_is_stable() {
        let gid = [0x22; 32];
        let mut store = DurableObjectRoomStateStore::new(MemoryDurableObjectStorage::new());

        store
            .append_accepted_bundle(
                gid,
                AcceptedBundleRecord {
                    we_epoch_id: [0x01; 32],
                    parent_root: [0x10; 32],
                    new_root: [0x11; 32],
                    bytes: vec![1],
                    accepted_at_ms: 1,
                },
            )
            .expect("append first bundle");
        store
            .append_accepted_bundle(
                gid,
                AcceptedBundleRecord {
                    we_epoch_id: [0x02; 32],
                    parent_root: [0x11; 32],
                    new_root: [0x12; 32],
                    bytes: vec![2],
                    accepted_at_ms: 2,
                },
            )
            .expect("append second bundle");

        let loaded = store
            .load_accepted_bundles(&gid)
            .expect("load accepted bundles");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].we_epoch_id, [0x01; 32]);
        assert_eq!(loaded[1].we_epoch_id, [0x02; 32]);
    }

    #[test]
    fn persisted_checkpoint_rehydrates_runtime_room_with_messages_and_routing_entries() {
        const ACCEPTED_AT_MS: u64 = 55;
        const MESSAGE_AT_MS: u64 = 60;
        const NOW_MS: u64 = 61;
        const PRUNE_INTERVAL_MS: u64 = 1_000;

        let retention = Duration::from_secs(60);
        let bootstrap = test_bootstrap();
        let bundle = demo_bundle("alice").expect("demo bundle");
        let gid: [u8; 32] = bundle.gid().try_into().expect("gid");
        let alice_leaf = demo_member_leaf("alice");
        let bundle_bytes = bundle.to_cbor().expect("bundle cbor");

        let (server, mut room_state, outcome, applied) = accepted_demo_room_state(
            &bootstrap,
            &bundle,
            bundle_bytes.clone(),
            ACCEPTED_AT_MS,
            retention,
            PRUNE_INTERVAL_MS,
        );
        assert_eq!(applied.gid, gid);
        let scope = store_room_message(
            &server,
            &mut room_state,
            RoomMessageWrite {
                we_epoch_id: bundle.we_epoch_id,
                sender_leaf: alice_leaf,
                ciphertext: vec![0x90, 0x91, 0x92],
                sender: alice_leaf.to_vec(),
                timestamp_ms: MESSAGE_AT_MS,
            },
            RoomRetentionPolicy {
                retention,
                prune_interval_ms: PRUNE_INTERVAL_MS,
            },
        )
        .expect("store message");
        assert_eq!(scope.gid, gid);

        let checkpoint = RoomStateCheckpoint {
            snapshot: RoomSnapshot {
                gid,
                format_version: 1,
                server_state_bytes: server
                    .export_runtime_metadata_bytes()
                    .expect("export runtime metadata"),
                last_parent_root: Some(outcome.parent_root),
                last_we_epoch_id: Some(bundle.we_epoch_id),
                accepted_bundle_count: 1,
                persisted_at_ms: MESSAGE_AT_MS,
            },
            accepted_bundles: vec![AcceptedBundleRecord {
                we_epoch_id: bundle.we_epoch_id,
                parent_root: outcome.parent_root,
                new_root: outcome.new_root,
                bytes: bundle_bytes.clone(),
                accepted_at_ms: ACCEPTED_AT_MS,
            }],
            volatile: room_state.snapshot(),
        };

        let mut store = DurableObjectRoomStateStore::new(MemoryDurableObjectStorage::new());
        store
            .persist_checkpoint(checkpoint.clone())
            .expect("persist checkpoint");

        let loaded = store
            .load_checkpoint(&gid)
            .expect("load checkpoint")
            .expect("checkpoint exists");
        assert_eq!(loaded, checkpoint);

        let routing_entries = derive_room_routing_entries(&loaded);
        assert_eq!(
            routing_entries,
            vec![cityg_runtime::RoomRoutingEntry {
                gid,
                we_epoch_id: bundle.we_epoch_id,
            }]
        );

        let rehydrated = rehydrate_runtime_room_from_checkpoint(&loaded, &bootstrap)
            .expect("rehydrate runtime room");
        let (server, mut room_state) = rehydrated.into_parts();

        assert!(server.members(&gid).contains(&alice_leaf));
        assert_eq!(
            room_state.member_metadata()[&alice_leaf].last_seen_timestamp_ms,
            MESSAGE_AT_MS
        );
        assert_eq!(
            fetch_room_bundle(
                &mut room_state,
                &bundle.we_epoch_id,
                NOW_MS,
                retention,
                PRUNE_INTERVAL_MS,
            )
            .expect("stored bundle")
            .bytes,
            bundle_bytes
        );
        assert_eq!(
            fetch_room_messages(
                &server,
                &mut room_state,
                &bundle.we_epoch_id,
                alice_leaf,
                NOW_MS,
                retention,
                PRUNE_INTERVAL_MS,
            )
            .expect("authorized fetch"),
            vec![StoredMessage {
                we_epoch_id: bundle.we_epoch_id,
                ciphertext: vec![0x90, 0x91, 0x92],
                sender: alice_leaf.to_vec(),
                timestamp_ms: MESSAGE_AT_MS,
            }]
        );
    }

    fn sample_checkpoint(gid: [u8; 32]) -> RoomStateCheckpoint {
        RoomStateCheckpoint {
            snapshot: RoomSnapshot {
                gid,
                format_version: 1,
                server_state_bytes: vec![1, 2, 3],
                last_parent_root: Some([0x33; 32]),
                last_we_epoch_id: Some([0x44; 32]),
                accepted_bundle_count: 1,
                persisted_at_ms: 123,
            },
            accepted_bundles: vec![AcceptedBundleRecord {
                we_epoch_id: [0x44; 32],
                parent_root: [0x33; 32],
                new_root: [0x55; 32],
                bytes: vec![9, 8, 7],
                accepted_at_ms: 321,
            }],
            volatile: RoomVolatileSnapshot {
                member_metadata: vec![MemberMetadataRecord {
                    leaf_id: [0x66; 32],
                    metadata: MemberMetadata {
                        join_timestamp_ms: 10,
                        last_seen_timestamp_ms: 11,
                    },
                }],
                weid_to_leaf: vec![EpochLeafBindingRecord {
                    we_epoch_id: [0x44; 32],
                    leaf_id: [0x66; 32],
                }],
                epoch_scopes: vec![EpochScopeRecord {
                    we_epoch_id: [0x44; 32],
                    scope: EpochScope {
                        gid,
                        membership_root: [0x77; 32],
                    },
                }],
                messages: vec![StoredMessage {
                    we_epoch_id: [0x44; 32],
                    ciphertext: vec![5, 4, 3],
                    sender: vec![2, 1],
                    timestamp_ms: 12,
                }],
                bundles: vec![StoredBundleRecord {
                    we_epoch_id: [0x44; 32],
                    bundle: StoredBundle {
                        bytes: vec![6, 6, 6],
                        stored_at_ms: 13,
                    },
                }],
                message_prune_due_ms: 14,
                bundle_prune_due_ms: 15,
            },
        }
    }

    fn test_bootstrap() -> WorkerRoomBootstrap {
        let mut kbroad_registry = BTreeMap::new();
        kbroad_registry.insert(DEMO_GID.to_vec(), kbroad_public().to_vec());
        WorkerRoomBootstrap {
            history_authority: WorkerHistoryAuthority::Disabled,
            acceptance_options: Some(AcceptanceOptions {
                bootstrap_policy: BootstrapPolicy::CaMlDsa {
                    public_key: bootstrap_public().to_vec(),
                },
                kbroad_registry: Some(kbroad_registry),
                ..AcceptanceOptions::default()
            }),
            ..WorkerRoomBootstrap::default()
        }
    }

    fn accepted_demo_room_state(
        bootstrap: &WorkerRoomBootstrap,
        bundle: &cityg_client::ClientEpochBundle,
        bundle_bytes: Vec<u8>,
        accepted_at_ms: u64,
        retention: Duration,
        prune_interval_ms: u64,
    ) -> (
        CityGServer,
        RoomVolatileState,
        ServerOutcome,
        AppliedBundleIndexes,
    ) {
        let mut server = bootstrap.build_server();
        let outcome = server.accept_epoch(bundle).expect("accept bundle");
        let mut room_state = RoomVolatileState::default();
        let applied = apply_bundle_indexes(
            &mut room_state,
            bundle,
            BundleIndexUpdate {
                we_epoch_id: bundle.we_epoch_id,
                bytes: bundle_bytes,
                membership_root: outcome.new_root,
                timestamp_ms: accepted_at_ms,
            },
            RoomRetentionPolicy {
                retention,
                prune_interval_ms,
            },
        )
        .expect("apply bundle indexes");
        (server, room_state, outcome, applied)
    }
}
