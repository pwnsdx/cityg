use std::{
    collections::HashSet,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use ahash::AHashMap;
use serde::{Deserialize, Serialize};

use crate::{
    EpochLeafBindingRecord, EpochScopeRecord, MemberMetadataRecord, RoomVolatileSnapshot,
    StoredBundleRecord,
};

/// Metadata tracked for a room member in the runtime layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberMetadata {
    pub join_timestamp_ms: u64,
    pub last_seen_timestamp_ms: u64,
}

/// Reverse index from accepted epochs back to a room and membership root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochScope {
    pub gid: [u8; 32],
    pub membership_root: [u8; 32],
}

/// Volatile message payload cached by runtime adapters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMessage {
    pub we_epoch_id: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub sender: Vec<u8>,
    pub timestamp_ms: u64,
}

/// Volatile bundle payload cached by runtime adapters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBundle {
    pub bytes: Vec<u8>,
    pub stored_at_ms: u64,
}

/// In-memory room indexes shared by runtime adapters.
#[derive(Clone, Debug, Default)]
pub struct RoomIndexes {
    member_metadata: AHashMap<[u8; 32], MemberMetadata>,
    weid_to_leaf: AHashMap<[u8; 32], [u8; 32]>,
    epoch_scopes: AHashMap<[u8; 32], EpochScope>,
}

impl RoomIndexes {
    pub fn record_member_join(
        &mut self,
        leaf_id: [u8; 32],
        we_epoch_id: [u8; 32],
        timestamp_ms: u64,
    ) {
        index_member_join(
            &mut self.member_metadata,
            &mut self.weid_to_leaf,
            leaf_id,
            we_epoch_id,
            timestamp_ms,
        );
    }

    pub fn revoke_members(&mut self, leaves: &[[u8; 32]]) -> HashSet<[u8; 32]> {
        revoke_members(&mut self.member_metadata, &mut self.weid_to_leaf, leaves)
    }

    pub fn record_epoch_scope(&mut self, we_epoch_id: [u8; 32], scope: EpochScope) {
        self.epoch_scopes.insert(we_epoch_id, scope);
    }

    pub fn epoch_scope_for_weid(&self, we_epoch_id: &[u8; 32]) -> Option<EpochScope> {
        self.epoch_scopes.get(we_epoch_id).copied()
    }

    #[must_use]
    pub fn epoch_scopes(&self) -> &AHashMap<[u8; 32], EpochScope> {
        &self.epoch_scopes
    }

    pub fn touch_member(&mut self, leaf_id: [u8; 32], timestamp_ms: u64) {
        if let Some(entry) = self.member_metadata.get_mut(&leaf_id) {
            entry.last_seen_timestamp_ms = timestamp_ms;
        }
    }

    pub fn prune_expired_weids(&mut self, expired: &[[u8; 32]]) {
        prune_epoch_indexes(&mut self.epoch_scopes, &mut self.weid_to_leaf, expired);
    }

    #[must_use]
    pub fn member_metadata(&self) -> &AHashMap<[u8; 32], MemberMetadata> {
        &self.member_metadata
    }

    #[must_use]
    pub fn weid_to_leaf(&self) -> &AHashMap<[u8; 32], [u8; 32]> {
        &self.weid_to_leaf
    }

    #[must_use]
    pub fn from_parts(
        member_metadata: AHashMap<[u8; 32], MemberMetadata>,
        weid_to_leaf: AHashMap<[u8; 32], [u8; 32]>,
        epoch_scopes: AHashMap<[u8; 32], EpochScope>,
    ) -> Self {
        Self {
            member_metadata,
            weid_to_leaf,
            epoch_scopes,
        }
    }
}

/// In-memory message backlog keyed by `we_epoch_id`.
#[derive(Clone, Debug, Default)]
pub struct MessageBacklog {
    messages: AHashMap<[u8; 32], Vec<StoredMessage>>,
}

impl MessageBacklog {
    pub fn store(&mut self, we_epoch_id: [u8; 32], message: StoredMessage) {
        self.messages.entry(we_epoch_id).or_default().push(message);
    }

    pub fn prune_expired(&mut self, now_ms: u64, retention: Duration) {
        prune_expired_messages(&mut self.messages, now_ms, retention);
    }

    #[must_use]
    pub fn messages_for_epoch(&self, we_epoch_id: &[u8; 32]) -> Vec<StoredMessage> {
        self.messages.get(we_epoch_id).cloned().unwrap_or_default()
    }

    #[must_use]
    pub fn messages(&self) -> &AHashMap<[u8; 32], Vec<StoredMessage>> {
        &self.messages
    }

    #[must_use]
    pub fn from_messages(messages: AHashMap<[u8; 32], Vec<StoredMessage>>) -> Self {
        Self { messages }
    }
}

/// In-memory bundle backlog keyed by `we_epoch_id`.
#[derive(Clone, Debug, Default)]
pub struct BundleBacklog {
    bundles: AHashMap<[u8; 32], StoredBundle>,
}

impl BundleBacklog {
    pub fn store(&mut self, we_epoch_id: [u8; 32], bundle: StoredBundle) {
        self.bundles.insert(we_epoch_id, bundle);
    }

    pub fn prune_expired(&mut self, now_ms: u64, retention: Duration) -> Vec<[u8; 32]> {
        prune_expired_bundles(&mut self.bundles, now_ms, retention)
    }

    #[must_use]
    pub fn bundle(&self, we_epoch_id: &[u8; 32]) -> Option<StoredBundle> {
        self.bundles.get(we_epoch_id).cloned()
    }

    #[must_use]
    pub fn contains(&self, we_epoch_id: &[u8; 32]) -> bool {
        self.bundles.contains_key(we_epoch_id)
    }

    #[must_use]
    pub fn bundles(&self) -> &AHashMap<[u8; 32], StoredBundle> {
        &self.bundles
    }

    #[must_use]
    pub fn from_bundles(bundles: AHashMap<[u8; 32], StoredBundle>) -> Self {
        Self { bundles }
    }
}

/// Consolidated room-local volatile state shared by runtime adapters.
#[derive(Clone, Debug, Default)]
pub struct RoomVolatileState {
    indexes: RoomIndexes,
    messages: MessageBacklog,
    bundles: BundleBacklog,
    message_prune_due_ms: u64,
    bundle_prune_due_ms: u64,
}

impl RoomVolatileState {
    pub fn record_member_join(
        &mut self,
        leaf_id: [u8; 32],
        we_epoch_id: [u8; 32],
        timestamp_ms: u64,
    ) {
        self.indexes
            .record_member_join(leaf_id, we_epoch_id, timestamp_ms);
    }

    pub fn revoke_members(&mut self, leaves: &[[u8; 32]]) -> HashSet<[u8; 32]> {
        self.indexes.revoke_members(leaves)
    }

    pub fn record_epoch_scope(&mut self, we_epoch_id: [u8; 32], scope: EpochScope) {
        self.indexes.record_epoch_scope(we_epoch_id, scope);
    }

    #[must_use]
    pub fn epoch_scope_for_weid(&self, we_epoch_id: &[u8; 32]) -> Option<EpochScope> {
        self.indexes.epoch_scope_for_weid(we_epoch_id)
    }

    pub fn touch_member(&mut self, leaf_id: [u8; 32], timestamp_ms: u64) {
        self.indexes.touch_member(leaf_id, timestamp_ms);
    }

    pub fn store_message(
        &mut self,
        we_epoch_id: [u8; 32],
        message: StoredMessage,
        now_ms: u64,
        retention: Duration,
        prune_interval_ms: u64,
    ) {
        self.messages.store(we_epoch_id, message);
        if should_prune_due(&mut self.message_prune_due_ms, now_ms, prune_interval_ms) {
            self.messages.prune_expired(now_ms, retention);
        }
    }

    #[must_use]
    pub fn messages_for_epoch(
        &mut self,
        we_epoch_id: &[u8; 32],
        now_ms: u64,
        retention: Duration,
        prune_interval_ms: u64,
    ) -> Vec<StoredMessage> {
        if should_prune_due(&mut self.message_prune_due_ms, now_ms, prune_interval_ms) {
            self.messages.prune_expired(now_ms, retention);
        }
        self.messages.messages_for_epoch(we_epoch_id)
    }

    pub fn store_bundle(
        &mut self,
        we_epoch_id: [u8; 32],
        bundle: StoredBundle,
        now_ms: u64,
        retention: Duration,
        prune_interval_ms: u64,
    ) {
        let expired = if should_prune_due(&mut self.bundle_prune_due_ms, now_ms, prune_interval_ms)
        {
            self.bundles.prune_expired(now_ms, retention)
        } else {
            Vec::new()
        };
        self.bundles.store(we_epoch_id, bundle);
        self.indexes.prune_expired_weids(&expired);
    }

    #[must_use]
    pub fn bundle(
        &mut self,
        we_epoch_id: &[u8; 32],
        now_ms: u64,
        retention: Duration,
        prune_interval_ms: u64,
    ) -> Option<StoredBundle> {
        let expired = if should_prune_due(&mut self.bundle_prune_due_ms, now_ms, prune_interval_ms)
        {
            self.bundles.prune_expired(now_ms, retention)
        } else {
            Vec::new()
        };
        self.indexes.prune_expired_weids(&expired);
        self.bundles.bundle(we_epoch_id)
    }

    #[must_use]
    pub fn member_metadata(&self) -> &AHashMap<[u8; 32], MemberMetadata> {
        self.indexes.member_metadata()
    }

    #[must_use]
    pub fn weid_to_leaf(&self) -> &AHashMap<[u8; 32], [u8; 32]> {
        self.indexes.weid_to_leaf()
    }

    #[must_use]
    pub fn epoch_scopes(&self) -> &AHashMap<[u8; 32], EpochScope> {
        self.indexes.epoch_scopes()
    }

    #[must_use]
    pub fn contains_bundle(&self, we_epoch_id: &[u8; 32]) -> bool {
        self.bundles.contains(we_epoch_id)
    }

    #[must_use]
    pub fn message_prune_due_ms(&self) -> u64 {
        self.message_prune_due_ms
    }

    #[must_use]
    pub fn bundle_prune_due_ms(&self) -> u64 {
        self.bundle_prune_due_ms
    }

    #[must_use]
    pub fn snapshot(&self) -> RoomVolatileSnapshot {
        let mut member_metadata = self
            .member_metadata()
            .iter()
            .map(|(leaf_id, metadata)| MemberMetadataRecord {
                leaf_id: *leaf_id,
                metadata: *metadata,
            })
            .collect::<Vec<_>>();
        member_metadata.sort_by_key(|record| record.leaf_id);

        let mut weid_to_leaf = self
            .weid_to_leaf()
            .iter()
            .map(|(we_epoch_id, leaf_id)| EpochLeafBindingRecord {
                we_epoch_id: *we_epoch_id,
                leaf_id: *leaf_id,
            })
            .collect::<Vec<_>>();
        weid_to_leaf.sort_by_key(|record| record.we_epoch_id);

        let mut epoch_scopes = self
            .epoch_scopes()
            .iter()
            .map(|(we_epoch_id, scope)| EpochScopeRecord {
                we_epoch_id: *we_epoch_id,
                scope: *scope,
            })
            .collect::<Vec<_>>();
        epoch_scopes.sort_by_key(|record| record.we_epoch_id);

        let mut messages = self
            .messages
            .messages()
            .values()
            .flat_map(|messages| messages.iter().cloned())
            .collect::<Vec<_>>();
        messages.sort_by_key(|message| (message.we_epoch_id, message.timestamp_ms));

        let mut bundles = self
            .bundles
            .bundles()
            .iter()
            .map(|(we_epoch_id, bundle)| StoredBundleRecord {
                we_epoch_id: *we_epoch_id,
                bundle: bundle.clone(),
            })
            .collect::<Vec<_>>();
        bundles.sort_by_key(|record| record.we_epoch_id);

        RoomVolatileSnapshot {
            member_metadata,
            weid_to_leaf,
            epoch_scopes,
            messages,
            bundles,
            message_prune_due_ms: self.message_prune_due_ms,
            bundle_prune_due_ms: self.bundle_prune_due_ms,
        }
    }

    #[must_use]
    pub fn from_snapshot(snapshot: RoomVolatileSnapshot) -> Self {
        let indexes = RoomIndexes::from_parts(
            snapshot
                .member_metadata
                .into_iter()
                .map(|record| (record.leaf_id, record.metadata))
                .collect(),
            snapshot
                .weid_to_leaf
                .into_iter()
                .map(|record| (record.we_epoch_id, record.leaf_id))
                .collect(),
            snapshot
                .epoch_scopes
                .into_iter()
                .map(|record| (record.we_epoch_id, record.scope))
                .collect(),
        );
        let messages = MessageBacklog::from_messages(snapshot.messages.into_iter().fold(
            AHashMap::<[u8; 32], Vec<StoredMessage>>::new(),
            |mut acc, message| {
                acc.entry(message.we_epoch_id).or_default().push(message);
                acc
            },
        ));
        let bundles = BundleBacklog::from_bundles(
            snapshot
                .bundles
                .into_iter()
                .map(|record| (record.we_epoch_id, record.bundle))
                .collect(),
        );
        Self {
            indexes,
            messages,
            bundles,
            message_prune_due_ms: snapshot.message_prune_due_ms,
            bundle_prune_due_ms: snapshot.bundle_prune_due_ms,
        }
    }
}

fn should_prune_due(prune_due_ms: &mut u64, now_ms: u64, interval_ms: u64) -> bool {
    if now_ms < *prune_due_ms {
        return false;
    }
    *prune_due_ms = now_ms.saturating_add(interval_ms);
    true
}

/// Update member metadata and the `we_epoch_id -> leaf_id` reverse index.
pub fn index_member_join(
    member_metadata: &mut AHashMap<[u8; 32], MemberMetadata>,
    weid_to_leaf: &mut AHashMap<[u8; 32], [u8; 32]>,
    leaf_id: [u8; 32],
    we_epoch_id: [u8; 32],
    timestamp_ms: u64,
) {
    member_metadata.insert(
        leaf_id,
        MemberMetadata {
            join_timestamp_ms: timestamp_ms,
            last_seen_timestamp_ms: timestamp_ms,
        },
    );
    weid_to_leaf.retain(|_, existing| *existing != leaf_id);
    weid_to_leaf.insert(we_epoch_id, leaf_id);
}

/// Remove revoked leaves from runtime indexes and return the revoked set.
pub fn revoke_members(
    member_metadata: &mut AHashMap<[u8; 32], MemberMetadata>,
    weid_to_leaf: &mut AHashMap<[u8; 32], [u8; 32]>,
    leaves: &[[u8; 32]],
) -> HashSet<[u8; 32]> {
    let revoked: HashSet<[u8; 32]> = leaves.iter().copied().collect();
    for leaf in &revoked {
        member_metadata.remove(leaf);
    }
    weid_to_leaf.retain(|_, existing| !revoked.contains(existing));
    revoked
}

/// Drop expired `we_epoch_id` keyed indexes after bundle pruning.
pub fn prune_epoch_indexes(
    epoch_scopes: &mut AHashMap<[u8; 32], EpochScope>,
    weid_to_leaf: &mut AHashMap<[u8; 32], [u8; 32]>,
    expired: &[[u8; 32]],
) {
    if expired.is_empty() {
        return;
    }
    let expired_set: HashSet<[u8; 32]> = expired.iter().copied().collect();
    epoch_scopes.retain(|weid, _| !expired_set.contains(weid));
    weid_to_leaf.retain(|weid, _| !expired_set.contains(weid));
}

/// Prune expired messages from the in-memory room backlog.
pub fn prune_expired_messages(
    store: &mut AHashMap<[u8; 32], Vec<StoredMessage>>,
    now_ms: u64,
    retention: Duration,
) {
    let retention_ms_u128 = retention.as_millis().min(u128::from(u64::MAX));
    let retention_ms = retention_ms_u128 as u64;
    let cutoff = now_ms.saturating_sub(retention_ms);

    store.retain(|_, messages| {
        messages.retain(|msg| msg.timestamp_ms >= cutoff);
        !messages.is_empty()
    });
}

/// Prune expired stored bundles and return expired `we_epoch_id`s.
pub fn prune_expired_bundles(
    store: &mut AHashMap<[u8; 32], StoredBundle>,
    now_ms: u64,
    retention: Duration,
) -> Vec<[u8; 32]> {
    let retention_ms_u128 = retention.as_millis().min(u128::from(u64::MAX));
    let retention_ms = retention_ms_u128 as u64;
    let cutoff = now_ms.saturating_sub(retention_ms);
    let mut expired = Vec::new();

    store.retain(|weid, bundle| {
        let keep = bundle.stored_at_ms >= cutoff;
        if !keep {
            expired.push(*weid);
        }
        keep
    });

    expired
}

/// Generic interval gate used for lazy pruning.
pub fn should_prune(prune_due_ms: &AtomicU64, now_ms: u64, interval_ms: u64) -> bool {
    let due = prune_due_ms.load(Ordering::Relaxed);
    if now_ms < due {
        return false;
    }
    prune_due_ms
        .compare_exchange(
            due,
            now_ms.saturating_add(interval_ms),
            Ordering::Relaxed,
            Ordering::Relaxed,
        )
        .is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use std::sync::atomic::AtomicU64;

    use super::*;

    #[test]
    fn member_join_rewrites_reverse_index() {
        let mut metadata = AHashMap::new();
        let mut weid_to_leaf = AHashMap::new();

        index_member_join(&mut metadata, &mut weid_to_leaf, [0x11; 32], [0x22; 32], 55);
        index_member_join(&mut metadata, &mut weid_to_leaf, [0x11; 32], [0x33; 32], 99);

        assert_eq!(metadata[&[0x11; 32]].join_timestamp_ms, 99);
        assert!(!weid_to_leaf.contains_key(&[0x22; 32]));
        assert_eq!(weid_to_leaf[&[0x33; 32]], [0x11; 32]);
    }

    #[test]
    fn revoke_members_prunes_metadata_and_reverse_index() {
        let mut metadata = AHashMap::new();
        let mut weid_to_leaf = AHashMap::new();
        index_member_join(&mut metadata, &mut weid_to_leaf, [0x11; 32], [0x22; 32], 55);
        index_member_join(&mut metadata, &mut weid_to_leaf, [0x33; 32], [0x44; 32], 66);

        let revoked = revoke_members(&mut metadata, &mut weid_to_leaf, &[[0x11; 32]]);

        assert!(revoked.contains(&[0x11; 32]));
        assert!(!metadata.contains_key(&[0x11; 32]));
        assert!(!weid_to_leaf.contains_key(&[0x22; 32]));
        assert!(weid_to_leaf.contains_key(&[0x44; 32]));
    }

    #[test]
    fn should_prune_only_allows_one_caller_per_interval() {
        let due = AtomicU64::new(0);
        assert!(should_prune(&due, 100, 50));
        assert!(!should_prune(&due, 120, 50));
        assert!(should_prune(&due, 151, 50));
    }

    #[test]
    fn room_indexes_wrap_join_scope_touch_and_prune() {
        let mut indexes = RoomIndexes::default();
        let scope = EpochScope {
            gid: [0x11; 32],
            membership_root: [0x22; 32],
        };

        indexes.record_member_join([0x33; 32], [0x44; 32], 10);
        indexes.record_epoch_scope([0x44; 32], scope);
        indexes.touch_member([0x33; 32], 20);

        assert_eq!(indexes.epoch_scope_for_weid(&[0x44; 32]), Some(scope));
        assert_eq!(
            indexes.member_metadata()[&[0x33; 32]].last_seen_timestamp_ms,
            20
        );

        indexes.prune_expired_weids(&[[0x44; 32]]);
        assert!(indexes.epoch_scope_for_weid(&[0x44; 32]).is_none());
        assert!(!indexes.weid_to_leaf().contains_key(&[0x44; 32]));
    }

    #[test]
    fn message_and_bundle_backlogs_round_trip() {
        let mut messages = MessageBacklog::default();
        let mut bundles = BundleBacklog::default();
        let weid = [0x55; 32];

        messages.store(
            weid,
            StoredMessage {
                we_epoch_id: weid,
                ciphertext: vec![1],
                sender: vec![2],
                timestamp_ms: 10,
            },
        );
        bundles.store(
            weid,
            StoredBundle {
                bytes: vec![3],
                stored_at_ms: 10,
            },
        );

        assert_eq!(messages.messages_for_epoch(&weid).len(), 1);
        assert_eq!(bundles.bundle(&weid).expect("bundle").bytes, vec![3]);
    }

    #[test]
    fn room_volatile_state_updates_indexes_and_backlogs() {
        let mut state = RoomVolatileState::default();
        let weid = [0x11; 32];
        let leaf = [0x22; 32];
        let scope = EpochScope {
            gid: [0x33; 32],
            membership_root: [0x44; 32],
        };

        state.record_member_join(leaf, weid, 5);
        state.record_epoch_scope(weid, scope);
        state.touch_member(leaf, 6);
        state.store_message(
            weid,
            StoredMessage {
                we_epoch_id: weid,
                ciphertext: vec![1],
                sender: vec![2],
                timestamp_ms: 6,
            },
            6,
            Duration::from_secs(60),
            1_000,
        );
        state.store_bundle(
            weid,
            StoredBundle {
                bytes: vec![3],
                stored_at_ms: 6,
            },
            6,
            Duration::from_secs(60),
            1_000,
        );

        assert_eq!(state.epoch_scope_for_weid(&weid), Some(scope));
        assert_eq!(
            state
                .messages_for_epoch(&weid, 6, Duration::from_secs(60), 1_000)
                .len(),
            1
        );
        assert_eq!(
            state
                .bundle(&weid, 6, Duration::from_secs(60), 1_000)
                .expect("bundle")
                .bytes,
            vec![3]
        );
        assert_eq!(state.member_metadata()[&leaf].last_seen_timestamp_ms, 6);
        assert_eq!(state.weid_to_leaf()[&weid], leaf);
    }

    #[test]
    fn room_volatile_state_snapshot_round_trips() {
        let mut state = RoomVolatileState::default();
        let weid = [0x21; 32];
        let leaf = [0x31; 32];
        state.record_member_join(leaf, weid, 40);
        state.record_epoch_scope(
            weid,
            EpochScope {
                gid: [0x41; 32],
                membership_root: [0x51; 32],
            },
        );
        state.touch_member(leaf, 41);
        state.store_message(
            weid,
            StoredMessage {
                we_epoch_id: weid,
                ciphertext: vec![9, 9],
                sender: vec![7; 32],
                timestamp_ms: 42,
            },
            42,
            Duration::from_secs(60),
            1_000,
        );
        state.store_bundle(
            weid,
            StoredBundle {
                bytes: vec![8, 8],
                stored_at_ms: 43,
            },
            43,
            Duration::from_secs(60),
            1_000,
        );

        let snapshot = state.snapshot();
        let mut restored = RoomVolatileState::from_snapshot(snapshot);

        assert_eq!(
            restored.epoch_scope_for_weid(&weid),
            state.epoch_scope_for_weid(&weid)
        );
        assert_eq!(
            restored.member_metadata()[&leaf],
            state.member_metadata()[&leaf]
        );
        assert_eq!(restored.weid_to_leaf()[&weid], state.weid_to_leaf()[&weid]);
        assert_eq!(
            restored.messages_for_epoch(&weid, 43, Duration::from_secs(60), 1_000),
            state.messages_for_epoch(&weid, 43, Duration::from_secs(60), 1_000)
        );
        assert_eq!(
            restored.bundle(&weid, 43, Duration::from_secs(60), 1_000),
            state.bundle(&weid, 43, Duration::from_secs(60), 1_000)
        );
    }
}
