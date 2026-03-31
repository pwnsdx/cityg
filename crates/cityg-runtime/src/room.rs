use std::time::Duration;

use ahash::AHashMap;
use cityg_server::CityGServer;

use crate::{EpochScope, MemberMetadata, RoomVolatileState, StoredBundle, StoredMessage};

/// Shared room-scoped runtime object used by deployment adapters.
///
/// This is the minimal shape both the native API and a future Worker Durable
/// Object need to converge on: one authoritative protocol state machine plus
/// room-local volatile indexes/backlogs.
pub struct RuntimeRoom {
    server: CityGServer,
    volatile: RoomVolatileState,
}

impl RuntimeRoom {
    #[must_use]
    pub fn new(server: CityGServer) -> Self {
        Self {
            server,
            volatile: RoomVolatileState::default(),
        }
    }

    #[must_use]
    pub fn from_parts(server: CityGServer, volatile: RoomVolatileState) -> Self {
        Self { server, volatile }
    }

    #[must_use]
    pub fn server(&self) -> &CityGServer {
        &self.server
    }

    pub fn server_mut(&mut self) -> &mut CityGServer {
        &mut self.server
    }

    #[must_use]
    pub fn volatile(&self) -> &RoomVolatileState {
        &self.volatile
    }

    pub fn volatile_mut(&mut self) -> &mut RoomVolatileState {
        &mut self.volatile
    }

    pub fn record_member_join(
        &mut self,
        leaf_id: [u8; 32],
        we_epoch_id: [u8; 32],
        timestamp_ms: u64,
    ) {
        self.volatile
            .record_member_join(leaf_id, we_epoch_id, timestamp_ms);
    }

    pub fn revoke_members(&mut self, leaves: &[[u8; 32]]) {
        let _ = self.volatile.revoke_members(leaves);
    }

    pub fn record_epoch_scope(&mut self, we_epoch_id: [u8; 32], scope: EpochScope) {
        self.volatile.record_epoch_scope(we_epoch_id, scope);
    }

    #[must_use]
    pub fn epoch_scope_for_weid(&self, we_epoch_id: &[u8; 32]) -> Option<EpochScope> {
        self.volatile.epoch_scope_for_weid(we_epoch_id)
    }

    pub fn touch_member(&mut self, leaf_id: [u8; 32], timestamp_ms: u64) {
        self.volatile.touch_member(leaf_id, timestamp_ms);
    }

    pub fn store_message(
        &mut self,
        we_epoch_id: [u8; 32],
        message: StoredMessage,
        now_ms: u64,
        retention: Duration,
        prune_interval_ms: u64,
    ) {
        self.volatile
            .store_message(we_epoch_id, message, now_ms, retention, prune_interval_ms);
    }

    #[must_use]
    pub fn messages_for_epoch(
        &mut self,
        we_epoch_id: &[u8; 32],
        now_ms: u64,
        retention: Duration,
        prune_interval_ms: u64,
    ) -> Vec<StoredMessage> {
        self.volatile
            .messages_for_epoch(we_epoch_id, now_ms, retention, prune_interval_ms)
    }

    pub fn store_bundle(
        &mut self,
        we_epoch_id: [u8; 32],
        bundle: StoredBundle,
        now_ms: u64,
        retention: Duration,
        prune_interval_ms: u64,
    ) {
        self.volatile
            .store_bundle(we_epoch_id, bundle, now_ms, retention, prune_interval_ms);
    }

    #[must_use]
    pub fn bundle(
        &mut self,
        we_epoch_id: &[u8; 32],
        now_ms: u64,
        retention: Duration,
        prune_interval_ms: u64,
    ) -> Option<StoredBundle> {
        self.volatile
            .bundle(we_epoch_id, now_ms, retention, prune_interval_ms)
    }

    #[must_use]
    pub fn member_metadata(&self) -> &AHashMap<[u8; 32], MemberMetadata> {
        self.volatile.member_metadata()
    }

    #[must_use]
    pub fn weid_to_leaf(&self) -> &AHashMap<[u8; 32], [u8; 32]> {
        self.volatile.weid_to_leaf()
    }

    #[must_use]
    pub fn into_parts(self) -> (CityGServer, RoomVolatileState) {
        (self.server, self.volatile)
    }
}

#[cfg(test)]
mod tests {
    use cityg_server::ServerConfig;

    use super::*;

    #[test]
    fn runtime_room_wraps_server_and_volatile_state() {
        let room = RuntimeRoom::new(CityGServer::new(ServerConfig::new()));
        assert!(room.volatile().member_metadata().is_empty());
    }

    #[test]
    fn runtime_room_exposes_room_level_volatile_helpers() {
        let mut room = RuntimeRoom::new(CityGServer::new(ServerConfig::new()));
        let weid = [0x11; 32];
        let leaf = [0x22; 32];
        let scope = EpochScope {
            gid: [0x33; 32],
            membership_root: [0x44; 32],
        };

        room.record_member_join(leaf, weid, 5);
        room.record_epoch_scope(weid, scope);
        room.touch_member(leaf, 7);
        room.store_message(
            weid,
            StoredMessage {
                we_epoch_id: weid,
                ciphertext: vec![1],
                sender: vec![2],
                timestamp_ms: 7,
            },
            7,
            Duration::from_secs(60),
            1_000,
        );
        room.store_bundle(
            weid,
            StoredBundle {
                bytes: vec![3],
                stored_at_ms: 7,
            },
            7,
            Duration::from_secs(60),
            1_000,
        );

        assert_eq!(room.epoch_scope_for_weid(&weid), Some(scope));
        assert_eq!(
            room.messages_for_epoch(&weid, 7, Duration::from_secs(60), 1_000)
                .len(),
            1
        );
        assert_eq!(
            room.bundle(&weid, 7, Duration::from_secs(60), 1_000)
                .expect("bundle")
                .bytes,
            vec![3]
        );
        assert_eq!(room.member_metadata()[&leaf].last_seen_timestamp_ms, 7);
        assert_eq!(room.weid_to_leaf()[&weid], leaf);
    }
}
