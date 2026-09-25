//! Room host of a Durable Object.
//!
//! One Durable Object serves one room (named `v2-<gid hex>`). Its storage
//! holds the room as a snapshot plus journal records under these keys:
//!
//! ```text
//! v2/<gid hex>/generation              current generation g (u64 BE)
//! v2/<gid hex>/snapshot/<g>            room snapshot of generation g
//! v2/<gid hex>/journal/<g>/<index>     records since that snapshot
//! ```
//!
//! Compaction writes snapshot `g + 1` and bumps the generation before it
//! deletes the keys of generation `g`, so an interrupted compaction leaves
//! a consistent generation behind.

use cityg_core::hash::Digest;
use cityg_proto::{ApiError, ErrorCode, Route, request_gid};
use cityg_runtime::{
    Handled, ServiceConfig, SessionRegistry, create_room, handle_room_request, persist_record,
};
use cityg_server::{Room, RoomStore, StoredRoom, restore_room};
use rand_core::CryptoRngCore;

use crate::DurableObjectStorage;

/// Error of [`DoRoomStore`].
#[derive(Debug, thiserror::Error)]
#[error("durable object room storage: {0}")]
pub struct DoRoomStoreError(String);

/// [`RoomStore`] over Durable Object storage.
#[derive(Debug)]
pub struct DoRoomStore<S> {
    storage: S,
}

fn prefix(gid: &Digest) -> String {
    format!("v2/{}", hex::encode(gid))
}

fn journal_key(gid: &Digest, generation: u64, index: u64) -> String {
    format!("{}/journal/{generation:020}/{index:020}", prefix(gid))
}

impl<S: DurableObjectStorage> DoRoomStore<S> {
    /// Store over `storage`.
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    fn backend(error: impl std::fmt::Display) -> DoRoomStoreError {
        DoRoomStoreError(error.to_string())
    }

    fn generation(&self, gid: &Digest) -> Result<u64, DoRoomStoreError> {
        match self
            .storage
            .get_bytes(&format!("{}/generation", prefix(gid)))
            .map_err(Self::backend)?
        {
            None => Ok(0),
            Some(bytes) => bytes
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| DoRoomStoreError("corrupt generation".into())),
        }
    }

    fn journal(
        &self,
        gid: &Digest,
        generation: u64,
    ) -> Result<Vec<(String, Vec<u8>)>, DoRoomStoreError> {
        let mut entries = self
            .storage
            .list_prefix(&format!("{}/journal/{generation:020}/", prefix(gid)))
            .map_err(Self::backend)?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }
}

impl<S: DurableObjectStorage> RoomStore for DoRoomStore<S> {
    type Error = DoRoomStoreError;

    fn load(&self, gid: &Digest) -> Result<Option<StoredRoom>, Self::Error> {
        let generation = self.generation(gid)?;
        let snapshot = if generation == 0 {
            None
        } else {
            Some(
                self.storage
                    .get_bytes(&format!("{}/snapshot/{generation}", prefix(gid)))
                    .map_err(Self::backend)?
                    .ok_or_else(|| DoRoomStoreError("missing snapshot".into()))?,
            )
        };
        let journal: Vec<Vec<u8>> = self
            .journal(gid, generation)?
            .into_iter()
            .map(|(_, record)| record)
            .collect();
        if snapshot.is_none() && journal.is_empty() {
            return Ok(None);
        }
        Ok(Some(StoredRoom { snapshot, journal }))
    }

    fn append(&mut self, gid: &Digest, record: &[u8]) -> Result<usize, Self::Error> {
        let generation = self.generation(gid)?;
        let index = self.journal(gid, generation)?.len();
        self.storage
            .put_bytes(&journal_key(gid, generation, index as u64), record.to_vec())
            .map_err(Self::backend)?;
        Ok(index + 1)
    }

    fn compact(&mut self, gid: &Digest, snapshot: &[u8]) -> Result<(), Self::Error> {
        let generation = self.generation(gid)?;
        let next = generation + 1;
        self.storage
            .put_bytes(
                &format!("{}/snapshot/{next}", prefix(gid)),
                snapshot.to_vec(),
            )
            .map_err(Self::backend)?;
        self.storage
            .put_bytes(
                &format!("{}/generation", prefix(gid)),
                next.to_be_bytes().to_vec(),
            )
            .map_err(Self::backend)?;
        for (key, _) in self.journal(gid, generation)? {
            self.storage.delete_bytes(&key).map_err(Self::backend)?;
        }
        if generation > 0 {
            self.storage
                .delete_bytes(&format!("{}/snapshot/{generation}", prefix(gid)))
                .map_err(Self::backend)?;
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<Digest>, Self::Error> {
        let mut gids: Vec<Digest> = self
            .storage
            .list_prefix("v2/")
            .map_err(Self::backend)?
            .into_iter()
            .filter_map(|(key, _)| {
                let hex = key.strip_prefix("v2/")?.get(..64)?;
                hex::decode(hex).ok()?.try_into().ok()
            })
            .collect();
        gids.sort_unstable();
        gids.dedup();
        Ok(gids)
    }
}

/// The room served by one Durable Object.
#[derive(Debug)]
pub struct WorkerRoomHost<S> {
    store: DoRoomStore<S>,
    room: Option<Room>,
    loaded: bool,
    sessions: SessionRegistry,
    config: ServiceConfig,
}

impl<S: DurableObjectStorage> WorkerRoomHost<S> {
    /// Host over `storage`.
    pub fn new(storage: S, config: ServiceConfig) -> Self {
        Self {
            store: DoRoomStore::new(storage),
            room: None,
            loaded: false,
            sessions: SessionRegistry::new(),
            config,
        }
    }

    fn ensure_loaded(&mut self, gid: &Digest) -> Result<(), ApiError> {
        if self.loaded && self.room.as_ref().is_some_and(|room| room.gid() == gid) {
            return Ok(());
        }
        let internal = |message: String| ApiError::new(ErrorCode::Internal, message);
        self.room = self
            .store
            .load(gid)
            .map_err(|error| internal(error.to_string()))?
            .map(|stored| {
                restore_room(&stored, self.config.room).map_err(|error| internal(error.to_string()))
            })
            .transpose()?;
        self.loaded = true;
        Ok(())
    }

    /// Handle one request.
    pub fn handle(
        &mut self,
        route: Route,
        body: &[u8],
        bearer: Option<&[u8; 32]>,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Handled, ApiError> {
        let gid = request_gid(body)?;
        self.ensure_loaded(&gid)?;
        let config = self.config;
        let handled = match (route, self.room.as_mut()) {
            (Route::CreateGroup, None) => {
                let (room, handled) = create_room(body, &config, now_ms)?;
                self.room = Some(room);
                handled
            }
            (_, None) => return Err(ApiError::new(ErrorCode::NotFound, "group not found")),
            (_, Some(room)) => handle_room_request(
                route,
                body,
                room,
                &mut self.sessions,
                bearer,
                &config,
                now_ms,
                rng,
            )?,
        };
        if let (Some(record), Some(room)) = (&handled.record, self.room.as_ref())
            && let Err(error) = persist_record(&mut self.store, room, record, config.compact_every)
        {
            self.room = None;
            self.loaded = false;
            return Err(error);
        }
        Ok(handled)
    }

    /// Check a subscription token; returns the log head.
    pub fn check_subscription(
        &mut self,
        gid: &Digest,
        token: &[u8; 32],
        now_ms: u64,
    ) -> Result<u64, ApiError> {
        self.ensure_loaded(gid)?;
        let room = self
            .room
            .as_ref()
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "group not found"))?;
        self.sessions.check(Some(token), room, now_ms)?;
        Ok(room.head_seq())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::MemoryDurableObjectStorage;
    use cityg_core::binding::SessionAuth;
    use cityg_core::identity::DeviceIdentity;
    use cityg_core::session::GroupSession;
    use cityg_proto::pb;
    use prost::Message;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn a_durable_object_serves_and_persists_a_room() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let config = ServiceConfig {
            compact_every: 3,
            ..ServiceConfig::default()
        };
        let mut host = WorkerRoomHost::new(MemoryDurableObjectStorage::new(), config);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let (pending, genesis) = GroupSession::create(&alice, 4, &mut rng).unwrap();
        let gid = *pending.gid();
        let mut session = pending.into_session().unwrap();
        let create = pb::CreateGroupRequest {
            gid: gid.to_vec(),
            commit: genesis.commit,
            group_info: genesis.group_info,
        }
        .encode_to_vec();
        let handled = host
            .handle(Route::CreateGroup, &create, None, 10, &mut rng)
            .unwrap();
        assert_eq!(handled.new_head, Some(1));
        assert_eq!(
            host.handle(Route::CreateGroup, &create, None, 10, &mut rng)
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );

        let auth = SessionAuth::sign(&gid, 10, &alice, &mut rng).unwrap();
        let opened = host
            .handle(
                Route::OpenSession,
                &pb::OpenSessionRequest {
                    gid: gid.to_vec(),
                    auth: auth.encoded().to_vec(),
                }
                .encode_to_vec(),
                None,
                10,
                &mut rng,
            )
            .unwrap();
        let token: [u8; 32] = pb::OpenSessionResponse::decode(opened.body.as_slice())
            .unwrap()
            .token
            .try_into()
            .unwrap();
        assert_eq!(host.check_subscription(&gid, &token, 10).unwrap(), 1);
        assert!(host.check_subscription(&gid, &[0; 32], 10).is_err());
        for index in 0..5u8 {
            let envelope = session
                .encrypt(&alice, 1, b"", &[index], 10, &mut rng)
                .unwrap();
            host.handle(
                Route::SendMessage,
                &pb::SendMessageRequest {
                    gid: gid.to_vec(),
                    envelope,
                }
                .encode_to_vec(),
                Some(&token),
                10,
                &mut rng,
            )
            .unwrap();
        }

        // A fresh object instance (after eviction) reloads the same room.
        let storage = host.store.storage.clone();
        let mut reloaded = WorkerRoomHost::new(storage.clone(), config);
        let info = reloaded
            .handle(
                Route::GroupInfo,
                &pb::GroupInfoRequest { gid: gid.to_vec() }.encode_to_vec(),
                None,
                10,
                &mut rng,
            )
            .unwrap();
        assert_eq!(
            pb::GroupInfoResponse::decode(info.body.as_slice())
                .unwrap()
                .head_seq,
            6
        );
        let store = DoRoomStore::new(storage);
        assert_eq!(store.list().unwrap(), vec![gid]);
        let stored = store.load(&gid).unwrap().unwrap();
        assert!(stored.snapshot.is_some(), "compacted");
        assert!(stored.journal.len() < 3);
        assert!(
            reloaded
                .handle(
                    Route::GroupInfo,
                    &pb::GroupInfoRequest { gid: vec![7; 32] }.encode_to_vec(),
                    None,
                    10,
                    &mut rng,
                )
                .is_err()
        );
    }
}
