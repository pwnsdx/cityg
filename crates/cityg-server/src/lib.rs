#![forbid(unsafe_code)]

//! City-G v0.2 delivery service: rooms, their journal and their storage.
//!
//! A room is identified by its group identifier `gid`. The delivery service
//! holds no group secret: it runs [`cityg_core::ledger::GroupLedger`] on
//! every commit and relays envelopes it cannot read.

mod record;
mod room;
mod store;

pub use record::{MAX_RECORD_BYTES, RoomRecord};
pub use room::{LogBody, LogEntry, LogPage, Room, RoomConfig, RoomError, RoomInfo};
#[cfg(not(target_arch = "wasm32"))]
pub use store::{FileRoomStore, FileRoomStoreError};
pub use store::{MemoryRoomStore, RoomStore, StoredRoom, restore_room};

#[cfg(test)]
mod tests;
