//! Durable storage of rooms: a snapshot plus a journal of records.
//!
//! A room is stored as the snapshot of its state at some journal generation
//! `g` and the records journaled since. Compaction writes the snapshot of
//! generation `g + 1` (which starts an empty journal `g + 1`) before it
//! deletes the files of generation `g`, so a crash at any point leaves a
//! snapshot and its matching journal: no record is applied twice or lost.

use std::collections::BTreeMap;

use cityg_core::hash::Digest;

use super::record::RoomRecord;
use super::room::{Room, RoomConfig, RoomError};

/// A stored room: its latest snapshot (if any) and the records since.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredRoom {
    pub snapshot: Option<Vec<u8>>,
    pub journal: Vec<Vec<u8>>,
}

/// Storage backend of rooms.
pub trait RoomStore {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load room `gid`.
    fn load(&self, gid: &Digest) -> Result<Option<StoredRoom>, Self::Error>;

    /// Append an encoded record to the journal of `gid`; returns the number
    /// of records in the journal.
    fn append(&mut self, gid: &Digest, record: &[u8]) -> Result<usize, Self::Error>;

    /// Replace the state of `gid` by `snapshot` and an empty journal.
    fn compact(&mut self, gid: &Digest, snapshot: &[u8]) -> Result<(), Self::Error>;

    /// Stored rooms.
    fn list(&self) -> Result<Vec<Digest>, Self::Error>;
}

/// Rebuild a room from storage.
pub fn restore_room(stored: &StoredRoom, config: RoomConfig) -> Result<Room, RoomError> {
    let records = stored
        .journal
        .iter()
        .map(|record| RoomRecord::decode(record))
        .collect::<Result<Vec<_>, _>>()?;
    match &stored.snapshot {
        Some(snapshot) => {
            let mut room = Room::from_snapshot(snapshot, config)?;
            for record in &records {
                room.apply_record(record)?;
            }
            Ok(room)
        }
        None => Room::replay(&records, config),
    }
}

/// In-memory store for tests and ephemeral deployments.
#[derive(Clone, Debug, Default)]
pub struct MemoryRoomStore {
    rooms: BTreeMap<Digest, StoredRoom>,
}

impl MemoryRoomStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl RoomStore for MemoryRoomStore {
    type Error = std::convert::Infallible;

    fn load(&self, gid: &Digest) -> Result<Option<StoredRoom>, Self::Error> {
        Ok(self.rooms.get(gid).cloned())
    }

    fn append(&mut self, gid: &Digest, record: &[u8]) -> Result<usize, Self::Error> {
        let room = self.rooms.entry(*gid).or_default();
        room.journal.push(record.to_vec());
        Ok(room.journal.len())
    }

    fn compact(&mut self, gid: &Digest, snapshot: &[u8]) -> Result<(), Self::Error> {
        self.rooms.insert(
            *gid,
            StoredRoom {
                snapshot: Some(snapshot.to_vec()),
                journal: Vec::new(),
            },
        );
        Ok(())
    }

    fn list(&self) -> Result<Vec<Digest>, Self::Error> {
        Ok(self.rooms.keys().copied().collect())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use file::{FileRoomStore, FileRoomStoreError};

#[cfg(not(target_arch = "wasm32"))]
mod file {
    use std::collections::BTreeMap;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};

    use cityg_core::hash::Digest;

    use super::{RoomStore, StoredRoom};

    /// Error of the file store.
    #[derive(Debug, thiserror::Error)]
    pub enum FileRoomStoreError {
        #[error("room storage I/O error: {0}")]
        Io(#[from] std::io::Error),
        #[error("corrupt room storage: {0}")]
        Corrupt(String),
    }

    /// Rooms stored under `root/rooms-v3/<gid hex>/`: `snapshot-<g>.cbor`
    /// and `journal-<g>.log` (records as big-endian u32 length frames),
    /// where `g` is the journal generation.
    #[derive(Clone, Debug)]
    pub struct FileRoomStore {
        root: PathBuf,
        journal_lengths: BTreeMap<Digest, usize>,
    }

    fn hex(gid: &Digest) -> String {
        gid.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn parse_hex(name: &str) -> Option<Digest> {
        if name.len() != 64 {
            return None;
        }
        let mut gid = [0u8; 32];
        for (index, byte) in gid.iter_mut().enumerate() {
            *byte = u8::from_str_radix(name.get(2 * index..2 * index + 2)?, 16).ok()?;
        }
        Some(gid)
    }

    impl FileRoomStore {
        /// Store rooms under `root`.
        pub fn new(root: impl Into<PathBuf>) -> Result<Self, FileRoomStoreError> {
            let root = root.into().join("rooms-v3");
            fs::create_dir_all(&root)?;
            Ok(Self {
                root,
                journal_lengths: BTreeMap::new(),
            })
        }

        fn dir(&self, gid: &Digest) -> PathBuf {
            self.root.join(hex(gid))
        }

        /// Highest snapshot generation in `dir` (0 when there is none).
        fn generation(dir: &Path) -> Result<u64, FileRoomStoreError> {
            let mut generation = 0;
            match fs::read_dir(dir) {
                Ok(entries) => {
                    for entry in entries {
                        let name = entry?.file_name();
                        if let Some(value) = name
                            .to_str()
                            .and_then(|name| name.strip_prefix("snapshot-"))
                            .and_then(|name| name.strip_suffix(".cbor"))
                            .and_then(|value| value.parse::<u64>().ok())
                        {
                            generation = generation.max(value);
                        }
                    }
                    Ok(generation)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
                Err(error) => Err(error.into()),
            }
        }

        fn snapshot_path(dir: &Path, generation: u64) -> PathBuf {
            dir.join(format!("snapshot-{generation}.cbor"))
        }

        fn journal_path(dir: &Path, generation: u64) -> PathBuf {
            dir.join(format!("journal-{generation}.log"))
        }

        fn read_journal(path: &Path) -> Result<Vec<Vec<u8>>, FileRoomStoreError> {
            let mut data = Vec::new();
            match File::open(path) {
                Ok(mut file) => {
                    file.read_to_end(&mut data)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Vec::new());
                }
                Err(error) => return Err(error.into()),
            }
            let mut records = Vec::new();
            let mut offset = 0usize;
            while let Some(header) = data.get(offset..offset + 4) {
                let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
                // A torn final frame is an append that never completed.
                let Some(record) = data.get(offset + 4..offset + 4 + len) else {
                    break;
                };
                records.push(record.to_vec());
                offset += 4 + len;
            }
            Ok(records)
        }
    }

    impl RoomStore for FileRoomStore {
        type Error = FileRoomStoreError;

        fn load(&self, gid: &Digest) -> Result<Option<StoredRoom>, Self::Error> {
            let dir = self.dir(gid);
            if !dir.exists() {
                return Ok(None);
            }
            let generation = Self::generation(&dir)?;
            let snapshot = if generation == 0 {
                None
            } else {
                Some(fs::read(Self::snapshot_path(&dir, generation))?)
            };
            let journal = Self::read_journal(&Self::journal_path(&dir, generation))?;
            if snapshot.is_none() && journal.is_empty() {
                return Ok(None);
            }
            Ok(Some(StoredRoom { snapshot, journal }))
        }

        fn append(&mut self, gid: &Digest, record: &[u8]) -> Result<usize, Self::Error> {
            let dir = self.dir(gid);
            fs::create_dir_all(&dir)?;
            let generation = Self::generation(&dir)?;
            let path = Self::journal_path(&dir, generation);
            let len = u32::try_from(record.len())
                .map_err(|_| FileRoomStoreError::Corrupt("record too large".into()))?;
            let known = match self.journal_lengths.get(gid) {
                Some(known) => *known,
                None => Self::read_journal(&path)?.len(),
            };
            let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
            let mut frame = Vec::with_capacity(4 + record.len());
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(record);
            file.write_all(&frame)?;
            file.sync_data()?;
            self.journal_lengths.insert(*gid, known + 1);
            Ok(known + 1)
        }

        fn compact(&mut self, gid: &Digest, snapshot: &[u8]) -> Result<(), Self::Error> {
            let dir = self.dir(gid);
            fs::create_dir_all(&dir)?;
            let generation = Self::generation(&dir)?;
            let next = generation + 1;
            let tmp = dir.join("snapshot.tmp");
            {
                let mut file = File::create(&tmp)?;
                file.write_all(snapshot)?;
                file.sync_all()?;
            }
            // Once the new snapshot is in place it wins; the previous
            // generation's files are no longer read and can go.
            fs::rename(&tmp, Self::snapshot_path(&dir, next))?;
            for old in [
                Self::snapshot_path(&dir, generation),
                Self::journal_path(&dir, generation),
            ] {
                if old.exists() {
                    fs::remove_file(old)?;
                }
            }
            self.journal_lengths.insert(*gid, 0);
            Ok(())
        }

        fn list(&self) -> Result<Vec<Digest>, Self::Error> {
            let mut gids = Vec::new();
            for entry in fs::read_dir(&self.root)? {
                let entry = entry?;
                if let Some(gid) = entry.file_name().to_str().and_then(parse_hex) {
                    gids.push(gid);
                }
            }
            gids.sort_unstable();
            Ok(gids)
        }
    }
}
