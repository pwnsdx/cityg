# cityg-server

Rooms of the City-G v0.3 delivery service: their ordered log, journal and
storage.

A room is identified by its group identifier `gid`. It runs
`cityg_core::ledger::GroupLedger`, which checks every commit against the
public group state (signatures, admissions, removal authorization, join
requests and their welcomes, update paths, tree and registry hashes) and
orders commits by epoch. The room holds no group secret: it relays message
envelopes it cannot read and only checks their sender, epoch and replay
window.

- **Log**: commits (with their signed group info and their LightCommit),
  message envelopes, removal proposals and join requests, numbered by
  `seq`; members page through it with `log_after(seq)`.
- **Joins and light members**: the welcomes of committed join requests and
  their status (`join_status`), the LightJoin of a committed request while
  its epoch is current (`light_join`), and leaf proofs against the current
  tree (`leaf_proofs`).
- **Retention**: messages and commits expire after their retention period
  and the log keeps at most `max_log_entries` entries; the latest commit
  always stays, so a member can always resync.
- **Journal**: every accepted request yields a `RoomRecord`; a room is
  restored by replaying its records on its latest snapshot
  (`restore_room`), deterministically.
- **Stores**: `MemoryRoomStore`, and `FileRoomStore` with crash-safe
  compaction (snapshot of generation `g + 1` written before the journal of
  generation `g` is deleted).

The transports (`cityg-api`, `cityg-worker`) drive rooms through the
request handlers of `cityg-runtime`.
