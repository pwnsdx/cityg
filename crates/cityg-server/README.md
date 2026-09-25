# cityg-server

Rooms of the City-G v0.2 delivery service: their ordered log, journal and
storage.

A room is identified by its group identifier `gid`. It runs
`cityg_core::ledger::GroupLedger`, which checks every commit against the
public group state (signatures, admission, removal authorization, update
paths, tree and roster hashes) and orders commits by epoch. The room holds
no group secret: it relays message envelopes it cannot read and only checks
their sender, epoch and replay window.

- **Log**: commits (with their signed group info), message envelopes and
  removal proposals, numbered by `seq`; members page through it with
  `log_after(seq)`.
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
