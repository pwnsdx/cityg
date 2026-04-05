# Slot Leases v0.2

## Goal

Replace barrier leaf single-assignment with reusable slot leases so that:

- `leaf_id` remains the stable device identity
- `N_max` becomes concurrent capacity only
- each slot occupancy is identified by `(slot_index, slot_generation)`
- old revokes and old `join_finalize_auth` tokens cannot apply to a later occupant of the same slot

## Invariants

- A slot may be reused only after its previous occupancy is released.
- Reuse of a slot MUST increment `slot_generation`.
- Validation, helpers, and provisioning artifacts MUST bind the full lease, not a naked slot index.
- The wire/profile move happens in `v0.2`; no backward compatibility is required.

## Phases

### 1. Server state and allocator

- [x] Add `SlotLease { slot_index, slot_generation }`
- [x] Add reusable slot allocator state to `GroupState`
- [x] Add `allocate_slot_lease`, `reserve_slot_lease`, `release_slot_lease`
- [x] Extend `pending_join_finalize_auth` to carry a full lease
- [x] Add unit tests for slot reuse and stale-generation rejection

### 2. Join and merge server flow

- [x] Replace monotonic leaf-slot consumption for new joins
- [x] Bind join provisioning to `SlotLease`
- [x] Rehydrate replayed `join_finalize_auth` against `SlotLease`
- [x] Release slot leases on leave/revoke
- [x] Clear superseded revoked-slot leases on reclaim `join_finalize`

### 3. Helper surfaces

- [x] Replace `BarrierJoinLeafRecord` with occupancy records
- [x] Replace naked revoked leaf indices with revoked occupancy records
- [~] Rework `ResolveJoinOccupanciesSince` and `ResolveRevokedOccupancies`
- [x] Update completeness attestations to cover occupancy records
  Rust runtime/schema/client surfaces now expose occupancy-oriented types and versioned revoked records; `helper_kind` completeness-attestation identifiers now also use the occupancy-oriented names, so the remaining legacy is mostly in selected CBOR field labels.

### 4. Barrier validation

- [x] Replace legacy `updater_leaf` binding with lease binding in the wire profile
  Les encodeurs/décodeurs runtime utilisent désormais `updater_slot_index` comme champ wire et comme nom interne; le reliquat restant est surtout un sweep documentaire plus large sur les anciennes formulations.
- [x] Update `join_finalize_auth` validation to match the current leased slot
- [x] Update receipts and full-verification witness payloads
  `BarrierIssueFullVerificationWitnessRequest` transporte désormais des records `Occupancy` versionnés.
- [x] Update snapshot reconstruction so reclaim joins remove the updater slot from the revoked set

### 5. API and runtime

- [x] Introduce `cityg.api.v2` for occupancy-oriented barrier helpers
- [x] Add protobuf `v2` helper request/response messages for occupancy-oriented barrier helpers
- [x] Remove legacy helper `v1` routes/messages once `v2` occupancies are in place
- [x] Remove orphaned protobuf `*LeafRecord` messages once all helper/ticket/witness wire paths consume `OccupancyRecord`
- [x] Replace `cover_leaf_index` fields in tickets with `slot_index` + `slot_generation`
- [x] Rename internal server/runtime ticket bundle fields from `cover_leaf_index` to `slot_index`
- [x] Align migrated ticket/runtime error terminology from `cover_leaf_index` to `slot_index`
- [x] Rename join/merge provisioning artifact CBOR fields from `cover_leaf_index` to `slot_index` and bump artifact labels to `v2`
- [x] Require explicit slot leases in the live server join/revoke delta path instead of deriving them from `leaf_id`
- [x] Require explicit slot leases in migrated server helper/validation paths instead of falling back to deterministic slot derivation
- [x] Replace `current_join_occupancies` and `current_revoked_occupancies`
  `JoinTicketResponse`, ses attestations de complétude, et les call sites runtime/client/gui utilisent désormais les noms `current_*_occupancies`.
- [x] Remove `current_revoked_leaf_indices` from `JoinTicketResponse` and join provisioning artifacts
- [x] Remove `leaf_indices` from revoked-helper responses
- [x] Remove `revoked_leaf_indices` from full-verification witness requests
- [x] Remove stored `leaf_indices` from `BarrierResolvedRevokedLeaves` client state
- [x] Remove stored `leaf_indices` from `ResolvedRevokedLeaves` server state
- [x] Remove helper-level `leaf_indices` compatibility accessors from client/server runtime surfaces
- [x] Remove helper-level `*Leaves` / `*Joins` compatibility shims from client/server/runtime Rust APIs
- [~] Update schema encoding/decoding
  `api-schema` now covers `v2` helper route extraction and occupancy-response protobuf encoding.
- [~] Update runtime service ticket preparation
- [x] Add occupancy-oriented Rust type aliases/surfaces in `server` / `runtime` / `api-client` / `api-schema`
  Internal `server` / `runtime` / `api-client` / `gui` call sites now consume the occupancy-named types directly.

### 6. Client and GUI

- [x] Persist the local slot as an explicit `SlotLease`
- [~] Replace prepared/runtime legacy `slot_index` + `slot_generation` pairs with `SlotLease`
- [~] Update bootstrap/join-finalize state
- [x] Update bootstrap/join-finalize state to persist versioned revoked records
- [x] Drop duplicated bootstrap/current revoked leaf-index caches where versioned records are already present
- [~] Update barrier recovery to compare full leases
- [~] Update tests and fixtures

### 7. KAT and conformance

- [~] Add KATs for slot reuse after leave/revoke
  `kat/kat-slot-lease-conformance-v0.2.json` now maps the shipped deterministic tests for reclaim clearing, stale `join_finalize_auth` rejection, helper generation binding, and public join/merge ticket tamper rejection. `scripts/run_slot_lease_conformance.sh` provides a repeatable runner for the current slot-lease suite; broader end-to-end vectors are still pending.
- [~] Add replay rejection tests for stale `join_finalize_auth`
- [~] Add historical chain-check tests where one slot has multiple generations
  Server helper coverage now exercises join-helper pruning across reused-slot generations, and `api-client` now checks that paginated `v2` revoked occupancies preserve distinct `slot_generation` values for one reused slot, rejects tampered `current_join_occupancies` and `current_revoked_occupancies` in join provisioning, and rejects tampered merge-ticket `slot_generation`. `cityg-client` snapshot/transition tests also cover reused-slot joins and versioned revocations; end-to-end client/history KATs still need to follow.
- [~] Update the primary spec text from single-assignment to versioned `SlotLease` semantics
  `docs/specs.md` now reflects reusable slots, versioned revoked/join records, and lease-bound `join_finalize_auth` / receipt / witness validation in the key barrier sections; full document sweep is still pending.

## Immediate next slice

1. Extend slot-lease coverage beyond deterministic/unit-style tests into fuller end-to-end vectors/KAT fixtures.
2. Sweep archived historical docs/changelogs only where the old terminology is still presented as active behavior rather than explicitly historical context.
3. Rename lingering local test variable names that still obscure the slot-lease model.
