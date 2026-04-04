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
- [~] Rework `ResolveJoinsSince` and `ResolveRevokedLeaves`
- [x] Update completeness attestations to cover occupancy records
  Rust runtime/schema/client surfaces now expose occupancy-oriented types and versioned revoked records; the remaining legacy is now mostly in public protobuf/message names and helper-kind identifiers, not in runtime call sites.

### 4. Barrier validation

- [ ] Replace `updater_leaf` binding with lease binding in the wire profile
  `api-client` mappe désormais explicitement le champ wire legacy `updater_leaf` vers `updater_slot_index` dans les adaptateurs de vérification, mais le format CBOR reste inchangé.
  `cityg-client` consomme désormais `updater_slot_index` en interne pour `ParsedBarrierUpdate` et les chemins de build/recovery associés.
- [x] Update `join_finalize_auth` validation to match the current leased slot
- [x] Update receipts and full-verification witness payloads
  `BarrierIssueFullVerificationWitnessRequest` transporte désormais des records `Occupancy` versionnés.
- [x] Update snapshot reconstruction so reclaim joins remove the updater slot from the revoked set

### 5. API and runtime

- [~] Introduce `cityg.api.v2`
- [x] Add `v2` helper route aliases for occupancy-oriented barrier helpers
- [x] Add protobuf `v2` helper request/response messages for occupancy-oriented barrier helpers
- [x] Remove orphaned protobuf `*LeafRecord` messages once all helper/ticket/witness wire paths consume `OccupancyRecord`
- [ ] Replace `cover_leaf_index` fields in tickets with `slot_index` + `slot_generation`
- [x] Rename internal server/runtime ticket bundle fields from `cover_leaf_index` to `slot_index`
- [x] Align migrated ticket/runtime error terminology from `cover_leaf_index` to `slot_index`
- [x] Rename join/merge provisioning artifact CBOR fields from `cover_leaf_index` to `slot_index` and bump artifact labels to `v2`
- [x] Require explicit slot leases in the live server join/revoke delta path instead of deriving them from `leaf_id`
- [x] Require explicit slot leases in migrated server helper/validation paths instead of falling back to deterministic slot derivation
- [~] Replace `current_join_records` and `current_revoked_records`
  `JoinTicketResponse` transporte désormais des `BarrierJoinOccupancyRecord` / `BarrierRevokedOccupancyRecord`; le renommage complet des champs et du reste du wire profile reste à faire.
- [x] Remove `current_revoked_leaf_indices` from `JoinTicketResponse` and join provisioning artifacts
- [x] Remove `leaf_indices` from `BarrierResolveRevokedLeavesResponse`
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
- [~] Replace prepared/runtime `cover_leaf_index` + `slot_generation` pairs with `SlotLease`
- [~] Update bootstrap/join-finalize state
- [x] Update bootstrap/join-finalize state to persist versioned revoked records
- [x] Drop duplicated bootstrap/current revoked leaf-index caches where versioned records are already present
- [~] Update barrier recovery to compare full leases
- [~] Update tests and fixtures

### 7. KAT and conformance

- [ ] Add KATs for slot reuse after leave/revoke
- [~] Add replay rejection tests for stale `join_finalize_auth`
- [~] Add historical chain-check tests where one slot has multiple generations
  Server helper coverage now exercises join-helper pruning across reused-slot generations; end-to-end client/history KATs still need to follow.
- [~] Update the primary spec text from single-assignment to versioned `SlotLease` semantics
  `docs/specs.md` now reflects reusable slots, versioned revoked/join records, and lease-bound `join_finalize_auth` / receipt / witness validation in the key barrier sections; full document sweep is still pending.

## Immediate next slice

1. Finish the remaining public/profile rename in protobuf message names and route enums that still say `ResolveRevokedLeaves` / `ResolveJoinsSince`.
2. Decide whether `helper_kind` and the CBOR wire label `updater_leaf` stay as documented legacy identifiers or also move in a hard `v0.2` cut.
3. Add KAT/conformance coverage that exercises reused-slot generations through the public helper/profile boundary.
