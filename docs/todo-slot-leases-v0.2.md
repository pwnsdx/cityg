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

- [ ] Replace `BarrierJoinLeafRecord` with occupancy records
- [ ] Replace naked revoked leaf indices with revoked occupancy records
- [ ] Rework `ResolveJoinsSince` and `ResolveRevokedLeaves`
- [ ] Update completeness attestations to cover occupancy records

### 4. Barrier validation

- [ ] Replace `updater_leaf` binding with lease binding in the wire profile
- [x] Update `join_finalize_auth` validation to match the current leased slot
- [x] Update receipts and full-verification witness payloads
- [x] Update snapshot reconstruction so reclaim joins remove the updater slot from the revoked set

### 5. API and runtime

- [ ] Introduce `cityg.api.v2`
- [ ] Replace `cover_leaf_index` fields in tickets with `slot_index` + `slot_generation`
- [~] Replace `current_join_records` and `current_revoked_leaf_indices`
- [x] Remove `current_revoked_leaf_indices` from `JoinTicketResponse` and join provisioning artifacts
- [ ] Update schema encoding/decoding
- [~] Update runtime service ticket preparation

### 6. Client and GUI

- [x] Persist the local slot as an explicit `SlotLease`
- [~] Replace prepared/runtime `cover_leaf_index` + `slot_generation` pairs with `SlotLease`
- [~] Update bootstrap/join-finalize state
- [x] Update bootstrap/join-finalize state to persist versioned revoked records
- [x] Drop duplicated bootstrap/current revoked leaf-index caches where versioned records are already present
- [~] Update barrier recovery to compare full leases
- [ ] Update tests and fixtures

### 7. KAT and conformance

- [ ] Add KATs for slot reuse after leave/revoke
- [ ] Add replay rejection tests for stale `join_finalize_auth`
- [ ] Add historical chain-check tests where one slot has multiple generations

## Immediate next slice

1. Replace remaining internal `cover_leaf_index`/`slot_generation` pairs with `SlotLease` in `api-client` verification and ticket prep.
2. Finish helper/API cleanup so all occupancy surfaces speak in versioned records only.
3. Remove the remaining naked revoked-leaf index compatibility from helper surfaces, not just join tickets.
4. Prepare the wire/profile `v0.2` cut once the runtime surfaces stop depending on naked slot indices.
