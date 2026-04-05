# Slot Leases (`v0.2`)

> [!IMPORTANT]
> This chapter is a `v0.2` protocol addendum for reusable barrier slots.
> It describes the post-`single-assignment` model implemented incrementally in
> the current codebase. It is intended to supersede the old "burn a leaf
> forever" lifecycle for future profile cuts.

## Goal

The `v0.1.x` barrier model treated a barrier leaf as a lifetime-consumed
address. With enough churn, a group exhausted its leaves even if concurrent
membership stayed small.

`v0.2` changes the meaning of `N_max`:

- `N_max` is the maximum number of concurrently occupied barrier slots.
- A slot is reusable after leave/revoke.
- Reuse is authenticated by a per-occupancy generation counter.

This removes churn-driven capacity exhaustion without requiring a dynamically
growing barrier tree.

## Core Invariants

`leaf_id`
- remains the stable 32-byte device identity used by message crypto and sender
  binding.

`SlotLease`
- identifies one authenticated slot occupancy:
  - `slot_index`
  - `slot_generation`

`slot_generation`
- starts at `0` for a fresh slot
- increments every time a slot is released
- prevents stale revocations, stale `join_finalize_auth`, and stale helper
  material from being applied to a later occupant of the same slot

Active occupancy
- at any committed history view, one `slot_index` has at most one active
  occupant
- a `leaf_id` has at most one active lease

## Server State Model

The server keeps three lease-bearing views:

- active leases: `leaf_slot_leases`
- revoked leases: `revoked_slot_leases`
- pending leases: `pending_join_finalize_auth`

Allocator state is tracked explicitly:

- `free_slots`
- `slot_generations`

The allocator no longer derives the live slot from `leaf_id`.

Relevant code:

- [`../../crates/cityg-server/src/roster_state.rs`](../../crates/cityg-server/src/roster_state.rs)
- [`../../crates/cityg-server/src/lib.rs`](../../crates/cityg-server/src/lib.rs)

## Lifecycle Rules

### Join ticket

When the server issues a join ticket, it allocates a `SlotLease` and binds it to
the pending `join_finalize_auth` capability.

### Join acceptance

When the join is accepted, the pending lease becomes active.

### Leave / revoke

When a member leaves or is revoked:

- the active lease is released
- the slot is returned to `free_slots`
- the stored generation for that slot is incremented
- the released lease is retained in `revoked_slot_leases` until reclaim/finalize
  logic clears the superseded revoked occupancy

### Reclaim join-finalize

If a new member reuses a revoked slot, the reclaim `join_finalize` must bind the
same `slot_index` and the current `slot_generation`. On acceptance, the server
removes the superseded revoked occupancy for that slot.

## Helper and Validation Semantics

The authenticated helper surface now treats revocations and joins as occupancy
records, not naked indices:

- joins carry `leaf_index` plus `slot_generation`
- revoked records carry `leaf_index` plus `slot_generation`

This matters because a revoked `(slot_index=5, generation=0)` must not revoke a
later occupant `(slot_index=5, generation=1)`.

The migrated validation paths now require explicit leases instead of silently
falling back to deterministic `leaf_id -> slot_index` derivation.

## Provisioning and Witness Binding

Provisioning artifacts, merge tickets, receipts, and full-verification witness
material must bind the full occupancy, not just the naked slot index.

Current code status:

- ticket/runtime surfaces use `slot_index` terminology
- join/merge provisioning artifacts were bumped to `v2`
- full-verification witness and receipt binding includes
  `updater_slot_generation`

Relevant code:

- [`../../crates/cityg-api-client/src/verification.rs`](../../crates/cityg-api-client/src/verification.rs)
- [`../../crates/cityg-client/src/barrier.rs`](../../crates/cityg-client/src/barrier.rs)
- [`../../crates/cityg-client/src/barrier_update.rs`](../../crates/cityg-client/src/barrier_update.rs)
- [`../../kat/kat-slot-lease-conformance-v0.2.json`](../../kat/kat-slot-lease-conformance-v0.2.json)
- [`../../scripts/run_slot_lease_conformance.sh`](../../scripts/run_slot_lease_conformance.sh)

## Operational Consequences

What this fixes:

- churn no longer consumes lifetime barrier capacity
- saturation now reflects concurrent occupancy, not historical churn
- replay of stale revocation/join-finalize material against a reused slot is
  structurally prevented by `slot_generation`

What this does not solve:

- increasing concurrent capacity beyond `N_max`
- in-place migration from old `v0.1.x` groups
- migration of historical archived docs/changelogs that intentionally retain
  pre-`v0.2` terminology for audit traceability

## Remaining Work

- cut a fully versioned `v0.2` spec profile in [`../specs.md`](../specs.md)
- extend the slot-lease conformance runner/manifest with heavier end-to-end
  vectors beyond the current deterministic coverage
- keep archived historical docs clearly marked when they still mention
  `cover_leaf_index`
