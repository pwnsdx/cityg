# 18 — Async-First Join Provisioning

This note summarizes the implemented `v0.1.4` design. It is explanatory, not normative; the normative rules live in `/Users/admin/Desktop/Repositories/cityg/docs/specs.md`.

## Current State

The current implementation uses the barrier-sealed HP transport to:

1. carry `hp` as an opaque client-to-client blob inside `header[97]`,
2. derive the HP AEAD key from authenticated barrier state and local secret state,
3. let a newly joined client self-finalize via `join_finalize`,
4. let cross-device epoch sync converge without copying any secret material out of band.

That behavior is visible in:

- `/Users/admin/Desktop/Repositories/cityg/crates/cityg-client/src/lib.rs`
- `/Users/admin/Desktop/Repositories/cityg/crates/cityg-gui/src/native.rs`
- `/Users/admin/Desktop/Repositories/cityg/crates/msphf-orchestrator/src/lib.rs`

## Product Property

The intended product property is now implemented:

- if the server authorizes a join,
- a newly authorized client can join alone,
- publish its own accepted `join_finalize`,
- become message-ready without another member online,
- and later read/send messages with other members when they come online,
- without the server ever learning the relevant secret material.

## What ME-OR Is And Is Not Doing

ME-OR remains the witness-dependent key derivation mechanism.

It is responsible for:

- deriving the per-epoch secret material from `hp + witness`,
- keeping the server blind to that derivation,
- binding epoch-key recovery to valid membership / join predicates.

ME-OR is not itself the HP transport mechanism.

The transport problem is handled separately by `barrier-sealed-v1`:

1. the publisher seals the local HP artifact into `header[97]`,
2. the server validates and relays the opaque blob,
3. clients re-derive the HP AEAD key from authenticated barrier state and local secret state.

## Pending `join_finalize` State Machine

The implementation-critical part is not the cryptography; it is the pending-state lifecycle around a self-finalizing joiner.

Required operational rules:

- persist the pending join/finalize correlation state before publishing any `join_finalize` candidate,
- on restart, correlate pending work against authenticated history and merge identity artifacts, not just the latest `barrier_version`,
- never discard pending state solely because time elapsed, transport failed, or the group advanced through unrelated epochs,
- only clear pending state after an authenticated success, an authenticated non-acceptance that rules out the candidate, or an explicit local reset/recovery flow,
- if the local history window is temporarily insufficient to decide, stay pending and retry history recovery rather than guessing.

That is the practical guard against the implementation pitfall where a joiner becomes permanently blind because crash/restart code loses the only linkage needed to recognize its accepted `join_finalize`.
