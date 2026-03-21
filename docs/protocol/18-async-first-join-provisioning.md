# 18 — Async-First Join Provisioning Gap

This note is an implementation reality check, not a new normative source.

## Current State

The current implementation still depends on a room-scoped `KBROAD` secret to:

1. recover `hp` from redacted accepted bundles,
2. derive `E_k` / `epoch_key` for epochs authored by other devices,
3. complete cross-device epoch sync after join.

That behavior is visible in:

- `/Users/admin/Desktop/Repositories/cityg/crates/cityg-client/src/lib.rs`
- `/Users/admin/Desktop/Repositories/cityg/crates/cityg-gui/src/native.rs`

In particular:

- `derive_epoch_secrets_with_kbroad_secret(...)` is still required when a bundle does not retain local HP material,
- `perform_epoch_sync(...)` still fails without a local `kbroad_secret`,
- GUI compatibility flows currently rely on a legacy invite that transports `kbroad_secret`.

## Why This Is A Product Gap

The intended product property is stronger:

- if the server authorizes a join,
- a newly authorized client should be able to join alone,
- become message-ready without another member online,
- and later read/send messages with other members when they come online,
- without the server ever learning the relevant secret material.

The current room-shared `KBROAD` secret model does not satisfy that property.

It allows:

- server blindness to `hp`,
- but not server-authorized async-first joins without an extra confidential provisioning path.

## What ME-OR Is And Is Not Doing

ME-OR remains the witness-dependent key derivation mechanism.

It is responsible for:

- deriving the per-epoch secret material from `hp + witness`,
- keeping the server blind to that derivation,
- binding epoch-key recovery to valid membership / join predicates.

ME-OR is not the transport mechanism that gets `hp` to a newly joined device.

That transport problem is the current gap.

## Immediate Consequence

The existing GUI `legacy invite` flow is a compatibility workaround, not the target async-first design.

It should not be treated as the product model for multi-device / cross-device join.

## Refactor Direction

To satisfy the async-first property without giving the server the secret, the room-shared `KBROAD` secret dependency must be removed from the cross-device join/read path.

The likely direction is:

1. replace room-shared `KBROAD` recovery for remote epochs with per-device or barrier-tree-addressed HP transport,
2. keep the server blind to `hp` and to any private decapsulation material,
3. let a newly joined device become readable/writable after its own accepted join-finalize path, without requiring a legacy invite or out-of-band room secret.

That is a protocol/implementation refactor, not a GUI-only change.
