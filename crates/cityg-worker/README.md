# cityg-worker

Cloudflare Worker oriented runtime adapter for City-G.

## Why this crate exists

`cityg-api` is a native server process. It binds a TCP listener, loads configuration from files and environment variables, keeps request-serving state in process memory, persists journals on the local filesystem, exports Prometheus metrics, and pushes room notifications through a local broadcast channel.

That model is a good fit for a conventional VM or container. It is not the right fit for Cloudflare Workers.

This crate exists to provide a dedicated runtime boundary for Cloudflare deployment without forcing the existing native server crate to absorb Worker-specific assumptions.

Reusable runtime seams are intentionally moving into a neutral shared crate, `cityg-runtime`. That keeps `cityg-worker` free to adopt Cloudflare-specific dependencies later without making the native API depend on Worker-only code.

## Design choices

### 1. Keep `cityg-server` as the protocol/state machine core

The protocol acceptance logic already lives in `cityg-server`, which is a mutable state machine with clear room-scoped semantics. That is the asset we want to preserve.

This crate should adapt that core to a Cloudflare execution model. It should not reimplement City-G validation logic.

### 2. Target one authoritative state machine per room

The recommended Cloudflare-native topology is:

- a Worker entrypoint as the public HTTP edge
- one Durable Object per `gid` as the authoritative room coordinator

The protocol is asynchronous for clients, but server acceptance is still stateful. Multi-head windows allow several valid branches to coexist, yet the server must still apply each accepted bundle atomically against a room's current head set, roster state, barrier state, and history commitment.

That makes per-room serialization a feature, not a limitation.

### 3. Do not port `cityg-api` directly

Porting `cityg-api` line-for-line would keep the wrong seams:

- bind address based startup
- filesystem persistence
- process-local caches as authoritative state
- process-local WebSocket fanout
- native Prometheus exporter assumptions

This crate should expose a Worker-facing API surface instead:

- room bootstrap configuration
- room engine construction
- runtime/storage abstraction points

The native `cityg-api` crate should reuse the same seams through `cityg-runtime`.
The goal is one shared service/bootstrap path with multiple runtime adapters,
not two independent server implementations that drift over time.

### 4. Separate authoritative state from convenience caches

In the native API today, several structures are process-local conveniences:

- stored message backlog
- stored bundles
- alias registry
- reverse indexes such as `weid -> leaf`
- merge ticket coalescing cache

For the Worker migration, this crate should make a clear distinction between:

- authoritative room state that must survive isolate churn
- derived indexes that can be rebuilt
- opportunistic caches that may be dropped safely

### 5. Keep the wire format stable

The Worker runtime should preserve the existing protobuf/CBOR contracts wherever possible. The migration goal is a runtime change, not a protocol fork.

## Non-goals

This crate should not:

- own the full native HTTP server surface
- parse local config files
- assume a writable local filesystem
- expose a long-lived TCP listener API
- become the new home for protocol correctness logic already implemented elsewhere

## Initial scope

The first step is intentionally small:

- create a dedicated crate for the Worker migration
- document the architectural decisions in one place
- define a Worker-oriented bootstrap surface that wraps `cityg-server`

This gives the migration a stable home before we introduce Cloudflare-specific dependencies and storage adapters.

## Planned evolution

Expected next steps for this crate:

1. Bridge the current `cityg-api` room-scoped endpoints onto the Worker edge without duplicating body parsing or `gid` extraction logic.
2. Move the remaining room-scoped API behavior behind explicit runtime adapters.
3. Rework message/bundle/index persistence away from process-local state.
4. Decide the first Worker-time realtime strategy: Durable Object WebSockets or temporary HTTP polling/SSE fallback.
5. Add Worker-focused integration tests.

## Current storage seam

`cityg-runtime` now defines a richer room checkpoint contract for Worker migration:

- opaque engine snapshot bytes for authoritative room state
- accepted bundle history for append/replay parity
- persisted volatile room snapshots for room-local indexes and backlogs

That checkpoint shape is now wired into two Worker-facing layers in this crate:

- `DurableObjectRoomStateStore<S>` provides the shared key/value checkpoint adapter.
- `CloudflareSqlDurableObjectStorage` provides the first real Cloudflare-backed implementation on top of Durable Object SQLite storage.

The `cloudflare` feature also exposes the first Worker runtime surface:

- a Worker `fetch` entrypoint
- a Durable Object class bound under `CITYG_ROOM`
- a global routing-index Durable Object bound under `CITYG_ROUTING_INDEX`
- a global known-room registry Durable Object bound under `CITYG_ROOM_REGISTRY`
- a global alias-registry Durable Object bound under `CITYG_ALIAS_INDEX`
- a config hook, `CITYG_WORKER_CONFIG_JSON`, for replay/bootstrap parity from serialized `CityGConfig`
- an optional backfill hook, `CITYG_WORKER_KNOWN_GIDS_JSON`, for seeding legacy room gids into the known-room registry
- an internal room route prefix, `/__cloudflare/rooms/:gid/...`
- shared protobuf route classification via `cityg-api-schema`
- checkpoint-to-room rehydration by replaying accepted bundles into `RuntimeRoom` and restoring persisted server runtime metadata

That route is intentionally internal for now. It avoids pretending that the current native HTTP contract can be forwarded unchanged before we have shared request parsing and `gid` extraction logic at the edge.

The current edge/runtime split now looks like this:

- direct-`gid` native API requests can be classified and dispatched toward the correct Durable Object
- `we_epoch_id` keyed requests now have a dedicated global lookup path through the routing-index Durable Object
- the Worker edge now also records known `gid`s in a separate room-registry Durable Object, so a `we_epoch_id` routing miss can trigger checkpoint-derived routing resync across known rooms before failing
- room checkpoints can now reconstruct their own `we_epoch_id -> gid` entries and resync them into the global routing index through the room Durable Object
- room status can now report whether the current checkpoint is rehydratable into a `RuntimeRoom`
- checkpoint `server_state_bytes` are now populated and replayed back into `CityGServer`, so kbroad metadata, explicit room-admin ACLs, and other non-bundle runtime metadata survive Durable Object isolate churn
- `/v1/accept_epoch` can now execute inside the room Durable Object, initializing or rehydrating the authoritative room engine, persisting the accepted bundle checkpoint, and upserting the live `we_epoch_id -> gid` routing entry after successful acceptance
- `/v1/rooms/bootstrap` can now execute inside the room Durable Object, verify the room-admin proof with the shared schema helpers, and persist the authoritative room runtime metadata into the checkpoint
- `/v1/rooms/rotate_kbroad`, `/v1/rooms/grant_admin`, `/v1/rooms/revoke_admin`, and `/v1/rooms/list_admins` can now execute inside the room Durable Object and persist updated runtime metadata when they mutate room-admin state
- `/v1/barrier/resolve_revoked_leaves`, `/v1/barrier/resolve_joins_since`, `/v1/barrier/fetch_public_tree`, and `/v1/barrier/lookup_merge_acceptance` can now execute inside the room Durable Object by rehydrating `RuntimeRoom` and reusing the shared runtime barrier-helper preparation logic
- `/v1/barrier/issue_full_verification_witness` can now execute inside the room Durable Object by rehydrating `RuntimeRoom` and reusing the shared runtime full-witness preparation flow
- `/v1/rooms/expel_member_ticket` can now execute inside the room Durable Object by rehydrating `RuntimeRoom`, verifying the room-admin proof payload with the shared schema helpers, and reusing the shared merge-ticket preparation and encoding flow
- `/v1/rooms/merge_ticket` can now execute inside the room Durable Object by rehydrating `RuntimeRoom`, reusing the shared runtime merge-ticket preparation flow, and sharing protobuf response encoding with the native API through `cityg-api-schema`
- `/v1/bundle` can now execute inside the room Durable Object directly from the persisted volatile checkpoint snapshot
- `/v1/messages` can now execute inside the room Durable Object by rehydrating `RuntimeRoom` and reusing the shared runtime authorization/backlog logic
- `/v1/send_message` can now execute inside the room Durable Object and persist the updated volatile room snapshot after shared runtime membership validation
- `/v1/pivot/refresh` can now execute inside the room Durable Object and persist refreshed room runtime metadata back into the checkpoint after the shared runtime pivot-refresh transition succeeds
- `/v1/members` and `/v1/members/search` can now execute inside the room Durable Object by rehydrating `RuntimeRoom`, reusing the shared room-member listing logic, and resolving aliases through the global alias registry Durable Object
- `/v1/rooms/join_ticket` can now execute inside the room Durable Object by reusing the shared join-ticket preparation flow, shared identity-binding verification, and the global alias registry Durable Object for TOFU alias registration
- `/v1/ws` can now route to the room Durable Object too: the DO performs room-membership authorization for the subscribing leaf, accepts the Worker websocket, and fans out message and membership notifications from the same authority that mutates room state
- the DO websocket path now also stores per-socket session metadata through websocket attachments and configures a DO-level `ping` -> `pong` auto-response for the first lightweight heartbeat layer
- the Worker websocket contract is now explicit rather than native-broadcast-shaped: `/v1/ws` is treated as a sequenced hint stream with `ack` / `resume`, bounded replay, `lag` warnings, and a `sync_required` control frame that tells clients to reconcile through HTTP and reconnect when the replay window is exhausted
- the Worker realtime policy is now tunable instead of hard-wired: `CITYG_SERVER_WS_MAX_LAG` still controls the soft lag budget, while `CITYG_WORKER_WS_REPLAY_WINDOW` and `CITYG_WORKER_WS_LAG_NOTICE_THRESHOLD` can widen retention or move the warning threshold without changing the core DO logic
- the internal room status route now exposes realtime diagnostics too, including active websocket count, next sequence, retained replay-window range, and the effective `lag` / `sync_required` policy, so operators can inspect the current DO behavior without attaching a debugger
- rehydration can now use `CITYG_WORKER_CONFIG_JSON` to reconstruct `WorkerRoomBootstrap` from the shared `CityGConfig`, instead of relying only on a hardcoded fallback bootstrap
- the remaining live-routing gap is narrower now: accepted epochs update the global `we_epoch_id -> gid` index immediately, while replay-only rebuild still relies on checkpoint-derived resync
- the routing fallback is stronger now: if the global routing index misses, the Worker can ask the known-room registry to resync registered rooms and retry the lookup before returning 404
- historical rooms can now be backfilled explicitly too: `CITYG_WORKER_KNOWN_GIDS_JSON` accepts a JSON array of 32-byte hex gids, and the Worker will seed those rooms into the known-room registry before running the miss-driven routing convergence path
- the room-admin HTTP surface now has a durable Worker path: bootstrap, rotate, grant, revoke, list, and expel all execute against the persisted room checkpoint model
- alias normalization, TOFU conflict handling, confirmed-leaf updates, and revoked-leaf unbinding now live in shared runtime code, while the Worker path persists them through the global alias registry Durable Object to preserve current native semantics
- all currently classified room-scoped HTTP routes now have a Durable Object execution path, and the first realtime path exists too through a DO-native `/v1/ws` fanout
- the remaining realtime gap is no longer basic routing, client semantics, or observability, but production tuning: replay-window sizing, notice thresholds, and whether the current `sync_required` policy is sufficient under real Worker traffic
- Worker-facing ML-DSA verification is now isolated behind the shared `cityg-pqc` crate, so the Worker adapter no longer depends on `pqcrypto-dilithium` directly for identity-binding or room-admin proof verification
- `cityg-client` demo fixtures are now feature-gated off for `wasm32`, and the remaining production ML-DSA paths in `msphf-core`, `msphf-orchestrator`, and `cityg-server` now route through `cityg-pqc`, so `cargo check -p cityg-worker --features cloudflare --target wasm32-unknown-unknown` now succeeds
- CI now guards both host and Wasm Worker builds: the main workflow compiles `cityg-worker` with `--features cloudflare` on the native test target and on `wasm32-unknown-unknown`
- the Worker crate now also has a higher-level memory-backed checkpoint integration test that exercises the intended Durable Object flow end-to-end: accept a real demo bundle, persist the checkpoint, derive routing entries, rehydrate `RuntimeRoom`, and verify restored message/bundle state
- the remaining replay gap is not the config hook itself anymore, but how far that hook should remain a raw JSON env binding versus evolving into typed/signed Worker-native policy delivery

## Why the crate is intentionally small today

The hardest part of the migration is not compiling Rust to Wasm. The hard part is getting the runtime boundaries right.

Starting with a small crate and a narrow API is deliberate. It avoids locking the repo into a fake "Cloudflare-ready" shape before the state and storage seams are correct.
