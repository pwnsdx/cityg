# Worker Migration TODO

This file tracks the ongoing work required to make the server Cloudflare Worker
friendly while keeping the native API and Worker paths aligned on shared
runtime code.

## Done

- [x] Create `cityg-worker` as the Worker-facing runtime adapter crate.
- [x] Create `cityg-runtime` as the neutral shared runtime crate.
- [x] Move shared bootstrap/config helpers into `cityg-runtime`.
- [x] Move shared room persistence contracts into `cityg-runtime`.
- [x] Consolidate volatile room indexes/backlogs into shared runtime types.
- [x] Collapse `cityg-api` room-local caches into `RoomVolatileState`.
- [x] Introduce `RuntimeRoom` as the shared room core shape.
- [x] Make `cityg-worker` wrap `RuntimeRoom` instead of raw `CityGServer`.
- [x] Expose room-local volatile helpers directly on `RuntimeRoom`.
- [x] Move accepted-bundle volatile index updates into shared runtime services.
- [x] Move shared room membership authorization checks into `cityg-runtime`.
- [x] Move accepted/replayed bundle materialization into shared runtime services.
- [x] Move `join_ticket` bundle/artifact preparation into shared runtime services.
- [x] Move `merge_ticket` and `expel_member_ticket` artifact preparation into shared runtime services.
- [x] Move `refresh_pivot` execution/conflict classification into shared runtime services.
- [x] Reuse shared merge-ticket artifact preparation inside `barrier_issue_full_verification_witness`.
- [x] Move barrier helper/current-state authority-profile envelope preparation into shared runtime services.
- [x] Move barrier helper pagination semantics into shared runtime services.
- [x] Move barrier helper endpoint preparation for revocations, joins, public tree, and merge acceptance into shared runtime services.
- [x] Move full verification witness preparation/validation into shared runtime services.
- [x] Move debug multi-head window seeding into shared runtime services.
  `seed_window_head` in `cityg-api` now delegates to `cityg-runtime`, so the multi-head window head-record construction no longer lives only in the native HTTP layer.
- [x] Move debug window/telemetry snapshot extraction into shared runtime and schema helpers.
  `get_window` now reuses shared `cityg-runtime` snapshot collectors, and both `get_window` / `get_telemetry` now share protobuf response encoding through `cityg-api-schema` instead of rebuilding those payloads inline in `cityg-api`.
- [x] Move debug window-limit validation and application into shared runtime services.
  `configure_window` in `cityg-api` now delegates request validation and `CityGServer` window-limit updates to `cityg-runtime`, so the native HTTP layer no longer owns those bounds or update semantics.
- [x] Move shared protobuf/server `HistoryCommitment` and forward-leap policy conversions into `cityg-api-schema`.
  Native `cityg-api` and Worker `cloudflare` now share the same protobuf decode/encode helpers for `HistoryCommitment` and `FsForwardLeapPolicy`, instead of carrying duplicate local converters.
- [x] Move full verification witness request decoding into `cityg-api-schema`.
  Native `cityg-api` and Worker `cloudflare` now share the protobuf-to-runtime validation and projection for `BarrierIssueFullVerificationWitnessRequest`, so only `room_id` routing stays adapter-specific.
- [x] Move read-only barrier helper request decoding into `cityg-api-schema`.
  Native `cityg-api` and Worker `cloudflare` now share the fixed-width field validation/projection for revoked-leaves, public-tree, and merge-acceptance helper requests instead of duplicating those byte-length checks in both adapters.
- [x] Move barrier-helper and full verification witness response encoding into `cityg-api-schema`.
  Native `cityg-api` and Worker `cloudflare` now share the protobuf response shaping for revoked-leaves, joins-since, public-tree, merge-acceptance, and full verification witness endpoints instead of rebuilding those envelopes inline in both adapters.
- [x] Move member-list response encoding into `cityg-api-schema`.
  Native `cityg-api` and Worker `cloudflare` now share the protobuf response shaping for `/v1/members` and `/v1/members/search`, so those adapters only keep alias lookup, paging, and request validation locally.
- [x] Move room-admin and bootstrap response encoding into `cityg-api-schema`.
  Native `cityg-api` and Worker `cloudflare` now share the protobuf response shaping for `/v1/rooms/bootstrap`, `/v1/rooms/rotate_kbroad`, `/v1/rooms/grant_admin`, `/v1/rooms/revoke_admin`, and `/v1/rooms/list_admins`, so those adapters no longer rebuild the same room-admin envelopes inline.
- [x] Define the shared Durable Object storage contract for authoritative room checkpoints and volatile room snapshots.
- [x] Add room-volatile snapshot/hydration helpers aligned with the shared checkpoint contract.
- [x] Implement the first Durable Object-backed `RoomStateStore`.
- [x] Introduce the first actual Cloudflare Worker/Durable Object runtime bindings.
- [x] Create a shared API schema crate and room-key extractor for Worker/native route parity.
- [x] Add the first global Worker routing-index Durable Object for `we_epoch_id -> gid` lookup.
- [x] Add checkpoint-derived routing-entry reconstruction for the Worker routing index.
- [x] Add room checkpoint -> `RuntimeRoom` rehydration by replaying accepted bundles in `cityg-worker`.
- [x] Restore persisted server runtime metadata during Worker room rehydration.
  Worker checkpoints now round-trip `server_state_bytes`, so non-replay-derived room state such as kbroad metadata and explicit room-admin ACLs survive isolate churn.
- [x] Execute the first native room-scoped Worker routes inside the room Durable Object.
  `/v1/bundle` now serves directly from the persisted volatile checkpoint snapshot, and `/v1/messages` now rehydrates `RuntimeRoom` and reuses the shared runtime authorization/backlog flow.
- [x] Expose Worker replay/bootstrap configuration from serialized shared config.
  `cityg-worker` now accepts `CITYG_WORKER_CONFIG_JSON` and derives `WorkerRoomBootstrap` from the shared `CityGConfig`, including seeded demo bootstrap policy and kbroad registry.
- [x] Port the first mutating native room-scoped endpoint into the room Durable Object.
  `/v1/send_message` now reuses shared runtime membership checks and persists the updated volatile room snapshot back into Durable Object storage.
- [x] Port the first authoritative state-transition endpoint into the room Durable Object.
  `/v1/accept_epoch` now reuses shared runtime acceptance logic, creates or rehydrates the room engine inside the Durable Object, persists accepted bundle checkpoints, and upserts the live `we_epoch_id -> gid` routing entry after successful acceptance.
- [x] Port the read-only room barrier helper endpoints into the room Durable Object.
  `/v1/barrier/resolve_revoked_leaves`, `/v1/barrier/resolve_joins_since`, `/v1/barrier/fetch_public_tree`, and `/v1/barrier/lookup_merge_acceptance` now rehydrate the room engine inside the Durable Object and reuse the shared runtime preparation flows.
- [x] Port the room-scoped merge-ticket path into the room Durable Object.
  `/v1/rooms/merge_ticket` now rehydrates the room engine in the Durable Object, reuses the shared runtime merge-ticket preparation flow, and shares protobuf response encoding through `cityg-api-schema`.
- [x] Port the first room-admin bootstrap path into the room Durable Object.
  `/v1/rooms/bootstrap` now creates or rehydrates the room engine inside the Durable Object, verifies the room-admin proof through `cityg-api-schema`, and persists server runtime metadata back into the checkpoint.
- [x] Port the room-admin expel ticket path into the room Durable Object.
  `/v1/rooms/expel_member_ticket` now rehydrates the room engine in the Durable Object, verifies room-admin proof payloads through `cityg-api-schema`, and reuses the shared merge-ticket encoding path.
- [x] Port the remaining room-admin Durable Object handlers.
  `/v1/rooms/rotate_kbroad`, `/v1/rooms/grant_admin`, `/v1/rooms/revoke_admin`, and `/v1/rooms/list_admins` now execute inside the room Durable Object and persist updated runtime metadata back into the checkpoint when they mutate room state.
- [x] Move alias TOFU semantics into shared runtime and shared schema helpers.
  Alias normalization/TOFU/update/revoke behavior now lives in `cityg-runtime`, while identity-binding verification and join-ticket protobuf encoding are shared through `cityg-api-schema`.
- [x] Move alias-backed member paging/filtering and identity-binding leaf derivation into shared helpers.
  Native and Worker runtimes now share room-member pagination/search behavior in `cityg-runtime`, plus shared protobuf member shaping and join identity-binding preparation in `cityg-api-schema`.
- [x] Add a Worker-safe global alias registry Durable Object.
  The Worker runtime now has a dedicated global alias binding service for alias registration, leaf lookup, and revoked-leaf unbinding.
- [x] Port the alias-backed room endpoints into the room Durable Object.
  `/v1/members`, `/v1/members/search`, and `/v1/rooms/join_ticket` now execute inside the room Durable Object and reuse the shared alias/runtime/schema helpers.
- [x] Port the remaining recognized room-scoped HTTP routes into the room Durable Object.
  `/v1/barrier/issue_full_verification_witness` and `/v1/pivot/refresh` now execute inside the room Durable Object too, so every `RoomScopedApiRoute` variant has a durable Worker handler except the separate `/v1/ws` realtime path.
- [x] Add the first Worker-focused CI guardrail for the Cloudflare adapter.
  The main CI workflow now compiles `cityg-worker` with the `cloudflare` feature and test targets enabled, so Worker-only code stops drifting silently from the native build.
- [x] Implement the first Worker realtime strategy on top of room Durable Objects.
  `/v1/ws` now routes to the room Durable Object, performs room-membership auth there, and fans out message/membership notifications directly from the same DO that executes `send_message` and `accept_epoch`.
- [x] Introduce a shared PQC adapter seam for Worker-facing ML-DSA verification.
  `cityg-pqc` now centralizes POP/admin signature verification so `cityg-api-schema`, `cityg-api`, and `cityg-worker` no longer depend on `pqcrypto-dilithium` directly for runtime verification, and the Worker target can switch to a pure-Rust Wasm backend behind one crate boundary.
- [x] Remove the transitive `pqcrypto-dilithium` blocker from the Worker Wasm dependency graph.
  `cityg-client` demo fixtures are now feature-gated off for `wasm32`, `msphf-core`, `msphf-orchestrator`, and `cityg-server` now route their production ML-DSA paths through `cityg-pqc`, and `cargo check -p cityg-worker --features cloudflare --target wasm32-unknown-unknown` now passes.
- [x] Add a true Wasm-target CI guardrail for the Cloudflare adapter.
  The main CI workflow now installs `wasm32-unknown-unknown` and compiles `cityg-worker` with `--features cloudflare --target wasm32-unknown-unknown`.
- [x] Add higher-level Worker integration coverage on top of the new Wasm-target build guardrail.
  `cityg-worker` now has a memory-backed checkpoint round-trip test that accepts a real demo bundle, persists the authoritative room checkpoint through the Durable Object store adapter, derives routing entries, rehydrates `RuntimeRoom`, and verifies the restored message/bundle backlogs.
- [x] Add a global known-room registry and miss-driven routing convergence fallback.
  The Worker edge now records `gid`s in a dedicated Durable Object registry, and a `we_epoch_id` routing miss can trigger room checkpoint resync across the registered rooms before returning 404.
- [x] Add an explicit legacy-room backfill path for the Worker routing registry.
  Operators can now seed historical room gids through `CITYG_WORKER_KNOWN_GIDS_JSON`, so a routing miss can register and resync rooms that predate the new known-room registry.
- [x] Adopt the first explicit Worker resume/ack websocket client behavior in the native GUI worker.
  The GUI websocket worker now sends `ack` for sequenced notifications and `resume` on reconnect, so the new Worker DO replay contract is exercised by at least one real client path instead of staying server-only.
- [x] Make the native GUI session treat replayed Worker websocket notifications explicitly.
  The GUI websocket worker now surfaces `sequence` and `replayed` metadata on message and membership notifications, the session/activity layer distinguishes replayed reconnect traffic from live traffic, and the backlog watcher tests only treat non-replayed notifications as fresh live traffic.
- [x] Extend the Worker replay websocket contract to the `join_leave` client path too.
  The `join_leave` notification listener now keeps a reusable sequence cursor, sends `resume` on reconnect and `ack` on sequenced notifications, exposes `sequence`/`replayed` on parsed events, and its watch-mode helpers can explicitly wait for live post-reconnect traffic instead of treating replayed backlog as fresh delivery.
- [x] Deduplicate the GUI-side Worker replay websocket client helper.
  The native GUI worker and the `join_leave` watcher now share one crate-local helper for websocket request setup, replay cursor tracking, and `ack` / `resume` / `sequence` / `replayed` protocol handling instead of carrying two drifting copies.

## In Progress

- [ ] Harden the Worker websocket path to match the native `/v1/ws` transport semantics more closely.
  The first DO-native fanout path exists now, and it now carries per-socket attachment metadata, app-level `ping`/`pong` plus explicit `ack`/`resume` parsing, per-room fanout sequences, a bounded replay buffer, ack-gap-based `lag` warnings, replay of still-retained notifications on heartbeat, and `lag_disconnect` once the client falls behind the retained replay window. The native GUI path and the `join_leave` client now both distinguish replayed reconnect traffic from live traffic, so the main remaining gap is productizing the replay contract across any remaining clients and deciding whether the current bounded replay window is sufficient.

## Next

- [x] Move `accept_epoch` persistence/index update flow behind shared runtime functions.
- [x] Move message and bundle fetch/store operations behind shared room methods/services.
- [x] Move `join_ticket`, `merge_ticket`, and `refresh_pivot` construction logic behind shared room services.
- [ ] Repoint the remaining room-scoped `cityg-api` handlers to shared runtime services instead of inline logic.
- [x] Bridge native `cityg-api` room-scoped endpoints onto the Cloudflare room route without duplicating request parsing or `gid` extraction logic.
- [x] Populate and maintain the Worker routing index from accepted/replayed room state so `we_epoch_id` keyed routes (`/v1/send_message`, `/v1/messages`, `/v1/bundle`) can reach the correct Durable Object.
  Checkpoint-based reconstruction, explicit room-side resync, live accept-path upserts, miss-driven convergence through the known-room registry, and explicit legacy-room seeding through `CITYG_WORKER_KNOWN_GIDS_JSON` now exist.

## Open Questions

- [ ] Which endpoints should remain edge-only in the Worker entrypoint versus execute inside the Durable Object.
- [ ] Whether the internal Cloudflare room route should stay URL-addressed (`/__cloudflare/rooms/:gid/...`) or eventually be replaced by shared protobuf-aware edge routing.
- [ ] Whether `CITYG_WORKER_CONFIG_JSON` is sufficient as the long-term delivery mechanism, or should be replaced by typed object bindings / signed policy documents.
- [ ] Whether the global alias registry should stay single-object for parity or be sharded once cross-room alias semantics are revisited explicitly.
- [ ] Whether the protocol should keep the historical `"ML-DSA-65"` label while using Dilithium5-compatible key/signature sizes, or whether that wire-level naming mismatch should be corrected in a versioned migration.
