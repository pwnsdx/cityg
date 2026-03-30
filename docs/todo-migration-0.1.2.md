# Migration TODO: 0.1.0 -> 0.1.2

> [!IMPORTANT]
> Historical migration tracker retained for audit traceability.
> The current profile state is governed by [`docs/specs.md`](./specs.md), not by this completed migration checklist.

This tracker captures the implementation migration from the FS-only profile
to the unified FS-hybrid + PRS barrier profile in `/Users/admin/Desktop/Repositories/cityg/docs/specs.md`.

## Status

- [x] Phase A: Profile/version freeze and compatibility gates (direct 0.1.2 cutover; no legacy path)
- [x] Phase B: Labels and device-chain v2 groundwork
- [x] Phase C: Barrier state model (server/client persistence)
- [x] Phase D: Barrier wire + canonical parsing/validation
- [x] Phase E: Acceptance gating (S10.4, S10.4A, S10.4B)
- [x] Phase F: Client recover/updater activation (S11.13/S11.14)
- [x] Phase G: PayloadEnvelope v2 + message anti-replay durability
- [x] Phase H: API/provisioning updates for barrier + PCS policy
- [x] Phase I: KAT/conformance + enforcement
- [x] Phase J: Concurrency and traffic hardening

## Phase A: Profile/version freeze and compatibility gates

- [x] Set normative profile/version references to 0.1.2 in spec/whitepaper/docs.
- [x] Remove compatibility gates and enforce direct 0.1.2 behavior (`fs/dev/chain/v2` + required `barrier_version`).
- [x] Document rollout order and rollback criteria.

## Phase B: Labels and device-chain v2 groundwork

- [x] Introduce barrier header key constants (`175`, `176`, `177`, `178`) in orchestrator header registry.
- [x] Add typed helpers for `barrier_update_digest` and fs device-chain v2 preimage shape.
- [x] Migrate fs device-chain hash call sites from `H_L("fs/dev/chain", [...])` to `H_L("fs/dev/chain/v2", [...])` (no compatibility branch).
- [x] Add/update tests for v2 binding (`barrier_version` and `barrier_update_digest` influence; missing `barrier_version` rejected on accept path).

## Phase C: Barrier state model (server/client persistence)

- [x] Server: add `barrier_initialized`, `barrier_version`, `barrier_roots_hash`, `kem_tree_hash_after`, `N_max`.
- [x] Server: add PCS policy state (`last_pcs_refresh_ec`, per-device last refresh).
- [x] Client: add persistent barrier secret state (`K_barrier`, `barrier_version`, `kem_tree_hash_after`, `dk_leaf`, `dk_n`, `pkhash_*`).
- [x] Server runtime: mirror accepted barrier state from `AcceptanceContext` into `GroupRoster` for API/state coherence.
- [x] Server runtime: resync `AcceptanceContext.kem_tree_hash_after` from roster-computed tree after join/revoke deltas so tickets and barrier tree snapshots stay coherent.
- [x] Client/updater: add crash-safe `pending_*` activation state.
  - [x] Persistence scaffold present in GUI session format (`pending` state serialized/deserialized).
  - [x] Runtime activation/correlation flow (`S11.14`) wired in GUI epoch sync (digest-correlated activation + stale pending discard).
  - [x] Persist-before-publish capture from merge emitters is wired for both leave (`reason=0`) and non-leaving PCS refresh (`reason=1`) paths, including pending digest/key-material persistence prior to publish.

## Phase D: Barrier wire + canonical parsing/validation

- [x] Implement `BarrierUpdate` and `KemTreeCoverPayload` parsers with deterministic CBOR verification.
- [x] Implement structural checks (`path_nodes`, `new_public_keys`, `node_ciphertexts` canonical ordering).
- [x] Client merge emitters (`cityg-gui` + `join_leave`) now derive `kem_tree_hash_after` from an authenticated `FetchBarrierPublicTree(kem_tree_hash_before)` snapshot instead of using a fixed placeholder.
- [x] Implement tree hash (`S11.4`) and pre/post snapshot construction (`S11.6`).

## Phase E: Acceptance gating (S10.4, S10.4A, S10.4B)

- [x] Enforce barrier genesis and non-genesis version rules.
- [x] Enforce revocation-change gating (reject with `960.11` when required).
- [x] Enforce proactive PCS refresh gating/rate-limit (reject `960.12`/`960.13`).
- [x] Keep proof ordering aligned with spec (`S10.5`).
- [x] Client merge/leave flow emits `barrier_update` with reason `0` and `barrier_version = BV+1` on revocation merges.
- [x] Remove bootstrap JOIN exception in acceptance once a first-class genesis MERGE bootstrap flow exists end-to-end.

## Phase F: Client recover/updater activation (S11.13/S11.14)

- [x] Join path now emits `header[177] barrier_leaf_pk` and stores local `dk_leaf` + `pkhash_leaf` (GUI + join_leave).
- [x] Implement unique-match recover with fail-closed semantics (`960.2`, `960.6`, `960.7`).
- [x] Implement deterministic `dk_n` storage on self path with `pkhash_n`.
  - [x] Runtime derives deterministic internal node key material (`S11.10`) and stores `(dk_n, pkhash_n)` on successful recover (`S11.13.5`).
- [x] Implement updater persist-before-publish and digest-correlated activation for the currently implemented emitting path.
  - [x] Persist-before-publish (`S11.14.1`) wired from the GUI leave merge emitter path (pending state persisted before publish).
  - [x] Digest-correlated activation on observed acceptance (`S11.14.2` core correlation logic) implemented in GUI epoch sync.
- [x] Add FULL-client `ek_n` verification path (`S11.13.6`).
  - [x] Runtime rejects barrier updates locally when derivable `ek_n` does not match announced `new_public_keys` entries (fail-closed `960.7` behavior).
  - [x] GUI epoch sync attempts barrier recover from accepted `header[175]` (deterministic CBOR parse, path/node shape checks, unique-match decap path, `ek_n` verification, PCS reseed derivation).
  - [x] Ticket `K_barrier` fallback is removed when a `barrier_update` is present: recover no-match/error now fails closed locally.

## Phase G: PayloadEnvelope v2 + anti-replay durability

- [x] Introduce `PayloadEnvelope = ["fs-hybrid-msg-v2", msg_index, ct_payload]`.
- [x] Implement `K_msg_epoch`/`K_msg`/`nonce`/AAD schedule bound to `barrier_version` + `K_barrier`.
- [x] Enforce `msg_index` uniqueness with crash-safe persistence.
- [x] Enforce receiver no-fallback rule on `K_barrier`.

## Phase H: API/provisioning updates

- [x] Extend join/merge provisioning to include barrier-required public fields (`cover_leaf_index`, `barrier_version`, `kem_tree_hash_after`, `N_max`, limits/policy).
  - [x] `JoinTicketResponse` and `MergeTicketResponse` now include `cover_leaf_index`, `barrier_version`, `kem_tree_hash_after`, `n_max`, `max_barrier_update_bytes`, and `profile_version`.
  - [x] Server-blind migration completed: server no longer provisions `k_barrier` in join/merge tickets.
  - [x] Legacy wire IDs for removed `k_barrier` fields are reserved in protobuf (`JoinTicketResponse:26`, `MergeTicketResponse:24`) for compatibility safety.
  - [x] GUI epoch sync reconciles barrier metadata (`barrier_version`, `kem_tree_hash_after`, limits) from merge tickets and performs client-side barrier recover (`S11.13`), fail-closed.
  - [x] Joiners enter pending barrier recovery and only activate messaging once a valid barrier update is recovered/activated (`S11.13`/`S11.14`).
- [x] Add server endpoints/contracts for:
  - [x] `ResolveRevokedLeaves`
  - [x] `ResolveJoinsSince`
  - [x] `FetchBarrierPublicTree`
- [x] Version API payloads so 0.1.0 and 0.1.2 clients cannot be mixed accidentally.
  - [x] `JoinTicketResponse` and `MergeTicketResponse` carry `profile_version`.
  - [x] API client fail-closes on profile mismatch (`v0.1.2` required).

## Phase I: KAT/conformance + enforcement

- [x] Implement mandatory KATs `S14.1`..`S14.6`.
  - [x] Added `kat/kat-s14-conformance-manifest-v0.1.2.json` to map each S14 requirement to deterministic implementation tests.
  - [x] `S14.1`: explicit `ExpectedNodeSet` conformance/rejection coverage in barrier parser/server validation tests.
  - [x] `S14.2`: FULL-client `ek_n` mismatch fail-closed test coverage.
  - [x] `S14.3`: recover AAD binding to full `pkhash_t` with positive and negative client coverage.
  - [x] `S14.4`: updater activation persistence/rehydration keeps `pkhash_n` for later matching.
  - [x] `S14.5`: proactive PCS refresh gating + rate/slot enforcement tests.
  - [x] `S14.6`: PCS reseed consistency and crash-safe pending activation tests.
- [x] Add crash/restart fault-injection tests for updater activation.
  - [x] Added unit tests for pending activation digest match and stale pending cleanup in GUI client state handling.
  - [x] Added client recover tests covering no-match (`960.6`) and successful recover + PCS reseed derivation from barrier update AAD/nonce semantics.
  - [x] Added session persistence roundtrip coverage for barrier `pending` + `on_path_key_material` crash/restart durability.
  - [x] Added client recover negative test for `pkhash_t` mismatch (fail-closed no recovery).
  - [x] Added pending-activation digest-mismatch fault-injection coverage (pending state cleared fail-closed on correlation mismatch).
- [x] No shadow/A-B rollout required for this migration track (explicit direct cutover policy).
- [x] Flip enforcement gates after conformance tests are stable.

## Phase J: Concurrency and traffic hardening

- [x] Add client ticket retry with bounded exponential backoff + jitter for concurrency race errors
  (`barrier_version`/window-full/head race), while preserving fail-closed behavior.
  - [x] Implemented on GUI native join/leave/refresh ticket fetch paths.
  - [x] Implemented on `join_leave` CLI join/leave ticket fetch paths.
  - [x] Added unit tests for retry classifier and delay bounds.
- [x] Replace global server lock with per-group execution lanes (actor or keyed lock) to improve
  throughput under many groups.
- [x] Add high-contention stress tests with many concurrent join/leave/refresh writers and retry convergence assertions.
- [x] Add operational metrics/SLOs for concurrency pressure (retry count, WINDOW_FULL rate,
  barrier version contention, accept latency p95/p99).
- [x] Add merge/revocation coalescing policy to reduce barrier traffic during bursty churn.

## Current verification gate

- [x] Workspace tests pass (`cargo test --workspace`).
- [x] Workspace line coverage >= 95% (`cargo llvm-cov --workspace --summary-only`, current total: 95.00%).
- [x] Native GUI runtime path (`--features native-app`) compiles and targeted barrier recover/persistence tests pass.

## Post-0.1.2 reconciliation backlog (spec vs implementation)

- [x] (Code) Enforce FULL receive-side barrier chain-check (`S11.11.2`) in GUI epoch sync before recover.
- [x] (Code) Preserve local barrier error-code semantics in receive path (`960.7` prevalidation, `960.9` snapshot auth, `960.8` hash-chain failures).
- [x] (Code+Spec) Align payload key schedule with `S8.3/S8.4`:
  - [x] Full tuple fields (`xk_hash`, `E_k`) are bound in message epoch salt, nonce, and AAD on send/receive paths.
  - [x] Normative reconciliation applied: `S8.3` now defines `K_msg_epoch` IKM as `E_k` for this profile implementation.
- [x] (Code) Strengthen deterministic-CBOR verification (`S1.3`) to explicitly reject duplicate keys/floats/indefinite forms at parse time, not only via decode+re-encode.
- [x] (Spec or transport refactor) Clarify/implement byte-level deterministic-CBOR verification for full anchor header maps where only decoded maps are currently exposed to GUI logic.
- [x] (Spec clarification) Reconcile `S12.2` join provisioning requirement for `initial K_fs` with current join flow that locally seeds `ForwardSecrecyState`.
