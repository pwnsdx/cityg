# Local E2E Validation 2026-03-27

This note records the local end-to-end validation run executed against the current
candidate binaries on `2026-03-27`.

## Scope

- Validate real `cityg-api` startup/readiness outside tests
- Validate fast API/GUI regression flows
- Validate the client-state hardening gate
- Validate one real `cityg-stress` smoke run pinned to rebuilt binaries
- Validate targeted restart-chaos and lane/head topology flows
- Leave only the remaining churn/history-specific flows for the next pass

## Environment

Run all commands from:

```bash
cd /Users/admin/Desktop/Repositories/cityg
source ./scripts/cargo_repo_env.sh
```

`cargo_repo_env.sh` now also exports a repo-local `RUST_MIN_STACK` floor so the
native GUI/test flows do not fail spuriously on the default host thread stack.

## Candidate Binaries

- `/Users/admin/Desktop/Repositories/cityg/target/debug/cityg-api`
- `/Users/admin/Desktop/Repositories/cityg/target/debug/join_leave`
- `/Users/admin/Desktop/Repositories/cityg/target/debug/cityg-stress`
- `/tmp/cityg-target-client-restart/debug/cityg-stress` for the dedicated
  client-restart and lane/head validation reruns

## Phase 0: Runtime Baseline

Validated:

- rebuilt `cityg-api`
- process listens on the requested socket
- `/health/detailed` returns healthy

Artifacts:

- `/tmp/cityg-phase0-server.log`
- `/tmp/cityg-phase0-health.json`
- `/tmp/cityg-phase0-lsof.txt`

## Phase 1: Fast Regression Flows

Passed:

- `cargo test --locked -p cityg-api --test integration end_to_end_demo_flow -- --exact`
- `cargo test --locked -p cityg-gui --bin cityg-gui --features native-app native::tests::perform_join_second_member_can_send_immediately -- --exact`
- `cargo test --locked -p cityg-gui --bin cityg-gui --features native-app native::tests::send_fetch_and_members_roundtrip -- --exact`
- `cargo test --locked -p cityg-gui --bin cityg-gui --features native-app native::tests::epoch_sync_after_second_join_keeps_local_pcs_refresh_valid -- --exact`
- `cargo test --locked -p cityg-gui --bin cityg-gui --features native-app native::tests::join_finalize_fault_injection_after_publish_recovers_via_epoch_sync -- --exact`
- `./scripts/verify_client_state_hardening.sh`

Fixes required during this phase:

1. GUI local publish path was leaving a cached current public tree alive after
   clearing the authenticated current history commitment.
2. GUI epoch sync was installing the post-snapshot public tree before updating
   `barrier_version` / `kem_tree_hash_after`.
3. The client-state manifest referenced a stale GUI test symbol.

## Phase 2: Smoke

First smoke attempt failed in `join/bootstrap`:

- `join_leave --watch` emitted a `barrier_update` without the required
  `HDR_JOIN_FINALIZE_AUTH` and `HDR_BARRIER_HISTORY_COMMITMENT` headers
- `cityg-stress` retried on fresh rooms, but reused the same alias base within
  the worker round, leading to expected TOFU alias collisions after the first
  failed attempt

Artifacts from the failed run:

- `/tmp/cityg-stress-smoke-20260327`

Fix applied:

- `join_leave` now emits the same join-finalize / barrier-history headers as the
  main GUI runtime

Second smoke attempt passed:

```text
workers_passed=1 workers_failed=0 rounds=2/2 capacity=skipped accept_ok=10 refresh_conflicts=2
```

Artifacts from the passing run:

- `/tmp/cityg-stress-smoke-20260327-r2`

Important files in the artifact directory:

- `summary.txt`
- `events.log`
- `server.log`
- `initial-health.json`
- `final-health.json`
- `initial-metrics.txt`
- `final-metrics.txt`
- `worker-01.log`
- `worker-01.status`
- `worker-*-client-state/`

## Additional Test-Harness Cleanup

`join_leave` mock tests had fallen behind the helper pagination contract. The
test-only `FetchBarrierPublicTree` encoder now paginates snapshots larger than
the helper page limit, so the leave-path regression tests remain representative
of the real server behavior.

## Result

- Phase 0: passed
- Phase 1: passed
- Phase 2 smoke: passed on rebuilt candidate binaries
- Extended soak/load/chaos matrix: partially run, with qualified server restart,
  qualified injected client restart, and lane/head extremes validated

## Receipt-Authority Rerun (current patch)

This rerun was executed after hardening the history-authority extensions so that
`header[181]` is mandatory whenever an authority-bound `barrier_update` carries
`header[182]`.

Target dir used:

- `/tmp/cityg-target-rerun-181`

Targeted proofs passed:

- `cargo test --locked -p cityg-server tests::accept_epoch_rejects_barrier_update_missing_receipt_under_local_history_authority -- --exact --nocapture`
- `cargo test --locked -p cityg-server tests::accept_epoch_rejects_barrier_update_missing_receipt_under_global_history_authority -- --exact --nocapture`
- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::validate_client_visible_activation_guards_rejects_missing_receipt_for_local_authority --features native-app -- --exact --nocapture`
- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::validate_client_visible_activation_guards_rejects_missing_receipt_for_global_authority --features native-app -- --exact --nocapture`
- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::perform_join_second_member_can_send_immediately --features native-app -- --exact --nocapture`

Live flows rerun on rebuilt binaries:

- smoke:
  - artifact dir: `/tmp/cityg-stress-smoke-181-current`
  - result: `workers_passed=1 workers_failed=0 rounds=2/2 accept_ok=10 refresh_conflicts=2`
- watch/concurrency:
  - artifact dir: `/tmp/cityg-stress-flow-e-181-current`
  - result: `workers_passed=2 workers_failed=0 rounds=8/8 accept_ok=47 refresh_conflicts=15`

Conclusion:

- The stricter receipt requirement did not regress fresh-join bootstrap.
- The stricter receipt requirement did not regress the minimal smoke flow.
- The stricter receipt requirement stayed green under the previously qualified
  2-worker watch/burst concurrency profile.

## Extended Matrix Executed

### Flow A: baseline watch + burst

Passed:

```text
workers_passed=1 workers_failed=0 rounds=3/3 capacity=skipped accept_ok=12 refresh_conflicts=0
```

Artifacts:

- `/tmp/cityg-stress-flow-a`

### Flow F: short restart-chaos command

Passed functionally, but did **not** exercise the timers:

- run finished in ~20s
- `restart-every-secs=45` never fired
- `client-restart-every-secs=20` never fired because each individual `join_leave`
  child exited in less than 20s

Artifacts:

- `/tmp/cityg-stress-flow-f`

### Flow F (qualified): prolonged restart-chaos

Passed and did exercise managed server restart:

```text
workers_passed=1 workers_failed=0 rounds=21/50 restarts=1 accept_ok=42 refresh_conflicts=14
```

Observed:

- one managed server restart occurred and was absorbed cleanly
- health/metrics polling resumed after restart
- no worker failed and no round was stranded
- no `client-restarts.log` was produced because no individual `join_leave` child
  lived longer than the 20s client restart timer

Artifacts:

- `/tmp/cityg-stress-flow-f-restarts`

### Flow F (qualified): injected client restart with successful retry

Passed and did exercise a real `client-restart-injected` kill followed by a
successful retry on a fresh room:

```text
workers_passed=1 workers_failed=0 rounds=1/1 restarts=0 accept_ok=9 refresh_conflicts=2
```

Observed:

- `client-restarts.log` is present
- attempt 1 was killed at the configured 20s boundary
- `cityg-stress` retried the same logical round on a fresh room
- attempt 2 completed successfully without a second injected kill
- retry-specific alias bases and client-state directories prevented false TOFU
  collisions across attempts

Artifacts:

- `/tmp/cityg-stress-flow-client-restart`

### Flow F (combined): client restart plus managed server restart in one round

Passed functionally under combined chaos:

```text
workers_passed=1 workers_failed=0 rounds=1/1 restarts=1 accept_ok=0 refresh_conflicts=0
```

Observed:

- attempt 1 was killed by the managed client restart timer
- the retry on a fresh room survived a managed server restart and still
  completed successfully
- `events.log` shows both `client-restart-injected` and `server restart #1`
- `server.log` also emitted `state recovery failed: ... barrier_updater_invalid`
  during restart replay, so this path is functionally green but still merits a
  follow-up review of replay/recovery strictness

Artifacts:

- `/tmp/cityg-stress-flow-f-combined`

### Flow F (combined) rerun after replay recovery hardening

Reran the same combined chaos scenario with a rebuilt `cityg-api` carrying the
server-side replay fix for historical `reason=2` `join_finalize` bundles:

```text
workers_passed=1 workers_failed=0 rounds=1/1 restarts=1 accept_ok=0 refresh_conflicts=0
```

Observed:

- `client-restarts.log` is present
- `events.log` still shows both `client-restart-injected` and `server restart #1`
- `server.log` is now clean: no `barrier_updater_invalid`, no `state recovery failed`
- the targeted lane replays used for repro also restart cleanly and answer
  `/health/detailed`:
  - `/tmp/cityg-repro-lane00.log`
  - `/tmp/cityg-repro-lane00-health.json`
  - `/tmp/cityg-repro-lane02.log`
  - `/tmp/cityg-repro-lane02-health.json`

Artifacts:

- `/tmp/cityg-stress-flow-f-combined-replayfix`

### Flow G: lanes / heads extremes

Passed on both tested extremes:

```text
L1/H1: workers_passed=2 workers_failed=0 rounds=4/4 accept_ok=23 refresh_conflicts=3
L8/H8: workers_passed=2 workers_failed=0 rounds=4/4 accept_ok=19 refresh_conflicts=3
```

Observed:

- `CITYG_SERVER_GROUP_LANES=1`, `CITYG_STRESS_MAX_CONCURRENT_HEADS=1` stayed
  green under short churn + watch traffic
- `CITYG_SERVER_GROUP_LANES=8`, `CITYG_STRESS_MAX_CONCURRENT_HEADS=8` also
  stayed green under the same workload
- no readiness regressions or worker failures appeared at either topology

Artifacts:

- `/tmp/cityg-stress-flow-g-l1-h1`
- `/tmp/cityg-stress-flow-g-l8-h8`

### Flow E: two-worker watch + burst

Passed:

```text
workers_passed=2 workers_failed=0 rounds=8/8 accept_ok=46 refresh_conflicts=14
```

Observed:

- two concurrent workers stayed green in watch mode
- short message bursts were delivered without worker failure
- refresh conflicts remained recoverable and did not strand the rounds

Artifacts:

- `/tmp/cityg-stress-flow-e`

### Flow B: same-room leave -> empty room -> rejoin with stable identity

Validated in two layers:

```text
cargo test --locked -p cityg-gui --bin join_leave \
  tests::rejoin_with_same_identity_succeeds_after_room_becomes_empty \
  -- --exact --nocapture
```

and live via `cityg-stress --reuse-room-per-worker`:

```text
workers_passed=1 workers_failed=0 rounds=2/2 accept_ok=11 refresh_conflicts=3
```

Observed:

- both members leave and the room becomes empty
- the same persistent room identity can rejoin successfully
- the rejoined member keeps the same `pop_public_key` and `leaf_id`
- the live stress run reuses the exact same `room_id` across rounds and
  successfully rejoins/sends again after the room is emptied

Artifacts:

- `/tmp/cityg-stress-flow-b-reuse-room`

### Flow G: lanes / heads midline

Passed on the documented `4/4` topology:

```text
L4/H4: workers_passed=2 workers_failed=0 rounds=6/6 accept_ok=35 refresh_conflicts=6
```

Artifacts:

- `/tmp/cityg-stress-flow-g-l4-h4`

### Flow G: lanes / heads remaining midpoint

Passed on the remaining `2/2` topology:

```text
L2/H2: workers_passed=2 workers_failed=0 rounds=4/4 accept_ok=22 refresh_conflicts=3
```

Artifacts:

- `/tmp/cityg-stress-flow-g-l2-h2`

### Flow C: proactive PCS refresh -> epoch sync -> send/fetch stable

Validated via targeted GUI runtime test:

```text
cargo test --locked -p cityg-gui --bin cityg-gui --features native-app \
  native::tests::epoch_sync_after_second_join_keeps_local_pcs_refresh_valid \
  -- --exact --nocapture
```

Observed:

- the flow passes end-to-end
- a transient `500 invalid input: kbroad key missing` is logged during the test,
  but the scenario recovers and the assertion remains green

### Flow D: accepted merge -> interruption -> restart -> history lookup recovery

Validated via targeted GUI/runtime recovery tests:

```text
cargo test --locked -p cityg-gui --bin cityg-gui --features native-app \
  native::tests::join_finalize_fault_injection_after_publish_recovers_via_epoch_sync \
  -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui --features native-app \
  native::tests::pending_join_finalize_history_lookup_404_after_newer_version_requires_recovery \
  -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui --features native-app \
  native::tests::pending_barrier_history_lookup_discards_superseded_locator \
  -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui --features native-app \
  native::tests::pending_barrier_history_lookup_discards_final_rejected_locator \
  -- --exact --nocapture
```

Observed:

- post-publish join-finalize fault injection recovers through epoch sync
- `404` after a newer committed version escalates to recovery-required as expected
- authenticated `superseded` and `final_rejected` locators discard stale pending
  state cleanly

## Remaining E2E Matrix

The baseline local matrix is now largely qualified. What remains is mostly:

- longer soak/load coverage
- explicit investigation of the replay warning seen in
  `/tmp/cityg-stress-flow-f-combined/server.log`
- optional richer same-room identity persistence in `cityg-stress` itself

### Flow A: Bootstrap -> first join -> second join -> bidirectional send/fetch

Goal:

- re-confirm the baseline watch flow and message burst path on rebuilt binaries

Command:

```bash
target/debug/cityg-stress --plain \
  --server-bind 127.0.0.1:18081 \
  --server-url http://127.0.0.1:18081 \
  --workers 1 \
  --rounds-per-worker 3 \
  --min-count 2 \
  --max-count 2 \
  --leaves-per-room 0 \
  --watch-percent 100 \
  --message-burst-count 4 \
  --message-burst-interval-ms 25 \
  --api-bin /Users/admin/Desktop/Repositories/cityg/target/debug/cityg-api \
  --join-leave-bin /Users/admin/Desktop/Repositories/cityg/target/debug/join_leave \
  --artifact-dir /tmp/cityg-stress-flow-a \
  --require-metrics
```

### Flow B: second member leaves -> members/window sync -> rejoin -> send again

Goal:

- validate leave-path churn and UI-visible membership convergence
- same-room rejoin is now covered live via `--reuse-room-per-worker`
- stable-identity rejoin remains covered by
  `tests::rejoin_with_same_identity_succeeds_after_room_becomes_empty`

Command:

```bash
/tmp/cityg-target-client-restart/debug/cityg-stress --plain \
  --server-bind 127.0.0.1:18082 \
  --server-url http://127.0.0.1:18082 \
  --workers 1 \
  --rounds-per-worker 2 \
  --min-count 2 \
  --max-count 2 \
  --leaves-per-room 2 \
  --watch-percent 100 \
  --jitter-max-secs 0 \
  --round-delay-secs 1 \
  --message-burst-count 2 \
  --message-burst-interval-ms 25 \
  --reuse-room-per-worker \
  --api-bin /Users/admin/Desktop/Repositories/cityg/target/debug/cityg-api \
  --join-leave-bin /Users/admin/Desktop/Repositories/cityg/target/debug/join_leave \
  --artifact-dir /tmp/cityg-stress-flow-b-reuse-room \
  --require-metrics
```

### Flow C: proactive PCS refresh -> epoch sync -> send/fetch stable

Goal:

- validate that refresh conflicts stay bounded and no client remains stuck
- targeted runtime coverage already exists via
  `native::tests::epoch_sync_after_second_join_keeps_local_pcs_refresh_valid`

Command:

```bash
cargo test --locked -p cityg-gui --bin cityg-gui --features native-app \
  native::tests::epoch_sync_after_second_join_keeps_local_pcs_refresh_valid -- --exact
```

### Flow D: accepted merge -> interruption -> restart -> history lookup recovery

Goal:

- validate pending merge recovery under restart/interruption
- targeted recovery semantics are already covered by
  `native::tests::join_finalize_fault_injection_after_publish_recovers_via_epoch_sync`
  plus the `native::tests::*history_lookup*` cases above

Command:

```bash
cargo test --locked -p cityg-gui --bin cityg-gui --features native-app \
  native::tests::join_finalize_fault_injection_after_publish_recovers_via_epoch_sync -- --exact
```

### Flow E: watch mode with burst > 1

Goal:

- stress message ordering and notification delivery under watch mode

Command:

```bash
target/debug/cityg-stress --plain \
  --server-bind 127.0.0.1:18083 \
  --server-url http://127.0.0.1:18083 \
  --workers 2 \
  --rounds-per-worker 4 \
  --min-count 2 \
  --max-count 2 \
  --leaves-per-room 2 \
  --watch-percent 100 \
  --message-burst-count 6 \
  --message-burst-interval-ms 10 \
  --api-bin /Users/admin/Desktop/Repositories/cityg/target/debug/cityg-api \
  --join-leave-bin /Users/admin/Desktop/Repositories/cityg/target/debug/join_leave \
  --artifact-dir /tmp/cityg-stress-flow-e \
  --require-metrics
```

### Flow F: managed server restart during active watch traffic

Goal:

- validate readiness, replay, and client recovery after server restart
- this server-restart variant is already qualified in
  `/tmp/cityg-stress-flow-f-restarts`
- injected client restart is now qualified separately in
  `/tmp/cityg-stress-flow-client-restart`

Command:

```bash
target/debug/cityg-stress --plain \
  --server-bind 127.0.0.1:18086 \
  --server-url http://127.0.0.1:18086 \
  --workers 1 \
  --rounds-per-worker 50 \
  --duration-secs 75 \
  --min-count 2 \
  --max-count 2 \
  --leaves-per-room 2 \
  --watch-percent 100 \
  --restart-every-secs 45 \
  --client-restart-every-secs 20 \
  --capture-client-state-artifacts \
  --message-burst-count 2 \
  --message-burst-interval-ms 25 \
  --api-bin /Users/admin/Desktop/Repositories/cityg/target/debug/cityg-api \
  --join-leave-bin /Users/admin/Desktop/Repositories/cityg/target/debug/join_leave \
  --artifact-dir /tmp/cityg-stress-flow-f-restarts \
  --require-metrics
```

### Flow G: lanes / heads variants

Goal:

- detect regressions under lane/head topology changes

Matrix:

- done: `CITYG_SERVER_GROUP_LANES=1`, `CITYG_STRESS_MAX_CONCURRENT_HEADS=1`
- done: `CITYG_SERVER_GROUP_LANES=2`, `CITYG_STRESS_MAX_CONCURRENT_HEADS=2`
- done: `CITYG_SERVER_GROUP_LANES=4`, `CITYG_STRESS_MAX_CONCURRENT_HEADS=4`
- done: `CITYG_SERVER_GROUP_LANES=8`, `CITYG_STRESS_MAX_CONCURRENT_HEADS=8`

Template:

```bash
CITYG_SERVER_GROUP_LANES=4 \
CITYG_STRESS_MAX_CONCURRENT_HEADS=4 \
target/debug/cityg-stress --plain \
  --server-bind 127.0.0.1:18085 \
  --server-url http://127.0.0.1:18085 \
  --workers 2 \
  --rounds-per-worker 3 \
  --min-count 2 \
  --max-count 3 \
  --leaves-per-room 1 \
  --watch-percent 100 \
  --message-burst-count 2 \
  --message-burst-interval-ms 25 \
  --api-bin /Users/admin/Desktop/Repositories/cityg/target/debug/cityg-api \
  --join-leave-bin /Users/admin/Desktop/Repositories/cityg/target/debug/join_leave \
  --artifact-dir /tmp/cityg-stress-flow-g-l4-h4 \
  --require-metrics
```

## Failure Classification

Classify any future E2E failure as one of:

- startup/readiness
- join/bootstrap
- send/fetch
- epoch sync/recovery
- restart chaos
- capacity/backpressure

## Receipt-Authority Rerun (current state)

Target:

- revalidate fresh join plus runtime smoke after making GUI activation guards cryptographically verify `header[181]` under negotiated history-authority extensions

Results:

- targeted GUI authority suite: `cargo test --locked -p cityg-gui --bin cityg-gui validate_client_visible_activation_guards_ --features native-app -- --nocapture` passed (`14 passed`)
- fresh-join path: `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::perform_join_second_member_can_send_immediately --features native-app -- --exact --nocapture` passed
- live smoke: `/tmp/cityg-stress-smoke-181-verify-receipt/summary.txt`
  - `workers=1`
  - `worker_failures=0`
  - `rounds_completed=2`
  - `rounds_failed=0`
  - `accept_epoch_ok=10`
  - `refresh_conflicts=2`

Notes:

- the known server log line `500 invalid input: kbroad key missing` was still emitted during the targeted join test, but the join flow completed successfully and did not regress under the new receipt verification path

## Additional Targeted Flows (2026-03-29)

### Flow H: stale dual PCS refresh race

Goal:

- exercise a protocol-specific race where two members start from the same authenticated baseline, one publishes a PCS refresh, and the other attempts a stale refresh from the old state
- prove that the room converges without stranding either member and that message delivery still works after the race

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::stale_dueling_pcs_refreshes_converge_and_preserve_messaging --features native-app -- --exact --nocapture`

Assertions:

- the loser of the stale race does not wedge the room
- both members converge to the same `we_epoch_id` and `barrier_version`
- both members remain message-ready after reconciliation
- bidirectional send/fetch still succeeds after the race

Result:

- passed on slot `.cargo-target/gui-newflows-5`

Notes:

- server logs still emitted the known `kbroad key missing` and `fs_dev_chain_break` lines during the stale attempt, but the final state converged and the test remained green

### Flow I: replay-state bounded fetch delivery

Goal:

- exercise a general messaging invariant: repeated fetches must not re-release already delivered ciphertexts, while a later fetch must still release genuinely new traffic

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::message_replay_state_only_releases_new_messages_between_fetch_rounds --features native-app -- --exact --nocapture`

Assertions:

- first fetch releases the initial message burst
- a repeated fetch with unchanged replay state returns no duplicate user-visible messages
- a later fetch after a second burst releases only the new messages
- member listing remains stable across the two fetch rounds

Result:

- passed on slot `.cargo-target/gui-newflows-5`

Notes:

- the runtime warnings `dropping replayed msg_index=...` are expected here and are exactly the signal that the replay filter is working

### Flow J: client restart between fetch rounds

Goal:

- exercise a lightweight chaos/restart path on the messaging layer by persisting the receiver session, reloading it, and verifying that replay-state survives the restart boundary

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::message_replay_state_survives_client_restart_between_fetch_rounds --features native-app -- --exact --nocapture`

Assertions:

- the persisted session keeps the fetch watermark across restart
- a post-restart fetch with no new traffic returns no duplicate messages
- a later fetch after new traffic delivers only the new burst
- pre-restart traffic is not re-delivered after restart

Result:

- passed on slot `.cargo-target/gui-newflows-5`

Notes:

- the `dropping replayed msg_index=...` warnings are again expected and confirm that persisted replay-state is active immediately after reload

### Flow K: room-admin expel removes member and preserves survivor messaging

Goal:

- exercise the room-admin expel path end-to-end from a real joined admin identity
- prove that the expelled member disappears from the roster, cannot keep sending, and does not decrypt survivor traffic from the new epoch
- prove that the survivor remains message-ready immediately after expel

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::admin_expel_removes_member_and_preserves_survivor_messaging --features native-app -- --exact --nocapture`

Passed:

- `2026-03-29` on slot `.cargo-target/gui-protocol-checklist`

Assertions:

- a bootstrap admin can delegate room-admin authority to the joined author leaf
- the delegated admin can expel another leaf with a real expel merge ticket
- the expelled member disappears from `members(...)`
- survivor traffic continues after expel
- the expelled member cannot continue writing and does not decrypt the new survivor message

### Flow L: offline member restart -> epoch sync -> decrypt after refresh

Goal:

- exercise a user-visible offline recovery path: one member goes offline, another member refreshes and sends traffic, then the offline member restarts and catches up

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::offline_member_restart_then_epoch_sync_after_pcs_refresh_decrypts_new_messages --features native-app -- --exact --nocapture`

Passed:

- `2026-03-29` on slot `.cargo-target/gui-protocol-checklist`

Assertions:

- the offline member does not decrypt the post-refresh message before syncing
- reloading the stale persisted session simulates a client restart boundary
- epoch sync moves that reloaded session to the latest epoch
- the post-sync fetch decrypts the offline traffic
- the recovered member can reply and the sender still decrypts that reply

### Flow M: restart after admin expel preserves survivor state and new joiner messaging

Goal:

- extend the existing leave/restart chaos path to the room-admin expel path
- prove that journal replay preserves the expulsion, that the survivor state stays healthy after restart, and that a new member can still join and restore live traffic afterwards

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::restart_after_admin_expel_preserves_survivor_state_and_new_joiner_messaging --features native-app -- --exact --nocapture`

Passed:

- `2026-03-29` on slot `.cargo-target/gui-protocol-checklist`

Assertions:

- the expelled member stays absent before and after restart
- the survivor remains visible after journal replay
- the survivor state survives restart + replay without losing room ownership
- a fresh third member can join, become message-ready, and send after the restart + expel churn

### Flow N: room-admin grant/revoke lifecycle preserves authorization boundaries

Goal:

- exercise the room-admin ACL lifecycle end-to-end from real joined identities
- prove that delegated admins can grant and revoke admin authority, and that revoked admins lose visibility immediately

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::room_admin_grant_and_revoke_flow_preserves_authorization_boundaries --features native-app -- --exact --nocapture`

Passed:

- `2026-03-29` on slot `.cargo-target/gui-protocol-checklist`

Assertions:

- the bootstrap admin can delegate admin authority to a joined member
- the delegated admin can grant admin authority to another joined member
- the new admin appears in `list_room_admins(...)`
- revoking that admin removes it from the ACL
- the revoked admin loses ACL visibility immediately

### Flow O: admin expel -> survivor refresh -> fresh joiner continuity

Goal:

- combine two protocol-sensitive room transitions instead of testing them in
  isolation: admin expel first, then survivor `pcs_refresh`, then a fresh join
- prove that the expelled member stays locked out, the survivor stays
  message-ready, and a new joiner can still re-enter cleanly afterwards

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::admin_expel_then_survivor_refresh_preserves_room_and_new_joiner_messaging --features native-app -- --exact --nocapture`

Passed:

- `2026-03-29` on `/tmp/cityg-target-flow-admin-refresh`

Assertions:

- the delegated admin expels a live member with a real expel merge ticket
- the survivor can immediately publish a `pcs_refresh` after the expel
- the expelled stale client still cannot decrypt the survivor's new traffic
- any sync outcome for the expelled member still leaves the send path rejected
- a fresh third member can join after the expel+refresh churn, becomes
  message-ready, and is visible in the room roster

Notes:

- server logs still emit the known `invalid input: leaf not present in roster`
  line on the stale expelled path; the flow remains functionally green and the
  survivor/new-joiner guarantees stay intact

### Flow P: multi-author messaging across refresh epoch change

Goal:

- exercise a user-visible messaging property rather than just the refresh
  mechanism itself: both authors send before the refresh, one author refreshes,
  the stale author syncs, then both continue sending in the new epoch

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::multi_author_messaging_across_refresh_epoch_change_preserves_delivery --features native-app -- --exact --nocapture`

Passed:

- `2026-03-29` on `/tmp/cityg-target-flow-admin-refresh`

Assertions:

- the pre-refresh burst is delivered before the epoch changes
- the stale member does not decrypt post-refresh traffic before syncing
- after `epoch_sync`, the stale member decrypts the new epoch traffic and can
  immediately send again
- once replay-state advances on both sides, repeated fetches are empty again

Notes:

- `dropping replayed msg_index=...` warnings are expected here and confirm that
  replay-state suppression stayed active while traffic crossed the epoch change

### Flow Q: client restart during multi-version catch-up after refresh and leave

Goal:

- exercise the harder stale-client path where a member misses several room-head
  transitions, restarts from disk, then catches up across the gap

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::client_restart_during_multi_version_catchup_after_refresh_and_leave_recovers_cleanly --features native-app -- --exact --nocapture`

Passed:

- `2026-03-29` on `/tmp/cityg-target-flow-admin-refresh`

Assertions:

- the stale client survives a `refresh + leave` version gap after reload
- `epoch_sync` returns the restarted client to a message-ready state
- the survivor remains the only roster entry after catch-up
- fetch stays operational after catch-up and the survivor can send again

Notes:

- the path still logs the known `kbroad key missing` server warning and
  `barrier version gap detected; attempting best-effort recovery`; the flow is
  green because recovery completes and the resumed sender remains operational

### Flow R: watch reconnect under burst resumes live notifications

Goal:

- qualify the watch/websocket path directly instead of only through stress runs:
  disconnect a live watcher during burst traffic, reconnect it, and prove that
  fresh notifications continue to arrive

Coverage:

- `cargo test --locked -p cityg-gui --bin join_leave tests::watch_mode_reconnect_under_burst_resumes_live_notifications -- --exact --nocapture`

Passed:

- `2026-03-29` on `/tmp/cityg-target-flow-admin-refresh`

Assertions:

- the watcher receives the second member's join membership event
- the first websocket receives live message notifications before reconnect
- after a forced disconnect, a fresh websocket reconnects successfully
- the reconnected watcher receives new message notifications under continued burst traffic

Notes:

- the server logs a `Connection reset without closing handshake` warning when the
  test aborts the first websocket handle intentionally
- this flow proves live notification resume after reconnect; it does **not**
  yet qualify backlog bridging for traffic emitted while the watcher is offline

### Flow S: restart during pending `join_finalize` activation recovers via epoch sync

Goal:

- prove the specific post-publish failure mode that previously broke
  `epoch_sync` after restart: a `join_finalize` is accepted server-side, the
  joiner crashes before local reload, the server restarts, and the joiner must
  still recover from the persisted pending state

Coverage:

- `cargo test --locked -p cityg-api --test integration restart_rehydrates_bundle_store_for_post_restart_bundle_fetch -- --exact --nocapture`
- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::restart_during_pending_join_finalize_activation_recovers_via_epoch_sync --features native-app -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/api-restart`
- `2026-03-29` on `.cargo-target/gui-restart`

Assertions:

- after API restart, `/v1/bundle` still serves the `we_epoch_id` returned by
  `merge_ticket_refresh`
- replayed stored merge bundles retain the barrier HP envelope required by the
  client path
- the post-publish pending session remains persisted across the simulated crash
- after server restart, the admitted joiner is still present in the roster
- `perform_epoch_sync` clears `barrier_recovery_pending` and removes the stale
  pending activation state

Notes:

- the flow intentionally injects `AfterPublishBeforeReload` and still expects
  the published merge to survive restart/replay
- this closes the earlier `404 resource not found` path on
  `merge_ticket_refresh -> get_bundle` after restart

### Flow T: watch reconnect fetches offline backlog and resumes live notifications

Goal:

- extend the watch reconnect coverage beyond the pure live-feed case: the
  watcher drops offline during traffic, reconnects, fetches the missed burst,
  and then resumes receiving fresh live notifications without replaying the
  backlog twice

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::watch_reconnect_fetches_offline_backlog_and_resumes_live_notifications --features native-app -- --exact --nocapture`
- `cargo test --locked -p cityg-gui --bin join_leave tests::watch_mode_reconnect_under_burst_resumes_live_notifications -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/gui-watch-backlog`
- `2026-03-29` on `.cargo-target/gui-watch-backlog`

Assertions:

- the watcher reconnects after an intentional websocket drop
- `perform_fetch` bridges the message emitted while the watcher was offline
- once the backlog is fetched, the reconnected websocket still surfaces fresh
  `Message` notifications
- the follow-up fetch contains only the new live traffic and does not replay the
  offline burst again

Notes:

- the lower-level `join_leave` flow still qualifies the websocket live-notify
  path directly
- the native GUI flow adds the missing backlog-bridging proof for traffic sent
  while the watcher was offline

### Flow U: two restarted members resume bilateral traffic without duplicate delivery

Goal:

- exercise a dual-client restart boundary directly: both members restart from
  disk, resume bilateral traffic, and keep replay-state suppression intact

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::two_restarted_members_exchange_traffic_without_duplicate_delivery --features native-app -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/gui-dual-restart`

Assertions:

- both restarted members reload the same accepted epoch from disk
- the first restarted sender can emit a burst immediately after restart
- the peer decrypts that burst exactly once, then sees an empty repeated fetch
- the second restarted sender can answer with its own burst, again without
  duplicate delivery
- replay watermarks survive a second simulated restart boundary on both sides

Notes:

- this flow complements the single-client restart tests by proving that both
  sides can cross the same restart boundary and continue exchanging traffic

### Flow U2: dual restarted watchers bridge backlog and resume live notifications

Goal:

- prove the stronger watch/runtime property that two members can both restart,
  miss traffic while offline, reconnect their websocket watchers, fetch the
  missed backlog exactly once, and then both resume receiving fresh live
  notifications

Coverage:

- `cargo test --locked -p cityg-gui --bin cityg-gui native::tests::dual_restarted_watchers_fetch_offline_backlog_and_resume_live_notifications --features native-app -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/gui-dual-watch-restart`

Assertions:

- both restarted watchers reconnect their websocket feed after loading from
  disk
- traffic emitted while both watchers were offline is bridged by `perform_fetch`
  on both clients
- once the backlog is fetched, repeated fetches are empty on both sides
- a later live message produces websocket `Message` notifications for both
  restarted watchers
- the follow-up fetch for each watcher includes only the fresh live traffic and
  does not replay the bridged backlog

Notes:

- this extends Flow T and Flow U together instead of validating those two
  properties in isolation
- the sender remains online while the two watchers cross the restart boundary,
  which is closer to the public-room watch UX than the bilateral-only restart
  flow

### Flow V: malformed join rejection does not poison room state or restart recovery

Goal:

- prove that a malicious join payload cannot strand a public room: the malformed
  payload must be rejected, the live roster must remain healthy, and a restart
  must not preserve any toxic partial state

Coverage:

- `cargo test --locked -p cityg-server malformed_join_rejection_does_not_poison_room_state -- --nocapture`
- `cargo test --locked -p cityg-api --test integration malformed_join_rejection_does_not_poison_restart_or_future_honest_joins -- --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/malformed-join-proof`
- `2026-03-29` on `.cargo-target/malformed-join-proof`

Assertions:

- a malformed join bundle with a missing `barrier_leaf_pk` is rejected
- the rejection does not add, evict, or corrupt the existing room membership
- after restart, the room still exposes the healthy roster from before the
  malicious attempt
- a later honest join still succeeds after the malformed rejection and restart

### Flow V2: concurrent malformed join and honest join preserve room state

Goal:

- prove that a malformed public join racing with an honest join does not block
  the honest member or poison the room before and after restart

Coverage:

- `cargo test --locked -p cityg-api --test integration concurrent_malformed_join_and_honest_join_preserve_room_across_restart -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/api-join-race`

Assertions:

- the malformed join is rejected as `400 Bad Request`
- the honest join succeeds while the malformed join is in flight
- before restart, the room roster contains both the original member and the honest joiner
- after restart, the same healthy roster is preserved

### Flow V3: restart during concurrent malformed join race still converges cleanly

Goal:

- prove that a server restart in the middle of a malformed public join race and
  an honest join still converges to the honest room state

Coverage:

- `cargo test --locked -p cityg-api --test integration restart_during_concurrent_malformed_join_and_honest_join_recovers_cleanly -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/api-join-race-restart`

Assertions:

- the malformed join is rejected or dropped by the restart without poisoning state
- the in-flight honest join either commits before restart or is retried cleanly after restart
- after convergence, the room roster contains both the original member and the honest joiner

Notes:

- the API proof surfaced the malformed join as `400 Bad Request: invalid bundle
  components`
- this complements the existing malformed ciphertext fetch tests by proving that
  malformed membership traffic also fails closed without poisoning recovery

### Flow W: malformed admin expel rejection does not poison room state or restart recovery

Goal:

- prove that a malicious room-admin revocation payload cannot strand a public
  room: the malformed expel must be rejected, the live roster must remain
  healthy, and a restart must not preserve any toxic partial state

Coverage:

- `cargo test --locked -p cityg-server malformed_admin_expel_rejection_does_not_poison_room_state -- --nocapture`
- `cargo test --locked -p cityg-server malformed_admin_expel_rejection_does_not_poison_restart_recovery -- --nocapture`
- `cargo test --locked -p cityg-api --test integration malformed_admin_expel_request_does_not_poison_restart_or_future_honest_joins -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/admin-malformed-proof`
- `2026-03-29` on `.cargo-target/admin-malformed-proof`
- `2026-03-29` on `.cargo-target/api-malformed-admin`

Assertions:

- a malformed admin expel bundle with a missing `barrier_update` is rejected
- the rejection does not evict, corrupt, or otherwise poison the live roster
- a later honest join still succeeds after the malformed admin rejection
- after restart, the room still exposes the healthy roster from before the
  malicious attempt
- a later honest join still succeeds after the malformed admin rejection and
  restart
- a malformed HTTP `expel_member_ticket` request with a truncated `target_leaf_id`
  is rejected as `400 Bad Request`
- the rejected control-plane request does not poison persisted room state, and a
  later honest first join still succeeds after restart

Notes:

- this proof targets the “malicious admin payload” concern directly, rather than
  only malformed public join traffic
- it complements the admin expel happy-path flows by proving malformed targeted
  revocation traffic also fails closed and remains recoverable, both for raw
  accepted bundles and for malformed HTTP control-plane requests

### Flow W2: malformed admin expel control-plane race does not beat an honest join

Goal:

- prove that a malformed admin expel request racing with an honest public join
  cannot poison the room before restart, and that restart preserves both the
  joined member and the room-admin ACL

Coverage:

- `cargo test --locked -p cityg-api --test integration malformed_admin_expel_request_concurrent_with_honest_join_survives_restart -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/api-admin-race`

Assertions:

- the malformed HTTP `expel_member_ticket` request is rejected as `400 Bad Request`
- an honest join still succeeds before restart after the malformed request
- after restart, the honest joined member remains visible in the room roster
- after restart, the room-admin ACL still lists the original admin key

### Flow W3: fully concurrent malformed admin expel request and honest join preserve room state

Goal:

- prove that a malformed admin control-plane request and an honest public join
  can run in parallel without poisoning the room, and that restart preserves
  the honest outcome

Coverage:

- `cargo test --locked -p cityg-api --test integration concurrent_malformed_admin_expel_request_and_honest_join_preserve_room_across_restart -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/api-admin-concurrent-race`

Assertions:

- the malformed HTTP `expel_member_ticket` request is rejected as `400 Bad Request`
- the honest join commits successfully even while the malformed request is in flight
- before restart, the room roster contains the honest joined member
- after restart, the honest joined member remains visible in the room roster
- after restart, the room-admin ACL still lists the original admin key

### Flow W4: restart during concurrent malformed admin race still converges cleanly

Goal:

- prove that a server restart in the middle of a malformed admin control-plane
  race and an honest join still converges to the honest room state

Coverage:

- `cargo test --locked -p cityg-api --test integration restart_during_concurrent_malformed_admin_race_and_honest_join_recovers_cleanly -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/api-restart-admin-race`

Assertions:

- the malformed HTTP `expel_member_ticket` request fails closed or is dropped by the restart without poisoning state
- the in-flight honest join either commits before restart or can be retried cleanly after restart
- after convergence, the room roster contains the honest joined member
- after restart, the room-admin ACL still lists the original admin key

### Flow X: malformed leave rejection does not poison room state

Goal:

- prove that a malicious self-removal payload cannot strand a public room: the
  malformed leave must be rejected and later honest room traffic must still
  succeed

Coverage:

- `cargo test --locked -p cityg-server malformed_leave_rejection_does_not_poison_room_state -- --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/server-malicious-mutations`

Assertions:

- a malformed leave bundle with a missing `barrier_update` is rejected
- the rejection does not evict or otherwise corrupt the live roster
- a later honest join still succeeds after the malformed leave rejection

### Flow Y: malformed refresh rejection does not poison room state

Goal:

- prove that a malicious epoch-advance payload, including a forged
  `barrier_update_reason=1`, cannot wedge the room or prevent later honest
  traffic

Coverage:

- `cargo test --locked -p cityg-server malformed_refresh_rejection_does_not_poison_room_state -- --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/server-malicious-mutations`

Assertions:

- a forged refresh-shaped bundle derived from a `join_finalize` baseline is
  rejected fail-closed
- the rejection does not corrupt membership state
- a later honest join still succeeds after the malformed refresh rejection

### Flow Y2: malformed refresh race does not beat an honest join or restart recovery

Goal:

- prove that a malformed refresh-shaped payload racing with a later honest join
  cannot override healthy room progress or poison restart recovery

Coverage:

- `cargo test --locked -p cityg-server malformed_refresh_concurrent_with_honest_join_does_not_poison_restart_recovery -- --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/server-race-refresh`

Assertions:

- a malformed refresh-shaped payload is rejected even after a later honest join
  has advanced the room
- the live roster remains healthy before restart
- after restart, the healthy roster is preserved
- a healthy survivor refresh ticket is still issuable after restart

### Flow Y3: structured barrier mutations fail closed without poisoning restart recovery

Goal:

- prove that a bundle with intact overall shape but corrupted authority or
  barrier bytes cannot poison the room or restart recovery

Coverage:

- `cargo test --locked -p cityg-server hostile_barrier_update_mutations_fail_closed_without_poisoning_restart_recovery -- --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/server-hostile-mutations`

Assertions:

- corrupted witness, receipt, attestation, barrier-update bytes, and mismatched
  reason are all rejected fail-closed
- repeated hostile mutations do not change the live roster
- a later honest join still succeeds after the hostile mutation sequence
- after restart, the healthy roster is preserved and a survivor refresh ticket
  is still issuable

### Flow Z: malformed `join_finalize` rejection does not poison restart recovery

Goal:

- prove that a malicious `reason=2` activation payload cannot corrupt persisted
  room state or block the post-restart recovery path

Coverage:

- `cargo test --locked -p cityg-server malformed_join_finalize_rejection_does_not_poison_restart_recovery -- --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/server-malicious-mutations`

Assertions:

- a malformed `join_finalize` bundle with a missing `join_finalize_auth` is
  rejected
- restart preserves the healthy pre-attack roster
- restart still yields a valid refresh ticket and a fresh `join_finalize`
  generation path for the surviving member

### Flow AA: malformed room-admin grant/revoke requests do not poison ACL state

Goal:

- prove that malformed control-plane room-admin mutations fail closed without
  corrupting ACL state, and that restart still preserves healthy admin
  governance for later honest mutations

Coverage:

- `cargo test --locked -p cityg-api --test integration malformed_room_admin_mutation_requests_do_not_poison_acl_or_restart -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/api-admin-mutations`

Assertions:

- malformed `grant_admin` and `revoke_admin` requests with truncated target
  POP keys are rejected as `400 Bad Request`
- the ACL remains unchanged after each malformed request
- after restart, a later honest `grant_admin` succeeds
- after the same restart, a later honest `revoke_admin` still succeeds

### Flow AB: stale leave race with honest join does not poison restart recovery

Goal:

- prove that a leave bundle built from stale room state cannot override a later
  honest join, and that restart still preserves the healthy room

Coverage:

- `cargo test --locked -p cityg-server stale_leave_race_with_honest_join_does_not_poison_restart_recovery -- --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/server-stale-race`

Assertions:

- a valid leave bundle built before later room progress is rejected once a
  concurrent honest join has already advanced the room
- the rejection preserves the healthy live roster
- after restart, the healthy roster remains intact
- restart still yields a healthy survivor refresh ticket

### Flow AC: replayed room-admin proof stays rejected after restart

Goal:

- prove that a previously valid room-admin proof cannot be replayed after
  restart to mutate ACL state or wedge later honest governance operations

Coverage:

- `cargo test --locked -p cityg-api --test integration replayed_room_admin_grant_proof_rejected_after_restart_without_poisoning_acl -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/api-admin-replay`

Assertions:

- an honest `grant_admin` succeeds once
- replaying the same signed proof after restart is rejected as an HTTP error
- ACL state remains intact after the replay attempt
- a later honest `revoke_admin` still succeeds

### Flow AD: malformed refresh live race preserves the healthy room state

Goal:

- prove that a malformed refresh-shaped bundle racing with a later honest join
  cannot poison the live room even before any restart path is exercised

Coverage:

- `cargo test --locked -p cityg-server malformed_refresh_concurrent_with_honest_join_preserves_live_state -- --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/server-malicious-mutations`

Assertions:

- a malformed refresh-shaped bundle derived from a `join_finalize` baseline is
  rejected once a later honest join has already advanced the room
- the rejection preserves the healthy live roster immediately, without relying
  on a restart boundary
- a later honest survivor refresh ticket is still buildable from the live room

### Composite closure note

The last runtime backlog items from the checklist are now closed either by a
direct flow or by an explicit composite of already-green flows:

- hostile `refresh` race: Flow AD plus the earlier restart proof
- hostile `join_finalize` interference: malformed `join_finalize` rejection,
  post-publish `epoch_sync` recovery, and restart-during-pending activation
- large public-room churn: expel/refresh/new-join continuity, offline catch-up,
  same-identity rejoin, replay-state after restart, and watch recovery
- mutation harness coverage: structured barrier mutations, helper-manifest
  guards, authority/header mismatch guards, and sender-binding spoof rejection

### Flow AE: paginated helper mutations fail closed

Goal:

- prove that helper responses cannot mutate authenticated manifest or
  attestation state between pages without the client failing closed

Coverage:

- `cargo test --locked -p cityg-api-client --lib tests::barrier_resolve_revoked_leaves_rejects_deployment_profile_manifest_mismatch_across_pages -- --exact --nocapture`
- `cargo test --locked -p cityg-api-client --lib tests::barrier_resolve_joins_since_rejects_global_history_attestation_mismatch_across_pages -- --exact --nocapture`
- `cargo test --locked -p cityg-api-client --lib tests::barrier_fetch_public_tree_rejects_deployment_profile_manifest_mismatch_across_pages -- --exact --nocapture`

Passed:

- `2026-03-29` on `.cargo-target/api-mutation-pages`

Assertions:

- `ResolveRevokedLeaves` rejects a deployment-profile manifest that changes
  across pages even when both pages remain individually signed/valid
- `ResolveJoinsSince` rejects a global history attestation that changes across
  pages even when both pages remain individually valid
- `FetchBarrierPublicTree` rejects a deployment-profile manifest that changes
  across pages even when both pages remain individually signed/valid
