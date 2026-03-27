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
