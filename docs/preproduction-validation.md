# Pre-Production Validation Plan

This document defines the minimum pre-production validation campaign for CityG before exposing a deployment to non-trivial real traffic.

`cityg-stress` is now the canonical runner for smoke, soak, and chaos validation. The legacy Bash scripts in `/Users/admin/Desktop/Repositories/cityg/scripts` are compatibility wrappers only and forward into this binary.

## Scope

These checks are not about wire/spec correctness. They are about runtime stability under:

- sustained uptime
- repeated joins/leaves/messages
- restart and recovery
- backpressure / capacity pressure
- degraded network conditions

## Exit Criteria

A candidate build is considered pre-production ready only if all of the following are true:

- release QA checklist passes
- smoke membership flow passes on current binaries
- soak run completes without server crash, journal corruption, or stuck pending barrier state
- load/concurrency run shows bounded latency and no unexpected freeze-code drift
- chaos run confirms restart/recovery behavior remains correct under interruption

## Prerequisites

- built binaries:
  - `cargo build -p cityg-api`
  - `cargo build -p cityg-gui --features native-app --bin join_leave`
  - `cargo build -p cityg-stress`
- local secrets/tokens for smoke:
  - `CITYG_CLIENT_ADMIN_TOKEN`
  - `CITYG_CLIENT_MESSAGE_AUTH_TOKEN`
  - `CITYG_SERVER_ROOMS_ADMIN_TOKEN`
  - `CITYG_SERVER_WINDOW_ADMIN_TOKEN`
  - `CITYG_SERVER_MESSAGE_AUTH_TOKEN`
- observability endpoints enabled:
  - `/health/detailed`
  - `/metrics`

## Phase 1: Baseline Smoke

Run:

```bash
cargo run -p cityg-stress -- \
  --server-bind 127.0.0.1:18080 \
  --server-url http://127.0.0.1:18080 \
  --workers 1 \
  --rounds-per-worker 1 \
  --min-count 2 \
  --max-count 2 \
  --leaves-per-room 2 \
  --watch-percent 100 \
  --jitter-max-secs 0 \
  --round-delay-secs 0 \
  --message-burst-count 1 \
  --message-burst-interval-ms 0 \
  --final-capacity-check
```

Success criteria:

- watch-mode join/leave flow completes successfully
- message send path emits and receives a notification event
- capacity test still raises the expected `freeze 925` / `mh_window_full` path

Artifacts:

- terminal transcript
- tail of server log

## Phase 2: Soak

Goal: prove the deployment stays healthy over time while repeatedly exercising membership churn and message delivery.

Suggested duration:

- minimum: 4 hours
- preferred: 24 hours
- high-confidence: 72 hours

Suggested loop:

```bash
cargo run -p cityg-stress -- \
  --server-bind 127.0.0.1:18080 \
  --server-url http://127.0.0.1:18080 \
  --workers 1 \
  --rounds-per-worker 200 \
  --min-count 2 \
  --max-count 2 \
  --leaves-per-room 2 \
  --watch-percent 100 \
  --round-delay-secs 0 \
  --require-metrics
```

Run this against a dedicated staging server with journaling enabled.

Recommended runner:

```bash
cargo run -p cityg-stress -- \
  --server-bind 127.0.0.1:18080 \
  --server-url http://127.0.0.1:18080 \
  --workers 1 \
  --rounds-per-worker 50 \
  --min-count 2 \
  --max-count 2 \
  --leaves-per-room 2 \
  --watch-percent 100 \
  --round-delay-secs 5 \
  --require-metrics \
  --final-capacity-check
```

Useful overrides:

```bash
CITYG_SOAK_ITERATIONS=50 \
cargo run -p cityg-stress -- \
  --server-bind 127.0.0.1:18080 \
  --server-url http://127.0.0.1:18080 \
  --workers 1 \
  --rounds-per-worker 50 \
  --min-count 2 \
  --max-count 2 \
  --leaves-per-room 2 \
  --watch-percent 100 \
  --round-delay-secs 5 \
  --require-metrics \
  --final-capacity-check
```

Notes:

- `cityg-stress` keeps one API process alive by default and exercises fresh room IDs on each iteration
- artifacts are written under `/tmp/cityg-stress-<timestamp>` unless `--artifact-dir` is set
- use `--no-manage-server` to point at an already-running staging server

Success criteria:

- no server crash
- no stuck WebSocket subsystem
- no journal replay failure after restart
- `GET /health/detailed` remains healthy
- no unbounded growth in memory or restart latency

Collect:

- server logs
- periodic `/health/detailed` snapshots
- periodic `/metrics` snapshots
- restart timestamps and replay duration

## Phase 3: Load / Concurrency

Goal: measure behavior under multiple simultaneous rooms and overlapping membership/message activity.

Recommended interactive runner:

```bash
cargo run -p cityg-stress -- \
  --server-bind 127.0.0.1:18090 \
  --server-url http://127.0.0.1:18090 \
  --workers 12 \
  --rounds-per-worker 20 \
  --min-count 3 \
  --max-count 6 \
  --watch-percent 70 \
  --message-burst-count 5 \
  --message-burst-interval-ms 10
```

Notes:

- `cityg-stress` manages a local `cityg-api` by default and renders live metrics in a `ratatui` dashboard
- use `--plain` when running in CI or when stdout is not a real terminal
- `--message-burst-count` and `--message-burst-interval-ms` turn each room round into a real message storm instead of a single dummy payload
- pass `--api-bin` and `--join-leave-bin` when you want to pin the run to explicitly-built candidate binaries
- the artifact directory is printed at the end of the run and contains `server.log`, worker logs, `summary.txt`, initial/final observability snapshots, and per-round observability snapshots

High-chatter variant:

```bash
cargo run -p cityg-stress -- \
  --server-bind 127.0.0.1:18095 \
  --server-url http://127.0.0.1:18095 \
  --workers 12 \
  --rounds-per-worker 20 \
  --min-count 3 \
  --max-count 6 \
  --watch-percent 70 \
  --message-burst-count 6 \
  --message-burst-interval-ms 25
```

This variant keeps the same membership churn but adds repeated message sends during each round, which is a better approximation of active rooms than the default single-message path.

Suggested method:

- run several independent `join_leave --watch --count=2` sessions in parallel on fresh room IDs
- vary `CITYG_SERVER_GROUP_LANES`
- vary `CITYG_PROTOCOL_MAX_CONCURRENT_HEADS`

Example:

```bash
for n in 1 2 4 8; do
  CITYG_SERVER_GROUP_LANES=$n cargo run -p cityg-stress -- \
    --server-bind 127.0.0.1:18080 \
    --server-url http://127.0.0.1:18080 \
    --workers 1 \
    --rounds-per-worker 1 \
    --min-count 2 \
    --max-count 2 \
    --leaves-per-room 2 \
    --watch-percent 100 \
    --jitter-max-secs 0 \
    --round-delay-secs 0 \
    --message-burst-count 1 \
    --message-burst-interval-ms 0 \
    --final-capacity-check
done
```

Then add parallelism:

```bash
for i in $(seq 1 4); do
  cargo run -p cityg-stress -- \
    --plain \
    --server-bind "127.0.0.1:$((18080 + i))" \
    --server-url "http://127.0.0.1:$((18080 + i))" \
    --workers 1 \
    --rounds-per-worker 1 \
    --min-count 2 \
    --max-count 2 \
    --leaves-per-room 2 \
    --watch-percent 100 \
    --jitter-max-secs 0 \
    --round-delay-secs 0 \
    --message-burst-count 1 \
    --message-burst-interval-ms 0 \
    --final-capacity-check &
done
wait
```

Success criteria:

- no unexpected `500` paths outside known test/control-plane cases
- bounded request latency
- bounded retry rates
- expected freeze codes only under deliberate capacity pressure

Watch metrics:

- request latency histograms
- WebSocket lag
- freeze code distribution
- join/merge ticket error rates

## Phase 4: Chaos / Restart

Goal: prove restart recovery, journal replay, and pending barrier activation remain correct under interruption.

Suggested scenarios:

1. kill the API during churn, restart, rerun smoke
2. kill the API after accepted merge but before client activation completes
3. restart repeatedly during sustained watch-mode traffic

Minimal manual drill:

```bash
cargo run -p cityg-stress -- \
  --server-bind 127.0.0.1:18080 \
  --server-url http://127.0.0.1:18080 \
  --workers 1 \
  --rounds-per-worker 1 \
  --min-count 2 \
  --max-count 2 \
  --leaves-per-room 2 \
  --watch-percent 100 \
  --jitter-max-secs 0 \
  --round-delay-secs 0 \
  --message-burst-count 1 \
  --message-burst-interval-ms 0 \
  --final-capacity-check
# while a separate watch run is active:
pkill -f cityg-api
# restart server
cargo run -p cityg-api
```

Recommended runner:

```bash
cargo run -p cityg-stress -- \
  --server-bind 127.0.0.1:18080 \
  --server-url http://127.0.0.1:18080 \
  --workers 8 \
  --rounds-per-worker 10 \
  --min-count 2 \
  --max-count 5 \
  --leaves-per-room 1 \
  --watch-percent 60 \
  --jitter-max-secs 1 \
  --require-metrics \
  --restart-every-secs 20
```

Useful overrides:

```bash
cargo run -p cityg-stress -- \
  --server-bind 127.0.0.1:18080 \
  --server-url http://127.0.0.1:18080 \
  --workers 8 \
  --rounds-per-worker 10 \
  --min-count 2 \
  --max-count 5 \
  --leaves-per-room 1 \
  --watch-percent 60 \
  --jitter-max-secs 1 \
  --require-metrics \
  --restart-every-secs 20
```

Notes:

- each worker uses a fresh room per round to avoid cross-round contamination
- the runner mixes `watch` and `batch` membership flows, with randomized member counts and explicit randomized leave order
- `CITYG_CHAOS_LEAVES_PER_ROOM=1` is the safest default because it avoids stale multi-revoke artifacts dominating the signal; raise it only when you intentionally want to probe repeated local leave sequencing
- use `--no-manage-server` to run against an existing staging server
- set `--restart-every-secs` only when you want deliberate restart turbulence during live traffic
- if another local campaign is already using `127.0.0.1:18080`, set `--server-bind` to a different port before starting a managed chaos run
- `--api-bin` and `--join-leave-bin` can point at explicitly-built binaries when you want to isolate a candidate patch from the repository's default `target/debug`

Success criteria:

- server restarts and becomes healthy
- journal replay succeeds
- historical barrier tree snapshots remain fetchable
- clients do not strand due to pending barrier activation state

## Recommended Thresholds

Use these as initial operational gates:

- health endpoint must remain green throughout the run
- no data-loss symptoms in join/leave/message smoke
- no unexpected freeze-code classes
- replay/restart latency must remain operationally bounded for the deployment target
- WebSocket stream must recover cleanly across reconnects

These thresholds should be tightened with deployment-specific SLOs once production baselines exist.

## Known Current Strengths

The repository already has strong validation coverage for:

- crash/restart replay
- historical barrier tree persistence
- sender-scoped replay protection
- pending barrier activation history correlation
- end-to-end orchestrator acceptance paths

Those tests reduce risk, but they do not replace long-running operational validation.

## Recommended Artifacts To Archive

- commit hash under test
- exact config and env overrides
- smoke transcripts
- `/metrics` snapshots
- `/health/detailed` snapshots
- server logs
- restart timing notes
- freeze code summary

## Sign-Off Rule

Do not treat a build as production-stable only because the unit/integration suites are green.

Require:

1. baseline smoke
2. soak
3. load/concurrency
4. chaos/restart

All four must pass on the same candidate build before declaring operational readiness.
