# Pre-Production Validation Plan

This document defines the minimum pre-production validation campaign for CityG before exposing a deployment to non-trivial real traffic.

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
  - `cargo build -p cityg-gui --bin join_leave`
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
./scripts/smoke_membership_capacity.sh
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
for i in $(seq 1 200); do
  ./scripts/smoke_membership_capacity.sh
done
```

Run this against a dedicated staging server with journaling enabled.

Recommended runner:

```bash
./scripts/soak_membership_campaign.sh
```

Useful overrides:

```bash
CITYG_SOAK_ITERATIONS=50 \
CITYG_SOAK_SLEEP_SECS=5 \
CITYG_SOAK_FINAL_CAPACITY=1 \
./scripts/soak_membership_campaign.sh
```

Notes:

- the soak runner keeps one API process alive by default and exercises fresh room IDs on each iteration
- artifacts are written under `/tmp/cityg-soak-<timestamp>` unless `CITYG_SOAK_ARTIFACT_DIR` is set
- set `CITYG_SOAK_MANAGE_SERVER=0` to point at an already-running staging server via `CITYG_SOAK_SERVER_URL`

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

Suggested method:

- run several independent `join_leave --watch --count=2` sessions in parallel on fresh room IDs
- vary `CITYG_SERVER_GROUP_LANES`
- vary `CITYG_PROTOCOL_MAX_CONCURRENT_HEADS`

Example:

```bash
for n in 1 2 4 8; do
  CITYG_SERVER_GROUP_LANES=$n ./scripts/smoke_membership_capacity.sh
done
```

Then add parallelism:

```bash
for i in $(seq 1 4); do
  CITYG_SMOKE_SERVER_BIND="127.0.0.1:$((18080 + i))" \
  ./scripts/smoke_membership_capacity.sh &
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
./scripts/smoke_membership_capacity.sh
# while a separate watch run is active:
pkill -f cityg-api
# restart server
cargo run -p cityg-api
```

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
