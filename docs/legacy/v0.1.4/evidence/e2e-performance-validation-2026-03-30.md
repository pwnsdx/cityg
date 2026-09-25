# E2E Performance Validation (2026-03-30)

This note captures the first post-cleanup E2E performance reruns on the current `main` state after
hardening the stale leave path in
[/Users/admin/Desktop/Repositories/cityg/crates/cityg-gui/src/bin/join_leave.rs](/Users/admin/Desktop/Repositories/cityg/crates/cityg-gui/src/bin/join_leave.rs).

## Scope

- Large-group churn with watch-heavy traffic and injected client restarts
- Restart-under-traffic chaos with managed server restarts and client restarts

The large-group rerun was necessary because the first attempt in
`/tmp/cityg-perf-large-20260330` exposed a real stale leave failure:
`acceptance error: fs_checkpoint_monotonicity`.

That path is now covered by the regression test
`perform_leave_retries_fresh_ticket_after_fs_checkpoint_monotonicity`.

## Commands

Large-group rerun:

```bash
CITYG_CARGO_TARGET_SLOT=stress-large-group-recheck \
CITYG_STRESS_ARTIFACT_DIR=/tmp/cityg-perf-large-recheck2-20260330 \
CITYG_STRESS_SERVER_BIND=127.0.0.1:18140 \
CITYG_STRESS_SERVER_URL=http://127.0.0.1:18140 \
CITYG_STRESS_DURATION_SECS=90 \
CITYG_STRESS_WORKERS=3 \
CITYG_STRESS_ROUNDS_PER_WORKER=10 \
CITYG_STRESS_MIN_COUNT=8 \
CITYG_STRESS_MAX_COUNT=16 \
CITYG_STRESS_MESSAGE_BURST_COUNT=8 \
CITYG_STRESS_CLIENT_RESTART_EVERY_SECS=45 \
./scripts/run_large_group_chaos.sh
```

Restart-under-traffic rerun:

```bash
CITYG_CARGO_TARGET_SLOT=stress-large-group-recheck \
CITYG_STRESS_ARTIFACT_DIR=/tmp/cityg-perf-restart-recheck-20260330 \
CITYG_STRESS_SERVER_BIND=127.0.0.1:18150 \
CITYG_STRESS_SERVER_URL=http://127.0.0.1:18150 \
CITYG_STRESS_DURATION_SECS=90 \
CITYG_STRESS_WORKERS=3 \
CITYG_STRESS_ROUNDS_PER_WORKER=12 \
CITYG_STRESS_RESTART_EVERY_SECS=30 \
CITYG_STRESS_CLIENT_RESTART_EVERY_SECS=15 \
CITYG_STRESS_MESSAGE_BURST_COUNT=10 \
./scripts/run_restart_traffic_chaos.sh
```

## Results

### Large-group rerun

Artifacts:
- `/tmp/cityg-perf-large-recheck2-20260330/summary.txt`
- `/tmp/cityg-perf-large-recheck2-20260330/final-metrics.txt`

Outcome:
- `worker_passes=3`
- `worker_failures=0`
- `rounds_completed=18`
- `rounds_failed=0`
- `accept_epoch_ok=432` in the runner summary
- `cityg_accept_epoch_total{result="ok"} = 488` in final metrics
- `cityg_refresh_pivot_conflict_total{reason="payload_diverges"} = 54` in final metrics

Acceptance latency from `cityg_accept_epoch_duration_seconds{result="ok"}`:
- `p50 = 101.7 ms`
- `p95 = 157.9 ms`
- `p99 = 227.5 ms`
- `count = 488`

Observed live dashboard range:
- `p95` settled mostly in the `151-166 ms` band after warm-up

### Restart-under-traffic rerun

Artifacts:
- `/tmp/cityg-perf-restart-recheck-20260330/summary.txt`
- `/tmp/cityg-perf-restart-recheck-20260330/restarts.log`
- `/tmp/cityg-perf-restart-recheck-20260330/worker-*-metrics.txt`

Outcome:
- `worker_passes=3`
- `worker_failures=0`
- `rounds_completed=30`
- `rounds_failed=0`
- `restarts=2`

Important note:
- the final `summary.txt` counters are not a good end-of-run total for `accept_epoch_ok` after managed restarts,
  because the runner’s live metrics can reset when the server restarts
- for this scenario, the stable evidence is the per-round metrics snapshots and live dashboard readings

Per-round `p95` extracted from `worker-*-metrics.txt`:
- minimum observed `p95 = 103.1 ms`
- maximum observed `p95 = 199.4 ms`
- last recorded per-round `p95 = 111.2 ms`

Observed live dashboard range:
- mostly `115-182 ms`
- transient peak around `226.6 ms` during restart churn

## Verdict

On the current code:
- the large-group E2E churn scenario is now stable again after the stale leave retry hardening
- the protocol stays in a sub-`160 ms` `p95` band in the steady large-group rerun
- the restart-under-traffic scenario remains stable with `0` worker failures and sub-`200 ms` per-round `p95`

This is good enough to call the current protocol/runtime path fast and operationally stable for the
tested local workload. Further confidence should come from longer soak runs, not from more small ad hoc flows.
