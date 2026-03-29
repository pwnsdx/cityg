# Pre-Production Validation Plan

This document defines the minimum pre-production validation campaign for CityG before exposing a deployment to non-trivial real traffic.

`cityg-stress` is the canonical runner for smoke, soak, and chaos validation.

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
- client-state hardening gate passes
- smoke membership flow passes on current binaries
- soak run completes without server crash, journal corruption, or stuck pending barrier state
- load/concurrency run shows bounded latency and no unexpected freeze-code drift
- chaos run confirms restart/recovery behavior remains correct under interruption

## Prerequisites

Prefer running the commands below after sourcing the repo-local Cargo environment:

```bash
cd /Users/admin/Desktop/Repositories/cityg
source ./scripts/cargo_repo_env.sh
```

This pins Cargo to the repo-local cache/home and applies the native-app test
stack floor used by the validation scripts.

- built binaries:
  - `cargo build -p cityg-api`
  - `cargo build -p cityg-gui --features native-app --bin join_leave`
  - `cargo build -p cityg-stress`
  - `./scripts/verify_client_state_hardening.sh`
- local secrets/tokens for smoke:
  - `CITYG_CLIENT_MESSAGE_AUTH_TOKEN`
  - `CITYG_SERVER_WINDOW_ADMIN_TOKEN`
  - `CITYG_SERVER_MESSAGE_AUTH_TOKEN`
  - normal public-room GUI smoke does **not** require `CITYG_CLIENT_ADMIN_TOKEN`
    or `CITYG_SERVER_ROOMS_ADMIN_TOKEN`
- observability endpoints enabled:
  - `/health/detailed`
  - `/metrics`

## Local Manual GUI Smoke

Use this when you want to verify the real GUI flow before or after a stress campaign.

Server:

```bash
cd /Users/admin/Desktop/Repositories/cityg
export CITYG_SERVER_ADDRESS=127.0.0.1:8080
export CITYG_SERVER_MESSAGE_AUTH_TOKEN=dev-message-token
cargo run -p cityg-api
```

GUI instance 1:

```bash
cd /Users/admin/Desktop/Repositories/cityg
export CITYG_CLIENT_MESSAGE_AUTH_TOKEN=dev-message-token
export CITYG_GUI_CONFIG_DIR=/tmp/cityg-gui-1
cargo run -p cityg-gui --features native-app
```

GUI instance 2:

```bash
cd /Users/admin/Desktop/Repositories/cityg
export CITYG_CLIENT_MESSAGE_AUTH_TOKEN=dev-message-token
export CITYG_GUI_CONFIG_DIR=/tmp/cityg-gui-2
cargo run -p cityg-gui --features native-app
```

Success criteria:

- the second joiner can send immediately after joining
- message send/receive works in both directions
- `PCS Refresh` succeeds without putting the room back into a stuck pending state
- the first creator can leave/restart/rejoin flows without any room admin token
  fallback

## Targeted Runtime Gates

Run these before longer smoke/chaos campaigns when you want fast signal on the
protocol-sensitive room state machine and the user-visible messaging contract.

Canonical protocol checklist:

- [`protocol/20-protocol-checklist.md`](protocol/20-protocol-checklist.md)

Commands:

```bash
cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::perform_join_second_member_can_send_immediately \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::send_fetch_and_members_roundtrip \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::offline_member_restart_then_epoch_sync_after_pcs_refresh_decrypts_new_messages \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::admin_expel_removes_member_and_preserves_survivor_messaging \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::admin_expel_then_survivor_refresh_preserves_room_and_new_joiner_messaging \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::room_admin_grant_and_revoke_flow_preserves_authorization_boundaries \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::stale_dueling_pcs_refreshes_converge_and_preserve_messaging \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::multi_author_messaging_across_refresh_epoch_change_preserves_delivery \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::message_replay_state_only_releases_new_messages_between_fetch_rounds \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::message_replay_state_survives_client_restart_between_fetch_rounds \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::watch_reconnect_fetches_offline_backlog_and_resumes_live_notifications \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::client_restart_during_multi_version_catchup_after_refresh_and_leave_recovers_cleanly \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::two_restarted_members_exchange_traffic_without_duplicate_delivery \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::restart_after_admin_expel_preserves_survivor_state_and_new_joiner_messaging \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin cityg-gui \
  native::tests::restart_during_pending_join_finalize_activation_recovers_via_epoch_sync \
  --features native-app -- --exact --nocapture

cargo test --locked -p cityg-gui --bin join_leave \
  tests::watch_mode_reconnect_under_burst_resumes_live_notifications \
  -- --exact --nocapture

cargo test --locked -p cityg-api --test integration \
  malformed_join_rejection_does_not_poison_restart_or_future_honest_joins \
  -- --exact --nocapture

cargo test --locked -p cityg-server \
  malformed_leave_rejection_does_not_poison_room_state \
  malformed_refresh_rejection_does_not_poison_room_state \
  malformed_refresh_concurrent_with_honest_join_does_not_poison_restart_recovery \
  hostile_barrier_update_mutations_fail_closed_without_poisoning_restart_recovery \
  malformed_join_finalize_rejection_does_not_poison_restart_recovery \
  stale_leave_race_with_honest_join_does_not_poison_restart_recovery \
  -- --nocapture

cargo test --locked -p cityg-server \
  malformed_admin_expel_rejection_does_not_poison_room_state \
  malformed_admin_expel_rejection_does_not_poison_restart_recovery \
  -- --nocapture

cargo test --locked -p cityg-api --test integration \
  malformed_admin_expel_request_does_not_poison_restart_or_future_honest_joins \
  malformed_admin_expel_request_concurrent_with_honest_join_survives_restart \
  -- --exact --nocapture

cargo test --locked -p cityg-api --test integration \
  malformed_room_admin_mutation_requests_do_not_poison_acl_or_restart \
  replayed_room_admin_grant_proof_rejected_after_restart_without_poisoning_acl \
  -- --exact --nocapture
```

These gates cover:

- fresh join plus bidirectional messaging baseline
- offline catch-up after `pcs_refresh` across a simulated client restart
- room-admin expel with survivor continuity
- room-admin expel followed by survivor refresh and a fresh rejoin
- room-admin grant/revoke lifecycle and ACL visibility
- stale dual-refresh convergence from one authenticated baseline
- multi-author messaging continuity across a real epoch change
- replay-state enforcement across repeated fetch rounds
- replay-state persistence across a simulated client restart
- watch reconnect bridging offline backlog before resuming the live feed
- client restart during multi-version catch-up after `refresh + leave`
- two restarted members resuming bilateral traffic without duplicate delivery
- restart + expel churn with later joiner messaging
- malformed join rejection without poisoning the room before or after restart
- malformed leave rejection without poisoning the room state
- malformed refresh rejection without poisoning the room state
- malformed refresh race against an honest join without poisoning restart recovery
- structured barrier header/update mutations staying fail-closed without poisoning restart recovery
- malformed `join_finalize` rejection without poisoning restart recovery
- malformed admin expel rejection without poisoning the room before or after restart
- malformed admin expel control-plane requests fail closed and still allow honest joins after restart
- malformed admin expel control-plane races still allow the honest join before restart, and restart preserves both that joined member and the room-admin ACL
- malformed admin grant/revoke control-plane requests fail closed without poisoning ACL state or restart recovery
- stale leave versus honest join race with clean post-restart recovery
- replayed room-admin proofs staying rejected after restart without poisoning ACL state
- restart during a published-but-not-reloaded `join_finalize` activation
- watch websocket reconnect resuming fresh notifications under active burst traffic

## Phase 1: Baseline Smoke

Run:

```bash
cargo run -p cityg-stress -- \
  --server-bind 127.0.0.1:18080 \
  --server-url http://127.0.0.1:18080 \
  --workers 1 \
  --rounds-per-worker 2 \
  --min-count 2 \
  --max-count 2 \
  --leaves-per-room 2 \
  --watch-percent 100 \
  --jitter-max-secs 0 \
  --round-delay-secs 2 \
  --message-burst-count 2 \
  --message-burst-interval-ms 25 \
  --restart-every-secs 45 \
  --client-restart-every-secs 20 \
  --capture-client-state-artifacts \
  --require-metrics
```

Success criteria:

- watch-mode join/leave flow completes successfully
- message send path emits and receives a notification event
- restart-chaos run produces `client-restarts.log` plus client-state artifacts
- capacity test still raises the expected `freeze 925` / `mh_window_full` path when requested separately

Artifacts:

- terminal transcript
- tail of server log
- client-state artifact directory

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
  --restart-every-secs 600 \
  --client-restart-every-secs 300 \
  --capture-client-state-artifacts \
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
  --restart-every-secs 600 \
  --client-restart-every-secs 300 \
  --capture-client-state-artifacts \
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
  --restart-every-secs 600 \
  --client-restart-every-secs 300 \
  --capture-client-state-artifacts \
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
- no client-state artifact showing a stuck `barrier_recovery_pending` after authenticated recovery
- `GET /health/detailed` remains healthy
- no unbounded growth in memory or restart latency

Collect:

- server logs
- periodic `/health/detailed` snapshots
- periodic `/metrics` snapshots
- restart timestamps and replay duration
- `client-restarts.log` and per-round `worker-*-client-state/*.json`

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
- `--client-restart-every-secs` injects managed harness restarts so restart handling is exercised during churn campaigns
- `--reuse-room-per-worker` keeps one stable room ID per worker and is useful for
  validating empty-room rejoin flows across multiple rounds
- `--capture-client-state-artifacts` exports anonymized per-session state snapshots for audit/review
- pass `--api-bin` and `--join-leave-bin` when you want to pin the run to explicitly-built candidate binaries
- with persisted state and restart-chaos, prefer the default `--server-ready-timeout-secs 180` or a larger override; replay on large journals can exceed `120s`
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

Same-room leave/rejoin variant:

```bash
cargo run -p cityg-stress -- \
  --plain \
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
  --reuse-room-per-worker
```

This run proves that a room can be emptied and then reused on the next round
without allocating a fresh room ID. Do not combine it with managed restart
chaos; `--reuse-room-per-worker` intentionally rejects that combination.

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
