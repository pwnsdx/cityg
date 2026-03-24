# City-G Release QA Checklist

Use this checklist to verify server + GUI readiness before a release.

For longer-running staging validation, see `/Users/admin/Desktop/Repositories/cityg/docs/preproduction-validation.md`.

## 1. Build and Unit/Integration Tests

- [ ] `cargo test -p cityg-server`
- [ ] `cargo test -p cityg-api`
- [ ] `cargo test -p cityg-gui --features native-app`
- [ ] `cargo test -p msphf-orchestrator`
- [ ] `./scripts/verify_client_state_hardening.sh`
- [ ] `./scripts/verify_no_secrets.sh`

## 2. API Runtime Checks

1. Start API server:

```bash
cargo run -p cityg-api
```

2. Verify health:

```bash
./scripts/healthcheck_api.sh http://127.0.0.1:8080/health/ready 30 1
curl -fsS http://127.0.0.1:8080/health/detailed
```

3. Confirm telemetry/window endpoints respond:

```bash
curl -fsS -X POST -H 'content-type: application/x-protobuf' --data-binary '' \
  http://127.0.0.1:8080/v1/window >/dev/null
curl -fsS -X POST -H 'content-type: application/x-protobuf' --data-binary '' \
  http://127.0.0.1:8080/v1/telemetry >/dev/null
```

## 3. Membership and Capacity Smoke

Run one-command smoke (starts local API, runs watch mode, validates freeze-925 behavior):

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

Expected result:
- Join + leave watch flow succeeds.
- Restart-chaos run succeeds with per-round client-state artifacts.
- Capacity run still fails with `freeze 925`/`mh_window_full` signal when explicitly requested.

For longer churn validation, run:

```bash
cargo run -p cityg-stress -- \
  --server-bind 127.0.0.1:18080 \
  --server-url http://127.0.0.1:18080 \
  --workers 1 \
  --rounds-per-worker 10 \
  --min-count 2 \
  --max-count 2 \
  --leaves-per-room 2 \
  --watch-percent 100 \
  --round-delay-secs 2 \
  --restart-every-secs 120 \
  --client-restart-every-secs 60 \
  --capture-client-state-artifacts \
  --require-metrics
```

## 4. GUI Smoke

- [ ] Launch API with explicit local auth:

```bash
export CITYG_SERVER_ADDRESS=127.0.0.1:8080
export CITYG_SERVER_MESSAGE_AUTH_TOKEN=dev-message-token
cargo run -p cityg-api
```

- [ ] Launch first GUI instance:

```bash
export CITYG_CLIENT_MESSAGE_AUTH_TOKEN=dev-message-token
export CITYG_GUI_CONFIG_DIR=/tmp/cityg-gui-1
cargo run -p cityg-gui --features native-app
```

- [ ] Launch second GUI instance with an isolated config dir:

```bash
export CITYG_CLIENT_MESSAGE_AUTH_TOKEN=dev-message-token
export CITYG_GUI_CONFIG_DIR=/tmp/cityg-gui-2
cargo run -p cityg-gui --features native-app
```

- [ ] Normal room creation/join/leave/refresh works without
  `CITYG_CLIENT_ADMIN_TOKEN` or `CITYG_SERVER_ROOMS_ADMIN_TOKEN`.
- [ ] Second joiner can send immediately after joining the room.
- [ ] Send/receive works in both directions.
- [ ] Members panel reflects join/leave updates.
- [ ] `PCS Refresh` succeeds without leaving either client stuck in pending barrier recovery.
- [ ] Crash/restart recovery path remains message-blocked while `barrier_recovery_pending` is true and recovers after epoch sync.

## 5. Container/Deployment Smoke

From `docs/examples`:

```bash
cp cityg.env.example cityg.env
docker compose up -d --build
```

- [ ] `cityg-api` becomes healthy.
- [ ] Prometheus scrapes `/metrics`.
- [ ] Grafana loads the `CityG Overview` dashboard.

## 6. Sign-Off

- [ ] Security checklist completed (`docs/security-review-checklist.md`).
- [ ] Audit pack reviewed (`docs/client-state-hardening-audit-pack.md`).
- [ ] Release notes updated.
- [ ] Rollback plan validated.
