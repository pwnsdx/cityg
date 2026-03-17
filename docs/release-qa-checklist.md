# City-G Release QA Checklist

Use this checklist to verify server + GUI readiness before a release.

For longer-running staging validation, see `/Users/admin/Desktop/Repositories/cityg/docs/preproduction-validation.md`.

## 1. Build and Unit/Integration Tests

- [ ] `cargo test -p cityg-server`
- [ ] `cargo test -p cityg-api`
- [ ] `cargo test -p cityg-gui --features native-app`
- [ ] `cargo test -p msphf-orchestrator`
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

Expected result:
- Join + leave watch flow succeeds.
- Capacity run fails with `freeze 925`/`mh_window_full` signal.

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
  --require-metrics
```

## 4. GUI Smoke

- [ ] Launch GUI binary:

```bash
cargo run -p cityg-gui --features native-app --bin cityg-gui
```

- [ ] Join room from GUI and send/receive at least one message.
- [ ] Members panel reflects join/leave updates.

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
- [ ] Release notes updated.
- [ ] Rollback plan validated.
