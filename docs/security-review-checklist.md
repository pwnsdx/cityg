# City-G Security Review Checklist

Use this checklist before cutting a release candidate or deploying a policy change.

## 1. Automated Baseline

Run these commands from the repository root:

```bash
./scripts/security_review.sh
./scripts/verify_client_state_hardening.sh
```

If you want to run steps manually:

```bash
cargo test -p cityg-server
cargo test -p cityg-api
cargo test -p cityg-gui --features native-app
cargo test -p msphf-orchestrator
./scripts/verify_client_state_hardening.sh
./scripts/verify_no_secrets.sh
```

## 2. Server-Blindness Controls

- [ ] `./scripts/verify_no_secrets.sh` passes all checks.
- [ ] No new server-side decryption helpers were introduced in `crates/msphf-orchestrator/src/accept` or `crates/cityg-server/src`.
- [ ] No API endpoint returns plaintext keys or `hp` material.

## 3. Forward-Secrecy Policy Review

- [ ] `CITYG_PROTOCOL_FS_POLICY_VERSION` is pinned and matches client expectations.
- [ ] `h_seconds`, checkpoint interval, and slack values are explicitly documented for the release.
- [ ] Any change to FS policy has a rollback plan.

## 4. Dependency and Supply-Chain

- [ ] `cargo audit` is clean (or approved exceptions are documented).
- [ ] `Cargo.lock` changes were reviewed for unexpected cryptography/runtime dependency drift.
- [ ] CI workflow still runs `verify_no_secrets.sh` and release matrix tests.
- [ ] CI workflow still runs `verify_client_state_hardening.sh` and validates `kat-client-state-manifest-v0.1.4.json`.

## 5. Runtime Security Smoke

- [ ] API health endpoints are reachable (`/health/live`, `/health/ready`, `/health/detailed`).
- [ ] Membership join/leave runtime smoke succeeds:

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

- [ ] Capacity guard smoke shows a 925 freeze when `h_max` is intentionally exceeded.
- [ ] Restart-chaos run produces `client-restarts.log` plus per-round client-state artifacts.

## 6. Evidence Bundle

Capture and store these artifacts with the release tag:

- [ ] Security review command output (`scripts/security_review.sh` output).
- [ ] Client-state hardening gate output (`scripts/verify_client_state_hardening.sh` output).
- [ ] CI run URL for the release matrix workflow.
- [ ] Forward-secrecy policy values shipped in deployment env/config.
- [ ] Nightly/staging restart-chaos artifact bundle, including client-state snapshots.
- [ ] Optional: `docs/evidence/` updates for timing or benchmark deltas.

## Exit Criteria

A release is security-ready only when all boxes above are checked or exceptions are documented with owner + deadline.
