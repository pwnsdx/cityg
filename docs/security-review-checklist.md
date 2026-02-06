# City-G Security Review Checklist

Use this checklist before cutting a release candidate or deploying a policy change.

## 1. Automated Baseline

Run these commands from the repository root:

```bash
./scripts/security_review.sh
```

If you want to run steps manually:

```bash
cargo test -p cityg-server
cargo test -p cityg-api
cargo test -p cityg-gui --features native-app
cargo test -p msphf-orchestrator
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

## 5. Runtime Security Smoke

- [ ] API health endpoints are reachable (`/health/live`, `/health/ready`, `/health/detailed`).
- [ ] Membership join/leave runtime smoke succeeds:

```bash
./scripts/smoke_membership_capacity.sh
```

- [ ] Capacity guard smoke shows a 925 freeze when `h_max` is intentionally exceeded.

## 6. Evidence Bundle

Capture and store these artifacts with the release tag:

- [ ] Security review command output (`scripts/security_review.sh` output).
- [ ] CI run URL for the release matrix workflow.
- [ ] Forward-secrecy policy values shipped in deployment env/config.
- [ ] Optional: `docs/evidence/` updates for timing or benchmark deltas.

## Exit Criteria

A release is security-ready only when all boxes above are checked or exceptions are documented with owner + deadline.
