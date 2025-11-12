# 14 — Deployment Guide

**Profile**: City-G `tswe/msphf-we/fs-hybrid` (Alpha (0.1.0))
**Status**: Informative (deployment guide for experimental/research use)

## Table of Contents

1. [Introduction](#1-introduction)
2. [Pre-Deployment Checklist](#2-pre-deployment-checklist)
3. [Server Configuration](#3-server-configuration)
4. [Client Configuration](#4-client-configuration)
5. [Monitoring and Observability](#5-monitoring-and-observability)
6. [Security Hardening](#6-security-hardening)
7. [Operational Procedures](#7-operational-procedures)
8. [High-Availability & Blue-Green Deployments](#8-high-availability--blue-green-deployments)

---

## 1. Introduction

This document provides deployment guidance for City-G `tswe/msphf-we/fs-hybrid` servers and clients in experimental and research environments. It covers configuration, monitoring, security hardening, and operational procedures.

**Target Audience**: DevOps engineers, system administrators, security architects

**Assumptions**:
- Familiarity with Rust deployment (cargo, rustc)
- Experimental/research infrastructure (load balancers, monitoring, logging)
- TLS/mTLS setup (out of scope for this guide)

---

## 2. Pre-Deployment Checklist

### 2.1 Code Verification

**✅ Security Audit**:
- [ ] Run automated security checks: `./scripts/verify_no_secrets.sh`
- [ ] Verify all 10 security checks pass
- [ ] Review `docs/protocol/10-security-model.md` for latest audit results

**✅ Test Suite**:
- [ ] Run full test suite: `cargo test --all --release`
- [ ] Verify 416/416 tests pass
- [ ] Run Known-Answer Tests (KATs): `cargo run --bin cityg-hps-kat`
- [ ] Verify KAT outputs match expected values

**✅ Constant-Time Verification**:
- [ ] Run DUDECT harness: `cargo run --release --bin dudect-harness`
- [ ] Verify all t-statistics < 4.5 (no timing leaks)

**✅ Build Configuration**:
```bash
# Production build (optimized, no debug symbols)
cargo build --release --locked

# Verify binary size
ls -lh target/release/cityg-server
# Expected: ~5-10 MB (depends on features)

# Strip debug symbols (optional)
strip target/release/cityg-server
```

---

### 2.2 Dependency Audit

**✅ Cargo Audit**:
```bash
cargo install cargo-audit
cargo audit

# Expected: 0 vulnerabilities
```

**✅ Dependency Review**:
```bash
cargo tree | grep -E "kyber|dilithium|blake3|chacha20"
```

**Key Dependencies** (verify versions):
- `pqcrypto-kyber`: ML-KEM-768 (FIPS 203)
- `pqcrypto-dilithium`: ML-DSA-65 (FIPS 204)
- `blake3`: BLAKE3 hashing
- `chacha20poly1305`: ChaCha20-Poly1305 AEAD

---

### 2.3 Platform Requirements

**Server**:
- **OS**: Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+)
- **CPU**: x86-64 with AVX2 (for NTT optimization)
- **RAM**: 4 GB minimum, 8 GB recommended
- **Disk**: 20 GB minimum (logs, cache, state)
- **Network**: 1 Gbps recommended

**Client**:
- **OS**: Linux, macOS, Windows, iOS, Android
- **CPU**: Any (ARM64, x86-64)
- **RAM**: 512 MB minimum
- **Disk**: 100 MB minimum

---

## 3. Server Configuration

### 3.1 AcceptanceContext Configuration

**File**: `config/server.toml` (example)

```toml
[acceptance]
# Multi-Head Window configuration
h_max = 16                # Max concurrent heads per WID (default: 16)
t_window_secs = 120       # TTL for head expiration (default: 120s)

# SRX configuration
srx_required = true       # Require SRX payload for join mode
srx_max_bytes = 1048576   # Max SRX payload size (1 MB, default)

# Policy configuration
policy_version = "v0.1.0" # Policy version string
allowed_crs_ids = [       # Allowed CRS identifiers
    "rlwe-merkle/v1",
]
allowed_vrf_ids = [       # Allowed VRF identifiers
    "lb-vrf/v1",
]
allowed_proof_modes = [   # Allowed proof modes
    "lin+zkvrf",
]

# KBROAD registry (group ID → public key)
[kbroad_registry]
"example-group-1" = "base64-encoded-ml-kem-768-public-key"
"example-group-2" = "base64-encoded-ml-kem-768-public-key"

# Bootstrap policy (optional)
[bootstrap]
enabled = false
# If enabled, configure bootstrap parameters here
```

---

### 3.2 AcceptanceContext Initialization

```rust
use msphf_orchestrator::{AcceptanceContext, AcceptanceOptions, BootstrapPolicy};
use std::collections::BTreeMap;
use std::time::Duration;

fn create_acceptance_context(config: &ServerConfig) -> AcceptanceContext {
    let options = AcceptanceOptions {
        bootstrap_policy: if config.bootstrap.enabled {
            Some(BootstrapPolicy::default())
        } else {
            None
        },
        srx_max_bytes: Some(config.acceptance.srx_max_bytes),
        srx_required: Some(config.acceptance.srx_required),
        allowed_crs_ids: Some(config.acceptance.allowed_crs_ids.clone()),
        allowed_vrf_ids: Some(config.acceptance.allowed_vrf_ids.clone()),
        allowed_proof_modes: Some(config.acceptance.allowed_proof_modes.clone()),
        kbroad_registry: Some(load_kbroad_registry(&config.kbroad_registry)),
        policy_version: Some(config.acceptance.policy_version.clone()),
        policy_timestamp: Some(OffsetDateTime::now_utc()),
    };

    AcceptanceContext::with_options(
        config.acceptance.h_max,
        Duration::from_secs(config.acceptance.t_window_secs),
        options,
    )
}
```

---

### 3.3 KBROAD Registry Management

**Purpose**: Map group IDs to KBROAD public keys (ML-KEM-768).

**Storage**: Secure key-value store (e.g., HashiCorp Vault, AWS Secrets Manager)

**Example**:
```rust
use std::collections::BTreeMap;

fn load_kbroad_registry(
    config: &BTreeMap<String, String>
) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut registry = BTreeMap::new();
    for (gid_str, pubkey_b64) in config {
        let gid = gid_str.as_bytes().to_vec();
        let pubkey = base64::decode(pubkey_b64).expect("Invalid base64");
        assert_eq!(pubkey.len(), 1184); // ML-KEM-768 public key size
        registry.insert(gid, pubkey);
    }
    registry
}
```

**Key Rotation**:
```bash
# Generate new ML-KEM-768 keypair
cargo run --bin keygen -- --group example-group-1 --output new_key.json

# Update registry in config
vim config/server.toml

# Restart server (graceful reload)
systemctl reload cityg-server
```

---

### 3.4 Rate Limiting and Quotas

**Purpose**: DoS mitigation (out-of-band, not part of protocol).

**Recommendations**:
- **Per-IP rate limit**: 10 anchors/second
- **Per-group rate limit**: 100 anchors/minute
- **Global rate limit**: 1000 anchors/second

**Example** (nginx reverse proxy):
```nginx
limit_req_zone $binary_remote_addr zone=cityg:10m rate=10r/s;

server {
    listen 443 ssl;
    server_name cityg.example.com;

    location /anchor {
        limit_req zone=cityg nodelay;
        proxy_pass http://localhost:8080;
    }
}
```

---

### 3.5 Cache Configuration

**VCK Cache** (Verify-Cache Key):
- **Purpose**: Cache freeze decisions (deterministic)
- **TTL**: T_WINDOW (default: 120s)
- **Size**: 10,000 entries (LRU eviction)

**Example**:
```rust
use lru::LruCache;
use std::time::Instant;

struct VckCache {
    cache: LruCache<[u8; 32], (FreezeError, Instant)>,
    ttl: Duration,
}

impl VckCache {
    fn get(&mut self, vck: &[u8; 32]) -> Option<FreezeError> {
        if let Some((freeze, inserted_at)) = self.cache.get(vck) {
            if inserted_at.elapsed() < self.ttl {
                return Some(*freeze);
            }
        }
        None
    }

    fn insert(&mut self, vck: [u8; 32], freeze: FreezeError) {
        self.cache.put(vck, (freeze, Instant::now()));
    }
}
```

---

## 4. Client Configuration

### 4.1 ClientEpochBundle Configuration

**File**: `config/client.toml` (example)

```toml
[client]
# Server endpoint
server_url = "https://cityg.example.com"

# KBROAD secret key storage
kbroad_secret_path = "/secure/keystore/kbroad_sk.bin" # Device-specific

# Retry configuration
max_retries = 3
retry_backoff_ms = 1000  # Exponential backoff base

# Timeout configuration
request_timeout_ms = 30000  # 30 seconds
```

---

### 4.2 KBROAD Secret Key Management

**Storage Options**:
1. **OS Keychain**: Secure enclave (iOS Keychain, Android Keystore, macOS Keychain)
2. **Hardware Security Module (HSM)**: Dedicated crypto hardware
3. **Encrypted file**: Password-protected, AES-256-GCM

**Example** (encrypted file):
```rust
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

fn store_kbroad_secret(
    kbroad_sk: &[u8],
    password: &str,
    path: &Path,
) -> Result<(), Error> {
    // Derive encryption key from password (Argon2id)
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    let key = &password_hash.hash.unwrap().as_bytes()[..32];

    // Encrypt secret key (ChaCha20-Poly1305)
    let cipher = ChaCha20Poly1305::new_from_slice(key)?;
    let nonce = [0u8; 12]; // NONCE FROM KDF (DO NOT REUSE)
    let ciphertext = cipher.encrypt(&nonce.into(), kbroad_sk)?;

    // Write to file
    fs::write(path, ciphertext)?;
    Ok(())
}

fn load_kbroad_secret(
    password: &str,
    path: &Path,
) -> Result<Vec<u8>, Error> {
    let ciphertext = fs::read(path)?;
    // Derive key, decrypt (inverse of store_kbroad_secret)
    // ...
    Ok(plaintext)
}
```

**Key Rotation**:
- Client generates new ML-KEM-768 keypair
- Submit new public key to publisher (out-of-band)
- Publisher includes new key in next anchor (KBROAD envelope)

---

### 4.3 Witness Caching

**Purpose**: Avoid redundant witness fetches.

**Cache Key**: `(parent_root, leaf_id)` → witness bytes

**Example**:
```rust
use std::collections::HashMap;

struct WitnessCache {
    cache: HashMap<([u8; 32], [u8; 32]), Vec<u8>>,
}

impl WitnessCache {
    fn get(&self, parent_root: &[u8; 32], leaf_id: &[u8; 32]) -> Option<&[u8]> {
        self.cache.get(&(*parent_root, *leaf_id)).map(|v| v.as_slice())
    }

    fn insert(&mut self, parent_root: [u8; 32], leaf_id: [u8; 32], witness: Vec<u8>) {
        self.cache.insert((parent_root, leaf_id), witness);
    }
}
```

---

## 5. Monitoring and Observability

### 5.1 Metrics

**Server Metrics** (Prometheus format):

```
# Acceptance pipeline
cityg_accept_total{status="ok"} 12345
cityg_accept_total{status="freeze", code="923"} 10
cityg_freeze_total{code="923", reason="msphf_lin_invalid"} 10

# Multi-Head Window
cityg_mhw_heads_total{wid="..."} 5
cityg_mhw_capacity_limit_total 2

# Cache
cityg_vck_cache_hits_total 5000
cityg_vck_cache_misses_total 1000

# Latency (histogram)
cityg_accept_duration_seconds{quantile="0.5"} 0.002
cityg_accept_duration_seconds{quantile="0.95"} 0.010
cityg_accept_duration_seconds{quantile="0.99"} 0.050
```

**Client Metrics**:

```
# Epoch derivation
cityg_epoch_derive_total{status="ok"} 100
cityg_epoch_derive_total{status="error"} 2

# Witness fetch
cityg_witness_fetch_total 100
cityg_witness_cache_hits_total 80
```

---

### 5.2 Logging

**Log Levels**:
- **ERROR**: Unexpected failures (internal errors, panic recovery)
- **WARN**: Freeze events, policy violations
- **INFO**: Accept success, MHW operations
- **DEBUG**: Detailed validation steps (development only)
- **TRACE**: Raw CBOR, proof bytes (development only)

**Example** (structured logging with `tracing`):
```rust
use tracing::{info, warn, error};

// Success
tracing::info!(
    we_epoch_id = ?we_epoch_id,
    wid = ?wid,
    "Anchor accepted"
);

// Freeze
tracing::warn!(
    we_epoch_id = ?we_epoch_id,
    freeze_code = freeze.code,
    freeze_reason = freeze.reason,
    "Anchor frozen"
);

// Internal error
tracing::error!(
    error = ?err,
    "Acceptance pipeline error"
);
```

**Log Aggregation**: Use centralized logging (ELK, Splunk, Loki).

---

### 5.3 Alerting

**Critical Alerts**:
- **Freeze spike**: Freeze rate > 10% for 5 minutes
- **Proof verification failure**: Code 923 spike (possible proof generation bug)
- **MHW capacity**: Window full events > 5/minute (capacity planning)
- **Server error rate**: 5xx responses > 1% for 5 minutes

**Example** (Prometheus AlertManager):
```yaml
groups:
- name: cityg
  rules:
  - alert: HighFreezeRate
    expr: rate(cityg_freeze_total[5m]) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High freeze rate detected"

  - alert: MHWCapacityIssue
    expr: rate(cityg_mhw_capacity_limit_total[5m]) > 5
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "MHW capacity limit reached frequently"
```

---

### 5.4 Tracing (Distributed)

**Tool**: OpenTelemetry

**Instrumentation**:
```rust
use tracing_opentelemetry::OpenTelemetryLayer;
use opentelemetry::global;

#[tracing::instrument]
async fn accept_anchor(
    ctx: &mut AcceptanceContext,
    header: &BTreeMap<u64, Value>,
) -> Result<ServerOutcome, ServerError> {
    // Span attributes automatically captured
    // ...
}
```

**Trace Sampling**: 1% in deployment (reduce overhead).

### 5.5 Annex M Telemetry Workbook

City-G exposes Annex M counters over both Prometheus metrics and the
`/v1/telemetry` API. Each entry is keyed by `(gid, parent_root)` and mirrors the
server-side `TelemetryCounters` structure. Use these counters to distinguish
between proof failures and capacity issues before paging cryptography teams.

| Field | Description | Typical Alert Threshold |
|-------|-------------|-------------------------|
| `head_attempts` | Total joins processed for the key | Sudden spikes without matching insertions |
| `head_insertions` | Successful head insertions | Drops to 0 while attempts climb |
| `freeze_window_full` | MHW capacity freezes (code 925) | >5/minute = add capacity or throttle publisher |
| `freeze_rho_replay` | ρ-replay freezes (code 924) | Any sustained non-zero rate |
| `last_active_heads` | Active heads currently in the window | Approaching `h_max` indicates tuning needed |

**Runbook — diagnosing window exhaustion**

1. Hit `/v1/telemetry` after a failure. If the failing `(gid,parent_root)` shows
   `freeze_window_full >= 1`, the acceptance pipeline is healthy and only the
   concurrency cap fired.
2. Check `/v1/window` to see how many heads were active when the freeze
   occurred. If the `age_ms` values cluster near the TTL, the workload simply
   needs a larger `h_max` or longer window.
3. After tuning, re-run the synthetic window test (`cargo test -p cityg-api
   window_full_rest_api_freeze`) against staging. The counter must increment in
   staging before you trust production alerts.

**Freeze code roll-up**

`/v1/telemetry` also returns `freeze_stats` (aggregated `code/reason → count`).
Export these counters to your observability system so you can fire alerts such
as “rho replay detected” without scraping every `(gid,parent_root)` row.

---

## 6. Security Hardening

### 6.1 Server Hardening

**✅ No Secrets in Server**:
- [ ] Verify: `./scripts/verify_no_secrets.sh` passes
- [ ] Review: `AcceptanceContext` has no secret fields
- [ ] Audit: No `ml_kem_decapsulate()` or AEAD decrypt in server code

**✅ Memory Safety**:
- [ ] Zero `unsafe` blocks in server code
- [ ] Run Miri (Rust interpreter) for undefined behavior detection:
  ```bash
  cargo +nightly miri test
  ```

**✅ Network Security**:
- [ ] TLS 1.3 mandatory (no TLS 1.2, no plaintext HTTP)
- [ ] mTLS for publisher authentication (recommended)
- [ ] Certificate pinning (clients)

**✅ Process Isolation**:
- [ ] Run server as non-root user
- [ ] Use systemd sandboxing:
  ```ini
  [Service]
  DynamicUser=yes
  ProtectSystem=strict
  ProtectHome=yes
  PrivateTmp=yes
  NoNewPrivileges=yes
  ```

---

### 6.2 Client Hardening

**✅ Secret Key Storage**:
- [ ] Use OS keychain (Keychain, Keystore, Windows Credential Manager)
- [ ] Never log secret keys
- [ ] Zeroize memory after use:
  ```rust
  use zeroize::Zeroize;
  let mut kbroad_sk = load_kbroad_secret(...);
  // Use kbroad_sk
  kbroad_sk.zeroize();
  ```

**✅ Witness Validation**:
- [ ] Always validate CAPSS Smallwood and ZK-VRF proofs (never skip)
- [ ] Verify SRX completeness (frontier + anchor pool)
- [ ] Check epoch context binding (xk_hash)

**✅ Replay Protection**:
- [ ] Track processed `we_epoch_id` values (avoid duplicate processing)
- [ ] Reject anchors older than TTL threshold (e.g., 1 hour)

---

### 6.3 Operational Security

**✅ Incident Response**:
- [ ] Define freeze code escalation matrix (which codes trigger alerts)
- [ ] Maintain audit logs (tamper-evident, write-only)
- [ ] Practice incident response drills (quarterly)

**✅ Key Rotation**:
- [ ] KBROAD keys: Rotate every 90 days (recommended)
- [ ] TLS certificates: Rotate every 365 days (Let's Encrypt)
- [ ] Publisher ML-DSA keys: Rotate on compromise only

**✅ Patch Management**:
- [ ] Subscribe to Rust security advisories (https://rustsec.org/)
- [ ] Monitor dependency vulnerabilities (`cargo audit` weekly)
- [ ] Apply patches within 48 hours (critical), 7 days (high)

---

## 7. Operational Procedures

### 7.1 Server Deployment

**1. Pre-deployment**:
```bash
# Build release binary
cargo build --release --locked

# Run tests
cargo test --all --release

# Run security checks
./scripts/verify_no_secrets.sh

# Verify binary
sha256sum target/release/cityg-server
```

**2. Deployment** (blue-green):
```bash
# Deploy to staging (green)
scp target/release/cityg-server staging:/opt/cityg/bin/

# Smoke test
curl https://staging.cityg.example.com/health

# Switch traffic (blue → green)
# (Load balancer configuration)

# Monitor for 1 hour
# (Check metrics, logs, alerts)

# If stable: promote green to active
# If issues: rollback to blue
```

**3. Post-deployment**:
```bash
# Verify version
curl https://cityg.example.com/version
# Expected: {"version": "0.1.0"}

# Check metrics
curl https://cityg.example.com/metrics | grep cityg_accept_total
```

---

### 7.2 Configuration Changes

**Policy Version Update**:
```bash
# Update config
vim config/server.toml
# Change: policy_version = "v0.2.0"

# Graceful reload (no downtime)
systemctl reload cityg-server

# Verify
curl https://cityg.example.com/policy
# Expected: {"version": "v0.2.0"}
```

**KBROAD Registry Update**:
```bash
# Generate new keypair
cargo run --bin keygen -- --group new-group --output new_key.json

# Add to config
vim config/server.toml
# Add: [kbroad_registry]
#      "new-group" = "base64-encoded-pubkey"

# Reload
systemctl reload cityg-server

# Verify
# (Submit test anchor with new group)
```

---

### 7.3 Monitoring and Alerts

**Daily Checks**:
- [ ] Check freeze rate (target: < 1%)
- [ ] Check MHW capacity (target: < 80% of H_MAX)
- [ ] Check VCK cache hit ratio (target: > 90%)
- [ ] Review error logs (no unexpected errors)

**Weekly Checks**:
- [ ] Run `cargo audit` (no vulnerabilities)
- [ ] Review security alerts (Prometheus)
- [ ] Check disk usage (logs, cache)

**Monthly Checks**:
- [ ] Rotate KBROAD keys (recommended)
- [ ] Review access logs (audit)
- [ ] Performance benchmarks (regression testing)

---

### 7.4 Incident Response

**Freeze Spike**:
1. **Identify cause**: Check freeze codes (923 = proof invalid, 930 = SRX invalid)
2. **Correlate with deployments**: Recent client/publisher updates?
3. **Notify stakeholders**: Publisher (if proof generation bug), clients (if outdated)
4. **Mitigation**: Rollback if server-side regression

**MHW Capacity Exhaustion**:
1. **Identify hot WIDs**: Query `cityg_mhw_heads_total` by WID
2. **Root cause**: Publisher sending too many joins? DoS attack?
3. **Mitigation**: Increase H_MAX (short-term), rate-limit publisher (long-term)

**Security Incident**:
1. **Isolate**: Take server offline (graceful shutdown)
2. **Preserve evidence**: Copy logs, memory dumps (if needed)
3. **Analyze**: Check for secrets in logs (should be none)
4. **Recover**: Restore from backup, rotate keys (if compromised)
5. **Post-mortem**: Document incident, update procedures

---

### 7.5 Forward-Secrecy Snapshot Restore (GUI & CLI)

City-G clients persist the forward-secrecy snapshot (the tuple
`{k_fs, fs_ec, fs_dev_commit, last_weid}`) inside their session JSON. The GUI
stores sessions under:

```
macOS   ~/Library/Application Support/cityg/gui/session-<hash>.json
Linux   ~/.config/cityg/gui/session-<hash>.json
Windows %APPDATA%\cityg\gui\session-<hash>.json
```

(`CITYG_GUI_CONFIG_DIR` overrides the base directory.) Each file contains a
`forward_state` block that mirrors `ForwardSecrecyState::snapshot()`, so
exporting a snapshot is equivalent to copying this JSON to a secure vault.

**Backup procedure**
1. Ask the user to quit the GUI so the session flushes (CLI deployments can
   call `ForwardSecrecyState::snapshot()` via their automation before shutdown).
2. Copy `session-<hash>.json` and `last-session.json` to encrypted storage.
   Verify the copy contains `forward_state.k_fs_hex`.
3. Record the accompanying `fs_policy_version` and `fs_epoch_base_ts`; they must
   match on restore.

**Restore procedure**
1. Deploy the same client version and policy bundle on the destination host.
2. Drop the backed-up session JSON into the config directory (or run the CLI
   import command). File permissions should be user-only (`chmod 600` on Linux).
3. Launch the client; it will call `ForwardSecrecyState::with_state` with the
   restored snapshot and immediately resume autonomic evolution without replay.
4. Verify in the GUI (“Forward Secrecy Epoch” panel) that the epoch counter,
   device commit, and base timestamp match the backed-up values.

Treat the session files as sensitive (they contain `k_fs`), but note that they
exclude KBROAD ciphertexts, so backing them up does not leak message payloads.

---

### 7.6 Journal Backup & Recovery

When `ServerConfig.state_path` is configured, `cityg-server` appends every
accepted bundle to a crash-safe CBOR journal (fsync after each write) and
replays it before accepting new traffic. Integrate the journal into your backup
plan:

**Rolling backup**
1. `systemctl stop cityg-api` (or pause the container) to quiesce writes.
2. Copy `/var/lib/cityg/journal.cbor` to a timestamped file and upload it to the
   backup store together with the configuration and policy files.
3. Optionally truncate the active journal (`:> journal.cbor`) so the server
   resumes with a fresh file. Restart the service and watch the logs for
   `state recovery complete (N entries)`.

**Disaster recovery**
1. Provision a clean node with the same `cityg-config` values.
2. Restore the latest journal backup to the path referenced by
   `ServerConfig.state_path`.
3. Start `cityg-api`; it will replay the journal before binding to its sockets.
4. Validate by invoking `/v1/window` and verifying the known heads are present.

Because the journal is append-only, standard tooling (restic, borg, S3
lifecycles) works well. Rotate or compact the file regularly to avoid
unbounded growth; nightly copies plus weekly retention match the protocol's
time-blind window nicely.

### 7.7 Crash-Recovery State Machine

`cityg-api` exposes three operational states:

1. **STARTUP** – process initialises, journal path determined. The HTTP layer has not yet bound sockets.
2. **REHYDRATING** – the server is replaying the journal and rebuilding acceptance context. During this phase all public endpoints MUST return `503 Service Unavailable` (gRPC: `UNAVAILABLE`) with `Retry-After` to signal clients to back off.
3. **LIVE** – replay finished, sockets bound, new anchors accepted.

Transitions:

```
STARTUP --(journal opened)--> REHYDRATING --(replay succeeds)--> LIVE
REHYDRATING --(replay failure)--> STARTUP (crash/exit)
```

Operators SHOULD monitor the `state_rehydrating` metric; publishers SHOULD treat `503/UNAVAILABLE` during rehydration as transient and retry after the indicated delay. No client traffic is processed until the instance reaches `LIVE`, ensuring deterministic acceptance after crashes.

**Crash recovery behavior:**

When `cityg-server` starts with an existing journal at `state_path` it:

1. **Replays the journal** sequentially.
2. **Rebuilds state** (multi-head window, pivot cache, roster).
3. **Restores the logical clock** (`AcceptClock`) to match the journal length (one tick per entry).
4. **Produces identical state** because acceptance is time-blind and deterministic.
5. **Binds sockets** only after replay completes (transition to LIVE).

**Troubleshooting crash recovery:**

| Issue | Diagnosis | Resolution |
|-------|-----------|------------|
| **Server fails to start** | Check logs for "failed to replay journal" | Verify journal file integrity with `file journal.cbor` (should show "CBOR data") |
| **Replay takes too long** | Journal file too large (>100k entries) | Truncate after successful replay: `:> journal.cbor` |
| **State mismatch after restart** | Non-deterministic replay (should not happen) | File a bug report with journal file and logs |
| **"Corrupted journal entry"** | Power loss during fsync | Restore from latest backup; the entry was never fully committed |
| **Wrong number of heads** | Policy mismatch during replay | Ensure `fs_policy_version` matches the journal's policy |

**Validation after recovery:**
```bash
# Check that replay completed
journalctl -u cityg-api | grep "state recovery complete"

# Verify window state
curl http://localhost:8080/v1/window | jq '.heads | length'

# Confirm logical clock (should match journal entry count)
curl http://localhost:8080/v1/telemetry | jq '.accept_instant_ticks'
```

**Best practices:**
- Store journal on durable storage (ext4/XFS with barriers enabled)
- Monitor journal file size and rotate weekly
- Test crash recovery regularly in staging environment
- Keep journal backups for at least 7 days (covers full FS checkpoint cycle)

---

## 8. High-Availability & Blue-Green Deployments

City-G runs well in a “n+1” topology where at least two `cityg-api` instances
share a load balancer. Keep each instance stateless beyond its journal: the
acceptance context, receiver cache, and roster rebuild themselves from the log,
so no external distributed database is required.

### 8.1 Reference Topology

- **Edge**: Global HTTPS load balancer (L7) with health checks on
  `/health/detailed`.
- **Blue / Green pools**: Two identical `cityg-api` Deployments (Kubernetes) or
  systemd units on separate nodes; each has its own `state_path` (e.g.,
  `/var/lib/cityg/blue/journal.cbor`).
- **Publisher ingress**: Publishers target the VIP; clients only see the shared
  hostname (`https://cityg.example.com`).
- **Observability**: Prometheus scrapes each instance directly so you can
  diff freeze rate across pools.

### 8.2 Blue-Green Procedure

1. **Bake config**: Start from `config/ha-bluegreen.toml` and add site-specific
   KBROAD keys via environment variables (`CITYG_ACCEPTANCE_KBROAD_REGISTRY_*`
   if you wrap server creation).
2. **Deploy Green**: Push the new `cityg-api` image using the HA config and
   point it at an empty journal (`/var/lib/cityg/green/journal.cbor`).
3. **Warm up**: Send synthetic joins to ensure CAPSS checkpoints and caches
   hydrate; watch `cityg_accept_total`.
4. **Flip traffic**: Update the load balancer to send 100% of requests to the
   green pool. Leave blue idling for at least one epoch window so you can roll
   back instantly.
5. **Validate**: Run `/v1/window`, `/v1/telemetry`, and merge-ticket smoke
   tests. Confirm acceptance/freeze metrics look normal after the cutover.
6. **Promote**: Once stable, truncate blue’s journal, upgrade it to the next
   version, and keep it ready for the next rollout.

### 8.3 Active/Active Considerations

- **Per-node journals**: Never share the same `state_path` between instances;
  each node must replay only the anchors it accepted.
- **Policy pinning**: Set `fs_policy_version` identically across pools. Mixed
  versions will cause deterministic freeze codes (`944.6`).
- **Clock discipline**: While acceptance is time-blind, keep NTP in sync so
  logs and Prometheus timestamps align when comparing blue vs. green.
- **Connection fairness**: Configure the load balancer for least-connections so
  large publishers don’t starve the other pool.

### 8.4 Sample Configuration

The `config/ha-bluegreen.toml` file in this repository contains a baseline
production profile with higher H_MAX and FS policy tuning for multi-instance
deployments. Copy it to `cityg.toml`, override sensitive values via environment
variables, and check it into your infrastructure repo so blue and green pools
remain byte-identical.

---

## Summary

Experimental deployment of City-G `tswe/msphf-we/fs-hybrid` requires:

1. **Pre-deployment**: Security audit, test suite, dependency audit
2. **Server configuration**: AcceptanceContext, KBROAD registry, rate limits, cache
3. **Client configuration**: Secret key management, witness caching, retry logic
4. **Monitoring**: Metrics (Prometheus), logging (structured), alerting (freeze spikes)
5. **Security hardening**: No secrets in server, TLS 1.3, process isolation, key rotation
6. **Operations**: Blue-green deployment, graceful reload, incident response

**Key Principle**: The server is **blind by construction** — compromise of the server does not leak secrets (hp, Y\*, E_k, eid).

**Next**: [15 — Label Registry](./15-label-registry.md)

---

**Document Version**: 0.1.0
**Blueprint Reference**: Alpha (0.1.0) §16 (Implementation Guidance)
**Implementation**: City-G 0.1.0
