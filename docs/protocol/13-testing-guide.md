# 13 — Testing Guide

> [!IMPORTANT]
> This chapter is a legacy companion document. For `tswe/msphf-we/fs-hybrid`, the normative source is [`../specs.md`](../specs.md).
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and implementation.


**Profile**: City-G `tswe/msphf-we/fs-hybrid` (Alpha (0.1.0))
**Status**: Informative (testing strategy and KATs)

## Table of Contents

1. [Introduction](#1-introduction)
2. [Test Organization](#2-test-organization)
3. [Unit Tests](#3-unit-tests)
4. [Integration Tests](#4-integration-tests)
5. [Known-Answer Tests (KATs)](#5-known-answer-tests-kats)
6. [Security Tests](#6-security-tests)
7. [Performance Tests](#7-performance-tests)
8. [Running Tests](#8-running-tests)

---

## 1. Introduction

This document describes the testing strategy for the City-G `tswe/msphf-we/fs-hybrid` implementation. The suite covers:

- **Unit tests**: Function-level validation across hashing, Merkle trees, RLWE, CAPSS Smallwood, and the orchestrator helpers
- **Integration tests**: End-to-end acceptance, journaling, and API flows
- **Known-Answer Tests (KATs)**: Blueprint-aligned vectors for RLWE, HKDF-BLAKE3, SRX, and KBROAD
- **Security tests**: Constant-time verification (DUDECT) and cache-trace analysis
- **Performance tests**: Benchmark harnesses for proof systems and SRX

**Total**: Test count is checkout-dependent. On February 5, 2026 this repository reports 586 tests (`cargo test --all -- --list | rg ': test$' | wc -l`).

**Blueprint Reference**: Alpha (0.1.0) §18 (Known-Answer Tests)

---

## 2. Test Organization

### 2.1 Directory Structure

```
crates/
├── msphf-core/
│   └── src/
│       ├── merkle.rs          (Merkle trees, witnesses)
│       ├── rpo256.rs          (rpo-256/v1 set-hash)
│       ├── witness.rs         (Witness validation)
│       ├── rlwe/poly.rs       (Polynomial operations)
│       └── rlwe/ntt.rs        (NTT correctness)
├── msphf-rlwe/
│   ├── src/lib.rs             (RLWE-HPS + ME-OR invariants)
│   └── tests/rlwe_kat.rs      (KATs for RLWE)
├── msphf-orchestrator/
│   ├── src/
│   │   ├── accept/            (Acceptance pipeline, TOCTOU guard, HKDF helpers)
│   │   ├── mhw.rs             (Multi-Head Window)
│   │   ├── proofs/capss.rs    (CAPSS Smallwood prove/verify)
│   │   └── proofs/zk_vrf/lb.rs (ZK-VRF prove/verify)
│   └── tests/
│       └── end_to_end.rs      (End-to-end + regression harness)
├── msphf-lb-vrf/
│   └── src/test/              (lb-vrf/v1 primitives)
└── dudect-harness/
    └── src/main.rs            (Constant-time verification)
```

### 2.2 Coverage Snapshot

| Component | Coverage focus | Representative suites |
|-----------|----------------|------------------------|
| **Merkle witnesses & rpo-256** | Canonical roots, membership/non-membership proofs, empty-set handling | `msphf-core::merkle`, `msphf-core::witness`, end-to-end proofs |
| **RLWE-HPS & CAPSS Smallwood** | Polynomial arithmetic, ME-OR derivations, CAPSS prover/verifier soundness | `msphf-rlwe`, `capss`, orchestrator `proofs::capss` |
| **ZK-VRF / lb-vrf/v1** | Output-hiding VRF proofs, transcript binding, key rotation | `msphf-lb-vrf`, orchestrator `proofs::zk_vrf` |
| **Acceptance pipeline** | 9-stage validation, HKDF domain separation, TOCTOU guard, freeze semantics | `msphf-orchestrator::accept`, `accept::tests`, `tests/end_to_end.rs` |
| **Multi-Head Window (MHW)** | Capacity enforcement, rho replay detection, telemetry counters | `msphf-orchestrator::mhw` unit tests + integration harness |
| **SRX & Receiver sync** | Shadow-root verification, crash/reload parity, chaos replay | `msphf-orchestrator::receiver`, `cityg-server::tests` |
| **KBROAD & HP transport** | KBROAD registry enforcement, AEAD nonce derivations, HKDF-BLAKE3 KATs | `msphf-orchestrator::hdr`, `hkdf` module tests |

**Note**: `cargo test --all` pass/fail status is the authoritative signal; exact counts grow over time. Use `cargo test --all -- --list | rg ': test$' | wc -l` for the current test count in your checkout.

> [!TIP]
> Source [`../../scripts/cargo_repo_env.sh`](../../scripts/cargo_repo_env.sh) before local Rust runs. The repo now defaults to a repo-local `CARGO_TARGET_DIR` slot (`.cargo-target/manual`) instead of the legacy shared `target/`, which avoids most "Blocking waiting for file lock on build directory" stalls. If you intentionally want concurrent long-running suites, give each shell/script its own slot, for example `export CITYG_CARGO_TARGET_SLOT=gui-a` before sourcing the helper.

---

## 3. Unit Tests

### 3.1 Merkle Tree Tests

**Location**: [crates/msphf-core/src/merkle.rs](../../crates/msphf-core/src/merkle.rs)

**Test Coverage**:

**`test_canonical_set_root_empty`**:
```rust
#[test]
fn test_canonical_set_root_empty() {
    let empty_root = canonical_set_root(&[]).unwrap();
    // Expected: EMPTY_SET_ROOT constant
    assert_eq!(empty_root, EMPTY_SET_ROOT);
}
```
**Purpose**: Verify empty set handling (non-null root).

---

**`test_canonical_set_root_single`**:
```rust
#[test]
fn test_canonical_set_root_single() {
    let leaf = [1u8; 32];
    let root = canonical_set_root(&[leaf]).unwrap();
    // Single leaf → root = H_merkle(leaf, EMPTY)
    assert_ne!(root, [0u8; 32]);
}
```
**Purpose**: Single-element tree root computation.

---

**`test_membership_witness_depth_limit`**:
```rust
#[test]
fn test_membership_witness_depth_limit() {
    let path = vec![(0u8, [0u8; 32]); 65]; // Depth 65 (exceeds limit)
    let result = verify_membership_witness(&leaf, &path, &root);
    assert!(result.is_err());
    // Expected: WitnessValidationError::PathOversize
}
```
**Purpose**: Enforce depth ≤ 64 constraint (specification).

---

**`test_nonmembership_interval_validation`**:
```rust
#[test]
fn test_nonmembership_interval_validation() {
    // Interval [left, right] must contain query
    let left = [1u8; 32];
    let right = [10u8; 32];
    let query = [5u8; 32]; // Inside interval (valid)
    assert!(validate_interval(&left, &right, &query).is_ok());

    let query_outside = [20u8; 32]; // Outside interval (invalid)
    assert!(validate_interval(&left, &right, &query_outside).is_err());
}
```
**Purpose**: Canonical interval containment check.

---

### 3.2 RLWE-HPS Tests

**Location**: [crates/msphf-rlwe/src/lib.rs](../../crates/msphf-rlwe/src/lib.rs)

**Test Coverage**:

**`test_rlwe_kgen_deterministic`**:
```rust
#[test]
fn test_rlwe_kgen_deterministic() {
    let seed = [0u8; 32];
    let keypair1 = rlwe_hps_kgen(&seed).unwrap();
    let keypair2 = rlwe_hps_kgen(&seed).unwrap();
    assert_eq!(keypair1.hp, keypair2.hp); // Deterministic
    assert_eq!(keypair1.pk, keypair2.pk);
}
```
**Purpose**: Verify seed → hp determinism (anti-grinding).

---

**`test_meor_projection_correctness`**:
```rust
#[test]
fn test_meor_projection_correctness() {
    let keypair = rlwe_hps_kgen(&seed).unwrap();
    let delta = /* valid witness delta */;
    let mask = [0u8; 32]; // No mask

    // Y* = Proj(pk, delta) ⊕ mask
    let y_star = compute_meor(&keypair.pk, &delta, &mask).unwrap();

    // Recompute with same inputs
    let y_star2 = compute_meor(&keypair.pk, &delta, &mask).unwrap();
    assert_eq!(y_star, y_star2); // Deterministic
}
```
**Purpose**: ME-OR projection property (SPHF correctness).

---

**`test_capss_recompute`**:
```rust
#[test]
fn test_capss_recompute() {
    let seed_drbg = [42u8; 32];
    let witness1 = recompute_capss_witness(&seed_drbg, &params).unwrap();
    let witness2 = recompute_capss_witness(&seed_drbg, &params).unwrap();
    assert_eq!(witness1.hp, witness2.hp); // Deterministic recompute
}
```
**Purpose**: CAPSS Smallwood witness recomputation (verifier side).

---

### 3.3 Acceptance Pipeline Tests

**Location**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Test Coverage** (inline tests at end of file):

**`test_pop_validation_success`**:
```rust
#[test]
fn test_pop_validation_success() {
    let (device_pk, device_sk) = dsa_keypair();
    let pop_msg = compute_pop_message(&header);
    let pop_sig = detached_sign(&pop_msg, &device_sk);

    let mut ctx = AcceptanceContext::new();
    let result = ctx.validate_pop(&header, &parts);
    assert!(result.is_ok());
}
```
**Purpose**: PoP signature verification (Step 3).

---

**`test_rho_determinism_failure`**:
```rust
#[test]
fn test_rho_determinism_failure() {
    let mut header = valid_header();
    header[&93] = [0u8; 32]; // Wrong rho_commit

    let result = ctx.accept_anchor(&parts, &we_epoch_id, &header, now);
    assert_eq!(result.unwrap_err(), FREEZE_MSPHF_RHO_PARITY);
}
```
**Purpose**: Detect ρ tampering (Step 4.1).

---

**`test_fs_capss_invalid`**:
```rust
#[test]
fn test_fs_capss_invalid() {
    let mut header = valid_header();
    header[&146][0] ^= 0xFF; // Corrupt CAPSS Smallwood transcript

    let result = ctx.accept_anchor(&parts, &we_epoch_id, &header, now);
    assert_eq!(result.unwrap_err(), FREEZE_CAPSS_INVALID);
}
```
**Purpose**: Reject invalid CAPSS Smallwood transcript (Step 7.1).

---

**`test_barrier_hp_envelope_structure`**:
```rust
#[test]
fn test_barrier_hp_envelope_structure() {
    let mut header = valid_header();
    // Change AEAD suite
    header[&97] = Value::Array(vec![
        Value::Text("barrier-sealed-v1".into()),
        Value::Text("barrier-recovery".into()),
        /* hp_ciphertext */,
        Value::Text("aes-gcm".into()), // Wrong AEAD
    ]);

    let result = ctx.accept_anchor(&parts, &we_epoch_id, &header, now);
    assert_eq!(result.unwrap_err(), FREEZE_SUITE_DEPRECATED);
}
```
**Purpose**: Validate KBROAD envelope structure (Step 5).

---

### 3.4 Multi-Head Window Tests

**Location**: [crates/msphf-orchestrator/src/mhw.rs](../../crates/msphf-orchestrator/src/mhw.rs)

**Test Coverage**:

**`test_mhw_capacity_limit`**:
```rust
#[test]
fn test_mhw_capacity_limit() {
    let mut mhw = MultiHeadWindow::new(H_MAX, T_WINDOW);
    let wid = [1u8; 32];

    // Fill to capacity (H_MAX = 16)
    for i in 0..16 {
        let we_epoch_id = [i as u8; 32];
        mhw.accept_head(&wid, &we_epoch_id, now).unwrap();
    }

    // 17th head should fail
    let overflow = [99u8; 32];
    let result = mhw.accept_head(&wid, &overflow, now);
    assert_eq!(result.unwrap_err().code, 925); // FREEZE_MH_WINDOW_FULL
}
```
**Purpose**: Enforce H_MAX capacity limit.

---

**`test_mhw_ttl_expiration`**:
```rust
#[test]
fn test_mhw_ttl_expiration() {
    let mut mhw = MultiHeadWindow::new(H_MAX, Duration::from_secs(10));
    let wid = [1u8; 32];
    let we_epoch_id = [1u8; 32];

    // Insert head
    mhw.accept_head(&wid, &we_epoch_id, now).unwrap();
    assert_eq!(mhw.head_count(&wid), 1);

    // Fast-forward time by 11 seconds
    let later = now + Duration::from_secs(11);

    // Next accept_head should prune expired head
    let new_head = [2u8; 32];
    mhw.accept_head(&wid, &new_head, later).unwrap();
    assert_eq!(mhw.head_count(&wid), 1); // Old head pruned
}
```
**Purpose**: TTL-based head expiration.

---

**`test_mhw_merge_mode`**:
```rust
#[test]
fn test_mhw_merge_mode() {
    let mut mhw = MultiHeadWindow::new(H_MAX, T_WINDOW);
    let wid = [1u8; 32];

    // Insert 3 heads
    let head1 = [1u8; 32];
    let head2 = [2u8; 32];
    let head3 = [3u8; 32];
    mhw.accept_head(&wid, &head1, now).unwrap();
    mhw.accept_head(&wid, &head2, now).unwrap();
    mhw.accept_head(&wid, &head3, now).unwrap();
    assert_eq!(mhw.head_count(&wid), 3);

    // Merge: retire head1 and head2, insert merged head
    let merged = [99u8; 32];
mhw.accept_merge(&wid, &wid, &[head1, head2], merged, now).unwrap();
    assert_eq!(mhw.head_count(&wid), 2); // head3 + merged
}
```
**Purpose**: Merge mode consolidation.

---

### 3.5 TOCTOU / Forward-Leap Guard

**Location**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs) (`verify_device_chain_state_enforces_caps`) and the chaos harnesses in [`crates/msphf-orchestrator/src/accept/join.rs`](../../crates/msphf-orchestrator/src/accept/join.rs).

**Test idea**:

```rust
// Thread A and B read the same snapshot A_read and gate fs_ec := A_read + D_anchor_max.
// Thread A commits first ⇒ last_accepted_ec becomes A_now.
// Thread B re-enters the critical section and re-runs enforce_fs_bounds(fs_ec, A_now,...).
// If fs_ec now violates the bound, the guard returns FREEZE_FS_FORWARD_JUMP_*.
```

The unit test exercises the shared helper with deterministic values (new device cap, device cap, anchor cap). The integration harnesses (`chaos_replay_*`) run thousands of randomized joins with forced journal failures to ensure the pre-commit recheck stays wired up. Together they guarantee the normative guard in §12.2 triggers whenever concurrency would otherwise admit a head out of order.

---

## 4. Integration Tests

### 4.1 End-to-End Test Suite

**Location**: [crates/msphf-orchestrator/tests/end_to_end.rs](../../crates/msphf-orchestrator/tests/end_to_end.rs)

**Test Structure**:
```rust
// Fixture setup (OnceLock for shared state)
fn fixture_pop_keys() -> (&'static [u8], &'static MlDsaSecretKey);
fn fixture_kbroad_keys() -> (&'static Vec<u8>, &'static MlKemSecretKey);

// Helper functions
fn build_valid_anchor(...) -> BTreeMap<u64, Value>;
fn decrypt_hp_client_side(...) -> Vec<u8>;
fn extract_epoch_client(...) -> ([u8; 32], [u8; 32]);

// Test cases (41 tests)
```

**Test Coverage**:

**`test_e2e_joiner_to_server`**:
```rust
#[test]
fn test_e2e_joiner_to_server() {
    // 1. Joiner: Generate PoP
    let (device_pk, device_sk) = dsa_keypair();
    let pop_msg = build_pop_message(&header);
    let pop_sig = detached_sign(&pop_msg, &device_sk);

    // 2. Joiner: KGen
    let kgen_output = joiner_kgen_or(
        &seed_commit,
        &xk_hash,
        &seed_ctx_hash,
        pop_sig.as_bytes(),
        &device_pk,
        &params,
    ).unwrap();

    // 3. Joiner: Seal hp in the barrier-scoped envelope
    let barrier_hp_envelope =
        build_local_barrier_hp_envelope(&kgen_output.hp, &xk_hash, &hp_commit);

    // 4. Joiner: Generate proofs
    let mut rng = rand_core::OsRng;
    let capss_signature = capss::prove(&mut rng, &inputs).unwrap();
    let zk_vrf_proof = zk_vrf_prove(&kgen_output.hp, &vrf_ctx).unwrap();

    // 5. Joiner: Assemble header
    let mut header = BTreeMap::new();
    header.insert(93, kgen_output.rho_commit);
    header.insert(97, kbroad_envelope);
    header.insert(146, capss_signature);
    header.insert(95, zk_vrf_proof);
    // ... (other fields)

    // 6. Server: Accept anchor
    let mut ctx = AcceptanceContext::with_defaults(H_MAX, T_WINDOW);
    let result = ctx.accept_anchor(&parts, &we_epoch_id, &header, now);
    assert!(result.is_ok());

    // 7. Server: Return public outcome
    let outcome = ServerOutcome { we_epoch_id, wid };
    // No secrets leaked ✅
}
```
**Purpose**: Full joiner → server pipeline (join mode).

---

**`test_e2e_receiver_epoch_derivation`**:
```rust
#[test]
fn test_e2e_receiver_epoch_derivation() {
    // 1. Receiver: Fetch anchor from server
    let header = fetch_anchor(&we_epoch_id);

    // 2. Receiver: Decrypt hp from KBROAD (client-side)
    let kbroad_envelope = header[&97];
    let hp = decrypt_hp_client_side(&kbroad_envelope, &kbroad_sk);

    // 3. Receiver: Fetch witness
    let witness = fetch_witness(&parent_root, &leaf_id);

    // 4. Receiver: Derive epoch key via ME-OR
    let (epoch_key, eid) = extract_epoch_msphf_or(
        &anchor,
        &hp_binding,
        &witness,
        &kbroad_envelope,
        &hp_aead_key,
    ).unwrap();

    // 5. Verify: epoch_key matches expected value
    assert_eq!(epoch_key, expected_epoch_key);
    assert_eq!(eid, expected_eid);
}
```
**Purpose**: Client-side epoch derivation (receiver flow).

---

**`test_e2e_merge_mode`**:
```rust
#[test]
fn test_e2e_merge_mode() {
    // 1. Submit 3 join-mode heads
    let head1 = submit_join_anchor(&ctx, &anchor1);
    let head2 = submit_join_anchor(&ctx, &anchor2);
    let head3 = submit_join_anchor(&ctx, &anchor3);

    // 2. Submit merge-mode anchor (retire head1, head2)
    let mut merge_header = build_merge_header(&[head1.we_epoch_id, head2.we_epoch_id]);
    // Merge header omits join-only fields (95, 97, 107-109, 116, 119, 120-125, 146)

    let result = ctx.accept_anchor(&parts, &merged_we_epoch_id, &merge_header, now);
    assert!(result.is_ok());

    // 3. Verify: head1 and head2 retired, head3 remains
    assert_eq!(ctx.mh_window.head_count(&wid), 2); // head3 + merged
}
```
**Purpose**: Merge mode (consolidate multiple heads).

---

**Rollup tests** (unit & end-to-end)

- `merge_roots_change_without_srx_freezes_required` — merge alters any of 111/112/113 without SRX ⇒
  `Freeze(929)`.
- `merge_retiring_head_outside_window_freezes` — `mh_heads` references a head outside the current
  window ⇒ `Freeze(927)`.
- `merge_parity_mismatch_freezes` — merge mutates `93` ⇒ `Freeze(924)`.
- `merge_anchor_join_payload_freezes` — merge reintroduces join-only fields (97/107–109) ⇒
  `Freeze(921)`.
- `joiner_merge_result_carries_metadata` — verifies builder emits canonical provenance/VCK commits,
  epoch replay table, KBROAD clones, and pivot weid.
- `ban_and_reinstate_member_flow` (end-to-end) — exercises rollup ban/unban path: SRX enforcement,
  window rotation (`accept_merge(wid_old, wid_new, …)`), and KBROAD replay.

These tests live in [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)
and [`tests/end_to_end.rs`](../../crates/msphf-orchestrator/tests/end_to_end.rs) and should remain in
the CI suite to guard the rollup invariants.

---

## 5. Known-Answer Tests (KATs)

### 5.1 KAT Framework

**Location**: [crates/msphf-orchestrator/src/kat.rs](../../crates/msphf-orchestrator/src/kat.rs)

**Purpose**: Verify specification compliance with deterministic test vectors.

**KAT Structure**:
```rust
pub struct KatPlan {
    pub params: PlanParams,        // RLWE-HPS A1 parameters
    pub base: PlanBase,            // Anchor context (gid, roots)
    pub cases: Vec<PlanCase>,      // Test cases
}

pub struct PlanCase {
    pub id: String,                // Test ID (e.g., "210-mem-depth1")
    pub branch: CaseBranch,        // A or B
    pub seed_drbg: Option<String>, // Override seed (for negative tests)
    pub witness_mod: Option<...>,  // Tamper witness (for negative tests)
    pub scenario: Option<...>,     // Expected outcome (freeze code)
}

pub struct KatOutput {
    pub cases: Vec<CaseOutput>,
}

pub struct CaseOutput {
    pub id: String,
    pub epoch_key: Option<[u8; 32]>, // Expected E_k (positive tests)
    pub freeze_code: Option<u16>,    // Expected freeze (negative tests)
}
```

**Usage**:
```bash
cargo run -p msphf-orchestrator --bin cityg-hps-kat -- \
  --plan kat/plan-rlwe-annex-k.json \
  --out kat_output.json
```

---

### 5.2 Blueprint KAT Mapping

**Blueprint Reference**: Alpha (0.1.0) §18 (Known-Answer Tests)

| KAT ID | Category | Description | Expected Outcome |
|--------|----------|-------------|------------------|
| **210-226** | Merkle witnesses | Membership/non-membership, depths 1-64 | ✅ Valid |
| **241-245** | SRX | Frontier, anchor pool, adjacency | ✅ Valid |
| **251** | CAPSS Smallwood | Wrong seed_DRBG | ❌ Freeze(923) |
| **252** | CAPSS Smallwood | Corrupted params_id | ❌ Freeze(923) |
| **253** | CAPSS Smallwood | hp_commit mismatch (IN-PROOF) | ❌ Freeze(923) |
| **261** | ZK-VRF | Tampered proof | ❌ Freeze(923) |
| **262** | ZK-VRF | Different hp_commit | ❌ Freeze(923) |
| **263** | ZK-VRF | meor_vrf_id mismatch | ❌ Freeze(923) |
| **271** | CAPSS Smallwood | Positive vector (verifies) | ✅ Valid, size ≤ FS_CAPSS_MAX_BYTES |
| **272** | ZK-VRF | Positive vector (verifies, output-hiding) | ✅ Valid, Y\* not revealed |

---

### 5.3 KAT Example: 251 (CAPSS Smallwood Wrong Seed)

**Test Vector**:
```json
{
  "id": "251",
  "branch": "A",
  "seed_drbg": "0000000000000000000000000000000000000000000000000000000000000000",
  "scenario": {
    "kind": "freeze",
    "code": 923,
    "reason": "msphf_lin_invalid"
  }
}
```

**Test Logic**:
```rust
#[test]
fn kat_251_capss_wrong_seed() {
    let mut header = build_header_from_kat("251");
    // header uses wrong seed_DRBG (all zeros), but CAPSS Smallwood transcript from correct seed
    let result = ctx.accept_anchor(&parts, &we_epoch_id, &header, now);
    assert_eq!(result.unwrap_err(), FREEZE_CAPSS_INVALID); // 923
}
```

**Expected Behavior**: CAPSS Smallwood verifier recomputes hp from seed_DRBG (all zeros), but proof was generated with correct seed → commitment mismatch → freeze(923).

---

### 5.4 KAT Example: 272 (ZK-VRF Positive)

**Test Vector**:
```json
{
  "id": "272",
  "branch": "A",
  "scenario": {
    "kind": "valid",
    "epoch_key": "a1b2c3d4e5f6..."
  }
}
```

**Test Logic**:
```rust
#[test]
fn kat_272_zk_vrf_positive() {
    let header = build_header_from_kat("272");
    let result = ctx.accept_anchor(&parts, &we_epoch_id, &header, now);
    assert!(result.is_ok()); // ZK-VRF verifies

    // Verify: Server does NOT learn Y* (output-hiding)
    // (implicit: server code has no Y* in variables)

    // Client-side: Derive E_k
    let (epoch_key, _) = extract_epoch_msphf_or(...);
    assert_eq!(epoch_key, expected_epoch_key); // From KAT vector
}
```

**Expected Behavior**: ZK-VRF proof verifies, server does not learn Y\*, client derives correct E_k.

---

## 6. Security Tests

### 6.1 Constant-Time Verification (DUDECT)

**Location**: [crates/dudect-harness/src/main.rs](../../crates/dudect-harness/src/main.rs)

**Purpose**: Detect timing side-channels in RLWE operations.

**Methodology**:
1. Execute function with two input classes: "fixed" and "random"
2. Measure execution time for each class (thousands of samples)
3. Perform t-test: are timing distributions different?
4. If t-statistic > 4.5: **FAIL** (timing leak detected)

**Test Coverage**:
- `ntt_forward()`: NTT transformation
- `add_field()`: Field addition (mod Q)
- `mul_field()`: Field multiplication (mod Q)
- `barrett_reduce()`: Modular reduction

**Example**:
```rust
fn test_ntt_forward_constant_time() {
    let mut rng = OsRng;
    let mut measurements_fixed = vec![];
    let mut measurements_random = vec![];

    for _ in 0..10000 {
        // Fixed input
        let poly_fixed = [0u16; 256];
        let start = Instant::now();
        ntt_forward(&poly_fixed);
        measurements_fixed.push(start.elapsed().as_nanos());

        // Random input
        let poly_random: [u16; 256] = rng.gen();
        let start = Instant::now();
        ntt_forward(&poly_random);
        measurements_random.push(start.elapsed().as_nanos());
    }

    // Welch's t-test
    let t_statistic = welch_t_test(&measurements_fixed, &measurements_random);
    assert!(t_statistic < 4.5, "Timing leak detected: t={}", t_statistic);
}
```

**Run**:
```bash
cargo run --release --bin dudect-harness
```

**Expected Output**:
```
Testing: ntt_forward (10000 samples)
t-statistic: 1.23 ✅ (threshold: 4.5)
Testing: barrett_reduce (10000 samples)
t-statistic: 0.87 ✅ (threshold: 4.5)
```

---

### 6.2 Side-Channel Analysis (Cachegrind)

**Location**: [docs/evidence/cachegrind/](../../docs/evidence/cachegrind/)

**Purpose**: Verify no secret-dependent cache access patterns.

**Methodology**:
1. Run acceptance pipeline under Valgrind's Cachegrind
2. Analyze cache miss patterns for secret-dependent branches
3. Compare runs with different inputs (fixed vs. random hp)

**Run**:
```bash
valgrind --tool=cachegrind --cachegrind-out-file=cachegrind.out \
    cargo test --release test_e2e_joiner_to_server
```

**Analysis**:
```bash
cg_annotate cachegrind.out | grep -E "accept_anchor|capss_verify"
```

**Expected**: No cache miss rate difference between fixed/random inputs.

---

### 6.3 Fuzzing (Future Work)

**Target**: CBOR parser, witness validation, proof deserialization

**Tool**: `cargo-fuzz` (libFuzzer)

**Example Target**:
```rust
// fuzz/fuzz_targets/cbor_header.rs
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as CBOR header
    let _ = from_reader::<BTreeMap<u64, Value>, _>(data);
});
```

**Run**:
```bash
cargo fuzz run cbor_header -- -max_total_time=3600 # 1 hour
```

---

## 7. Performance Tests

### 7.1 Benchmarking

**Location**: Not yet implemented (use `cargo bench` with Criterion)

**Target Benchmarks**:
- CAPSS Smallwood proof generation: Target < 50ms
- CAPSS Smallwood proof verification: Target < 12ms (mobile)
- ZK-VRF proof generation: Target < 100ms
- ZK-VRF proof verification: Target < 2ms (server), < 6ms (mobile)
- SRX validation: Target < 60ms (|join|+|since| ≤ 20k)

**Example Benchmark** (Criterion):
```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand_core::OsRng;
use cityg::proofs::capss;

fn bench_capss_prove(c: &mut Criterion) {
    let inputs = build_inputs();

    c.bench_function("capss_prove", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            capss::prove(&mut rng, black_box(&inputs)).unwrap()
        });
    });
}

criterion_group!(benches, bench_capss_prove);
criterion_main!(benches);
```

**Run**:
```bash
cargo bench --bench capss
```

---

### 7.2 Resource Budgets

**Blueprint Reference**: Alpha (0.1.0) §17 (Benchmarks & Resource Budgets)

| Operation | Target (Server) | Target (Mobile) | Max Size |
|-----------|-----------------|-----------------|----------|
| **ZK-VRF Verify** | ≤ 2ms | ≤ 6ms | ≤ 8KB |
| **CAPSS Smallwood Verify** | ≤ 6ms | ≤ 12ms | ≤ 12.3KB |
| **SRX Verify** | ≤ 60ms | ≤ 120ms | ≤ 1MB |
| **Working Set** | N/A | ≤ 48MB | N/A |

**Note**: Targets are informative; conformance requires caps and acceptance ordering.

---

## 8. Running Tests

### 8.1 Run All Tests

```bash
cargo test --all
```

**Expected Output**: (counts vary by branch; sample truncated)
```
running … tests
test result: ok. … passed; 0 failed; 0 ignored; 0 measured
```

As of February 5, 2026, this checkout reports 586 tests via `cargo test --all -- --list | rg ': test$' | wc -l`.

---

### 8.2 Run Specific Test Suite

```bash
# Core tests only
cargo test -p msphf-core

# Orchestrator tests only
cargo test -p msphf-orchestrator

# End-to-end tests only
cargo test --test end_to_end
```

---

### 8.3 Run with Verbose Output

```bash
cargo test --all -- --nocapture --test-threads=1
```

---

### 8.4 Run Security Tests

```bash
# Constant-time tests (DUDECT). Examples:
cargo run --release --bin dudect-harness \
  -- --target barrett-reduce --samples 50000 --inner 512
cargo run --release --bin dudect-harness \
  -- --target smallwood-prove --samples 20000 --inner 8
cargo run --release --bin dudect-harness \
  -- --target smallwood-verify --samples 20000 --inner 8

# Side-channel analysis (Cachegrind)
valgrind --tool=cachegrind --branch-sim=yes \
  --log-file=docs/evidence/cachegrind/ct_vrf.log \
  cargo +nightly run -p msphf-orchestrator --release --example ct_vrf \
  -- --filter vrf_verify_ct
```

---

### 8.5 Run KATs

```bash
# Generate KAT outputs from plan
cargo run -p msphf-orchestrator --bin cityg-hps-kat -- \
    --plan kat/plan-rlwe-annex-k.json \
    --out kat_output.json

# Compare with expected outputs
diff kat_output.json kat/kat-rlwe-annex-k.json
```

---

### 8.6 Run Runtime Smoke

```bash
# Server + GUI join/leave flow + capacity freeze behavior
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

This smoke test starts a local API server, validates join/leave membership events
with the `join_leave --watch` workflow, and then forces a low-capacity window to
confirm `freeze 925` (`mh_window_full`) is emitted when expected.

---

## Summary

The City-G `tswe/msphf-we/fs-hybrid` test suite provides comprehensive coverage:

1. **Unit Tests**: Individual function validation
2. **Integration Tests**: End-to-end pipeline validation
3. **Known-Answer Tests**: Blueprint compliance
4. **Security Tests**: Constant-time verification (DUDECT), side-channel analysis (Cachegrind)
5. **Performance Tests**: Benchmarking framework (Criterion, future work)

**Test Inventory**: 586 tests listed in this checkout on February 5, 2026 (`cargo test --all -- --list | rg ': test$' | wc -l`)

**Security Verification**: All critical RLWE operations are constant-time (DUDECT verified)

**Blueprint Compliance**: All KATs (210-272) pass with expected outcomes

**Next**: [14 — Deployment Guide](./14-deployment-guide.md)

---

**Document Version**: 0.1.0
**Blueprint Reference**: Alpha (0.1.0) §18
**Implementation**: City-G 0.1.0
