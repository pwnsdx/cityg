# 11 — Implementation Guide

> [!IMPORTANT]
> This chapter is a legacy companion document. For `tswe/msphf-we/fs-hybrid`, the normative source is [`../specs.md`](../specs.md).
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and implementation.


**Profile**: City-G `tswe/msphf-we/fs-hybrid` (Alpha (0.1.0))
**Status**: Informative (implementation binding)

## Table of Contents

1. [Introduction](#1-introduction)
2. [Architecture Overview](#2-architecture-overview)
3. [Crate Structure](#3-crate-structure)
4. [Core Crates](#4-core-crates)
5. [Orchestrator Crate](#5-orchestrator-crate)
6. [Client and Server Crates](#6-client-and-server-crates)
7. [Key Algorithms](#7-key-algorithms)
8. [Data Flow](#8-data-flow)
9. [Testing Strategy](#9-testing-strategy)

---

## 1. Introduction

This document provides a **file-by-file walkthrough** of the City-G `tswe/msphf-we/fs-hybrid` implementation. It maps specification concepts to source code locations, explains architectural decisions, and guides developers through the ~18,000-line codebase.

**Target Audience**: Rust developers, security auditors, protocol implementers

**Prerequisites**: Familiarity with Rust, basic cryptography, Merkle trees

---

## 2. Architecture Overview

### 2.1 System Components

```
┌────────────────────────────────────────────────────────────┐
│ CLIENT (cityg-client)                                      │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ ClientEpochBundle::derive_epoch_secrets()              │ │
│ │ - Decrypts hp from KBROAD envelope                     │ │
│ │ - Computes Y* via ME-OR                                │ │
│ │ - Derives E_k := H_epoch(X_k, Y*)                      │ │
│ └────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
                           │
                           │ Anchor + Proofs
                           ▼
┌────────────────────────────────────────────────────────────┐
│ SERVER (cityg-server)                                      │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ ServerContext::accept_anchor()                         │ │
│ │ - Validates structure, PoP, CAPSS Smallwood, ZK-VRF, SRX       │ │
│ │ - Returns (we_epoch_id, wid) — PUBLIC ONLY             │ │
│ │ - NEVER decrypts hp or learns Y*                       │ │
│ └────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────┐
│ ORCHESTRATOR (msphf-orchestrator)                          │
│ ├─ AcceptanceContext (9-step validation pipeline)         │
│ ├─ CapssProver/Verifier (seed→hp determinism + FS bind)|
│ ├─ ZkVrfProver/Verifier (Y* uniqueness, output-hiding)    │
│ ├─ MultiHeadWindow (concurrency control)                  │
│ └─ Joiner KGen pipeline (client-side anchor creation)     │
└────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────┐
│ CORE (msphf-core, msphf-rlwe)                              │
│ ├─ RLWE-HPS A1 (SPHF construction)                        │
│ ├─ Merkle witnesses (canonical format)                    │
│ ├─ rpo-256/v1 (set-hash)                                  │
│ ├─ BLAKE3 domain separation (H_L)                         │
│ └─ CBOR canonical encoding                                │
└────────────────────────────────────────────────────────────┘
```

### 2.2 Dependency Graph

```
cityg-client ───────┐
                    ├──► msphf-orchestrator ──► msphf-core
cityg-server ───────┘                            │
                                                 ├──► msphf-rlwe
                                                 └──► anchor-seed
```

**Key Insight**: `msphf-core` contains primitive operations (no secrets), `msphf-orchestrator` contains both client (KGen) and server (acceptance) logic, `cityg-client`/`cityg-server` are thin wrappers.

---

## 3. Crate Structure

### 3.1 Overview

| Crate | Lines | Purpose |
|-------|-------|---------|
| **msphf-core** | ~4,500 | RLWE primitives, Merkle, hashing, witnesses |
| **msphf-rlwe** | ~800 | RLWE-HPS A1 SPHF instantiation |
| **msphf-orchestrator** | ~7,000 | Acceptance pipeline, proofs, MHW, KGen |
| **msphf-lb-vrf** | ~2,000 | lb-vrf/v1 implementation (ZK-VRF) |
| **anchor-seed** | ~400 | ANCHOR_SEED_CTX construction |
| **cityg-client** | ~400 | Client API (epoch derivation) |
| **cityg-server** | ~300 | Server API (anchor acceptance) |
| **cityg-api** | ~500 | HTTP server (example) |

**Total**: ~18,000 lines of Rust (excluding tests)

### 3.2 File Organization

```
crates/
├── msphf-core/
│   ├── src/
│   │   ├── lib.rs           (exports, error types)
│   │   ├── hash.rs          (BLAKE3 H_L, domain separation)
│   │   ├── merkle.rs        (Merkle tree, canonical set root)
│   │   ├── witness.rs       (MEM/NONMEM witness validation)
│   │   ├── rpo256.rs        (rpo-256/v1 set-hash)
│   │   ├── instance.rs      (AnchorInstance struct)
│   │   ├── params.rs        (RLWE-HPS A1 parameters)
│   │   ├── ds.rs            (Data structure constants)
│   │   ├── errors.rs        (Error enums)
│   │   ├── serde_utils.rs   (CBOR helpers)
│   │   └── rlwe/            (RLWE arithmetic)
│   │       ├── mod.rs
│   │       ├── poly.rs      (Polynomial operations)
│   │       ├── polyvec.rs   (Vector operations)
│   │       ├── arithmetic.rs (Field arithmetic)
│   │       ├── matrix.rs    (Matrix operations)
│   │       ├── ntt.rs       (Number-Theoretic Transform)
│   │       ├── noise.rs     (Noise sampling)
│   │       └── constants.rs (NTT roots)
│   └── Cargo.toml
├── msphf-rlwe/
│   ├── src/
│   │   └── lib.rs           (RLWE-HPS KGen, ME-OR, CAPSS Smallwood recompute)
│   └── Cargo.toml
├── msphf-orchestrator/
│   ├── src/
│   │   ├── lib.rs           (Joiner KGen, epoch extraction)
│   │   ├── accept/          (Acceptance module: join/merge orchestration)
│   │   ├── mhw.rs           (Multi-Head Window)
│   │   ├── hdr.rs           (Header key constants)
│   │   ├── policy.rs        (Bootstrap policy)
│   │   ├── receiver.rs      (Anchor receiver struct)
│   │   ├── kat.rs           (Known-Answer Tests)
│   │   └── proofs/
│   │       ├── mod.rs
│   │       ├── capss.rs (CAPSS Smallwood prover/verifier)
│   │       ├── hp_binding.rs (hp commit verification)
│   │       └── zk_vrf/
│   │           ├── mod.rs
│   │           └── lb.rs    (lb-vrf/v1 wrapper)
│   ├── tests/
│   │   └── end_to_end.rs    (E2E acceptance/regression tests)
│   └── Cargo.toml
├── msphf-lb-vrf/
│   ├── src/
│   │   ├── lib.rs
│   │   ├── lbvrf.rs         (Prove/Verify)
│   │   ├── keypair.rs       (Keygen)
│   │   ├── poly.rs, poly32.rs, poly256.rs (Polynomial arithmetic)
│   │   ├── ntt.rs           (NTT for VRF)
│   │   └── param.rs         (VRF parameters)
│   └── Cargo.toml
├── anchor-seed/
│   ├── src/
│   │   └── lib.rs           (ANCHOR_SEED_CTX, seed_bundle_commit)
│   └── Cargo.toml
├── cityg-client/
│   ├── src/
│   │   ├── lib.rs           (ClientEpochBundle API)
│   │   └── demo.rs          (Example usage)
│   └── Cargo.toml
├── cityg-server/
│   ├── src/
│   │   └── lib.rs           (ServerContext, ServerOutcome)
│   └── Cargo.toml
└── cityg-api/
    ├── src/
    │   ├── lib.rs           (REST API types)
    │   └── main.rs          (HTTP server)
    └── Cargo.toml
```

---

## 4. Core Crates

### 4.1 msphf-core

#### 4.1.1 `lib.rs` (150 lines)

**Purpose**: Module exports, error types, version constants

**Key Exports**:
```rust
pub use errors::{MsphfError, WitnessValidationError};
pub use hash::{h_l, hash_bytes_with_label};
pub use merkle::{canonical_frontier, canonical_set_root};
pub use witness::{CanonicalWitness, ValidatedMembership, ValidatedNonMembership};
pub use instance::AnchorInstance;
pub use params::RLWE_HPS_A1_PARAMS;
```

**Location**: [crates/msphf-core/src/lib.rs](../../crates/msphf-core/src/lib.rs)

---

#### 4.1.2 `hash.rs` (200 lines)

**Purpose**: BLAKE3-based domain separation (H_L construction)

**Key Function**:
```rust
pub fn h_l<T: Serialize>(label: &str, val: &T) -> Result<[u8; 32], MsphfError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label.as_bytes());
    hasher.update(&[0x00]); // Domain separator
    let cbor = to_cbor_vec(val)?;
    hasher.update(&cbor);
    Ok(hasher.finalize().into())
}
```

**Blueprint Reference**: Alpha (0.1.0) §6 (Crypto, Domains, and Labels)

**Usage**:
- `H_L("msphf/rho/der", [pop_sig, xk_hash])` → ρ
- `H_L("mhw/window", [gid, parent_root, seed_ctx_hash])` → WID
- `H_L("msphf/lin_fs/chal", [commitments, bind])` → CAPSS Smallwood binding digest

**Location**: [crates/msphf-core/src/hash.rs](../../crates/msphf-core/src/hash.rs)

---

#### 4.1.3 `merkle.rs` (600 lines)

**Purpose**: Canonical Merkle tree operations, set-hash

**Key Functions**:
```rust
// Compute canonical set root for sorted leaf_ids
pub fn canonical_set_root(leaf_ids: &[[u8; 32]]) -> Result<[u8; 32], MsphfError>;

// Compute frontier for a tree with N leaves
pub fn canonical_frontier(num_leaves: u64) -> Vec<[u8; 32]>;

// Verify membership witness (leaf → root)
pub fn verify_membership_witness(
    leaf: &[u8; 32],
    path: &[(u8, [u8; 32])],
    expected_root: &[u8; 32],
) -> Result<(), MsphfError>;
```

**Blueprint Reference**: Alpha (0.1.0) §5 (Canonical Merkle Witnesses)

**Implementation Details**:
- Uses rpo-256/v1 for hashing (Rescue-Prime)
- Enforces depth ≤ 64 (specification constraint)
- Validates path directions (0=left, 1=right)

**Location**: [crates/msphf-core/src/merkle.rs](../../crates/msphf-core/src/merkle.rs)

---

#### 4.1.4 `witness.rs` (888 lines)

**Purpose**: Canonical witness structures, validation logic

**Key Structs**:
```rust
pub struct CanonicalWitness {
    pub membership: Option<ValidatedMembership>,
    pub non_membership: Option<ValidatedNonMembership>,
}

pub struct ValidatedMembership {
    pub leaf_id: [u8; 32],
    pub root: [u8; 32],
    pub path: Vec<(u8, [u8; 32])>,
}

pub struct ValidatedNonMembership {
    pub interval: CanonicalInterval,
    pub left_path: Vec<(u8, [u8; 32])>,
    pub right_path: Vec<(u8, [u8; 32])>,
    pub root: [u8; 32],
}
```

**Key Functions**:
```rust
// Parse and validate membership witness
pub fn validate_membership_witness(
    raw: &RawMembershipWitness,
    expected_root: &[u8; 32],
) -> Result<ValidatedMembership, WitnessValidationError>;

// Parse and validate non-membership witness
pub fn validate_nonmembership_witness(
    raw: &RawNonMembershipWitness,
    expected_root: &[u8; 32],
    leaf_id: &[u8; 32],
) -> Result<ValidatedNonMembership, WitnessValidationError>;
```

**Blueprint Reference**: Alpha (0.1.0) §5 (Canonical Witnesses), Appendix F (SRX)

**Location**: [crates/msphf-core/src/witness.rs](../../crates/msphf-core/src/witness.rs)

---

#### 4.1.5 `rpo256.rs` (400 lines)

**Purpose**: rpo-256/v1 set-hash (Rescue-Prime Optimized)

**Key Function**:
```rust
pub fn rpo256_hash(input: &[[u8; 32]]) -> [u8; 32];
```

**Algorithm**:
1. Initialize state: `[0u64; 12]`
2. For each input block:
   - Absorb into state (rate=8, capacity=4)
   - Apply Rescue-Prime permutation (10 rounds)
3. Squeeze output (first 256 bits)

**Security**: 256-bit preimage resistance (algebraic hash function)

**Blueprint Reference**: Alpha (0.1.0) Appendix B (rpo-256/v1)

**Location**: [crates/msphf-core/src/rpo256.rs](../../crates/msphf-core/src/rpo256.rs)

---

#### 4.1.6 `rlwe/` Module (2,500 lines)

**Purpose**: RLWE arithmetic primitives (N=256, Q=3329, K=3)

**Key Files**:

**`rlwe/poly.rs`** (600 lines):
- `Poly<N>`: Polynomial with N coefficients (mod Q)
- `add_poly()`, `sub_poly()`, `mul_poly_ntt()`: Operations
- NTT-based multiplication (O(N log N))

**`rlwe/ntt.rs`** (400 lines):
- Forward NTT: `ntt_forward(poly) → ntt_poly`
- Inverse NTT: `ntt_inverse(ntt_poly) → poly`
- Constant-time (fixed loop counts, no data-dependent branches)

**`rlwe/noise.rs`** (200 lines):
- `sample_noise_eta2()`: Sample from centered binomial distribution (η₂=2)
- Uses BLAKE3-DRBG for randomness

**`rlwe/arithmetic.rs`** (300 lines):
- `add_field()`, `sub_field()`, `mul_field()`: Field operations (mod Q=3329)
- `barrett_reduce()`: Constant-time modular reduction

**Blueprint Reference**: Alpha (0.1.0) §9 (Instantiations), Appendix C (RLWE-HPS Parameters)

**Location**: [crates/msphf-core/src/rlwe/](../../crates/msphf-core/src/rlwe/)

---

### 4.2 msphf-rlwe

#### 4.2.1 `lib.rs` (800 lines)

**Purpose**: RLWE-HPS A1 instantiation (SPHF construction)

**Key Functions**:

**KGen** (KeyGen):
```rust
pub fn rlwe_hps_kgen(seed_drbg: &[u8; 32]) -> Result<RlweHpsKeypair, MsphfError> {
    // 1. Derive A matrix from seed (public CRS)
    let A = derive_matrix_a(seed_drbg);

    // 2. Sample noise vectors s, e
    let s = sample_noise_eta2(seed_drbg, "rlwe/hps/s");
    let e = sample_noise_eta2(seed_drbg, "rlwe/hps/e");

    // 3. Compute projection key: pk = A*s + e (mod Q)
    let pk = matrix_mul_vec(&A, &s) + &e;

    // 4. Secret key: hp = s (kept by client)
    Ok(RlweHpsKeypair { hp: s, pk })
}
```

**ME-OR** (Masked-Equality OR):
```rust
pub fn compute_meor(
    pk: &PolyVec<K>,
    delta: &PolyVec<K>,
    mask: &Poly<N>,
) -> Result<[u8; 32], MsphfError> {
    // Projection: Y_raw = <pk, delta> (inner product mod Q)
    let y_raw = inner_product_mod_q(pk, delta);

    // Unmask: Y* = Y_raw XOR mask
    let y_star = xor_poly(&y_raw, mask);

    // Encode to bytes
    Ok(encode_poly_to_bytes(&y_star))
}
```

**CAPSS Smallwood Recompute**:
```rust
pub fn recompute_capss_witness(
    seed_drbg: &[u8; 32],
    params: &RlweHpsParams,
) -> Result<CapssWitnessBundle, MsphfError> {
    // Re-derive A, s, e from seed (deterministic)
    let A = derive_matrix_a(seed_drbg);
    let s = sample_noise_eta2(seed_drbg, "rlwe/hps/s");
    let e = sample_noise_eta2(seed_drbg, "rlwe/hps/e");

    // Recompute pk = A*s + e
    let pk = matrix_mul_vec(&A, &s) + &e;

    // Return witness bundle (for CAPSS Smallwood verification)
    Ok(CapssWitnessBundle { seed_drbg, A, s, e, pk })
}
```

**Blueprint Reference**: Alpha (0.1.0) §8 (ME-OR), §9 (Instantiations)

**Location**: [crates/msphf-rlwe/src/lib.rs](../../crates/msphf-rlwe/src/lib.rs)

---

### 4.3 anchor-seed

#### 4.3.1 `lib.rs` (400 lines)

**Purpose**: ANCHOR_SEED_CTX construction, seed_bundle_commit

**Key Functions**:

**Build ANCHOR_SEED_CTX**:
```rust
pub fn build_anchor_seed_ctx(
    header: &BTreeMap<u64, Value>,
) -> Result<Value, MsphfError> {
    // Extract header minus proof/materialization fields.
    let mut ctx = header.clone();

    // Remove: rho_commit, seed_bundle_commit, hp_commit, PoP, legacy SRX keys.
    ctx.remove(&93); // msphf_kgen_rho_commit
    ctx.remove(&94); // seed_bundle_commit
    ctx.remove(&99); // msphf_hp_commit
    ctx.remove(&107); ctx.remove(&108); ctx.remove(&109); // PoP
    ctx.remove(&120); ctx.remove(&121); ctx.remove(&122); // legacy+SRX payload
    ctx.remove(&123); ctx.remove(&124); // legacy SRX hints

    Ok(Value::Map(ctx))
}
```

**Compute seed_ctx_hash (91)**:
```rust
pub fn compute_seed_ctx_hash(
    anchor_seed_ctx: &Value,
) -> Result<[u8; 32], MsphfError> {
    let cbor = to_cbor_vec(anchor_seed_ctx)?;
    h_l("seedctx", &cbor)
}
```

**Compute seed_bundle_commit (94)**:
```rust
pub fn compute_seed_bundle_commit(
    fields: &SeedCommitFields,
) -> Result<[u8; 32], MsphfError> {
    h_l("msphf/seed_bundle", &fields)
}
```

**Blueprint Reference**: Alpha (0.1.0) §12.0-bis (ANCHOR_SEED_CTX)

**Location**: [crates/anchor-seed/src/lib.rs](../../crates/anchor-seed/src/lib.rs)

---

## 5. Orchestrator Crate

### 5.1 `accept/` module (≈5,000 lines)

**Purpose**: 9-step server-side acceptance pipeline

**Key Struct**:
```rust
pub struct AcceptanceContext {
    pub mh_window: MultiHeadWindow,                     // ✅ Public
    rho_guard: RhoReplayGuard,                          // ✅ Commitments
    vck_cache: VckCache,                                 // ✅ Public VRF keys
    bootstrap_policy: BootstrapPolicy,                   // ✅ Config
    srx_max_bytes: usize,                                // ✅ Config
    srx_required: bool,                                  // ✅ Config
    allowed_crs_ids: Option<BTreeSet<String>>,          // ✅ Registry
    kbroad_registry: Option<BTreeMap<Vec<u8>, Vec<u8>>>, // ✅ Public keys
    pending_capss_witness: Option<CapssWitnessBundle>,  // ✅ Public witness
    telemetry: BTreeMap<TelemetryKey, TelemetryCounters>, // ✅ Counters
    fs_policy_version: Option<String>,                   // ✅ FS policy pin
    allowed_fs_policy_version: Option<String>,           // ✅ FS allowlist
    policy_timestamp: Option<OffsetDateTime>,            // ✅ Timestamp
    srx_root_sw: Option<[u8;32]>,                        // ✅ Durable SRX shadow root
}
```

**Key Method**:
```rust
pub fn accept_anchor(
    &mut self,
    parts: &AnchorInstanceParts,
    we_epoch_id: &[u8; 32],
    header: &BTreeMap<u64, Value>,
    now: Instant,
) -> Result<(), AcceptanceError> {
    // Step 0: Pre-filters
    self.pre_filter_checks(header)?;

    // Step 1: Structure/presence
    self.validate_structure(header)?;

    // Step 2: Gates & policy
    self.validate_gates(header)?;

    // Step 3: PoP (join only)
    if is_join { self.validate_pop(header, parts)?; }

    // Step 4: ρ determinism & seed-bundle
    self.validate_rho_determinism(header, parts)?;

    // Step 5: KBROAD binding (PUBLIC, NO DECRYPT)
    self.validate_kbroad_envelope_structure(header)?;

    // Step 6: Proofs commit precheck (fail-fast)
    self.validate_proofs_commit(header)?;

    // Step 7: Proofs (FS Smallwood -> VRF -> SRX when required on merges)
    self.verify_capss(header)?;
    self.verify_zk_vrf(header)?;
    if is_merge && srx_required_for_merge {
        self.verify_srx_smallwood(header, parts)?;
    }

    // Step 8: Defense-in-depth
    self.defense_in_depth_checks(header)?;

    // Step 9: Cache
    self.cache_vck(we_epoch_id, header, now);

    Ok(())
}
```

**Blueprint Reference**: Alpha (0.1.0) §12.2 (Acceptance Pipeline)

**Location**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Key Sections**:
- Lines 469-507: `AcceptanceContext` struct definition
- Lines 854-898: KBROAD registry validation
- Lines 1953-2029: KBROAD envelope structure + length guard
- Lines 2283-2394: ρ determinism (Step 4)
- Lines 2569-2713: Proof verification (Step 7)
- Lines 2735-2870: Defense-in-depth (Step 8)

---

### 5.2 `lib.rs` (2,000 lines)

**Purpose**: Joiner KGen pipeline, epoch extraction

**Key Functions**:

**Joiner KGen**:
```rust
pub fn joiner_kgen(
    seed_commit: &[u8; 32],
    xk_hash: &[u8; 32],
    seed_ctx_hash: &[u8; 32],
    pop_sig: &[u8],
    device_pk: &MlDsaPublicKey,
) -> Result<JoinerKGenOutput, MsphfError> {
    // 1. Derive ρ from PoP signature
    let rho_raw = h_l("msphf/rho/der", &RhoSig { pop_sig, xk_hash })?;
    let rho_commit = h_l("msphf/kgen/rho", &RhoCommit(&rho_raw))?;

    // 2. Derive seed_DRBG
    let seed_drbg = h_l("msphf/drbg", &Drbg {
        seed_commit,
        rho: &rho_raw,
        xk_hash,
        seed_ctx_hash,
    })?;

    // 3. KGen: seed_DRBG → hp
    let keypair = rlwe_hps_kgen(&seed_drbg)?;

    // 4. Compute hp_commit
    let hp_commit = h_l("msphf/hp/commit", &keypair.hp)?;

    // 5. Compute masks M_A, M_B
    let masks = derive_masks(&seed_drbg, xk_hash)?;

    Ok(JoinerKGenOutput { rho_commit, hp: keypair.hp, hp_commit, masks })
}
```

**Epoch Extraction** (Client-side):
```rust
pub fn extract_epoch_msphf_or(
    anchor: &AnchorInstance,
    hp_binding: &HpBinding,
    witness_bytes: &[u8],
    hp_ciphertext: &[u8],
    hp_aead_key: &[u8; 32],
) -> Result<[u8; 32], MsphfError> {
    // 1. Decrypt hp from KBROAD envelope
    let hp = decrypt_hp_client_side(hp_ciphertext, hp_aead_key)?;

    // 2. Parse witness
    let witness = parse_canonical_witness(witness_bytes, anchor)?;

    // 3. Compute Δ (branch selection)
    let delta = compute_delta_for_branch(witness, anchor)?;

    // 4. Compute Y* via ME-OR
    let pk = hp_binding.pk;
    let mask = hp_binding.mask;
    let y_star = compute_meor(&pk, &delta, &mask)?;

    // 5. Derive E_k
    let epoch_key = h_epoch(&anchor.X_k, &y_star)?;

    Ok(epoch_key)
}
```

**Blueprint Reference**: Alpha (0.1.0) §10 (Seed-Binding), §8 (ME-OR)

**Location**: [crates/msphf-orchestrator/src/lib.rs](../../crates/msphf-orchestrator/src/lib.rs)

**Key Sections**:
- Lines 1743-1850: Joiner KGen pipeline
- Lines 1879-2057: `extract_epoch_msphf_or` (client epoch derivation)

---

### 5.3 `mhw.rs` (200 lines)

**Purpose**: Multi-Head Window (concurrency control)

**Key Struct**:
```rust
pub struct MultiHeadWindow {
    windows: BTreeMap<WindowId, HeadList>,
    h_max: usize,        // Default: 16
    t_window: Duration,  // Default: 120s
}

pub struct HeadRecord {
    pub we_epoch_id: [u8; 32],
    pub inserted_at: Instant,
}
```

**Key Methods**:

**Accept Head** (Join Mode):
```rust
pub fn accept_head(
    &mut self,
    wid: &[u8; 32],
    we_epoch_id: &[u8; 32],
    now: Instant,
) -> Result<(), FreezeError> {
    // 1. Get or create window
    let heads = self.windows.entry(*wid).or_default();

    // 2. Prune expired heads
    heads.retain(|h| now.duration_since(h.inserted_at) < self.t_window);

    // 3. Check capacity
    if heads.len() >= self.h_max {
        return Err(FREEZE_MH_WINDOW_FULL);
    }

    // 4. Insert new head
    heads.push(HeadRecord { we_epoch_id: *we_epoch_id, inserted_at: now });
    Ok(())
}
```

**Accept Merge** (Merge Mode):
```rust
pub fn accept_merge(
    &mut self,
    wid_old: &[u8],
    wid_new: &[u8],
    retire_heads: &[[u8; 32]],
    merged: HeadRecord,
    now: Instant,
) -> Result<(), FreezeError> {
    if !is_sorted_unique(retire_heads) {
        return Err(FreezeError::MERGE_INVALID);
    }

    let entry_old = self.prune(wid_old, now);
    for retire in retire_heads {
        if let Some(pos) = entry_old.iter().position(|h| &h.we_epoch_id == retire) {
            entry_old.remove(pos);
        } else {
            return Err(FreezeError::MERGE_INVALID);
        }
    }

    if wid_old == wid_new {
        if entry_old.len() >= self.h_max {
            return Err(FreezeError::WINDOW_FULL);
        }
        entry_old.push(merged);
        return Ok(());
    }

    if entry_old.is_empty() {
        self.windows.remove(wid_old);
    }

    let entry_new = self.prune(wid_new, now);
    if entry_new.len() >= self.h_max {
        return Err(FreezeError::WINDOW_FULL);
    }
    entry_new.push(merged);
    Ok(())
}
```

**Blueprint Reference**: Alpha (0.1.0) §13 (Epoch Routing & Concurrency), Annex M (MHW)

**Location**: [crates/msphf-orchestrator/src/mhw.rs](../../crates/msphf-orchestrator/src/mhw.rs)

---

### 5.4 `proofs/capss.rs` (CAPSS Smallwood wrapper)

**Purpose**: Deterministically seed the CAPSS Smallwood prover, serialize the transcript as a
`CapssSignature`, and verify it against the same public tuple on the server. The file keeps the
historic module name but now delegates to the shared `capss` crate.

**Key Functions**:

```rust
pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, inputs: &Inputs<'_>) -> Result<Proof, MsphfError>;
pub fn verify(inputs: &Inputs<'_>, proof: &Proof) -> Result<(), AcceptanceError>;
```

- `Inputs` captures the public tuple; `Inputs.bind` contains the forward-secrecy fields that must be
  bound by the proof (`fs_epoch_commit`, `fs_ec`, device chain commits, CRS/params, etc.).
- `Proof` is a thin wrapper around the serialized `CapssSignature` (just a `Vec<u8>`). `verify`
  rebuilds the CAPSS context and hands the signature to `smallwood_verifier`.

**Blueprint Reference**: Alpha (0.1.0) Annex L (CAPSS Smallwood)

**Location**: [crates/msphf-orchestrator/src/proofs/capss.rs](../../crates/msphf-orchestrator/src/proofs/capss.rs)

---

### 5.5 `proofs/zk_vrf/lb.rs` (150 lines)

**Purpose**: lb-vrf/v1 wrapper (ZK-VRF proof)

**Key Functions**:

**Prove**:
```rust
pub fn zk_vrf_prove(
    hp: &[u8],
    vrf_ctx: &VrfCtx,
) -> Result<Vec<u8>, MsphfError> {
    // 1. Compute Y* = VRF(hp, VRF_CTX)
    let y_star = compute_vrf_output(hp, vrf_ctx)?;

    // 2. Compute mask_digest (output-hiding)
    let mask_digest = h_l("vrf/mask", &MaskDigest {
        hp_commit: vrf_ctx.hp_commit,
        vrf_ctx_hash: vrf_ctx.vrf_ctx_hash,
        mask_nonce: &derive_mask_nonce(hp)?,
    })?;

    // 3. Generate proof (prove Y* correctness without revealing it)
    let proof = lb_vrf_prove(hp, vrf_ctx, &mask_digest)?;

    Ok(proof)
}
```

**Verify**:
```rust
pub fn zk_vrf_verify(
    proof_bytes: &[u8],
    vrf_ctx: &VrfCtx,
) -> Result<(), MsphfError> {
    // 1. Parse proof
    let proof = VrfProof::from_bytes(proof_bytes)?;

    // 2. Verify proof (checks binding to hp_commit, VRF_CTX)
    lb_vrf_verify(&proof, vrf_ctx)?;

    // 3. Check output-hiding property (verifier learns mask_digest, not Y*)
    // (implicit in lb_vrf_verify)

    Ok(())
}
```

**Blueprint Reference**: Alpha (0.1.0) §11 (ZK-VRF-for-ME-OR), Appendix V (lb-vrf/v1)

**Location**: [crates/msphf-orchestrator/src/proofs/zk_vrf/lb.rs](../../crates/msphf-orchestrator/src/proofs/zk_vrf/lb.rs)

---

## 6. Client and Server Crates

### 6.1 cityg-client

#### 6.1.1 `lib.rs` (370 lines)

**Purpose**: Client API for epoch derivation

**Key Struct**:
```rust
pub struct ClientEpochBundle {
    pub anchor: AnchorInstance,
    pub hp_binding: HpBinding,
    pub witness: Option<Vec<u8>>,
    pub hp_ciphertext: Vec<u8>,
    pub hp_aead_key: [u8; 32],
}
```

**Key Method**:
```rust
impl ClientEpochBundle {
    pub fn derive_epoch_secrets(&self)
        -> Result<([u8; 32], [u8; 32]), CityGError>
    {
        // 1. Extract epoch key via ME-OR
        let epoch_key = extract_epoch_msphf_or(
            &self.anchor,
            &self.hp_binding,
            self.witness.as_deref().unwrap_or(&[]),
            &self.hp_ciphertext,
            &self.hp_aead_key,
        )?;

        // 2. Derive eid from epoch_key
        let eid = eid_from_epoch(&epoch_key)?;

        Ok((epoch_key, eid))
    }
}
```

**Location**: [crates/cityg-client/src/lib.rs](../../crates/cityg-client/src/lib.rs)

---

### 6.2 cityg-server

#### 6.2.1 `lib.rs` (300 lines)

**Purpose**: Server API for anchor acceptance

**Key Struct**:
```rust
pub struct ServerContext {
    acceptance: AcceptanceContext,
}

pub struct ServerOutcome {
    pub we_epoch_id: [u8; 32],  // ✅ Public window epoch ID
    pub wid: [u8; 32],          // ✅ Public window identifier
}
```

**Key Method**:
```rust
impl ServerContext {
    pub fn accept_anchor(
        &mut self,
        header_cbor: &[u8],
    ) -> Result<ServerOutcome, ServerError> {
        // 1. Parse header
        let header: BTreeMap<u64, Value> = from_cbor(header_cbor)?;

        // 2. Extract public fields
        let gid = header.get(&90)?.as_bytes()?;
        let parent_root = header.get(&110)?.as_bytes()?;
        let seed_ctx_hash = header.get(&91)?.as_bytes()?;

        // 3. Compute WID
        let wid = compute_window_id(gid, parent_root, seed_ctx_hash)?;

        // 4. Compute we_epoch_id
        let we_epoch_id = derive_we_epoch_id(gid, &header)?;

        // 5. Validate via acceptance pipeline
        let parts = build_instance_parts(&header)?;
        self.acceptance.accept_anchor(&parts, &we_epoch_id, &header, Instant::now())?;

        // 6. Return public outcome (NO SECRETS)
        Ok(ServerOutcome { we_epoch_id, wid })
    }
}
```

**Location**: [crates/cityg-server/src/lib.rs](../../crates/cityg-server/src/lib.rs)

---

## 7. Key Algorithms

### 7.1 Seed Derivation Hierarchy

```
pop_sig (ML-DSA-65 signature)
    ↓ H_L("msphf/rho/der", [pop_sig, xk_hash])
ρ_raw [32 bytes]
    ↓ H_L("msphf/kgen/rho", [ρ_raw])
rho_commit (93) [32 bytes]

seed_commit (from ANCHOR_SEED_CTX)
    ↓ H_L("msphf/drbg", [seed_commit, ρ, xk_hash, seed_ctx_hash])
seed_DRBG [32 bytes]
    ↓ rlwe_hps_kgen(seed_DRBG)
hp (RLWE-HPS secret key)
    ↓ H_L("msphf/hp/commit", [hp])
hp_commit (99) [32 bytes]
```

**Implementation**: [crates/msphf-orchestrator/src/lib.rs](../../crates/msphf-orchestrator/src/lib.rs)

---

### 7.2 Epoch Key Derivation

```
hp (decrypted from KBROAD)
    +
witness (MEM or NONMEM)
    ↓ compute_delta() [branch A or B]
Δ (field vector)
    +
pk (projection key from msphf_hp)
mask (M_A or M_B)
    ↓ MEOR(pk, Δ, mask)
Y* [32 bytes] (VRF output)
    +
X_k (epoch context)
    ↓ H_epoch(X_k, Y*)
E_k [32 bytes] (epoch key)
    ↓ H_L("we/eid", [E_k])
eid [32 bytes] (epoch identifier)
```

**Implementation**: [crates/msphf-orchestrator/src/lib.rs](../../crates/msphf-orchestrator/src/lib.rs)

---

### 7.3 Window Identifier (WID)

```
gid [variable bytes] (group ID)
    +
parent_root (110) [32 bytes]
    +
seed_ctx_hash (91) [32 bytes]
    ↓ H_L("mhw/window", [gid, parent_root, seed_ctx_hash])
WID [32 bytes]
```

**Properties**:
- Public (no secrets)
- Deterministic (same inputs → same WID)
- Collision-resistant (BLAKE3 security)

**Implementation**: [crates/msphf-orchestrator/src/lib.rs:compute_window_id](../../crates/msphf-orchestrator/src/lib.rs)

---

## 8. Data Flow

### 8.1 Joiner (Client) Flow

```
1. Device generates PoP signature
   └─► pop_sig = ML-DSA-65.Sign(device_sk, PoP_MSG)

2. Derive ρ and seed_DRBG
   └─► rho_raw = H_L("msphf/rho/der", [pop_sig, xk_hash])
   └─► seed_DRBG = H_L("msphf/drbg", [seed_commit, rho, xk_hash, seed_ctx_hash])

3. KGen: Generate hp
   └─► keypair = rlwe_hps_kgen(seed_DRBG)
   └─► hp = keypair.hp, pk = keypair.pk

4. Encrypt hp in KBROAD envelope
   └─► (ct_kem, ss) = ML-KEM-768.Encap(kbroad_pub)
   └─► KEK = HKDF-BLAKE3(ss, ...)
   └─► wrap = AEAD.Enc(KEK, hp_k_bytes)
   └─► C_hp = AEAD.Enc(hp_k_bytes, hp)

5. Generate proofs
   └─► capss_proof = CAPSS Smallwood.Prove(inputs)
   └─► zk_vrf_proof = ZK-VRF.Prove(hp, vrf_ctx)

6. Assemble header
   └─► header[97] = ["barrier-sealed-v1", hp_ciphertext, "chacha20-poly1305"]
   └─► header[146] = capss_proof
   └─► header[95] = zk_vrf_proof

7. Submit to server
   └─► POST /anchor (header + SRX payload)
```

---

### 8.2 Server Flow

```
1. Receive anchor (header_cbor)
   └─► header = CBOR.Decode(header_cbor)

2. Pre-filter checks
   └─► Validate sizes: |95| ≤ 8192, |97| ≤ 16400, |146| ≤ 16384, |161| ≤ 16384, |122| ≤ 1048576

3. Structure validation
   └─► Verify required keys present (90, 91, 92, ...)

4. PoP validation (join only)
   └─► leaf_id = H_L("leaf_id", [device_pk])
   └─► ML-DSA-65.Verify(device_pk, PoP_MSG, pop_sig)

5. ρ determinism
   └─► Recompute rho_raw = H_L("msphf/rho/der", [pop_sig, xk_hash])
   └─► Verify: H_L("msphf/kgen/rho", [rho_raw]) == header[93]

6. Barrier-sealed HP envelope structure (NO DECRYPT)
   └─► Validate: header[97] = ["barrier-sealed-v1", hp_ciphertext, "chacha20-poly1305"]
   └─► Require: 16 <= len(hp_ciphertext) <= 16400
   └─► Reject any legacy/unknown mode before JOIN/MERGE-specific acceptance continues

7. SRX validation (merge-only, conditional)
   └─► Join mode forbids 121/122/160/161
   └─► Merge mode requires all-or-none 121/122/160/161 per §22
   └─► Verifier sources srx_root_sw_before from durable GroupState

8. Proof verification
   └─► CAPSS Smallwood.Verify(header[146], inputs)
   └─► ZK-VRF.Verify(header[95], vrf_ctx; include 160 when SRX applies)
   └─► SRX/Smallwood.Verify(header[161], srx_ctx) only when SRX applies

9. Defense-in-depth
   └─► Cross-check: header fields vs proof bindings

10. Cache VCK
    └─► vck_cache[we_epoch_id] = (proofs_commit, expires_at)

11. Return outcome
    └─► ServerOutcome { we_epoch_id, wid }

### 8.2.1 Merge Builder (Parity-Preserving)

```
1. Gather retired heads
   └─► retired_parities = pivot_store.list(gid, parent_root)
   └─► Sort + dedupe ⇒ mh_heads (Vec<[u8;32]>)

2. Select deterministic pivot
   └─► pivot = retired_parities.max_by(accept_seq, xk_hash)

3. Inherit parity
   └─► header[93] = pivot.rho_commit  // merges NEVER mint ρ

4. Recompute seed context
   └─► seed_ctx = build_anchor_seed_ctx(header)
   └─► header[91] = H_L("seedctx", seed_ctx)
   └─► header[94] = H_L("msphf/seedbundle", [seed_ctx, pivot.rho_commit])

5. Carry proofs / suite fields verbatim
   └─► header[104/105/146/119/120–124]* = pivot snapshot

6. SRX handling
   └─► roots_changed = (111/112/113) ≠ pivot.snapshot
       · IF true  → populate_join_srx(header, parts, params)
       · IF false → strip SRX keys (120–124)

7. Derive epoch id + metadata
   └─► we_epoch_id = derive_we_epoch_id(gid, parent_root, header[91])
   └─► mh_heads recorded in header[130] (sorted)

8. Record rollup telemetry
   └─► header[131] = pivot.we_epoch_id
   └─► header[133] = epoch replay table (sorted, unique)
   └─► header[136] = KBROAD clones for `is_join=true`
   └─► header[132]/[134] = provenance / optional VCK commits

*Only the SRX keys are conditional; HP/POP material (97, 107–109) is stripped in both cases.
```

**Implementation**: [`joiner_kgen_merge_or`](../../crates/msphf-orchestrator/src/lib.rs#L2170)

**Rollup hygiene**:
- Persist `(weid → VCK, hp_envelope)` in durable storage; acceptance freezes if provenance material
  is missing at rollup time.
- Canonicalise rollup arrays (132/133/134/136) before hashing: sort by `weid`, reject duplicates,
  emit CBOR in canonical form.
- See [`examples/rollup_replay.rs`](../../crates/msphf-orchestrator/examples/rollup_replay.rs) for a
  minimal script that parses the replay metadata and recomputes the provenance/VCK commits.

```

---

### 8.3 Receiver (Client) Flow

```
1. Fetch anchor from server
   └─► GET /anchor/:we_epoch_id

2. Build ClientEpochBundle
   └─► anchor = parse_header_to_instance(header)
   └─► hp_ciphertext = header[97]
   └─► hp_aead_key = derive_kbroad_key(kbroad_sk, ct_kem)

3. Fetch witness (if needed)
   └─► GET /witness/:parent_root/:leaf_id

4. Derive epoch secrets
   └─► (epoch_key, eid) = bundle.derive_epoch_secrets()
   └─► E_k = extract_epoch_msphf_or(anchor, hp_binding, witness, hp_ct, key)

5. Decrypt messages
   └─► plaintext = AEAD.Dec(epoch_key, ciphertext)
```

---

## 9. Testing Strategy

### 9.1 Test Organization

```
crates/msphf-orchestrator/tests/
├── end_to_end.rs (workspace regression harness)
│   ├── Unit tests (individual functions)
│   ├── Integration tests (full pipeline)
│   └── Known-Answer Tests (KATs)
```

### 9.2 Test Coverage

| Component | Coverage focus |
|-----------|----------------|
| **Merkle witnesses** | Canonical format, depth, validation |
| **rpo-256/v1** | Set-hash, empty sets, large sets |
| **RLWE-HPS** | KGen, ME-OR, field ops |
| **CAPSS Smallwood** | Prove/verify, challenge derivation |
| **ZK-VRF** | Prove/verify, output-hiding |
| **Acceptance pipeline** | All 9 steps, error paths |
| **Multi-Head Window** | Join/merge, capacity, TTL |
| **SRX validation** | Frontier, anchor pool, adjacency |
| **KBROAD** | Envelope structure, registry |
| **End-to-end** | Full joiner→server→receiver flow |

**Total**: Test count is checkout-dependent (586 tests listed on February 5, 2026 in this repository; see [13 — Testing Guide](./13-testing-guide.md) for how to recalculate).

### 9.3 Known-Answer Tests (KATs)

**Blueprint Reference**: Alpha (0.1.0) §18 (Known-Answer Tests)

**Test Cases**:
- **210-226**: Merkle witnesses (membership, non-membership, depth)
- **241-245**: SRX mode (v1-complete, frontier, anchor pool)
- **251-253**: CAPSS Smallwood (wrong seed, params corruption, hp_commit mismatch)
- **261-263**: ZK-VRF (tampered proof, different hp_commit, meor_vrf_id mismatch)
- **271**: CAPSS Smallwood positive vector (verifies within FS_CAPSS_MAX_BYTES)
- **272**: ZK-VRF positive vector (verifies, Y\* not revealed)

**Location**: [crates/msphf-orchestrator/src/kat.rs](../../crates/msphf-orchestrator/src/kat.rs)

### 9.4 Security Tests

**Constant-Time Verification**:
- DUDECT harness for RLWE operations
- Validates no data-dependent branches in field arithmetic

**Side-Channel Tests**:
- Cachegrind analysis (cache access patterns)
- Timing analysis (reject sampling in noise sampling)

**Location**: [crates/dudect-harness/](../../crates/dudect-harness/)

---

## Summary

The City-G `tswe/msphf-we/fs-hybrid` implementation consists of:

1. **Core Primitives** (msphf-core, msphf-rlwe): RLWE arithmetic, Merkle trees, hashing
2. **Orchestration** (msphf-orchestrator): Server acceptance, client KGen, proofs, MHW
3. **APIs** (cityg-client, cityg-server): Thin wrappers with public-only interfaces
4. **Support** (anchor-seed, msphf-lb-vrf): Helper crates for seed context and ZK-VRF

**Key Architectural Decisions**:
- **Type-safe server blindness**: No secret key fields in `AcceptanceContext`
- **Modular proof systems**: CAPSS Smallwood and ZK-VRF as separate modules
- **Canonical witness format**: Strict validation (depth≤64, sorted, anchored)
- **Multi-Head Window**: Time-bounded, capacity-limited concurrency control

**Code Quality**:
- ~18,000 lines of Rust (excluding tests)
- Workspace currently lists 586 tests in this checkout (February 5, 2026); verify pass/fail with `cargo test --all`
- No `unsafe` in the acceptance path; optional `unsafe-ntt` exists in `msphf-core` behind a feature flag
- Constant-time critical operations (NTT, field arithmetic)

**Next**: [12 — Error Reference](./12-error-reference.md)

---

**Document Version**: 0.1.0
**Blueprint Reference**: Alpha (0.1.0) (entire spec)
**Implementation**: City-G 0.1.0
