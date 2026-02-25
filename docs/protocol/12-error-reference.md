# 12 — Error Reference

> [!IMPORTANT]
> This chapter is a legacy companion document. For `tswe/msphf-we/fs-hybrid`, the normative source is [`../specs.md`](../specs.md).
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and implementation.


**Profile**: City-G `tswe/msphf-we/fs-hybrid` (Alpha (0.1.0))
**Status**: Normative (error codes and semantics)

## Table of Contents

1. [Introduction](#1-introduction)
2. [Error Semantics](#2-error-semantics)
3. [Error Code Structure](#3-error-code-structure)
4. [Complete Error Catalog](#4-complete-error-catalog)
5. [Error Handling Guidelines](#5-error-handling-guidelines)
6. [Mapping to Implementation](#6-mapping-to-implementation)

---

## 1. Introduction

This document provides a catalog of deterministic protocol outcome codes for
City-G `tswe/msphf-we/fs-hybrid`. The unified action model is
`REJECT(code)` for protocol validation failures. Some implementation modules
still use the historical `FreezeError` type name for numeric codes.

**Blueprint Reference**: Alpha (0.1.0) §15 (Error Semantics and Codes)

### 1.1 Purpose

Error codes serve multiple purposes:
1. **Deterministic validation**: Same input → same error code
2. **Cache efficiency**: Server can cache deterministic outcomes (VCK cache)
3. **Debugging**: Precise error reasons for client/publisher diagnosis
4. **Auditability**: Outcome codes are logged for transparency
5. **DoS mitigation**: Fast rejection of malformed requests

---

## 2. Error Semantics

### 2.1 Action Model

| Error Type | Cacheability | Determinism | Use Case |
|------------|--------------|-------------|----------|
| **REJECT(code)** | ✅ Cacheable (by implementation policy) | ✅ Deterministic | Protocol validation failure (PoP, proofs, witnesses) |
| **DROP / QUARANTINE / FREEZE(group)** | ⚠️ Operational policy | context-dependent | Optional anti-spam or authenticated corruption handling |
| **Reject (transport/internal)** | ❌ Not protocol-cacheable | ⚠️ May vary | Transient server/runtime failures |

`REJECT(code)` means the input is invalid under protocol rules. No acceptance
state is mutated for that input.

**Blueprint Quote** (Alpha (0.1.0) §15):
> Reject: stateless failure; not cacheable. Freeze(code,reason): deterministic, cacheable.

---

### 2.2 Deterministic-Code Properties

**Deterministic**:
```
∀ anchor A, server S:
  S.validate(A) = REJECT(code)
  ⇒ S.validate(A) = REJECT(code) (always)
```

**Cacheable**:
```
VCK (Verify-Cache Key) = H_L("msphf/proofs", [95, 146, (160,161 if present)])
Cache entry: (VCK, outcome_code, expires_at)
```

**Public**:
- Outcome codes do not leak secrets (no hp, Y\*, E_k in error messages)
- Reason strings are generic ("proof_invalid", not specific Y\* values)

### 2.3 Transport mapping & retry guidance

| Error class | HTTP status | gRPC status | Retry guidance |
|-------------|-------------|-------------|----------------|
| `907.x` (malformed CBOR/structure) | `400 Bad Request` | `INVALID_ARGUMENT` | ❌ Do not retry (input malformed) |
| `921-934` (cryptographic/proof failures) | `400 Bad Request` | `FAILED_PRECONDITION` | ❌ Permanent until client fixes anchor |
| `944.x` (suite deprecated/unsupported) | `400 Bad Request` | `UNIMPLEMENTED` | ❌ Permanent until policy updated |
| `947.x` (forward-leap guards) | `409 Conflict` | `ABORTED` | ⚠️ Retry only after the server’s `A` advances (e.g., after later epochs) |
| `925` (window full) | `429 Too Many Requests` | `RESOURCE_EXHAUSTED` | ⏳ Retry with backoff once telemetry indicates capacity freed |
| `Reject` (transient errors) | `503 Service Unavailable` | `UNAVAILABLE` | ⏳ Retry with exponential backoff |

Servers SHOULD include a `Retry-After` header for 925/947-class freezes to signal when a client may safely retry. Freeze codes remain deterministic; the transport mapping simply communicates whether immediate retry is meaningful.

---

## 3. Error Code Structure

### 3.1 Code Ranges

| Range | Category | Examples |
|-------|----------|----------|
| **907.x** | Structural/CBOR | 907.1 (malformed), 907.2 (nonmem), 907.3 (leaf bind) |
| **921-928** | Cryptographic | 921 (CRS untrusted), 922 (seedctx), 923 (proofs), 924 (rho) |
| **929-930** | SRX | 929 (srx_required), 930 (srx_invalid) |
| **931-934** | Policy | 931 (bootstrap), 932 (unsupported), 934 (suite deprecated) |

### 3.2 Reason Strings

Reason strings are **lowercase**, **snake_case**, and **generic**:
- ✅ "msphf_lin_invalid" (good)
- ❌ "CAPSS Smallwood proof failed: challenge mismatch at step 3" (too specific, leaks info)

**Format**:
```
Freeze(code: u16, reason: &'static str)
```

**Example**:
```rust
pub const FREEZE_CAPSS_INVALID: FreezeError = FreezeError {
    code: 923,
    reason: "msphf_lin_invalid",
};
```

---

## 4. Complete Error Catalog

### 4.1 Structural Errors (907.x)

#### 907.1 — cbor_malformed

**Category**: CBOR encoding errors
**Cacheability**: ✅ Freeze
**Description**: Header failed basic structural checks (malformed CBOR, missing required field, wrong type, unknown key, or duplicate key).

**Sub-reasons**:
- `field_missing`: Required header key absent or of the wrong type

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §15, code 907.1

**Example Trigger**:
```rust
// Missing required key (93)
let mut header = valid_header();
header.remove(&93); // msphf_kgen_rho_commit
// Result: Freeze(907.1, "field_missing")
```

---

#### 907.2 — nonmem_noncanonical

**Category**: Non-membership witness validation
**Cacheability**: ✅ Freeze
**Description**: Non-membership witness is not in canonical format (invalid path, interval mismatch, adjacency failure).

**Sub-reasons**:
- `nonmem_path_invalid`: Merkle path does not verify
- `nonmem_interval_mismatch`: Interval (left, right) does not contain leaf_id
- `nonmem_adj_incoherent`: Anchored adjacency check failed (SRX)

**Implementation**: [crates/msphf-core/src/witness.rs](../../crates/msphf-core/src/witness.rs)

**Blueprint**: Alpha (0.1.0) §5 (Canonical Witnesses), §15

**Example Trigger**:
```rust
// Tampered non-membership path
let mut nonmem = valid_nonmem_witness();
nonmem.left_path[0].1[0] ^= 0xFF; // Corrupt sibling hash
// Result: Freeze(907.2, "nonmem_path_invalid")
```

---

#### 907.21 — mem_malformed

**Category**: Membership witness validation
**Cacheability**: ✅ Freeze
**Description**: Membership witness is malformed (CBOR parse error, invalid structure).

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §15, code 907.21

---

#### 907.3 — leaf_bind_mismatch

**Category**: Leaf ID binding
**Cacheability**: ✅ Freeze
**Description**: Computed `leaf_id` from PoP does not match witness leaf_id.

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §15, code 907.3

**Example Trigger**:
```rust
// PoP signature for device A, but witness for device B
let leaf_id_a = H_L("leaf_id", [device_pk_a]);
let witness_b = membership_witness(leaf_id_b);
// Result: Freeze(907.3, "leaf_bind_mismatch")
```

---

#### 907.4 — proj_eval_fail

**Category**: SPHF projection evaluation
**Cacheability**: ✅ Freeze
**Description**: ME-OR projection evaluation failed (invalid RLWE parameters, arithmetic error).

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §15, code 907.4

---

#### 907.5 — path_oversize

**Category**: Merkle witness depth
**Cacheability**: ✅ Freeze
**Description**: Merkle path depth exceeds 64 (specification limit).

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §5 (depth ≤ 64), §15

**Example Trigger**:
```rust
// Path with 65 entries
let mut path = vec![(0u8, [0u8; 32]); 65];
// Result: Freeze(907.5, "path_oversize")
```

---

#### 907.6 — set_conflict

**Category**: Set-hash conflicts
**Cacheability**: ✅ Freeze
**Description**: Conflicting set relations (e.g., leaf in both parent and revoked sets).

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §15, code 907.6

---

### 4.2 Cryptographic Errors (921-928)

#### 921 — msphf_crs_untrusted

**Category**: CRS/policy validation
**Cacheability**: ✅ Freeze
**Description**: Algorithm, suite, or policy violation (untrusted CRS, forbidden parent EID, invalid PoP).

**Sub-reasons**:
- `kbroad_parent_mismatch`: KBROAD public key mismatch (registry check)
- `leafid_policy`: Leaf ID mode policy violation
- `parent_eid_forbidden`: Parent-EID envelope forbidden (Alpha (0.1.0))
- `pop_invalid`: PoP signature verification failed

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §15, code 921

**Example Trigger**:
```rust
// Wrong KBROAD public key
let mut header = valid_header();
header[&104] = wrong_kbroad_pub; // Mismatch with registry
// Result: Freeze(921, "kbroad_parent_mismatch")
```

---

#### 922 — msphf_seedctx_mismatch

**Category**: Seed context validation
**Cacheability**: ✅ Freeze
**Description**: `seed_ctx_hash` (91) does not match recomputed value from ANCHOR_SEED_CTX.

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §12.0-bis (ANCHOR_SEED_CTX), §15

**Example Trigger**:
```rust
// Tampered seed_ctx_hash
let mut header = valid_header();
header[&91] = [0u8; 32]; // Wrong seed_ctx_hash
// Result: Freeze(922, "msphf_seedctx_mismatch")
```

---

#### 923 — proof_invalid

**Category**: Proof verification
**Cacheability**: ✅ Freeze
**Description**: CAPSS Smallwood or ZK-VRF proof verification failed.

**Sub-reasons**:
- `msphf_lin_invalid`: CAPSS Smallwood proof failed (Step 7.1)
- `vrf_invalid`: ZK-VRF proof failed (Step 7.2)
- `msphf_hp_binding_invalid`: HP binding check failed (Stark oversize)

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §12.2 (Step 7), §15

**Example Trigger**:
```rust
// Tampered CAPSS Smallwood transcript
let mut header = valid_header();
header[&146][0] ^= 0xFF; // Corrupt first byte
// Result: Freeze(923, "msphf_lin_invalid")
```

---

#### 924 — msphf_rho_parity

**Category**: ρ determinism
**Cacheability**: ✅ Freeze
**Description**: ρ commitment (93) mismatch — ρ is not deterministically derived from PoP signature.

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §12.2 (Step 4.1), §15

**Example Trigger**:
```rust
// Wrong rho_commit
let rho_raw = h_l("msphf/rho/der", [pop_sig, xk_hash]);
let correct_rho_commit = h_l("msphf/kgen/rho", [rho_raw]);
header[&93] = [0u8; 32]; // Wrong commitment
// Result: Freeze(924, "msphf_rho_parity")
```

---

#### 925 — mh_window_full

**Category**: Multi-Head Window capacity
**Cacheability**: ✅ Freeze (transient, but cacheable per WID)
**Description**: MHW capacity exceeded (H_MAX heads already present for this WID).

**Implementation**: [crates/msphf-orchestrator/src/mhw.rs](../../crates/msphf-orchestrator/src/mhw.rs)

**Blueprint**: Alpha (0.1.0) §13 (MHW), Annex M

**Example Trigger**:
```rust
// 16 heads already present (H_MAX=16)
for _ in 0..16 {
    ctx.mh_window.accept_head(wid, we_epoch_id, now)?;
}
// 17th head:
// Result: REJECT(925, "mh_window_full")
```

---

#### 927 — mh_heads_invalid

**Category**: Merge mode validation
**Cacheability**: ✅ Freeze
**Description**: Merge mode: one or more `retire_heads` not found in MHW.

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §13 (Merge Mode), §15

**Example Trigger**:
```rust
// Merge with non-existent retire_head
let retire_heads = vec![fake_we_epoch_id]; // Not in MHW
// Result: Freeze(927, "mh_heads_invalid")
```

---

#### 928 — epochid_mismatch

**Category**: Epoch ID validation
**Cacheability**: ✅ Freeze
**Description**: Computed `we_epoch_id` does not match expected value.

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §15, code 928

---

### 4.3 SRX Errors (929-930)

#### 929 — srx_required

**Category**: SRX policy
**Cacheability**: ✅ Freeze
**Description**: SRX payload required but missing (policy enforcement).

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §15, code 929

---

#### 930 — srx_invalid

**Category**: SRX validation
**Cacheability**: ✅ Freeze
**Description**: SRX payload validation failed (completeness, anchoring, canonicity).

**Sub-reasons**:
- `srx_oversize_hint`: Hints exceed budget (MAX_HINT_COUNTS, MAX_HINT_SIZES)
- `srx_hint_under`: Insufficient hints for tree size
- `srx_frontier_mismatch`: Frontier does not match parent_root
- `srx_anchor_missing`: Expected anchor not in anchor pool
- `srx_anchor_mismatch`: Anchor root mismatch
- `srx_anchor_oob`: Anchor index out of bounds
- `srx_anchor_pool_unsorted`: Anchor pool not sorted
- `srx_anchors_overbudget`: Too many anchors (DoS limit)
- `srx_commit_mismatch`: SRX commit (121) mismatch

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) Appendix F (SRX), §15

**Example Trigger**:
```rust
// Frontier mismatch
let srx = build_srx_payload();
srx.frontier[0] ^= 0xFF; // Corrupt frontier entry
// Result: Freeze(930, "srx_frontier_mismatch")
```

---

### 4.4 Policy Errors (931-934)

#### 931 — bootstrap_invalid

**Category**: Bootstrap validation
**Cacheability**: ✅ Freeze
**Description**: Bootstrap anchor validation failed (Genesis profile).

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) Appendix G (Bootstrap Profile), §15

---

#### 932 — bootstrap_unsupported

**Category**: Bootstrap policy
**Cacheability**: ✅ Freeze
**Description**: Bootstrap mode not supported by server policy.

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §15, code 932

---

#### 934 — suite_deprecated

**Category**: Suite policy
**Cacheability**: ✅ Freeze
**Description**: Algorithm suite is deprecated or forbidden by policy (e.g., wrong AEAD, CRS, VRF ID).

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Blueprint**: Alpha (0.1.0) §12.1 (Algorithm Gates), §15

**Example Trigger**:
```rust
// Wrong AEAD suite
let mut kbroad_envelope = valid_envelope();
kbroad_envelope[4] = "aes-gcm"; // Not chacha20-poly1305
// Result: Freeze(934, "suite_deprecated")
```

---

### 4.5 Barrier & FS-Hybrid Error Codes (v0.1.2)

> [!IMPORTANT]
> The following error codes are defined in specs.md S13 (v0.1.2). For normative definitions, see [`../specs.md`](../specs.md) section S13.

#### Barrier codes (960.x)

| Code | Name | Scope |
|------|------|-------|
| 960.1 | barrier_updater_invalid | Server + client |
| 960.2 | barrier_recover_multi_match | Client |
| 960.3 | barrier_expectedpairs_failure | Server |
| 960.4 | barrier_merge_delegation_forbidden | Server |
| 960.5 | barrier_proactive_forbidden | Server |
| 960.6 | barrier_recover_no_match | Client-local only |
| 960.7 | barrier_update_malformed | Server + client |
| 960.8 | barrier_tree_hash_chain_failure | Server + FULL client |
| 960.9 | barrier_tree_snapshot_auth_failure | Client-local / updater-local |
| 960.10 | barrier_genesis_required | Server |
| 960.11 | barrier_update_required_on_revocation_change | Server |
| 960.12 | pcs_refresh_rate_limited | Server |
| 960.13 | pcs_refresh_forbidden_while_pending_revocations | Server |

**Encoding note**: Dotted forms (e.g., `960.10`) are the documentation form. In machine fields, implementations encode as decimal digits without a dot (e.g., `96010`).

#### FS/acceptance codes

| Code | Name |
|------|------|
| 907.1 | malformed CBOR / unknown key / duplicate key |
| 945.0 | fs_base_mismatch |
| 947.0 | fs_dev_chain_break |
| 947.2 | fs_dev_chain_bind_mismatch |
| 947.4 | fs_forward_jump_device |
| 947.5 | fs_forward_jump_first |
| 947.6 | fs_forward_jump_group |
| 948.0 | fs_policy_window_incompatible |
| 944.6 | fs_policy_version_unsupported |

---

### 4.6 Implementation-Specific Errors (Legacy)

These errors are defined in the implementation but not explicitly listed in Alpha (0.1.0) §15:

#### FREEZE_MERGE_JOIN_KEYS (155)

**Description**: Merge mode anchor contains join-only keys (e.g., 97, 107-109).

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

#### FREEZE_PARAMS_ID_INVALID (160)

**Description**: RLWE-HPS params_id (106) is invalid or untrusted.

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

#### FREEZE_TSWE_SALT_MISMATCH (165)

**Description**: TSWE algorithm salt mismatch (reserved for future use).

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

#### FREEZE_NONMEM_ADJ_INCOHERENT (323)

**Description**: Non-membership witness anchored adjacency check failed (SRX).

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

#### FREEZE_ENVELOPE_COMMIT_MISMATCH (338)

**Description**: KBROAD envelope commitment mismatch (reserved, not actively used).

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

#### FREEZE_ENVELOPE_ENC_INVALID (343)

**Description**: KBROAD envelope encryption structure invalid.

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

#### FREEZE_POP_INVALID (348)

**Description**: PoP signature verification failed (ML-DSA-65).

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

## 5. Error Handling Guidelines

### 5.1 Server Implementation

**Freeze Handling**:
```rust
match ctx.accept_anchor(&parts, &we_epoch_id, &header, now) {
    Ok(()) => {
        // Cache success (VCK)
        ctx.cache_vck(&we_epoch_id, &header, now);
        return Ok(ServerOutcome { we_epoch_id, wid });
    }
    Err(AcceptanceError::Freeze(freeze)) => {
        // Cache freeze decision
        ctx.cache_freeze(&we_epoch_id, freeze, now);
        return Err(ServerError::Freeze(freeze));
    }
    Err(AcceptanceError::Reject(reason)) => {
        // Transient error, do not cache
        return Err(ServerError::Reject(reason));
    }
}
```

**Cache Key** (VCK):
```rust
let vck = h_l("msphf/proofs", &ProofsCommit {
    vrf_proof: header[&95],
    fs_capss: header[&146],
})?;
```

---

### 5.2 Client Implementation

**Retry Logic**:
```rust
match client.submit_anchor(anchor) {
    Ok(outcome) => {
        // Success
        println!("Anchor accepted: {:?}", outcome);
    }
    Err(ServerError::Freeze(freeze)) => {
        // Permanent failure, do not retry
        eprintln!("Anchor frozen: code={}, reason={}", freeze.code, freeze.reason);
        // Diagnose: check PoP, proofs, SRX payload
    }
    Err(ServerError::Reject(reason)) => {
        // Transient failure, may retry with backoff
        eprintln!("Server rejected: {}", reason);
        // Retry with exponential backoff
    }
}
```

**Diagnostic Mapping**:
| Freeze Code | Likely Cause | Action |
|-------------|--------------|--------|
| 921 ("pop_invalid") | PoP signature wrong | Re-sign with correct device key |
| 922 ("msphf_seedctx_mismatch") | ANCHOR_SEED_CTX tampering | Rebuild header from scratch |
| 923 ("msphf_lin_invalid") | CAPSS Smallwood proof wrong | Regenerate proof with correct seed_DRBG |
| 923 ("vrf_invalid") | ZK-VRF proof wrong | Regenerate proof with correct hp |
| 924 ("msphf_rho_parity") | ρ not deterministic | Check PoP signature determinism |
| 930 ("srx_invalid") | SRX payload wrong | Rebuild SRX with correct frontier/anchors |

---

### 5.3 Logging and Monitoring

**Server Logging**:
```rust
tracing::warn!(
    freeze_code = freeze.code,
    freeze_reason = freeze.reason,
    we_epoch_id = ?we_epoch_id,
    wid = ?wid,
    "Anchor frozen"
);
```

**Metrics**:
- `freeze_total{code="923", reason="msphf_lin_invalid"}` (counter)
- `freeze_rate{window="1m"}` (gauge)
- `cache_hit_ratio` (VCK cache efficiency)

**Alerting**:
- Spike in 923 ("proof_invalid") → possible proof generation bug
- High 925 ("mh_window_full") → capacity planning needed
- 934 ("suite_deprecated") → client using old suite

---

## 6. Mapping to Implementation

### 6.1 Error Constants

**Location**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Definition Pattern**:
```rust
pub const FREEZE_<NAME>: FreezeError = FreezeError {
    code: <CODE>,
    reason: "<reason>",
};
```

**Example**:
```rust
pub const FREEZE_CAPSS_INVALID: FreezeError = FreezeError {
    code: 923,
    reason: "msphf_lin_invalid",
};
```

---

### 6.2 Error Conversion

**WitnessValidationError → FreezeError**:
```rust
// crates/msphf-orchestrator/src/accept/mod.rs
impl From<WitnessValidationError> for FreezeError {
    fn from(err: WitnessValidationError) -> Self {
        match err {
            WitnessValidationError::CborMalformed => FREEZE_HASH_CBOR,
            WitnessValidationError::NonCanonical => FREEZE_HASH_NONCANONICAL,
            WitnessValidationError::LeafBindMismatch => FREEZE_HASH_LEAF_BIND,
            WitnessValidationError::ProjEvalFail => FREEZE_HASH_PROJ_FAIL,
            WitnessValidationError::PathOversize => FREEZE_HASH_PATH_OVERSIZE,
        }
    }
}
```

---

### 6.3 AcceptanceError Enum

**Location**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Definition**:
```rust
pub enum AcceptanceError {
    Freeze(FreezeError),
    Reject(String),
}
```

**Usage**:
```rust
// Freeze (deterministic, cacheable)
return Err(AcceptanceError::Freeze(FREEZE_POP_INVALID));

// Reject (transient, not cacheable)
return Err(AcceptanceError::Reject("internal_error".to_string()));
```

---

## Summary

The City-G `tswe/msphf-we/fs-hybrid` protocol defines **deterministic, cacheable freeze codes** for validation failures:

1. **Structural (907.x)**: CBOR, witnesses, leaf binding (12 codes)
2. **Cryptographic (921-928)**: CRS, proofs, ρ determinism (8 codes)
3. **SRX (929-930)**: Completeness, anchoring (10+ sub-codes)
4. **Policy (931-934)**: Bootstrap, suite deprecation (4 codes)

**Key Properties**:
- ✅ **Deterministic**: Same input → same freeze code
- ✅ **Cacheable**: VCK = H_L("msphf/proofs", [95, 146])
- ✅ **Generic**: Reason strings do not leak secrets
- ✅ **Auditable**: All freeze codes logged

**Error Handling**:
- **Freeze**: Permanent failure, do not retry, diagnose root cause
- **Reject**: Transient failure, may retry with backoff

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs) (60-367, 448-465)

**Next**: [13 — Testing Guide](./13-testing-guide.md)

---

**Document Version**: 0.1.0
**Blueprint Reference**: Alpha (0.1.0) §15
**Implementation**: City-G 0.1.0
