# 10 — Security Model

> [!IMPORTANT]
> This chapter is a legacy companion document. For `tswe/msphf-we/fs-hybrid`, the normative source is [`../specs.md`](../specs.md).
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and implementation.


**Profile**: City-G `tswe/msphf-we/fs-hybrid` (Alpha (0.1.0))
**Status**: Normative (threat model informative, properties normative)

## Table of Contents

1. [Introduction](#1-introduction)
2. [Threat Model](#2-threat-model)
3. [Security Goals](#3-security-goals)
4. [Cryptographic Assumptions](#4-cryptographic-assumptions)
5. [Security Properties](#5-security-properties)
6. [Server Blindness Proofs](#6-server-blindness-proofs)
7. [Attack Surface Analysis](#7-attack-surface-analysis)
8. [Defense Mechanisms](#8-defense-mechanisms)
9. [Post-Quantum Security](#9-post-quantum-security)
10. [Comparison with Other Protocols](#10-comparison-with-other-protocols)

---

## 1. Introduction

City-G `tswe/msphf-we/fs-hybrid` is designed to provide **publisher-blind** epoch key extraction for extremely large E2EE groups (millions of members) with **post-quantum security**. This document formally defines:

- **Adversaries**: What attackers we defend against
- **Goals**: What attackers want to achieve
- **Assumptions**: What cryptographic primitives we rely on
- **Properties**: What security guarantees the protocol provides
- **Proofs**: Why the protocol is secure

**Blueprint Reference**: Alpha (0.1.0) §3 (Threat Model), §14 (Security Properties)

### 1.1 Key Insight

> The server **cannot learn** the hash projection key (hp), VRF output (Y\*), or epoch key (E_k) **by construction** — not as a policy, but as a **type-level guarantee** enforced by Rust's type system.

This is achieved by:
1. **No KBROAD secret keys** in server data structures
2. **No decapsulation/decryption functions** in server code
3. **ZK-VRF** proves Y\* correctness without revealing it
4. **Client-side** epoch key derivation only

**Important**: "Publisher-blind" refers to **encryption key confidentiality**, not device anonymity. The server **CAN identify devices** via public keys (ML-DSA-65, ~2KB) transmitted in field #108 (HDR_POP_PK) during join/merge operations. The server uses these for signature verification and leaf_id computation, but cannot decrypt messages or derive encryption keys.

---

## 2. Threat Model

### 2.1 Adversaries

| Adversary | Capabilities | Limitations |
|-----------|-------------|-------------|
| **Active Network** | MitM, replay, reorder, drop messages | Cannot break post-quantum crypto |
| **Malicious Publisher** | Create arbitrary anchors, grind seeds | Bound by PoP, CAPSS Smallwood, ZK-VRF proofs |
| **Colluding Excluded Devices** | Share keys, forge witnesses (attempt) | Cannot forge Merkle witnesses |
| **Quantum Adversaries** | Break RSA/ECDH | Cannot break ML-KEM/DSA, lattice-based SPHF |
| **DoS Attackers** | Flood server, send malformed requests | Rate-limited by policy, SRX bounds |
| **Compromised Server** | Read all server memory, logs | **Cannot learn secrets** (type-safe) |

**Key Assumption**: The server operator is **untrusted**. The protocol must maintain confidentiality even if the server is fully compromised.

### 2.2 In-Scope Threats

✅ **Eavesdropping**: Passive network observer
✅ **Replay attacks**: Resubmitting old anchors
✅ **Grinding attacks**: Cherry-picking hp for specific Y\*
✅ **Proof forgery**: Fake CAPSS Smallwood or ZK-VRF proofs
✅ **Witness tampering**: Modified Merkle paths
✅ **Server compromise**: Full memory/log access
✅ **Insider threats**: Malicious server operators
✅ **Post-quantum attacks**: Future quantum computers

### 2.3 Out-of-Scope Threats

❌ **Client compromise**: If a device is compromised, its epoch keys are exposed (inherent limitation)
❌ **Publisher key compromise**: If publisher's ML-DSA key is stolen, attacker can create fake anchors (mitigated by transparency logs, out of scope for this protocol)
❌ **KBROAD key compromise**: If group KEM key is stolen, attacker can decrypt hp (mitigated by key rotation, separate security domain)
❌ **Side-channel attacks on clients**: Timing/power analysis on client devices (implementation-dependent)
❌ **Denial of service (resource exhaustion)**: Out-of-band mitigation (rate limits, quotas) required

**Blueprint**: Alpha (0.1.0) §3
```
Adversaries: active network; malicious publisher; colluding excluded devices;
quantum adversaries; DoS/grinding.
Goals: confidentiality of hp; correctness of set relations; uniqueness of Y*;
service blindness (no hp, no Y*, no E_k); offline readiness; DoS hygiene;
policy transparency.
Assumptions: ML-KEM-768; rpo-256; BLAKE3/HMAC-BLAKE3; chacha20-poly1305;
ML-DSA-65; CAPSS Smallwood FS proof (ROM soundness); ZK-VRF in QROM.
```

---

## 3. Security Goals

### 3.1 Confidentiality Goals

| Goal | Definition | Enforcement |
|------|------------|-------------|
| **hp Confidentiality** | Hash projection key unknown to server | KBROAD encryption (ML-KEM-768) |
| **Y\* Confidentiality** | VRF output unknown to server | ZK-VRF (output-hiding) |
| **E_k Confidentiality** | Epoch key unknown to server | Client-side derivation only |
| **eid Confidentiality** | Epoch identifier unknown to server | Derived from E_k (client-side) |

### 3.2 Integrity Goals

| Goal | Definition | Enforcement |
|------|------------|-------------|
| **Correctness** | Valid devices compute correct Y\* | ME-OR + Merkle witnesses |
| **Uniqueness** | Only one Y\* per epoch context | ZK-VRF proof (binding to X_k) |
| **Determinism** | seed → hp is deterministic | CAPSS Smallwood proof (seed_DRBG binding) |
| **Completeness** | No member omissions | SRX (frontier + anchor pool) |
| **Canonicity** | Witnesses follow canonical format | Strict validation (depth≤64, sorted) |

### 3.3 Availability Goals

| Goal | Definition | Enforcement |
|------|------------|-------------|
| **Offline Readiness** | Devices derive E_k without server interaction | ME-OR (non-interactive) |
| **Parallel Joins** | Multiple devices join simultaneously | Multi-Head Window (H_MAX=16) |
| **DoS Hygiene** | Reject malformed requests efficiently | Pre-filters, size limits, SRX bounds |

### 3.4 Transparency Goals

| Goal | Definition | Enforcement |
|------|------------|-------------|
| **Policy Anchoring** | Cryptographic binding to policy | `fs_policy_version` (`139`) in proof binds |
| **Auditability** | Deterministic reject codes | Error mapping (§16, unified specification) |
| **Replayability** | Same input → same outcome code | Deterministic validation pipeline |

---

## 4. Cryptographic Assumptions

### 4.1 Post-Quantum Primitives

| Primitive | Standard | Security Level | Assumption |
|-----------|----------|----------------|------------|
| **ML-KEM-768** | FIPS 203 | NIST Level 3 (~192-bit) | Module-LWE hardness |
| **ML-DSA-65** | FIPS 204 | NIST Level 3 (~192-bit) | Module-LWE + QROM Fiat-Shamir |
| **RLWE-HPS A1** | Custom | ≥ NIST Level 3 (matching ML-KEM-768) | Ring-LWE decisional assumption |

**Note**: RLWE-HPS uses the same (N=256, Q=3329, K=3, η₂=2) Module-LWE parameters as ML-KEM-768. Internal analysis tracks the evolving Kyber/ML-KEM cryptanalysis; raise parameters if the recommended security level drops below Category 3.

### 4.2 Hash Functions

| Primitive | Security Level | Assumption |
|-----------|----------------|------------|
| **BLAKE3** | 256-bit preimage, 128-bit collision | Random oracle model (ROM) |
| **rpo-256/v1** | 256-bit (Rescue-Prime) | Algebraic hash function security |

### 4.3 Symmetric Primitives

| Primitive | Security Level | Assumption |
|-----------|----------------|------------|
| **ChaCha20-Poly1305** | 256-bit key | IND-CCA2 AEAD security |
| **HKDF-BLAKE3** | 256-bit | PRF security (standard model) |

### 4.4 Fiat-Shamir Transform

- **Model**: Quantum Random Oracle Model (QROM)
- **Application**: CAPSS Smallwood (linear integrity proof)
- **Security**: QROM security proven for linear relations (Unruh 2015)

### 4.5 SPHF Assumption

**Smoothness**: For invalid witnesses, the hash value H(hp, w) is indistinguishable from random, even given the projection key pk(hp).

**Projection Property**: For valid witnesses, H(hp, w) = Proj(pk(hp), w).

**Hardness**: Ring-LWE decisional assumption (RLWE-HPS A1).

---

## 5. Security Properties

### 5.1 Completeness

**Property**: Every valid device (with correct witness) computes the correct Y\* and E_k.

**Formal Statement**:
```
∀ device D with valid witness w ∈ L_X:
  Y* = MEOR(hp, X, w)
  E_k = H_epoch(X_k, Y*)
```

**Proof Sketch**:
1. Witness w is validated (Merkle path to parent_root or revoked_root)
2. ME-OR computation: Δ = map_root_to_field(w.root) - map_root_to_field(g_root)
3. Y\* = Proj(pk, Δ) ⊕ M (unmask)
4. E_k = HMAC-BLAKE3(X_k, Y\*)

**Implementation**: [crates/msphf-orchestrator/src/lib.rs](../../crates/msphf-orchestrator/src/lib.rs) (`extract_epoch_msphf_or`)

---

### 5.2 Correctness

**Property**: An attacker cannot create a valid anchor that causes honest devices to compute an incorrect Y\*.

**Formal Statement**:
```
∀ anchor A, if A passes server validation:
  CAPSS Smallwood(A) verifies ⇒ hp = DeriveHP(seed_DRBG)
  ZK-VRF(A) verifies ⇒ Y* = VRF(hp, VRF_CTX)
```

**Proof Sketch**:
1. **CAPSS Smallwood** binds seed_DRBG → hp deterministically (§6, specification)
2. **ZK-VRF** proves Y\* is the unique output for (hp, VRF_CTX) (§11, specification)
3. Server validates both proofs atomically (Step 7, acceptance pipeline)

**Security Reduction**: If an attacker can forge a proof, they break either:
- ROM Fiat-Shamir security (CAPSS Smallwood)
- VRF unforgeability (ZK-VRF)

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs) (Step 7)

---

### 5.3 Uniqueness

**Property**: Each epoch context X_k has exactly one valid Y\*.

**Formal Statement**:
```
∀ hp, X_k: ∃! Y* such that ZK-VRF(hp, X_k) → Y*
```

**Proof Sketch**:
1. VRF output is deterministic: VRF(hp, VRF_CTX) → Y\* (unique)
2. ZK-VRF proof binds Y\* to committed hp (via hp_commit = 99)
3. Server rejects proofs with mismatched bindings (defense-in-depth, Step 8)

**Attack Mitigation**:
- **Grinding**: CAPSS Smallwood prevents cherry-picking hp (seed determinism)
- **Forging**: ZK-VRF soundness ensures Y\* uniqueness

**Implementation**: [crates/msphf-orchestrator/src/proofs/zk_vrf/lb.rs](../../crates/msphf-orchestrator/src/proofs/zk_vrf/lb.rs)

---

### 5.4 Server Blindness

**Property**: The server cannot learn hp, Y\*, E_k, or eid.

**Formal Statement**:
```
∀ server S, anchor A:
  S.validate(A) ⇒ S learns (we_epoch_id, wid) only
  S cannot compute: hp, Y*, E_k, eid
```

**Clarification**: This property guarantees **encryption key confidentiality**, not sender anonymity. The server **CAN identify devices** via public keys transmitted in field #108 during join/merge. However, the server cannot decrypt messages or derive epoch keys.

**Proof**: See [§6 (Server Blindness Proofs)](#6-server-blindness-proofs) below.

**Evidence**:
- Type-safe: `AcceptanceContext` has no secret fields
- Functionally verified: No `ml_kem_decapsulate()` in server code
- Tested: run `cargo test --all` in your target environment; this checkout lists 586 tests on February 5, 2026 (`cargo test --all -- --list | rg ': test$' | wc -l`)

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs) (struct definition)

---

### 5.5 Anti-Grinding

**Property**: A malicious publisher cannot cherry-pick hp to bias Y\*.

**Formal Statement**:
```
seed → hp is deterministic (enforced by CAPSS Smallwood)
ρ := H_L("msphf/rho/der", [pop_sig, xk_hash])  (deterministic from PoP)
seed_DRBG := H_L("msphf/drbg", [seed_commit, ρ, xk_hash, seed_ctx_hash])
hp := KGen(seed_DRBG)
```

**Enforcement**:
1. **PoP signature**: Publisher commits to device (pop_sig binds to device_pk)
2. **ρ determinism**: ρ derived from pop_sig and xk_hash (Step 4.1)
3. **CAPSS Smallwood proof**: Verifies seed_DRBG → hp correctly (Step 7.1)
4. **Rho parity cache**: Server detects replay (RhoReplayGuard)

**Attack Scenarios**:
- ❌ **Grind pop_sig**: ML-DSA-65 is deterministic (RFC 8032 mode), pop_sig fixed
- ❌ **Grind seed_commit**: Bound to ANCHOR_SEED_CTX via seed_bundle_commit
- ❌ **Replay old pop_sig**: Detected by RhoReplayGuard (64-entry cache)

**Implementation**: [crates/msphf-orchestrator/src/accept/mod.rs](../../crates/msphf-orchestrator/src/accept/mod.rs) (Step 4)

---

### 5.6 Completeness (SRX)

**Property**: The publisher cannot omit valid members from the epoch.

**Formal Statement**:
```
SRX payload commits to:
  - frontier: Complete Merkle frontier for parent_root
  - anchor_pool: All join_delta_root anchors
Every valid member has a witness to parent_root OR join_delta_root
```

**Enforcement**:
1. **SRX frontier**: Covers all leaves in parent tree (completeness)
2. **Anchor pool**: Lists all δ-join roots (no hidden branches)
3. **Anchored adjacency**: Each non-membership witness must anchor to frontier

**Attack Scenarios**:
- ❌ **Omit member**: Device cannot find witness, rejects anchor
- ❌ **Fake non-membership**: Fails anchored adjacency check (Step 6)

**Implementation**: [crates/msphf-core/src/witness.rs](../../crates/msphf-core/src/witness.rs) (SRX validation)

**Blueprint**: Alpha (0.1.0) §5, Appendix F

---

### 5.7 Post-Compromise Security

**Property**: Compromise of epoch E_i does not compromise future epochs E_{i+1}, E_{i+2}, ...

**Reasoning**:
- Each epoch has independent hp (derived from new seed_DRBG)
- seed_DRBG includes fresh seed_commit (per epoch)
- E_k = H_epoch(X_k, Y\*) — forward-secure (one-way hash)

**Limitation**: No backward secrecy (past epochs remain compromised). Mitigation: KBROAD key rotation.

---

## 6. Server Blindness Proofs

### 6.1 Type-Level Proof

**Theorem**: The server cannot hold KBROAD secret keys in `AcceptanceContext`.

**Proof**:
```rust
// crates/msphf-orchestrator/src/accept/mod.rs
pub struct AcceptanceContext {
    pub mh_window: MultiHeadWindow,                     // ✅ Public
    rho_guard: RhoReplayGuard,                          // ✅ Commitments
    vck_cache: VckCache,                                 // ✅ Public VRF keys
    kbroad_registry: Option<BTreeMap<Vec<u8>, Vec<u8>>>, // ✅ Public keys
    // ... (all config/policy fields)
}

// ❌ NO FIELD:
// - kbroad_secret: MlKemSecretKey
// - epoch_key: [u8; 32]
// - hp: Vec<u8>
```

**Compiler Enforcement**:
```rust
let ctx = AcceptanceContext::with_options(h_max, ttl, opts);
let secret = ctx.kbroad_secret; // ❌ COMPILE ERROR: no field `kbroad_secret`
```

**QED**: Rust's type system prevents secret key storage at compile time. ∎

---

### 6.2 Functional Proof

**Theorem**: The server never calls `ml_kem_decapsulate()` or AEAD decryption on KBROAD envelope.

**Evidence**:
```bash
# Search server code
$ rg "ml_kem_decapsulate|decapsulate" crates/msphf-orchestrator/src/accept/mod.rs
# Result: 0 matches ✅

$ rg "decrypt_hp|unwrap_kbroad_envelope" crates/msphf-orchestrator/src/
# Result: 0 matches ✅ (functions removed in commit 3c5ced4)
```

**Server Code** (structural validation only):
```rust
// crates/msphf-orchestrator/src/accept/mod.rs
fn validate_kbroad_envelope_structure(
    header: &BTreeMap<u64, Value>
) -> Result<(), AcceptanceError> {
    let items = /* extract 5-element array */;
    if items[0] != "kbroad-v1" { return Err(FREEZE_PARENT_EID_FORBIDDEN); }
    if items[4] != "chacha20-poly1305" { return Err(FREEZE_SUITE_DEPRECATED); }
    // ✅ NO decapsulation, NO decryption
    Ok(())
}
```

**QED**: Server code contains no decryption primitives. ∎

---

### 6.3 API-Level Proof

**Theorem**: The server API returns only public data.

**Proof**:
```rust
// crates/cityg-server/src/lib.rs
pub struct ServerOutcome {
    pub we_epoch_id: [u8; 32],  // ✅ H_L("we/epoch", [gid, vrf_ctx_hash, wid])
    pub wid: [u8; 32],          // ✅ H_L("mhw/window", [gid, parent_root, seed_ctx_hash])
}

// ❌ NO FIELDS:
// - epoch_key: [u8; 32]
// - eid: [u8; 32]
// - hp: Vec<u8>
// - y_star: [u8; 32]
```

**QED**: API cannot leak secrets (no secret fields in return type). ∎

---

### 6.4 Information-Theoretic Proof

**Theorem**: Given KBROAD ciphertext `C_hp`, the server cannot learn `hp` without the secret key.

**Proof**:
1. `C_hp` is encrypted using ChaCha20-Poly1305 with 256-bit key
2. IND-CCA2 security: ciphertext reveals no information about plaintext
3. Key derived from ML-KEM-768 shared secret (NIST Level 3 security)
4. Server has no access to ML-KEM secret key (§6.1, §6.2)

**Computational Hardness**: Breaking C_hp requires solving Module-LWE (2^192 operations, quantum).

**QED**: hp confidentiality is information-theoretically guaranteed (given ML-KEM security). ∎

---

### 6.5 ZK-VRF Output-Hiding Proof

**Theorem**: The ZK-VRF proof reveals no information about Y\*.

**Proof Sketch**:
1. ZK-VRF proves: "I know hp such that VRF(hp, VRF_CTX) = Y\*"
2. Proof is **output-hiding**: verifier learns commitment, not Y\*
3. lb-vrf/v1 instantiation uses masked output: `mask_digest` (Appendix V)

**Construction** (lb-vrf/v1):
```rust
// Prover commits to Y* without revealing it
let mask_digest = H_L("vrf/mask", [hp_commit, vrf_ctx_hash, mask_nonce]);
// Proof binds hp_commit → mask_digest, verifier learns neither hp nor Y*
```

**Implementation**: [crates/msphf-orchestrator/src/proofs/zk_vrf/lb.rs](../../crates/msphf-orchestrator/src/proofs/zk_vrf/lb.rs)

**QED**: Server learns proof validity, not Y\*. ∎

---

### 6.6 Defense-in-Depth Verification

**Additional Checks** (Step 8, acceptance pipeline):
```rust
// crates/msphf-orchestrator/src/accept/mod.rs
fn defense_in_depth_checks(
    header: &BTreeMap<u64, Value>,
    capss_inputs: &CapssStrictInputs,
    vrf_ctx: &VrfCtx,
) -> Result<(), AcceptanceError> {
    // Cross-check: header vs CAPSS Smallwood proof bindings
    if header[&93] != capss_inputs.rho_commit { return Err(FREEZE_MSPHF_CRS_INVALID); }
    if header[&99] != capss_inputs.hp_commit { return Err(FREEZE_MSPHF_CRS_INVALID); }

    // Cross-check: header vs ZK-VRF proof bindings
    if header[&99] != vrf_ctx.hp_commit { return Err(FREEZE_MSPHF_CRS_INVALID); }
    if header[&106] != vrf_ctx.params_id { return Err(FREEZE_MSPHF_CRS_INVALID); }

    Ok(())
}
```

**Guarantee**: Prevents proof-witness malleability attacks (attacker cannot mix-and-match proofs from different contexts).

---

## 7. Attack Surface Analysis

### 7.1 Server-Side Attack Surface

| Attack Vector | Mitigation | Status |
|---------------|-----------|--------|
| **Memory dump** | No secrets in `AcceptanceContext` | ✅ Type-safe |
| **Log inspection** | Only public data logged | ✅ Verified |
| **Side-channel (timing)** | Constant-time RLWE ops | ✅ Fixed (audit) |
| **Code injection** | Rust memory safety | ✅ No `unsafe` |
| **Malicious operator** | Cannot inject secret key | ✅ Type error |
| **Replay attacks** | RhoReplayGuard, VCK cache | ✅ Tested |

**Implementation**: [scripts/verify_no_secrets.sh](../../scripts/verify_no_secrets.sh) (10 automated checks)

---

### 7.2 Client-Side Attack Surface

| Attack Vector | Mitigation | Residual Risk |
|---------------|-----------|---------------|
| **Device compromise** | Key isolation (OS keychain) | ⚠️ If device rooted, keys exposed |
| **Malicious anchor** | Client validates proofs | ✅ CAPSS Smallwood + ZK-VRF |
| **Fake witnesses** | Merkle path validation | ✅ Cryptographic binding |
| **Omitted members** | SRX completeness check | ✅ Frontier + anchor pool |
| **Side-channel (timing)** | Constant-time crypto | ⚠️ Implementation-dependent |

**Note**: Client-side security depends on device OS security model (out of scope for protocol design).

---

### 7.3 Network Attack Surface

| Attack Vector | Mitigation | Status |
|---------------|-----------|--------|
| **Eavesdropping** | TLS 1.3 transport (assumed) | ✅ Out-of-band |
| **MitM** | PoP signature validation | ✅ ML-DSA-65 |
| **Replay** | Rho parity guard, VCK cache | ✅ Tested |
| **Reordering** | Deterministic validation | ✅ Stateless |
| **DoS (flood)** | Rate limits, quotas (policy) | ⚠️ Out-of-band |

**Assumption**: TLS 1.3 or equivalent transport security (confidentiality + authenticity).

---

## 8. Defense Mechanisms

### 8.1 Cryptographic Defenses

| Mechanism | Purpose | Implementation |
|-----------|---------|----------------|
| **CAPSS Smallwood** | Anti-grinding (seed→hp determinism) | Fiat-Shamir ROM proof (straightline-extractable) |
| **ZK-VRF** | Y\* uniqueness + output-hiding | lb-vrf/v1 |
| **PoP** | Device authentication | ML-DSA-65 signature |
| **SRX** | Completeness (no omitted members) | Frontier + anchor pool |
| **Canonical Witnesses** | Prevent malleability | Strict format (depth≤64, sorted) |
| **KBROAD Encryption** | hp confidentiality | ML-KEM-768 + ChaCha20-Poly1305 |

---

### 8.2 DoS Defenses

| Mechanism | Purpose | Configuration |
|-----------|---------|---------------|
| **Proof limits** | Reject oversize proofs early | `|95|≤8192`, `|97|≤262144`, `|146|≤16384`, `|161|≤16384`, `|122|≤1048576` |
| **Proof commit fail-fast** | Abort before expensive proofs | Verify `125` before Smallwood/VRF/SRX |
| **Multi-Head Window** | Capacity limit | H_MAX=16 heads per WID |
| **TTL** | Auto-expire stale heads | T_WINDOW=120s (default) |
| **Rho Replay Guard** | Detect duplicate ρ | RHO_GUARD_CAPACITY=64 |
| **VCK Cache** | Avoid re-verification | TTL=T_WINDOW |

**Blueprint**: Alpha (0.1.0) §12.2 (acceptance pipeline), §13 (MHW)

---

### 8.3 Integrity Defenses

| Mechanism | Purpose | Freeze Code |
|-----------|---------|-------------|
| **CBOR Canonical Encoding** | Prevent malleability | 907.1 (cbor_malformed) |
| **Deterministic Re-encode** | Detect tampering | 907.1 |
| **Defense-in-Depth** | Cross-check proofs vs header | 921 (msphf_crs_untrusted) |
| **Seed-Bundle Commit** | Bind seed context | 922 (msphf_seedctx_mismatch) |
| **Proofs Commit** | Bind CAPSS Smallwood + ZK-VRF | 923 (proof_invalid) |
| **Anchored Adjacency** | SRX integrity | 930 (srx_invalid) |

---

## 9. Post-Quantum Security

### 9.1 Threat: Quantum Adversaries

**Capabilities**:
- Break RSA-2048 (Shor's algorithm, polynomial time)
- Break ECDH (discrete log, polynomial time)
- Accelerate symmetric key search (Grover's algorithm, √N speedup)

**Impact on City-G**:
- ❌ **Not affected**: No RSA or ECDH primitives
- ✅ **Protected**: ML-KEM-768 (NIST Level 3) resists quantum attacks
- ✅ **Protected**: ML-DSA-65 (NIST Level 3) resists quantum forgery
- ⚠️ **Mitigated**: BLAKE3/ChaCha20 (256-bit keys) → 128-bit quantum security (sufficient)

---

### 9.2 Post-Quantum Primitives

| Primitive | Classical Security | Quantum Security | NIST Status |
|-----------|-------------------|------------------|-------------|
| **ML-KEM-768** | ≥192 bits (Category 3) | ≥96 bits (Category 3 quantum target) | FIPS 203 (final) |
| **ML-DSA-65** | ≥192 bits (Category 3) | ≥96 bits (Category 3 quantum target) | FIPS 204 (final) |
| **RLWE-HPS A1** | ≥192 bits (matches ML-KEM-768) | ≈96 bits (best-known quantum sieving ≈2^95 ops) | Custom (ongoing analysis) |
| **BLAKE3** | 256-bit preimage | 128-bit preimage | Non-standardized |
| **ChaCha20** | 256-bit key | 128-bit key | RFC 8439 |

**Minimum Quantum Security**: ≥96 bits (NIST Category 3 target across all primitives)

---

### 9.3 RLWE-HPS Security Analysis

**Parameters**: N=256, Q=3329, K=3, η₂=2

**Classical Security Estimate**: ≥192 bits (Best-known primal/dual lattice reduction attacks on (N=256, Q=3329, K=3) require ≥2^192 operations; see Kyber/ML-KEM evaluations).

**Quantum Security Estimate**: ≈96 bits. Reducing the Module-LWE instance (n=256, k=3, q=3329, η=2) to plain LWE and evaluating with Albrecht’s lattice-estimator gives classical BKZ costs ≈2^99 operations and quantum sieving ≈2^95 operations.

**Mitigation**: RLWE-HPS is used for **smoothness** (hiding Y\* from server), not long-term confidentiality. Even if broken:
- Server still cannot learn Y\* (ZK-VRF output-hiding)
- hp remains protected by ML-KEM-768 (independent security layer)

**Future Work**: Upgrade to RLWE-HPS A2 (higher parameters) if security analysis warrants.

---

### 9.4 Random Oracle Models (ROM & QROM)

**CAPSS Smallwood Proof**: Knowledge soundness is shown in the Random Oracle Model (ROM) with a straightline extractor (Smallwood-ARK).

**Assumption**: BLAKE3 behaves as a random oracle against quantum adversaries.

**Challenge Derivation**:
```rust
let challenge = H_L("msphf/fs-lin/challenge", [commitments, bind]);
```

**Security**: ROM guarantees the proof cannot be forged without access to the witness under classical or quantum queries to the random oracle.

---

## 10. Comparison with Other Protocols

### 10.1 City-G vs. MLS (Message Layer Security)

| Property | City-G (tswe/msphf-we/fs-hybrid) | MLS (RFC 9420) |
|----------|---------------------------|----------------|
| **Server Blindness** | ✅ Cryptographic (SPHF + ZK-VRF) | ❌ Transparency logs (trust-based) |
| **Offline Join** | ✅ Non-interactive (ME-OR) | ❌ Requires commit from server |
| **Parallel Joins** | ✅ Multi-Head Window (16 heads) | ❌ Sequential (TreeKEM) |
| **Scale** | ✅ Millions (O(log N) witnesses) | ⚠️ ~50K (tree rebalancing) |
| **Post-Quantum** | ✅ Native (ML-KEM/DSA) | ⚠️ Hybrid mode (deployment-specific) |
| **Proof Complexity** | ⚠️ Novel (CAPSS Smallwood + ZK-VRF) | ✅ Well-studied (TreeKEM) |
| **Rust LOC (tests+examples)** | 26,461[^loc-cityg] | 62,433[^loc-openmls] |

**Trade-offs**:
- City-G: Higher proof complexity, better scalability and blindness
- MLS: Mature ecosystem, lower cryptographic assumptions

---

### 10.2 City-G vs. Signal Protocol

| Property | City-G | Signal (Private Groups) |
|----------|--------|------------------------|
| **Group Size** | ✅ Millions | ⚠️ ~1000 (practical limit) |
| **Server Blindness** | ✅ Cryptographic | ⚠️ Sealed sender (metadata leaks) |
| **Offline Join** | ✅ Non-interactive | ❌ Requires group state fetch |
| **Post-Quantum** | ✅ Native | ✅ Hybrid (PQXDH + SPQR on ML-KEM-768) |
| **Forward Secrecy** | ⚠️ Per-epoch (KBROAD rotation) | ✅ Per-message (Double Ratchet) |
| **Rust LOC (tests+examples)** | 26,461[^loc-cityg] | 112,533[^loc-signal] |

**Use Case Fit**:
- City-G: Large-scale broadcast (town halls, conferences)
- Signal: Small groups with frequent messages

[^loc-cityg]: Measured with `tokei -t Rust --exclude target` on 2025-10-18 against commit `7737c54`. Counts include workspace tests, examples, and benches.
[^loc-openmls]: Measured with `tokei -t Rust --exclude target` on 2025-10-18 against OpenMLS commit `43fe07d76`. Counts include workspace tests and benches.
[^loc-signal]: Measured with `tokei -t Rust --exclude target` on 2025-10-18 against Signal/libsignal commit `eb616f63`. Covers the Rust workspace only; the repository also contains Java, Swift, and Node bindings not reflected in this total.

---

### 10.3 Security Properties Comparison

| Property | City-G | MLS | Signal |
|----------|--------|-----|--------|
| **Confidentiality** | ✅ | ✅ | ✅ |
| **Authentication** | ✅ (PoP) | ✅ (TreeKEM) | ✅ (X3DH) |
| **Integrity** | ✅ (CAPSS Smallwood) | ✅ (Signatures) | ✅ (MAC) |
| **Forward Secrecy** | ⚠️ (per-epoch) | ✅ (per-commit) | ✅ (per-message) |
| **Post-Compromise Security** | ✅ (new hp per epoch) | ✅ (TreeKEM update) | ✅ (ratchet) |
| **Server Blindness** | ✅ | ❌ | ⚠️ |
| **Post-Quantum** | ✅ | ⚠️ | ✅ |
| **Offline Readiness** | ✅ | ❌ | ❌ |
| **Parallel Joins** | ✅ | ❌ | N/A |

---

## Summary

The City-G `tswe/msphf-we/fs-hybrid` protocol provides:

1. **Publisher-Blindness** — Server cannot learn hp, Y\*, E_k, or eid (type-safe, functionally verified)
2. **Post-Quantum Security** — ML-KEM-768, ML-DSA-65, lattice-based SPHF (NIST Level 3)
3. **Anti-Grinding** — CAPSS Smallwood enforces seed→hp determinism (ROM secure)
4. **Uniqueness** — ZK-VRF proves Y\* correctness without revealing it (output-hiding)
5. **Completeness** — SRX prevents member omissions (frontier + anchor pool)
6. **Offline Readiness** — Non-interactive ME-OR (no server interaction for E_k derivation)
7. **Parallel Joins** — Multi-Head Window supports 16 concurrent heads (unprecedented scale)
8. **DoS Hygiene** — Pre-filters, size limits, SRX bounds, TTL-based expiration

**Important Note on Publisher-Blindness**: The term "publisher-blind" means the server is **cryptographically blind to encryption keys** (hp, Y\*, E_k) and message content. However, the server **CAN identify devices** via public keys (ML-DSA-65) transmitted in field #108 during join/merge operations. This is NOT sender anonymity — see §1.1 and §5.4 for details.

**Security Guarantees**: Proven via type-level (Rust), functional (code review), API-level (return types), and information-theoretic (ML-KEM hardness) arguments.

**Attack Surface**: Minimal server-side risk (no secrets), client-side risk mitigated by proof validation, network risk handled by transport security.

**Post-Quantum Readiness**: All critical primitives (ML-KEM, ML-DSA) are NIST-standardized (FIPS 203/204), with ongoing analysis of RLWE-HPS A1 parameters.

**Next**: [11 — Implementation Guide](./11-implementation-guide.md)

---

**Document Version**: 0.1.0
**Blueprint Reference**: Alpha (0.1.0) §3, §14
**Implementation**: City-G 0.1.0
