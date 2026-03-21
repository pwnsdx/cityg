# 17 — Frequently Asked Questions (FAQ)

> [!IMPORTANT]
> This chapter is a legacy companion document. For `tswe/msphf-we/fs-hybrid`, the normative source is [`../specs.md`](../specs.md).
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and implementation.


**Profile**: City-G `tswe/msphf-we/fs-hybrid` (Alpha (0.1.0))
**Status**: Informative

## Table of Contents

1. [General Questions](#1-general-questions)
2. [Technical Questions](#2-technical-questions)
3. [Security Questions](#3-security-questions)
4. [Implementation Questions](#4-implementation-questions)
5. [Deployment Questions](#5-deployment-questions)

---

## 1. General Questions

### Q1.1: What is City-G?

**A**: City-G is a **post-quantum, publisher-blind E2EE protocol** for extremely large groups (millions of members). It enables offline-ready epoch key extraction using Smooth Projective Hash Functions (SPHF) with Masked-Equality OR (ME-OR).

**Key Features**:
- **Server blindness**: Cryptographic guarantee (server cannot learn epoch keys)
- **Offline-ready**: Devices derive keys without server interaction
- **Extreme scale**: Millions of members with O(log N) overhead
- **Post-quantum**: ML-KEM-768, ML-DSA-65 (NIST-standardized)

---

### Q1.2: How does City-G differ from MLS?

**A**: City-G and MLS have fundamentally different designs:

| Feature | City-G | MLS |
|---------|--------|-----|
| **Server Blindness** | Cryptographic (SPHF) | Transparency logs (trust-based) |
| **Scale** | Millions | ~50K practical |
| **Offline Join** | Non-interactive | Interactive (requires server) |
| **Post-Quantum** | Native (ML-KEM/DSA) | Hybrid (experimental) |
| **Forward Secrecy** | Per-epoch | Per-commit (finer) |

**Use Cases**:
- **City-G**: Public broadcasts, whistleblower platforms, extremely large groups
- **MLS**: Corporate messaging, consumer chat, small-to-medium groups

See [16 — Comparison with MLS](./16-comparison-mls.md) for details.

---

### Q1.3: What does "publisher-blind" mean?

**A**: The server **cannot learn** the hash projection key (hp), VRF output (Y\*), or epoch key (E_k), even if the server is fully compromised. This is a **type-level guarantee** enforced by Rust's type system:

1. `AcceptanceContext` has no secret fields (compiler-enforced)
2. No `ml_kem_decapsulate()` or AEAD decryption in server code
3. ZK-VRF proves Y\* correctness without revealing it (output-hiding)

**Important**: "Publisher-blind" means the server cannot decrypt messages or derive encryption keys. However, the server **CAN identify devices** via public keys transmitted in field #108 during join/merge. This is NOT sender anonymity.

**Evidence**: See [10 — Security Model](./10-security-model.md) §6 (Server Blindness Proofs).

---

### Q1.4: Why "offline-ready"?

**A**: Clients derive epoch keys **without** contacting the server (given anchor + witness). This enables:

- **Mobile clients**: Batch processing (fetch anchor once, derive keys offline)
- **IoT devices**: Low-power operation (no continuous server connection)
- **Edge computing**: Local epoch derivation (reduced latency)

**Mechanism**: ME-OR (Masked-Equality OR) allows clients to compute Y\* locally using their witness.

---

### Q1.5: What is "tswe/msphf-we/fs-hybrid"?

**A**: The protocol profile name:
- **tswe**: Time-Stamped Witness Extraction
- **msphf-we**: Masked SPHF with Witness Extraction
- **fs-hybrid**: Minutes-grade forward secrecy with time-blind enforcement

**Full Name**: City-G `tswe/msphf-we/fs-hybrid` (Alpha (0.1.0))

City-G uses SPHF/ME-OR to let clients derive epoch digests from their membership witnesses; it does not rely on a general witness-encryption primitive.

---

## 2. Technical Questions

### Q2.1: What is SPHF (Smooth Projective Hash Functions)?

**A**: SPHF is a cryptographic primitive with two key properties:

1. **Projection**: For valid witnesses, `H(hp, w) = Proj(pk(hp), w)` (public computation)
2. **Smoothness**: For invalid witnesses, `H(hp, w)` is indistinguishable from random (hiding)

**Usage in City-G**: RLWE-HPS A1 instantiation enables ME-OR (Masked-Equality OR) for epoch key derivation.

**Reference**: [05 — SPHF and ME-OR](./05-sphf-meor.md)

---

### Q2.2: What is ME-OR (Masked-Equality OR)?

**A**: ME-OR is a construction that allows computing Y\* via OR logic over two branches:

- **Branch A**: Membership witness (leaf ∈ parent_root)
- **Branch B**: Join witness (leaf ∈ join_delta_root) AND non-membership (leaf ∉ revoked_root)

**Formula**:
```
Y* = Proj(pk, Δ_A) ⊕ M_A   (if Branch A valid)
Y* = Proj(pk, Δ_B) ⊕ M_B   (if Branch B valid)
```

**Property**: Both branches yield the **same Y\*** (mask coherence), enabling flexible join logic.

**Reference**: [05 — SPHF and ME-OR](./05-sphf-meor.md) §3

---

### Q2.3: What are CAPSS Smallwood and ZK-VRF?

**A**: Proof systems used in City-G:

**CAPSS Smallwood (Fiat-Shamir Linear Integrity)**:
- **Purpose**: Prove `seed_DRBG → hp` deterministically (anti-grinding)
- **Size**: ~12KB typical (≤16KB cap)
- **Verification**: ~12ms (mobile)

**ZK-VRF (Zero-Knowledge Verifiable Random Function)**:
- **Purpose**: Prove Y\* uniqueness without revealing it (output-hiding)
- **Size**: ≤6KB
- **Verification**: ~6ms (mobile)

**Reference**: [06 — Proof Systems](./06-proof-systems.md)

---

### Q2.4: What is SRX?

**A**: **SRX (Set-Relation eXtension)** validates completeness of member lists:

1. **Frontier**: Merkle frontier covering all leaves in parent tree
2. **Anchor Pool**: List of join_delta_root values (δ-join branches)
3. **Anchored Adjacency**: Non-membership witnesses must anchor to frontier

**Guarantee**: Publisher cannot omit valid members (clients verify completeness).

**Reference**: [04 — Witness Validation](./04-witness-validation.md) §4

---

### Q2.5: What is Multi-Head Window (MHW)?

**A**: MHW enables **parallel joins** by maintaining multiple concurrent heads per window:

- **WID**: Window identifier (deterministic from gid, parent_root, seed_ctx_hash)
- **H_MAX**: Capacity limit (default: 16 concurrent heads)
- **T_WINDOW**: TTL for head expiration (default: 120s)

**Use Case**: Stadium event with 200 simultaneous joins (processed in 16-head batches).

**Reference**: [09 — Multi-Head Window](./09-multi-head-window.md)

---

### Q2.6: What is KBROAD?

**A**: **KBROAD** is the current HP transport mechanism:

1. Publisher encrypts hp using ML-KEM-768 (KBROAD public key)
2. Envelope structure: `["kbroad-v1", ct_kem, wrap, C_hp, "chacha20-poly1305"]`
3. Server **never decrypts** (structural validation only)
4. Clients decrypt hp using KBROAD secret key

Important implementation note:

- In the current codebase, this still creates an async-first product gap for cross-device joins, because recovering remote epochs depends on confidential provisioning of KBROAD material.
- ME-OR still protects witness-dependent epoch-key derivation and keeps the server blind to `hp`, but ME-OR does not by itself solve the transport/provisioning problem for a newly joined device.
- See [18 — Async-First Join Provisioning Gap](./18-async-first-join-provisioning.md).

**Security**: Server cannot learn hp (type-safe, no decryption primitives).

**Reference**: [08 — Client Operations](./08-client-operations.md) §3

---

### Q2.7: How does SPHF ME-OR relate to Witness Encryption?

**A**: City-G's SPHF ME-OR construction achieves **witness-dependent key derivation** with properties analogous to Witness Encryption (Garg et al., STOC 2013):

**Key similarities**:
- ✅ **Witness-dependent output**: Only valid witnesses produce correct Y*
- ✅ **Soundness**: Invalid witnesses yield pseudorandom output (under RLWE)
- ✅ **NP language support**: Merkle membership/non-membership predicates
- ✅ **No trapdoor**: Server cryptographically cannot learn Y*

**Critical distinction**: City-G uses **witness-dependent key derivation** (deterministic Y* → E_k) rather than a general witness-encryption primitive. This provides:
- **Practical efficiency**: O(log N) witnesses, ~100ms validation
- **Post-quantum security**: Module-LWE (NIST Category 3)
- **Algebraic foundation**: RLWE-HPS rather than multilinear maps

**Characterization**: First practical large-scale deployment of witness-dependent cryptography under lattice assumptions.

**Reference**: [05 — SPHF and ME-OR](./05-sphf-meor.md) §11 (Relationship to Witness Encryption)

---

### Q2.8: Does the epoch counter (`fs_ec`) alone order messages?

**A**: Only partially. FS enforces a strict order **between epochs**—you cannot generate material for
`fs_ec = t+1` without evolving past `t`, and the FLG rules ensure anchors observe that monotonicity.
However:

- Two messages encrypted under the same epoch remain unordered. Add a per-device sequence or hash
  chain if you need FIFO behavior.
- As long as a device retains τₑ (Annex J), it can still publish a ciphertext “dated” in a recent
  epoch. The effective guarantee is bounded by `max(H, tau_cache_retention)`.
- The transport layer does not necessarily expose `fs_ec`; receivers typically attempt decryption
  under recent epochs.

**Tip**: Sort by `(fs_ec, local sequence, receive_ts)` and, if a total order matters, include a
message commit (e.g., `H_L("msg/chain", …)`) so peers can verify it. See
[08 — Client Operations](./08-client-operations.md#10-message-ordering--timeline-considerations) for
full guidance.

---

## 3. Security Questions

### Q3.1: Is the server truly blind to secrets?

**A**: **Yes**, verified at multiple levels:

1. **Code structure**: `AcceptanceContext` is intentionally limited to public fields; CI guards freeze any attempt to add secrets.
2. **Functional**: No `ml_kem_decapsulate()` or AEAD decryption in server code.
3. **API-level**: `ServerOutcome` returns only public data (we_epoch_id, wid).
4. **Information-theoretic**: ML-KEM-768 ciphertext reveals no plaintext info.

**Verification**:
```bash
./scripts/verify_no_secrets.sh
# Expected: ✅ ALL CHECKS PASSED
```

**Reference**: [10 — Security Model](./10-security-model.md) §6

---

### Q3.2: What if the server is compromised?

**A**: Server compromise does **not leak secrets**:

- ✅ No hp (encrypted in KBROAD)
- ✅ No Y\* (output-hiding ZK-VRF)
- ✅ No E_k (client-side derivation only)
- ✅ No eid (derived from E_k)

**Attacker gains**: Public metadata (gid, parent_root, freeze codes), but no epoch keys.

**Reference**: [10 — Security Model](./10-security-model.md) §7.1

---

### Q3.3: Is City-G post-quantum secure?

**A**: **Yes**, all critical primitives are post-quantum:

| Primitive | Quantum Security | Standard |
|-----------|------------------|----------|
| **ML-KEM-768** | 192 bits | FIPS 203 |
| **ML-DSA-65** | 192 bits | FIPS 204 |
| **BLAKE3** | 128 bits | Non-standardized |
| **ChaCha20** | 128 bits | RFC 8439 |
| **RLWE-HPS A1** | ≈96 bits (Module-LWE, best-known quantum ≈2^95 ops) | Custom (ongoing analysis) |

**Minimum**: 128-bit quantum security (BLAKE3/ChaCha20, reduced by Grover).

**Reference**: [10 — Security Model](./10-security-model.md) §9

---

### Q3.4: What about forward secrecy?

**A**: City-G provides **per-epoch** forward secrecy:

- **Granularity**: Each epoch has independent hp (derived from new seed_DRBG)
- **Compromise**: Compromising epoch E_i does not affect E_{i+1}
- **Rotation**: KBROAD key rotation (recommended every 90 days)

**Trade-off**: MLS has finer-grained FS (per-commit), but City-G's per-epoch FS is sufficient for broadcast use cases.

**Reference**: [10 — Security Model](./10-security-model.md) §5.7

---

### Q3.5: Can a malicious publisher omit members?

**A**: **No**, SRX (Set-Relation eXtension) prevents omissions:

1. **Frontier** commits to all leaves in parent tree
2. **Anchor pool** lists all join_delta_root values
3. Clients verify completeness (no hidden branches)

**Attack**: If publisher omits a member, client cannot find a valid witness → rejects anchor.

**Reference**: [10 — Security Model](./10-security-model.md) §5.6

---

### Q3.6: What prevents grinding attacks?

**A**: **CAPSS Smallwood** enforces seed→hp determinism:

1. ρ := H_L("msphf/rho/der", [pop_sig, xk_hash]) (deterministic from PoP)
2. seed_DRBG := H_L("msphf/drbg", [seed_commit, ρ, xk_hash, seed_ctx_hash])
3. CAPSS Smallwood proof verifies: hp = KGen(seed_DRBG) (no cherry-picking)

**Attack**: Publisher cannot grind seed_DRBG to produce favorable Y\* (ρ is deterministic).

**Reference**: [10 — Security Model](./10-security-model.md) §5.5

---

## 4. Implementation Questions

### Q4.1: Which programming languages are supported?

**A**: Currently **Rust only** (reference implementation).

**Status**:
- ✅ Rust: Alpha stage (City-G 0.1.0)
- ⚠️ Other languages: Future work (bindings via FFI)

**Recommendation**: Use Rust for maximum security (memory safety, type-level guarantees).

---

### Q4.2: How do I run the tests?

**A**:
```bash
# All tests
cargo test --all

# Specific suite
cargo test -p msphf-orchestrator

# With verbose output
cargo test --all -- --nocapture

# Security verification
./scripts/verify_no_secrets.sh
```

**Expected**: `cargo test --all` passes and all 10 security checks pass.

**Reference**: [13 — Testing Guide](./13-testing-guide.md)

---

### Q4.3: Where is the documentation?

**A**: Complete documentation in `docs/protocol/`:

1. [00 — README](./00-README.md) (start here)
2. [01 — Overview](./01-overview.md) (protocol introduction)
3. [02 — Cryptographic Primitives](./02-cryptographic-primitives.md)
4. [03 — Data Structures](./03-data-structures.md)
5. [04 — Witness Validation](./04-witness-validation.md)
6. [05 — SPHF and ME-OR](./05-sphf-meor.md)
7. [06 — Proof Systems](./06-proof-systems.md)
8. [07 — Server Acceptance](./07-server-acceptance.md)
9. [08 — Client Operations](./08-client-operations.md)
10. [09 — Multi-Head Window](./09-multi-head-window.md)
11. [10 — Security Model](./10-security-model.md)
12. [11 — Implementation Guide](./11-implementation-guide.md)
13. [12 — Error Reference](./12-error-reference.md)
14. [13 — Testing Guide](./13-testing-guide.md)
15. [14 — Deployment Guide](./14-deployment-guide.md)
16. [15 — Label Registry](./15-label-registry.md)
17. [16 — Comparison with MLS](./16-comparison-mls.md)
18. [17 — FAQ](./17-faq.md) (this document)

---

### Q4.4: How large is the codebase?

**A**: ~18,000 lines of Rust (excluding tests):

| Crate | Lines | Purpose |
|-------|-------|---------|
| msphf-core | ~4,500 | RLWE primitives, Merkle, hashing |
| msphf-rlwe | ~800 | RLWE-HPS A1 SPHF |
| msphf-orchestrator | ~7,000 | Acceptance, proofs, MHW, KGen |
| msphf-lb-vrf | ~2,000 | lb-vrf/v1 (ZK-VRF) |
| anchor-seed | ~400 | Seed context construction |
| cityg-client | ~400 | Client API |
| cityg-server | ~300 | Server API |

**Reference**: [11 — Implementation Guide](./11-implementation-guide.md)

---

### Q4.5: What are the system requirements?

**A**:

**Server**:
- OS: Linux (Ubuntu 22.04+, RHEL 9+)
- CPU: x86-64 with AVX2
- RAM: 8 GB recommended
- Disk: 20 GB (logs, cache)

**Client**:
- OS: Linux, macOS, Windows, iOS, Android
- CPU: Any (ARM64, x86-64)
- RAM: 512 MB minimum

**Reference**: [14 — Deployment Guide](./14-deployment-guide.md) §2.3

---

## 5. Deployment Questions

### Q5.1: Is City-G production-ready?

**A**: **No, this is alpha software**:

✅ **Completed**:
- Security audit completed (all timing side-channels fixed)
- Comprehensive test inventory (`cargo test --all -- --list | rg ': test$' | wc -l` reports 586 in this checkout on February 5, 2026)
- Type-safe server blindness (verified)
- Post-quantum primitives (NIST-standardized)

⚠️ **Alpha-stage considerations**:
- Modern lattice-based cryptography (fewer third-party deployments to date compared with MLS)
- Ecosystem currently centered on Rust
- RLWE-HPS A1 analysis tracks ML-KEM research (currently aligned with NIST Category 3 security)
- Not yet battle-tested in production environments

**Recommendation**: Suitable for research and experimental deployments only. Not recommended for production use.

---

### Q5.2: How do I deploy a server?

**A**:

1. **Build**:
```bash
cargo build --release --locked
```

2. **Configure** (`config/server.toml`):
```toml
[acceptance]
h_max = 16
t_window_secs = 10
srx_required = true

[kbroad_registry]
"group-1" = "base64-encoded-ml-kem-768-public-key"
```

3. **Run**:
```bash
./target/release/cityg-server --config config/server.toml
```

4. **Monitor**:
- Metrics: Prometheus (port 9090)
- Logs: Structured (JSON)
- Alerts: Freeze spikes, MHW capacity

**Reference**: [14 — Deployment Guide](./14-deployment-guide.md)

---

### Q5.3: How do I integrate with my application?

**A**:

**Server-side**:
```rust
use cityg_server::{ServerContext, ServerOutcome};

let mut ctx = ServerContext::new();
match ctx.accept_anchor(header_cbor) {
    Ok(outcome) => {
        // outcome.we_epoch_id, outcome.wid (public only)
    }
    Err(err) => {
        // Handle freeze (deterministic) or reject (transient)
    }
}
```

**Client-side**:
```rust
use cityg_client::ClientEpochBundle;

let bundle = ClientEpochBundle {
    anchor,
    hp_binding,
    witness,
    hp_ciphertext,
    hp_aead_key,
};

let (epoch_key, eid) = bundle.derive_epoch_secrets()?;
// Use epoch_key for AEAD encryption
```

**Reference**: [11 — Implementation Guide](./11-implementation-guide.md) §6

---

### Q5.4: What monitoring should I set up?

**A**:

**Key Metrics**:
- `cityg_accept_total{status="ok"}` (success rate)
- `cityg_freeze_total{code="923"}` (proof verification failures)
- `cityg_mhw_capacity_limit_total` (MHW capacity issues)
- `cityg_vck_cache_hit_ratio` (cache efficiency)

**Alerts**:
- Freeze rate > 10% for 5 minutes (high severity)
- MHW capacity limit > 5/minute (capacity planning)
- Server error rate > 1% (critical)

**Reference**: [14 — Deployment Guide](./14-deployment-guide.md) §5

---

### Q5.5: How do I handle errors?

**A**:

**Freeze** (deterministic, cacheable):
```rust
match result {
    Err(ServerError::Freeze(freeze)) => {
        eprintln!("Anchor frozen: code={}, reason={}", freeze.code, freeze.reason);
        // Do not retry (permanent failure)
        // Diagnose: check PoP, proofs, SRX payload
    }
}
```

**Reject** (transient, not cacheable):
```rust
match result {
    Err(ServerError::Reject(reason)) => {
        eprintln!("Server rejected: {}", reason);
        // Retry with exponential backoff
    }
}
```

**Reference**: [12 — Error Reference](./12-error-reference.md)

---

## Summary

City-G `tswe/msphf-we/fs-hybrid` is a **post-quantum, publisher-blind E2EE protocol** for extremely large groups. Key features:

- ✅ **Server blindness** (cryptographic, type-safe)
- ✅ **Offline-ready** (non-interactive epoch derivation)
- ✅ **Extreme scale** (millions of members)
- ✅ **Post-quantum** (ML-KEM-768, ML-DSA-65)
- ✅ **Parallel joins** (Multi-Head Window)

**Use Cases**: Public broadcasts, whistleblower platforms, mass events, IoT deployments

**Documentation**: [docs/protocol/](../../docs/protocol/)

**Support**: [GitHub Issues](https://github.com/anthropics/claude-code/issues)

---

**Document Version**: 0.1.0
**Blueprint Reference**: Alpha (0.1.0) (entire spec)
**Implementation**: City-G 0.1.0
