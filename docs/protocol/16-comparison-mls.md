# 16 — Comparison with MLS

> [!IMPORTANT]
> This chapter is companion material, not the normative specification.
> For the current `tswe/msphf-we/fs-hybrid + prs-barrier` profile, the normative source is [`../specs.md`](../specs.md).
> Inline references below to `Alpha (0.1.0)` are historical blueprint citations only.
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and live code/tests.


**Current profile coverage:** City-G `tswe/msphf-we/fs-hybrid + prs-barrier`
**Historical blueprint lineage:** Alpha (0.1.0)
**Status**: Informative (protocol comparison)

## Table of Contents

1. [Introduction](#1-introduction)
2. [Protocol Overviews](#2-protocol-overviews)
3. [Feature Comparison](#3-feature-comparison)
4. [Security Properties](#4-security-properties)
5. [Performance and Scale](#5-performance-and-scale)
6. [Use Case Fit](#6-use-case-fit)

---

## 1. Introduction

This document compares City-G `tswe/msphf-we/fs-hybrid` with **MLS (Message Layer Security)** RFC 9420, the IETF standard for group end-to-end encryption. While both protocols provide group E2EE, they differ fundamentally in:

- **Server blindness**: Cryptographic (City-G) vs. transparency logs (MLS)
- **Scalability**: Architecturally O(log N) targeting millions (City-G; tested to N_max=2048) vs. ~50K practical limit (MLS)
- **Join mechanism**: Non-interactive (City-G) vs. interactive commit (MLS)
- **Post-quantum**: Native (City-G) vs. hybrid mode (MLS)

**Note**: This comparison is informative and reflects MLS RFC 9420 (January 2023) and City-G Alpha (0.1.0).

---

## 2. Protocol Overviews

### 2.1 City-G (tswe/msphf-we/fs-hybrid)

**Design Goals**:
- **Publisher-blind**: Server cannot learn epoch keys (cryptographic guarantee)
- **Offline-ready**: Devices derive keys without server interaction
- **Extreme scale**: O(log N) overhead targeting millions of members (tested to N_max=2048; large-scale benchmarks pending)
- **Parallel joins**: Multiple devices join simultaneously (Multi-Head Window)

**Key Mechanisms**:
- **SPHF/ME-OR**: Smooth Projective Hash Functions with Masked-Equality OR
- **KBROAD**: Group key distribution without server decryption
- **CAPSS Smallwood + ZK-VRF**: Anti-grinding and uniqueness proofs
- **SRX**: Completeness verification (no member omissions)

**Trade-offs**:
- Modern cryptography portfolio (fewer third-party deployments today)
- Higher proof complexity (CAPSS Smallwood ≤16KB, typically ~12KB; ZK-VRF ≤8KB)
- No per-message forward secrecy (per-epoch only), though payload keys depend on E_k + K_barrier (independent of K_fs)

---

### 2.2 MLS (Message Layer Security)

**Design Goals**:
- **Standard protocol**: IETF RFC 9420 (broad adoption)
- **TreeKEM**: Efficient group key updates (O(log N) operations)
- **Forward secrecy**: Per-commit key rotation
- **Interoperability**: Multiple implementations (OpenMLS, Cisco, Wire)

**Key Mechanisms**:
- **TreeKEM**: Binary tree of Diffie-Hellman keys
- **Commit messages**: Group state updates broadcast by server
- **Transparency logs**: Auditability via append-only logs (trust-based)
- **Epoch updates**: Sequential state progression

**Trade-offs**:
- Server observes group structure (not cryptographically blind)
- Sequential commits (no parallel joins)
- Scalability limits (~50K members practical)
- Post-quantum mode experimental (hybrid ECDH + PQ-KEM)

---

## 3. Feature Comparison

### 3.1 Core Features

| Feature | City-G | MLS | Advantage |
|---------|--------|-----|-----------|
| **Group Size** | Architecturally O(log N) to millions; tested to N_max=2048, large-scale benchmarks pending | ~50K practical | City-G |
| **Server Blindness** | ✅ Cryptographic (SPHF) | ❌ Transparency logs (trust) | City-G |
| **Offline Join** | ✅ Non-interactive (ME-OR) | ❌ Requires commit from server | City-G |
| **Parallel Joins** | ✅ Multi-Head Window (16 concurrent) | ❌ Sequential (TreeKEM) | City-G |
| **Post-Quantum** | ✅ Native (ML-KEM/DSA) | ⚠️ Hybrid mode (experimental) | City-G |
| **Forward Secrecy** | ⚠️ Per-epoch (minutes-grade). Payload keys require E_k (ME-OR) + K_barrier (PRS), both independent of K_fs — K_fs compromise alone cannot decrypt. | ✅ Per-commit (TreeKEM) | Nuanced (see §4.4) |
| **Maturity** | ⚠️ City-G 0.1.0 (alpha stage, not production-ready) | ✅ IETF Standard (RFC 9420) | MLS |
| **Ecosystem** | ⚠️ Focused (Rust toolchain today) | ✅ Wide adoption | MLS |

---

### 3.2 Cryptographic Primitives

| Primitive | City-G | MLS |
|-----------|--------|-----|
| **KEM** | ML-KEM-768 (NIST Level 3) | ECDH P-256/X25519 (MLS 1.0), Hybrid (draft) |
| **Signature** | ML-DSA-65 (NIST Level 3) | Ed25519, ECDSA P-256, Ed448 |
| **Hash** | BLAKE3 (256-bit) | SHA-256, SHA-512 |
| **AEAD** | ChaCha20-Poly1305 | AES-GCM, ChaCha20-Poly1305 |
| **HKDF** | HKDF-BLAKE3 | HKDF-SHA256/SHA512 |
| **SPHF** | RLWE-HPS A1 (custom) | N/A |
| **ZK-VRF** | lb-vrf/v1 (custom) | N/A |

**Quantum Security**:
- **City-G**: 128-bit minimum (all primitives)
- **MLS**: Pre-quantum (ECDH vulnerable to Shor's algorithm)

---

### 3.3 Group Operations

| Operation | City-G | MLS |
|-----------|--------|-----|
| **Add Member** | Anchor (join mode) | Commit (Add proposal) |
| **Remove Member** | Anchor (revoked set) | Commit (Remove proposal) |
| **Update Key** | New anchor (KBROAD rotation) | Commit (Update proposal) |
| **Merge Branches** | Anchor (merge mode) | N/A (external merge) |
| **Epoch Transition** | Publisher creates anchor | Any member creates commit |

**Key Difference**: City-G uses **publisher-driven** anchors; MLS uses **member-driven** commits.

---

### 3.4 Server Interaction

| Interaction | City-G | MLS |
|-------------|--------|-----|
| **Join** | 1 POST (anchor) | 2+ round-trips (welcome, commit) |
| **Receive Epoch Key** | 0 (client-side ME-OR) | 1 GET (fetch commit, decrypt) |
| **Send Message** | 1 POST (AEAD ciphertext) | 1 POST (AEAD ciphertext) |
| **Key Material** | Server never sees E_k | Server sees TreeKEM structure (not E_k) |

**Offline Readiness**:
- **City-G**: Client derives E_k without server (given anchor + witness)
- **MLS**: Client must fetch commit from server (online requirement)

---

## 4. Security Properties

### 4.1 Confidentiality

| Property | City-G | MLS |
|----------|--------|-----|
| **Epoch Key** | ✅ Server-blind (SPHF) | ⚠️ Server sees tree (not keys) |
| **Message Content** | ✅ AEAD-encrypted | ✅ AEAD-encrypted |
| **Metadata** | ⚠️ gid, parent_root visible | ⚠️ Group ID, sender visible |

**Important Clarification on "Server Blindness"**: In City-G, "server-blind" means the server **cannot decrypt messages or derive encryption keys** (hp, Y*, E_k, eid). However, the server **CAN identify devices** via public keys (ML-DSA-65, ~2KB) transmitted in field #108 during join/merge operations. This is NOT sender anonymity — it's encryption key confidentiality.

**Server Compromise**:
- **City-G**: Server compromise does not leak epoch keys (type-safe)
- **MLS**: Server compromise does not leak epoch keys (if TreeKEM secret paths protected)

---

### 4.2 Authentication

| Property | City-G | MLS |
|----------|--------|-----|
| **Member Auth** | ✅ PoP (ML-DSA-65) | ✅ TreeKEM signature |
| **Publisher Auth** | ✅ Anchor signature | ✅ Commit signature |
| **Replay Protection** | ✅ ρ determinism, VCK cache | ✅ Epoch counter |

---

### 4.3 Integrity

| Property | City-G | MLS |
|----------|--------|-----|
| **Epoch Key** | ✅ CAPSS Smallwood (seed→hp), ZK-VRF (Y\*) | ✅ TreeKEM path integrity |
| **Member List** | ✅ SRX (completeness) | ✅ TreeKEM roster |
| **Commit Order** | ⚠️ Multi-head (eventual) | ✅ Sequential (strict) |

---

### 4.4 Forward Secrecy

| Property | City-G | MLS |
|----------|--------|-----|
| **Granularity** | Per-epoch (KBROAD rotation) | Per-commit (TreeKEM update) |
| **Compromise Recovery** | ✅ New epoch independent | ✅ TreeKEM path update |

**Example**:
- **City-G**: Compromise of epoch E_i does not affect E_{i+1} (new hp, new seed)
- **MLS**: Compromise of epoch E_i does not affect E_{i+1} (TreeKEM ratchet)

**Difference**: MLS has finer-grained FS (per-commit), City-G has per-epoch FS. However, City-G's payload key schedule requires both E_k (derived via ME-OR, independent of K_fs) and K_barrier (derived via KEM-tree PRS, independent of K_fs). Compromising K_fs alone does **not** yield payload decryption keys — an attacker must also compromise the ME-OR or PRS paths. This layered design partially mitigates the coarser epoch granularity.

---

### 4.5 Post-Compromise Security

| Property | City-G | MLS |
|----------|--------|-----|
| **Recovery** | ✅ New anchor (fresh hp) | ✅ TreeKEM update proposal |
| **Latency** | 1 epoch (~seconds to hours) | 1 commit (~seconds) |

---

## 5. Performance and Scale

### 5.1 Computation Overhead

| Operation | City-G | MLS |
|-----------|--------|-----|
| **Join (Publisher)** | ~100ms (CAPSS Smallwood + ZK-VRF) | ~10ms (TreeKEM add) |
| **Join (Server)** | ~20ms (CAPSS Smallwood + ZK-VRF verify) | ~5ms (signature verify) |
| **Join (Receiver)** | ~50ms (ME-OR + witness) | ~10ms (TreeKEM decrypt) |
| **Send Message** | ~1ms (AEAD) | ~1ms (AEAD) |
| **Receive Message** | ~1ms (AEAD) | ~1ms (AEAD) |

**Note**: City-G has higher join overhead (proofs), but amortizes across many receivers (offline-ready).

---

### 5.2 Bandwidth Overhead

| Artifact | City-G | MLS |
|----------|--------|-----|
| **Anchor/Commit** | ~300KB estimated (w/ SRX ~1MB; pending validation at scale) | ~10KB (TreeKEM commit) |
| **Witness** | ~2KB (O(log N) path) | ~5KB (TreeKEM path) |
| **Message** | ~100B (AEAD overhead) | ~100B (AEAD overhead) |

**Trade-off**: City-G has larger anchors (proofs), but enables offline joins (no per-member commit).

---

### 5.3 Scalability

| Group Size | City-G | MLS |
|------------|--------|-----|
| **1K members** | ✅ | ✅ |
| **10K members** | ✅ | ✅ |
| **50K members** | ✅ | ⚠️ (TreeKEM rebalancing) |
| **100K members** | ⚠️ (architectural; untested beyond 2048) | ❌ (impractical) |
| **1M members** | ⚠️ (architectural; untested beyond 2048) | ❌ (not supported) |

**Bottleneck**:
- **City-G**: SRX payload size (~1MB for 20K joins)
- **MLS**: TreeKEM commit propagation (O(N) for full roster update)

---

### 5.4 Latency

| Metric | City-G | MLS |
|--------|--------|-----|
| **Join Latency** | 1 POST + ME-OR (~100ms total) | 2+ round-trips (~200ms+ total) |
| **Message Latency** | 1 POST (~50ms) | 1 POST (~50ms) |
| **Epoch Transition** | Publisher creates anchor (~100ms) | Any member creates commit (~50ms) |

**Offline Advantage**: City-G receivers derive E_k without server interaction (0 latency).

---

## 6. Use Case Fit

### 6.1 City-G Strengths

**✅ Extremely Large Groups**:
- City/municipality groups (100K+ residents)
- Discord/Telegram-scale communities (50K+ members)
- Conference coordination (conferences, open-source projects)
- Newsletter/broadcast distribution (large subscriber bases)
- Large enterprise messaging (10K+ employees)

**✅ Publisher-Blind Architecture**:
- Activist networks and emergency alerts (server cannot read content)
- High-security applications (zero-trust server)
- Platforms requiring cryptographic (not policy-based) server blindness

**✅ Offline-Ready**:
- Mobile clients (intermittent connectivity)
- IoT devices (low-power, batch processing)
- Edge computing (local epoch derivation)

**✅ Parallel Joins**:
- High-concurrency events (many simultaneous joins/leaves)
- Public events with rapid membership changes

---

### 6.2 MLS Strengths

**✅ Mature Ecosystem**:
- IETF standard (broad adoption)
- Multiple implementations (OpenMLS, Cisco, Wire)
- Interoperability (cross-platform)

**✅ Per-Commit Forward Secrecy**:
- Frequent key rotation (every commit)
- Fine-grained security (per-message compromise recovery)

**✅ Small Group Optimization**:
- Low overhead for <1K members
- Fast commit propagation
- Tight latency bounds

**✅ Flexibility**:
- Proposals (add, remove, update)
- External commits (merge, reinit)
- Application messages

---

### 6.3 Hybrid Approach (Future Work)

**Scenario**: Use City-G for **broadcast** (1M followers), MLS for **small discussions** (10 members).

**Example**:
1. Publisher creates City-G anchor (1M receivers derive E_k)
2. Subset of receivers form MLS group (10 members)
3. MLS group discusses, references City-G anchor context

**Benefits**:
- Scale (City-G) + fine-grained FS (MLS)
- Publisher-blindness (City-G) + interoperability (MLS)

---

## Summary

| Dimension | City-G | MLS | Winner |
|-----------|--------|-----|--------|
| **Scale** | O(log N) to 1M+ (tested to 2048) | ~50K practical | City-G |
| **Server Blindness** | Cryptographic | Transparency logs | City-G |
| **Offline Join** | Non-interactive | Interactive | City-G |
| **Parallel Joins** | 16 concurrent | Sequential | City-G |
| **Post-Quantum** | Native | Hybrid (draft) | City-G |
| **Forward Secrecy** | Per-epoch (E_k + K_barrier independent of K_fs) | Per-commit | Nuanced |
| **Maturity** | Alpha (0.1.0) | IETF RFC 9420 | MLS |
| **Ecosystem** | Limited | Wide adoption | MLS |
| **Join Overhead** | ~300KB (estimated, pending validation) | ~10KB | MLS |
| **Proof Complexity** | High (CAPSS Smallwood + ZK-VRF) | Low (signatures) | MLS |

**Conclusion**:
- **City-G**: Best for extremely large groups, publisher-blind architecture, offline-ready, post-quantum native
- **MLS**: Best for small-to-medium groups, mature ecosystem, fine-grained forward secrecy, broad adoption

**Use Case Mapping**:
- **City/municipality groups, Discord/Telegram-scale communities**: City-G ✅
- **Newsletter distribution, conference coordination**: City-G ✅
- **Corporate messaging (1K-10K)**: MLS ✅
- **Consumer chat (10-100)**: MLS ✅

**Next**: [17 — FAQ](./17-faq.md)

---

**Document Version**: 0.1.4
**References**:
- City-G: v0.1.4 (`tswe/msphf-we/fs-hybrid + prs-barrier`)
- MLS: RFC 9420 (January 2023)
