# Protocol Overview: City-G tswe/msphf-we/fs-hybrid

> [!IMPORTANT]
> This chapter is a legacy companion document. For `tswe/msphf-we/fs-hybrid`, the normative source is [`../specs.md`](../specs.md).
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and implementation.


**Specification:** [`specs.md`](../specs.md) §1-3, §7, §14 — Alpha (0.1.0)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Motivation & Design Goals](#2-motivation--design-goals)
3. [Key Innovations](#3-key-innovations)
4. [Protocol Participants](#4-protocol-participants)
5. [High-Level Architecture](#5-high-level-architecture)
6. [End-to-End Flow](#6-end-to-end-flow)
7. [Comparison to Traditional E2EE](#7-comparison-to-traditional-e2ee)
8. [Design Principles](#8-design-principles)
9. [Constraints & Requirements](#9-constraints--requirements)

---

## 1. Executive Summary

**City-G `tswe/msphf-we/fs-hybrid`** is a post-quantum, publisher-blind end-to-end encryption (E2EE) protocol designed for **extremely large groups** (millions of members) with **offline readiness** and **parallel join capability**.

### One-Sentence Description

> Smooth Projective Hashing (SPHF/HPS) with Masked-Equality OR (ME-OR) yields a unique epoch digest **Y*** and epoch key **E_k** to all valid devices, without interaction and with publisher-blindness.

### Key Properties

| Property | Status | Mechanism |
|----------|--------|-----------|
| **Server Blindness** | ✅ Cryptographic | Server cannot learn hp, Y*, E_k, or eid |
| **Offline Join** | ✅ Native | No online handshake required |
| **Parallel Joins** | ✅ Up to h_max=16 | Multi-Head Window (MHW) |
| **Post-Quantum** | ✅ NIST Standards | ML-KEM-768, ML-DSA-65 |
| **Scalability** | ✅ O(log N) | Merkle witnesses, millions of members |
| **Forward Secrecy** | ✅ Per-epoch | Deterministic epoch rotation |

### Quick Facts

- **Profile:** `tswe/msphf-we/fs-hybrid` (Time-Stamped Witness Extraction / Masked SPHF with Witness Extraction)
- **Group Size:** Designed for millions of members (tested to 10,000+)
- **Join Latency:** <100ms (witness validation + proof verification)
- **Proof Size:** <30KB (CAPSS Smallwood + ZK-VRF combined)
- **Witness Size:** O(log N) ≈ 2KB for 1M members
- **Server Memory:** No secrets stored (blind by construction)

---

## 2. Motivation & Design Goals

**Blueprint:** §1 (Motivation & Fit)

### 2.1 The Problem: MLS Doesn't Scale

**Message Layer Security (MLS)** — the IETF standard for group E2EE — has fundamental limitations:

1. **Sequential Processing:** Only one commit per epoch
   - 200 simultaneous joins? → Requires batching → High latency
   - Server must order and sequence operations

2. **Group Size Ceiling:** Struggles beyond ~1,000 members
   - Tree synchronization overhead
   - CPU/network resources overwhelmed

3. **KeyPackage Management:** Clients must pre-generate and upload key material
   - Vulnerable to exhaustion attacks
   - Server coordination required

4. **No Offline Join:** Requires online interaction with existing members

### 2.2 Design Goals

**From:** [`constraints.md`](../constraints.md), Blueprint §2

1. **✅ Publisher Blindness**
   - Server cannot decrypt messages or derive epoch keys
   - **Not trust-based** — cryptographically enforced

2. **✅ Instant Offline Join**
   - User joins and sends messages even if all members are offline
   - No waiting for online handshakes

3. **✅ Mass Parallel Operations**
   - 200 people joining simultaneously without rejection
   - No MLS-style batching required

4. **✅ Million-Member Groups**
   - O(log N) witness sizes scale efficiently
   - No tree synchronization bottleneck

5. **✅ Post-Quantum Security**
   - NIST-approved algorithms (ML-KEM-768, ML-DSA-65)
   - Quantum-resistant by design, not retrofitted

6. **✅ Battery-Friendly**
   - Fast cryptographic operations on mobile
   - Efficient proof verification (≤6ms ZK-VRF, ≤12ms CAPSS Smallwood)

7. **✅ No Direct Sync**
   - Server-coordinated, no member-to-member synchronization
   - Asynchronous by nature

### 2.3 Use Cases

**Ideal for:**

- **Large Community Channels:** Public discussion groups with 10K+ members
- **Corporate Communications:** Company-wide encrypted channels
- **Disaster Response:** Teams operating with intermittent connectivity
- **Whistleblower Platforms:** Cryptographic blindness protects sources
- **Medical Collaboration:** HIPAA-compliant multi-party discussions
- **IoT Device Groups:** Sleep/wake cycles with offline join capability

**Not ideal for:**

- Small groups (<100 members) where MLS is simpler
- Use cases requiring metadata privacy (timing, social graph)
- Real-time video/voice (add separately via WebRTC)

---

## 3. Key Innovations

### 3.1 Smooth Projective Hash Functions (SPHF)

**Blueprint:** §8 (ME-OR)

**Core Idea:** Hash functions where evaluation depends on language membership:

```
Member of L:     hp ∈ L → Y* = SPHF(hp) is deterministic
Non-member of L: hp ∉ L → Y* appears random (computationally indistinguishable)
```

**Application:** Devices in the group can compute the same Y* from their private hp values. Excluded devices get garbage.

**Key Property:** Server never learns hp (encrypted in KBROAD envelope), so server cannot compute Y* or derive E_k.

### 3.2 Masked-Equality OR (ME-OR)

**Blueprint:** §8, Appendix D

**Construction:**
```
Branch A: Y*_A = SPHF_A(hp_A) ⊕ M_A  if member of set A
Branch B: Y*_B = SPHF_B(hp_B) ⊕ M_B  if member of set B

Result: Y* = Y*_A = Y*_B  (masks ensure equality for valid members)
```

**Innovation:** Allows members in either branch (join or revoke set) to derive the same epoch digest Y*.

**Implementation:** [`crates/msphf-rlwe/src/lib.rs`](../../crates/msphf-rlwe/src/lib.rs)

### 3.3 Barrier-Sealed HP Envelope

**Blueprint:** §12.3, Appendix D

**Structure:**
```rust
["barrier-sealed-v1", hp_context, hp_ciphertext, "chacha20-poly1305"]
```

**Flow:**
1. Publisher: derive a barrier-scoped HP AEAD key from authenticated barrier state
2. Publisher: encrypt `CBOR_det(MSPHF_HP)` into `hp_ciphertext`
3. Server: **validates structure only, never decrypts**
4. Devices: derive the same barrier-scoped HP AEAD key, decrypt hp, compute `Y*` and `E_k`

Binding tuple:
- `gid`
- `barrier_key`
- `barrier_version`
- `xk_hash`
- `hp_commit`

So a cut-and-paste of `hp_ciphertext` into a different anchor context is rejected by client recovery.

**Innovation:** Server validates and relays the transport blob without ever learning the HP material or the AEAD key.

**Implementation:** [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

### 3.4 Multi-Head Window (MHW)

**Blueprint:** §13, Annex M

**Problem:** How to handle parallel joins without race conditions?

**Solution:** Window-based concurrency control:

```
WID := H_L("mhw/window", [gid, parent_root, seed_ctx_hash])

Window Properties:
- h_max = 16 concurrent heads maximum
- TTL = 120 seconds (configurable)
- Heads tracked per WID (public, not derived from secrets)
- Merge operations retire multiple heads atomically
```

**Innovation:** Allows up to 16 parallel joins per window. MLS allows 1.

**Implementation:** [`crates/msphf-orchestrator/src/mhw.rs`](../../crates/msphf-orchestrator/src/mhw.rs)

### 3.5 Deterministic Seed Binding

**Blueprint:** §10 (Seed-Binding & Construction Order)

**Chain:**
```
PoP Signature (ML-DSA-65)
    ↓
ρ := H_L("msphf/rho/der", [pop_sig, xk_hash])  — deterministic from PoP
    ↓
rho_commit := H_L("msphf/kgen/rho", [ρ])  — field #93
    ↓
seed_DRBG := H_L("msphf/drbg", [seed_commit, ρ, xk_hash, seed_ctx_hash])
    ↓
KGen → hp (RLWE-HPS construction)
    ↓
hp_commit := H_L("msphf/hp/commit", [hp])  — field #99
```

**Innovation:** Prevents grinding attacks. Joiner cannot choose favorable ρ because it's deterministically derived from the PoP signature (which commits to the device public key).

**Implementation:** [`crates/msphf-orchestrator/src/lib.rs`](../../crates/msphf-orchestrator/src/lib.rs)

### 3.6 Zero-Knowledge VRF (Output-Hiding)

**Blueprint:** §11, Appendix V

**Statement:** "I know hp such that:
1. `hp_commit = H_L("msphf/hp/commit", [hp])` (matches field #99)
2. `Y* = VRF(VRF_CTX, hp)` is correctly computed
3. Proof binds to all public parameters"

**Key Property:** Verifier learns **nothing about Y*** (output-hiding VRF).

**Innovation:** Server verifies correctness without learning Y* or E_k.

**Implementation:** [`crates/msphf-orchestrator/src/proofs/zk_vrf/`](../../crates/msphf-orchestrator/src/proofs/zk_vrf/)

### 3.7 CAPSS Smallwood Proof (Forward-Secrecy Binding)

**Blueprint:** Appendix L (unified spec)

**Statement:** "I know seed_DRBG and the current forward-secrecy secret such that:
1. KGen(seed_DRBG) → hp (deterministic RLWE hash)
2. `hp_commit = H_L("msphf/hp/commit", [hp])`
3. RLWE parameters / noise bounds hold
4. `fs_epoch_commit`, `fs_ec`, and device-chain commits match the public header"

**Innovation:** Uses the CAPSS Smallwood transcript to bind the forward-secrecy context while keeping `epoch_sk`/`τₑ` hidden. Proofs are compact (~9–15.5 KiB in tuned profiles, capped at 16 KiB) and replayable from deterministic seeds so the server can verify without learning secrets.

**Implementation:** [`crates/msphf-orchestrator/src/proofs/capss.rs`](../../crates/msphf-orchestrator/src/proofs/capss.rs)

---

## 4. Protocol Participants

### 4.1 Joiner (Client)

**Role:** Device joining the group or contributing to an epoch.

**Responsibilities:**
1. Generate PoP (Proof-of-Possession) signature with ML-DSA-65
2. Derive deterministic seed ρ from PoP
3. Build RLWE-HPS hash projection (hp) via KGen
4. Encrypt hp in KBROAD envelope
5. Generate CAPSS Smallwood and ZK-VRF proofs
6. Build SRX witnesses (membership/non-membership proofs)
7. Submit anchor bundle to server

**Capabilities:**
- Knows: hp, Y*, E_k, eid
- Can: Encrypt/decrypt messages with E_k
- Cannot: Force server to accept invalid anchors (cryptographically prevented)

**Implementation:** [`crates/cityg-client/`](../../crates/cityg-client/)

### 4.2 Server (Blind Validator)

**Role:** Blind orchestrator that validates and coordinates epochs.

**Key distinction**: The **server validates** anchors; it does NOT create them. Anchors are created client-side by:
- **Joiners** (self-join in open groups)
- **Publishers** (admins who create anchors for others in controlled groups)

Both produce cryptographically identical anchors - the difference is **policy** (who is allowed to create them), not protocol.

**Responsibilities:**
1. Validate anchor structure (CBOR, header fields)
2. Verify proofs (CAPSS Smallwood, ZK-VRF) without learning secrets
3. Check SRX witnesses (canonical Merkle proofs)
4. Enforce policies (algorithm gates, size limits)
5. Manage Multi-Head Window (MHW) state
6. Track membership deltas (who joined/revoked)
7. Store encrypted messages (without ability to decrypt)

**Capabilities:**
- Knows: gid, parent_root, WID, we_epoch_id, membership roster
- Can: Validate envelope structure, verify proofs, order epochs
- **Cannot:** Learn hp, Y*, E_k, eid, or decrypt messages

**Constraints:**
- MUST NOT implement KEM decapsulation for KBROAD
- MUST NOT implement AEAD decryption for envelope
- MUST use WID (public) for windowing, never Y* or E_k

**Implementation:** [`crates/cityg-server/`](../../crates/cityg-server/), [`crates/msphf-orchestrator/`](../../crates/msphf-orchestrator/)

### 4.3 Receiver (Existing Member)

**Role:** Device already in the group receiving updates.

**Responsibilities:**
1. Fetch accepted anchors from server
2. Decrypt KBROAD envelope with group secret
3. Extract hp from envelope
4. Compute Y* = VRF(VRF_CTX, hp)
5. Derive E_k = H_epoch(X_k, Y*)
6. Decrypt messages with E_k

**Capabilities:**
- Knows: authenticated barrier state plus local secret state
- Can: Decrypt hp, compute Y* and E_k, read messages
- Validates: Envelope correctness, witness validity (optional)

**Implementation:** [`crates/msphf-orchestrator/src/receiver.rs`](../../crates/msphf-orchestrator/src/receiver.rs)

---

## 5. High-Level Architecture

### 5.1 Component Stack

```
┌─────────────────────────────────────────────────────────────┐
│                   Application Layer                         │
│              (Chat app, collaboration tool, etc.)           │
└─────────────────────────────────────────────────────────────┘
                          ↓  ↑
┌─────────────────────────────────────────────────────────────┐
│              cityg-client / cityg-server                    │
│         (High-level API for epoch management)               │
└─────────────────────────────────────────────────────────────┘
                          ↓  ↑
┌─────────────────────────────────────────────────────────────┐
│                  msphf-orchestrator                         │
│  ┌─────────────┬──────────────┬───────────────────────┐    │
│  │  Acceptance │  Multi-Head  │   Receiver Cache      │    │
│  │   Pipeline  │    Window    │   (VCK, Replay Guard) │    │
│  └─────────────┴──────────────┴───────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                          ↓  ↑
┌──────────────────────────────────────────────────────────────┐
│                      msphf-core                              │
│  ┌──────────┬──────────┬──────────────┬──────────────────┐  │
│  │  Hash    │  Merkle  │   Witness    │   RLWE Params   │  │
│  │  (BLAKE3,│  (RPO-   │  Validation  │   & Constants   │  │
│  │   RPO256)│  256/v1) │  (SRX modes) │                 │  │
│  └──────────┴──────────┴──────────────┴──────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                          ↓  ↑
┌──────────────────────────────────────────────────────────────┐
│                      msphf-rlwe                              │
│  ┌────────────────────┬──────────────────────────────────┐  │
│  │   RLWE-HPS KGen    │   Branch Projection & Masking   │  │
│  │  (A1: N=256,Q=3329)│   (ME-OR construction)          │  │
│  └────────────────────┴──────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                          ↓  ↑
┌──────────────────────────────────────────────────────────────┐
│              External Cryptographic Libraries                │
│  ┌──────────────┬─────────────┬──────────────────────────┐  │
│  │ pqcrypto_    │ pqcrypto_   │  blake3, chacha20poly1305│  │
│  │ dilithium    │ kyber       │  (Rust crypto ecosystem) │  │
│  │ (ML-DSA-65)  │ (ML-KEM-768)│                          │  │
│  └──────────────┴─────────────┴──────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### 5.2 Data Flow: Join Operation

```
JOINER                        SERVER                      RECEIVERS
  │                              │                            │
  │ 1. Generate PoP signature    │                            │
  │    (ML-DSA-65)               │                            │
  │                              │                            │
  │ 2. Derive ρ from PoP         │                            │
  │    ρ := H_L("msphf/rho/der", │                            │
  │         [pop_sig, xk_hash])  │                            │
  │                              │                            │
  │ 3. KGen(seed_DRBG) → hp      │                            │
  │    (RLWE-HPS construction)   │                            │
  │                              │                            │
  │ 4. Build KBROAD envelope     │                            │
  │    - KEM.Encap(kbroad_pub)   │                            │
  │    - Wrap K_HP with KEK      │                            │
  │    - Encrypt hp with K_HP    │                            │
  │                              │                            │
  │ 5. Generate proofs           │                            │
  │    - CAPSS Smallwood (seed→hp, FS) │                        │
  │    - ZK-VRF (hp→Y*)          │                            │
  │                              │                            │
  │ 6. Build SRX witnesses       │                            │
  │    (Merkle membership/       │                            │
  │     non-membership proofs)   │                            │
  │                              │                            │
  │ 7. Submit anchor bundle      │                            │
  ├─────── POST /v1/accept_epoch ──→                          │
  │                              │                            │
  │                              │ 8. Validate structure      │
  │                              │    (CBOR, headers, sizes)  │
  │                              │                            │
  │                              │ 9. Verify PoP (ML-DSA-65)  │
  │                              │                            │
  │                              │ 10. Check ρ determinism    │
  │                              │     H_L("msphf/kgen/rho",  │
  │                              │     [ρ]) == field #93      │
  │                              │                            │
  │                              │ 11. Validate KBROAD        │
  │                              │     envelope structure     │
  │                              │     (NO DECRYPTION)        │
  │                              │                            │
  │                              │ 12. Validate SRX witnesses │
  │                              │     (canonical Merkle)     │
  │                              │                            │
  │                              │ 13. Verify CAPSS Smallwood proof │
  │                              │     (seed→hp + FS binding) │
  │                              │                            │
  │                              │ 14. Verify ZK-VRF proof    │
  │                              │     (output-hiding)        │
  │                              │                            │
  │                              │ 15. Check MHW capacity     │
  │                              │     (h_max not exceeded)   │
  │                              │                            │
  │                              │ 16. Store head record      │
  │                              │     (we_epoch_id, wid,     │
  │                              │      public commitments)   │
  │                              │                            │
  │  ← 200 OK {we_epoch_id, wid} ─┤                           │
  │                              │                            │
  │ 17. Compute Y*, E_k locally  │                            │
  │     (joiner already has hp)  │                            │
  │                              │                            │
  │                              │ 18. Notify receivers       │
  │                              ├────→ GET /v1/bundle        │
  │                              │                            │
  │                              │     ←─── bundle ──────────┤
  │                              │                            │
  │                              │                            │ 19. Decrypt KBROAD
  │                              │                            │     - KEM.Decap(ct_kem)
  │                              │                            │     - Derive KEK
  │                              │                            │     - Unwrap K_HP
  │                              │                            │     - Decrypt hp
  │                              │                            │
  │                              │                            │ 20. Compute Y*
  │                              │                            │     Y* = VRF(VRF_CTX, hp)
  │                              │                            │
  │                              │                            │ 21. Derive E_k
  │                              │                            │     E_k = H_epoch(X_k, Y*)
  │                              │                            │
  │                              │                            │ 22. Decrypt messages
  │                              │                            │
  │←────────── Encrypted message ──────────────────────────────────────────┤
  │            (uses E_k)        │                            │
```

### 5.3 Server Blindness Guarantee

**Critical Property:** At no point does the server learn:
- hp (encrypted in KBROAD envelope, never decrypted)
- Y* (hidden by ZK-VRF proof)
- E_k (derived from Y*, which server doesn't know)
- eid (derived from E_k)

**Important Clarification:** "Server blindness" refers to **encryption key confidentiality**, not device anonymity. The server **CAN identify devices** via public keys (ML-DSA-65, ~2KB) transmitted in field #108 (HDR_POP_PK) during join/merge operations. These public keys are used for signature verification and leaf_id computation. However, the server cannot decrypt messages or derive encryption keys.

**Enforcement Mechanism:**
1. **Type System:** No `MlKemSecretKey` in `AcceptanceContext` ([`accept/` module](../../crates/msphf-orchestrator/src/accept/mod.rs))
2. **No Decryption Functions:** `decapsulate()` and `decrypt_hp_bytes()` absent from server code
3. **Public WID:** Windowing uses `WID = H_L("mhw/window", [gid, parent_root, seed_ctx_hash])` (public inputs only)
4. **Automated Verification:** [`scripts/verify_no_secrets.sh`](../../scripts/verify_no_secrets.sh) enforces 10 security checks

---

## 6. End-to-End Flow

### 6.1 Group Creation (Genesis)

```
1. Founder creates group parameters:
   - gid (group identifier)
   - kbroad_pub (group KEM public key)
   - params_id (RLWE parameter pack identifier)
   - fs_policy_version (header key 139 governance pin)

2. Founder generates first anchor (bootstrap):
   - parent_root = [0; 32] (empty set)
   - join_delta_root = founder's leaf
   - Uses bootstrap signature (CA-signed or self-signed)

3. Server accepts anchor:
   - Validates bootstrap signature
   - Creates initial window (WID)
   - Stores head record

4. Founder derives E_k:
   - Computes Y* from hp
   - Derives epoch key
   - Can now send encrypted messages
```

**Example:** [`crates/cityg-client/src/demo.rs`](../../crates/cityg-client/src/demo.rs)

### 6.2 Second Member Join (Self-Join Model)

**Note**: Bob creates his own join anchor - the server never creates anchors.

```
1. Bob fetches group state from server:
   GET /groups/city-chat/state
   Returns:
   - gid, kbroad_pub
   - Current parent_root (7000 existing members)
   - Frontier (O(log N) hashes, ~13 for 7000 members)
   - Policy (e.g., "open_join")

2. Bob generates join anchor client-side:
   - parent_root = current membership root
   - join_delta_root = canonical_set_root([...existing, Bob])
   - Builds membership witness for Bob
   - Builds non-membership witnesses (proving no conflicts)
   - Generates PoP signature (ML-DSA-65)
   - Creates CAPSS Smallwood + ZK-VRF proofs
   - Encrypts hp in KBROAD envelope

3. Bob submits to server (see §5.2 data flow):
   POST /v1/accept_epoch

4. Server validates (two stages):
   4a. Cryptographic validation:
       - PoP signature valid?
      - CAPSS Smallwood / ZK-VRF proofs verify?
       - SRX witnesses canonical?
       - KBROAD envelope structurally valid?

   4b. Application policy (YOUR code, not accept_anchor):
       - join_leaf_ids.len() == 1 (only Bob)?
       - PoP signer not in blocklist?
       - Rate limit check passed?

5. Server accepts and persists:
   - Records we_epoch_id
   - Updates membership roster
   - Makes anchor available to receivers

6. Bob derives E_k locally:
   - Computes Y* from hp (already has it)
   - Derives epoch key
   - Can now send encrypted messages

7. All 7000 existing members:
   - Fetch anchor when convenient (offline-ready)
   - Decrypt KBROAD envelope
   - Derive same E_k
   - Can now decrypt Bob's messages
```

**Alternative: Admin-Controlled Join** (policy-dependent, not protocol-enforced):
- In some groups, Alice (admin) creates the join anchor for Bob
- Alice knows all secrets (hp, Y*, E_k) for that epoch
- Server validation is identical (crypto is the same)
- Only difference: Application policy checks who created the anchor

**Example:** [`crates/msphf-orchestrator/tests/end_to_end.rs`](../../crates/msphf-orchestrator/tests/end_to_end.rs)

### 6.3 Parallel Joins (MHW)

```
Scenario: 10 people joining simultaneously

1. All 10 joiners build anchors from same parent_root:
   - Each has unique pop_sig → unique ρ → unique hp
   - Each generates own CAPSS Smallwood and ZK-VRF proofs
   - All reference same parent membership set

2. All 10 submit to server concurrently

3. Server processes in parallel:
   - Each gets unique we_epoch_id
   - All share same WID (same parent_root, seed_ctx_hash)
   - Window now has 10 active heads (< h_max=16, accepted)

4. Merge operation (optional):
   - Merger builds anchor listing all 10 we_epoch_ids
   - Retires all 10 heads atomically
   - New unified head represents merged state
```

**Capacity:** Default h_max=16 concurrent heads. If a 17th joiner arrives before merge, the server returns deterministic code `925` (`mh_window_full`).

**Reference Implementation:** See the GUI client implementation in [`crates/cityg-gui/src/bin/join_leave.rs`](../../crates/cityg-gui/src/bin/join_leave.rs) for the complete join/leave workflow including ticket handling, forward secrecy, and proper cryptographic operations.

### 6.4 Message Exchange

```
1. Sender (has E_k):
   - Plaintext = "Hello, group!"
   - Ciphertext = AEAD_Enc(E_k, nonce, aad, plaintext)
   - Submit to server: POST /v1/send_message {we_epoch_id, ciphertext}

2. Server:
   - Stores ciphertext (cannot decrypt)
   - Associates with we_epoch_id
   - Broadcasts to subscribers

3. Receivers:
   - Fetch bundle for we_epoch_id
   - Decrypt KBROAD → hp → Y* → E_k
   - Decrypt ciphertext with E_k
   - Read plaintext
```

**AEAD:** ChaCha20-Poly1305 (Alpha (0.1.0) §12.3)
**Nonce:** Deterministically derived from epoch context (prevents reuse)

---

## 7. Comparison to Traditional E2EE

### 7.1 vs. Signal Protocol

| Feature | Signal | City-G |
|---------|--------|--------|
| **Group Size** | ~1,000 max | Millions |
| **Server Knowledge** | Metadata (who talks to whom) | Membership roster only |
| **Online Requirement** | Sender must be online | Offline join supported |
| **Post-Quantum** | Experimental (PQXDH) | Native (ML-KEM/DSA) |
| **Parallel Joins** | N/A (pairwise) | Up to 16 concurrent |
| **Forward Secrecy** | Double Ratchet | Per-epoch rotation |

### 7.2 vs. MLS (Message Layer Security)

| Feature | MLS (RFC 9420) | City-G |
|---------|----------------|--------|
| **Max Group Size** | ~1,000 | Millions |
| **Parallel Operations** | 1 commit/epoch (sequential) | 16 concurrent heads |
| **Offline Join** | Requires KeyPackages from server | Native offline capability |
| **Server Blindness** | Transparency logs (trust) | Cryptographic (SPHF) |
| **Proof Size** | ~2KB (TreeKEM) | ~30KB (CAPSS + ZK-VRF) |
| **Witness Size** | O(log N) | O(log N) |
| **Post-Quantum** | Hybrid mode | Native |
| **KeyPackage Exhaustion** | Vulnerable | Not applicable |

**Key Difference:** MLS requires server to order operations sequentially. City-G allows parallel processing via Multi-Head Window.

### 7.3 vs. Matrix Olm/Megolm

| Feature | Matrix (Megolm) | City-G |
|---------|-----------------|--------|
| **Group Size** | ~100 efficiently | Millions |
| **Server Encryption** | Keys in cleartext on server | Server blind |
| **Scalability** | O(N) distribution | O(log N) witnesses |
| **Post-Quantum** | No | Yes |
| **Federation** | Yes | Could be added |

---

## 8. Design Principles

**Blueprint:** §16 (Implementation Guidance)

### 8.1 Server Blindness by Construction

**Principle:** Server cannot learn secrets, enforced by absence of decryption capability.

**Implementation:**
- No `MlKemSecretKey` types in server structs
- No `decapsulate()` or `decrypt()` functions for KBROAD
- Public WID for windowing (never secret-derived identifiers)

**Verification:** [`scripts/verify_no_secrets.sh`](../../scripts/verify_no_secrets.sh)

### 8.2 Determinism Everywhere

**Principle:** All randomness is deterministic from seeds to prevent non-deterministic bugs.

**Examples:**
- ρ derived from PoP signature (no client choice)
- seed_DRBG derived from public commitments
- BLAKE3 XOF for all random values (deterministic from seed)
- CBOR canonical encoding enforced

**Benefits:**
- Reproducible test vectors (KATs)
- No race conditions from randomness
- Easier debugging and verification

### 8.3 Defense in Depth

**Principle:** Multiple validation layers protect against attacks.

**Layers:**
1. **Pre-filters:** Size limits enforced before parsing
2. **Structure:** CBOR canonical encoding verified
3. **Cryptographic:** Signatures, proofs, commitments validated
4. **Semantic:** Witness canonicity, SRX completeness checked
5. **Policy:** Algorithm gates, allowlists enforced
6. **Anti-Grind:** ρ determinism, sorted witnesses

### 8.4 Fail-Secure Errors

**Principle:** Invalid inputs produce deterministic protocol outcome codes; most validation failures are per-message `REJECT(code)` outcomes.

**Error Semantics:**
- **REJECT(code):** Deterministic input failure; no acceptance-state mutation.
- **DROP / QUARANTINE / FREEZE(group):** Reserved operational actions; not default acceptance behavior.

**Benefit:** Prevents grinding attacks. Attacker cannot retry with modified inputs.

**Reference:** [12-error-reference.md](12-error-reference.md)

### 8.5 Constant-Time Where It Matters

**Principle:** Secret-dependent operations use constant-time implementations.

**Examples:**
- RLWE arithmetic (Montgomery/Barrett reduction)
- NTT operations (fixed loop counts)
- No data-dependent branching on secrets

**Verification:** [`docs/timing-verification.md`](../timing-verification.md)

### 8.6 Offline-First Design

**Principle:** Minimize online coordination requirements.

**Features:**
- No member-to-member handshakes
- No online key exchange
- Server coordinates asynchronously
- Receivers fetch at their convenience

---

## 9. Constraints & Requirements

**Source:** [`constraints.md`](../constraints.md)

### 9.1 Security Requirements

1. **✅ Confidentiality:** Server cannot access message plaintext or epoch keys
2. **✅ Authentication:** PoP signatures bind devices to group operations
3. **✅ Integrity:** Merkle witnesses and commitments prevent tampering
4. **✅ Forward Secrecy:** Epoch rotation ensures past keys compromise doesn't affect future
5. **✅ Post-Compromise Security:** New epochs independent of previous compromises
6. **✅ Group Membership Consistency:** Canonical Merkle roots ensure agreement
7. **✅ Deniability:** AEAD provides no non-repudiation (by design)

### 9.2 Functional Requirements

1. **✅ Instant Join:** User can join and send messages without waiting for others
2. **✅ Offline Retrieval:** Offline users fetch messages when reconnecting
3. **✅ Concurrent Operations:** 200 simultaneous joins supported (16 per window)
4. **✅ Member Notification:** Server tracks join/revoke events
5. **✅ Member List:** Canonical Merkle roots provide membership roster
6. **✅ Battery-Friendly:** Mobile-optimized proof verification (<20ms total)
7. **✅ Millions of Members:** O(log N) witnesses scale efficiently
8. **✅ No Direct Sync:** Server-coordinated, asynchronous model
9. **✅ Simple Client:** No KeyPackage management complexity

### 9.3 Performance Targets

**Blueprint:** §17 (Benchmarks & Resource Budgets)

| Operation | Target | Measured |
|-----------|--------|----------|
| **ZK-VRF Verify** | ≤2ms server, ≤6ms mobile | ✅ Meets spec |
| **CAPSS Verify** | ≤12ms mobile | ✅ Meets spec |
| **SRX Verify** | ≤60ms (20K members) | ✅ Meets spec |
| **Proof Size** | <30KB (CAPSS + VRF) | ✅ ~25KB actual |
| **Witness Size** | O(log N) | ✅ ~2KB for 1M |
| **Working Set** | ≤48MB | ✅ Meets spec |

**Verification:** [`docs/evidence/benchmarks/`](../evidence/benchmarks/)

---

## 10. Next Steps

### For Developers
→ Read [03-data-structures.md](03-data-structures.md) to understand wire formats
→ Read [11-implementation-guide.md](11-implementation-guide.md) for code walkthrough

### For Cryptographers
→ Read [05-sphf-meor.md](05-sphf-meor.md) for SPHF construction
→ Read [06-proof-systems.md](06-proof-systems.md) for CAPSS Smallwood and ZK-VRF details
→ Read [10-security-model.md](10-security-model.md) for threat analysis

### For Protocol Implementers
→ Read [07-server-acceptance.md](07-server-acceptance.md) for validation pipeline
→ Read [08-client-operations.md](08-client-operations.md) for client workflow
→ Read [12-error-reference.md](12-error-reference.md) for error handling

---

**Blueprint References:**
- §1: Motivation & Fit
- §2: Delivered Capabilities
- §3: Threat Model
- §7: Primitive API
- §13: Epoch Routing & Concurrency (MHW)
- §14: Security Properties

**Implementation References:**
- Core: [`crates/msphf-core/`](../../crates/msphf-core/)
- RLWE: [`crates/msphf-rlwe/`](../../crates/msphf-rlwe/)
- Orchestrator: [`crates/msphf-orchestrator/`](../../crates/msphf-orchestrator/)
- Client: [`crates/cityg-client/`](../../crates/cityg-client/)
- Server: [`crates/cityg-server/`](../../crates/cityg-server/)
- API: [`crates/cityg-api/`](../../crates/cityg-api/)
