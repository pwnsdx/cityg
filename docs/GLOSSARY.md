# City-G Glossary

A comprehensive reference for City-G terminology, organized alphabetically for quick lookup.

---

## A

### Acceptance
The process by which the server validates an anchor (or epoch bundle) cryptographically without learning secrets. See [Server Acceptance](./protocol/07-server-acceptance.md).

### AcceptanceOptions
Configuration parameters that control coarse-grained policy for anchor validation (allowed SRX modes, suite IDs, bootstrap rules). Configured once per deployment.

### Anchor
A signed, server-blind update representing a state transition (e.g., member join, merge, or revocation). The server can validate it cryptographically but cannot decrypt the protected header containing epoch keys. Devices derive and use those keys privately.

**Anchor types** (v0.1.2, spec S4.1):
- **JOIN**: introduces a new device leaf; carries `barrier_leaf_pk` (key 177).
- **MERGE**: carries merge/checkpoint state; may carry `barrier_update` (key 175).
- **REGULAR**: any anchor that is neither JOIN nor MERGE.

**Also known as**: Epoch bundle, ClientEpochBundle

**See also**: [Protocol Overview](./protocol/01-overview.md)

### AEAD
Authenticated Encryption with Associated Data. Used in City-G for encrypting the KBROAD envelope (ChaCha20-Poly1305).

**See also**: KBROAD

---

## B

### Barrier (PRS Barrier)
The post-revocation secrecy subsystem introduced in v0.1.2 (spec S11). Uses a KEM-tree cover to rotate `K_barrier` after revocations, ensuring that revoked members cannot decrypt future messages.

**Components**: `K_barrier`, `barrier_version`, `BarrierUpdate`, `KemTreeCoverPayload`

**See also**: K_barrier, BarrierUpdate

### BarrierUpdate
A CBOR structure (spec S11.5) carried in anchor header key 175 on MERGE anchors. Contains the KEM-tree cover payload that lets non-revoked members derive the new `K_barrier`.

**Wire tag**: `"barrier-v1"`

### barrier_version
A monotonically increasing integer tracking the current barrier epoch. Bound into the payload key schedule (S8.3) and device-chain commit (S7.4).

---

## C

### CAPSS Smallwood
A hash-based polynomial commitment scheme providing zero-knowledge proofs. In City-G, it proves that `hp` (hash projection key) was derived deterministically from a seed and binds forward-secrecy metadata without revealing secrets.

**Proof Size**: ~12KB typical, ≤16KB maximum
**Field**: `146: fs_capss` in anchor headers

**See also**: [CAPSS README](../crates/capss/README.md), [Proof Systems](./protocol/06-proof-systems.md)

### Checkpoint
A compact summary that replaces many anchors, allowing newcomers to sync quickly without gaining extra decryption ability for past content. Also called a **rollup**.

**See also**: Rollup, Epoch

### Ciphertext
The encrypted message content stored on the server. Only group members with valid epoch keys can decrypt it.

**See also**: E_k, Epoch

### ClientEpochBundle
The CBOR-encoded data structure containing all cryptographic material for an anchor: proofs, witnesses, epoch metadata, and encrypted secrets.

**See also**: Anchor, [Data Structures](./protocol/03-data-structures.md)

---

## D

### DECS
Distributed Encrypted Commitment Scheme. Part of CAPSS Smallwood using Merkle trees and polynomial masking.

### Device
A physical endpoint (phone, laptop, server) with its own cryptographic identity (ML-DSA signing key, VRF keypair).

---

## E

### E_k (Epoch Key)
The symmetric encryption key used to encrypt/decrypt messages within a specific epoch. In v0.1.2, the payload key schedule binds to `K_barrier` and `barrier_version` (spec S8.3): `K_msg_epoch` is derived via HKDF-BLAKE3 from `E_k` with `K_barrier` in the salt, ensuring revoked members cannot decrypt.

**Security**: Server never learns E_k (cryptographically enforced).

### Epoch
A cryptographic snapshot of the group state at a specific point in time, including:
- Merkle tree root of all members
- Witness extraction key material
- VRF proofs
- Forward secrecy metadata

**Also known as**: Anchor, WE-epoch (Witness Extraction epoch)

**See also**: Anchor, E_k, Y*

### Epoch ID (eid)
A 32-byte identifier uniquely identifying an epoch, derived as `H("msphf/eid", xk_hash, Y*)`.

**See also**: [Client Operations](./protocol/08-client-operations.md)

---

## F

### Forward Secrecy (FS)
Cryptographic property ensuring that compromise of current keys does not reveal past communications. City-G provides **minutes-grade forward secrecy** through automatic epoch rotation.

**Granularity**: Configurable (default: 5 minutes via `H` parameter)
**Enforcement**: Time-blind (client-enforced, not server-controlled)

**See also**: [Protocol Overview](./protocol/01-overview.md#key-innovations)

### Freeze Code
A numeric error code returned when the server rejects an anchor during validation. Each code indicates a specific validation failure (witness error, parent not found, window full, etc.).

**See also**: [Error Reference](./protocol/12-error-reference.md)

### Frontier
The set of Merkle tree hashes needed to compute the root and generate witnesses. For N members, frontier size is O(log₂ N):
- 1,000 members → ~10 hashes (320 bytes)
- 1,000,000 members → ~20 hashes (640 bytes)

**See also**: Merkle Root, Witness

---

## G

### Group ID (gid)
A string identifier for a City-G room (e.g., `"demo-room"`, `"team-alpha"`).

---

## H

### H_L (Domain-Separated Hash)
Domain-separated hash function producing 32 bytes, used throughout City-G for label-separated derivations (spec S2.2):
`H_L(label, args[]) := BLAKE3_derive_key(context="city-g|h_l|v1", message="city-g|" || ASCII(label) || 0x00 || CBOR_det(args[]))`

### Hash Projection Key (hp)
A Ring-LWE parameter set used to compute Y* via smooth projective hash functions. The server never learns hp (encrypted in KBROAD envelope).

**Generation**: RLWE-HPS (Hash-based Public-Key Encryption)
**Security**: ML-KEM-768 IND-CCA2 protects hp

### Head
A parallel branch in the Multi-Head Window representing concurrent state evolution. City-G supports up to `h_max` heads (default: 16).

**See also**: MHW


### HKDF-BLAKE3
Key derivation function used throughout City-G (spec S2.3). `HKDF-BLAKE3(ikm, salt32, info_bytes, L=32)` performs Extract then Expand using BLAKE3 keyed hashing. L is always 32 bytes in this profile.

---

## J

### Join Flow
The process where a new member joins a group:
1. Fetch group state (roots, frontier, KBROAD public key)
2. Create anchor locally with proofs
3. Submit to server for validation
4. Begin sending/receiving messages

**Time**: <100ms for validation
**Offline**: No online handshake required

**See also**: [Workflows](./workflows.md#join-flow)

---

## K

### K_barrier
The group-wide barrier secret (32 bytes) used to bind the payload key schedule (spec S8.3, S11). Rotated via `BarrierUpdate` after revocations (post-revocation secrecy) or proactive PCS refresh. Provisioned to joiners during the join flow (spec S12.2).

**See also**: Barrier, BarrierUpdate

### KBROAD (Key Broadcasting)
Group key broadcasting envelope that encrypts `hp` using ML-KEM-768 + ChaCha20-Poly1305. Structure:
```
["kbroad-v1", ct_kem, wrap, C_hp, "chacha20-poly1305"]
```

**Server Role**: Validates structure only, never decrypts
**Field**: `97: kbroad_envelope` in anchor headers

**See also**: [Protocol Overview](./protocol/01-overview.md#33-kbroad-envelope)

---

## L

### LB-VRF
Lattice-Based Verifiable Random Function. Provides deterministic, verifiable randomness used in City-G's ME-OR construction for Y* derivation.

**Security**: Post-quantum secure (Module-LWE hardness)
**Proof Size**: ≤8KB

**See also**: [LB-VRF README](../crates/msphf-lb-vrf/README.md)

### Leaf ID
A 32-byte hash identifying a device: `H(device_public_key)`. Each member has a unique leaf ID in the Merkle tree.

**Format**: Hex-encoded (64 characters)
**Privacy**: Server sees leaf IDs, not raw public keys

**See also**: Device, Merkle Root

### LVCS
Linear Verifiable Commitment Scheme. Part of CAPSS with layout management and opening proofs.

---

## M

### ME-OR (Masked-Equality OR)
A cryptographic construction allowing members in either the join or revoke set to derive the same epoch digest Y* using SPHF with carefully computed masks.

**Innovation**: Enables offline admission and parallel operations
**Result**: All valid members compute identical Y* without interaction

**See also**: [SPHF & ME-OR](./protocol/05-sphf-meor.md)

### Merkle Root
A 32-byte hash representing the complete state of the member tree. Roots change as members join/leave, providing tamper-evident membership tracking.

**Types**:
- `parent_root`: Previous state
- `join_delta_root`: Current state after adds
- `revoked_root`: Accumulated revocations

### MHW (Multi-Head Window)
Concurrency control mechanism allowing up to `h_max` parallel anchors within a time window. Prevents race conditions and enables high-throughput joins.

**Parameters**:
- `h_max`: 16 concurrent heads (default)
- `TTL`: 120 seconds (default; raise only if clients routinely exceed 2 minutes of jitter)
- `WID`: Window identifier (public, deterministic)

**See also**: [Multi-Head Window](./protocol/09-multi-head-window.md)

### ML-DSA
Module Lattice Digital Signature Algorithm (NIST FIPS 204, formerly Dilithium). Used for Proof-of-Possession (PoP) signatures in City-G.

**Variant**: ML-DSA-65
**Security**: Post-quantum secure (~128-bit classical, ~96-bit quantum)

### ML-KEM
Module Lattice Key Encapsulation Mechanism (NIST FIPS 203, formerly Kyber). Used for KBROAD envelope encryption.

**Variant**: ML-KEM-768
**Security**: Post-quantum secure, IND-CCA2

---

## P

### PACS
Polynomial Algebraic Constraint System. Defines constraint relations for witness data in CAPSS proofs.

### Parent Root
The Merkle root representing the group state before a new anchor is applied. Each anchor must reference a valid parent root known to the server.

### Pivot
Forward secrecy component that rotates periodically (every `H` seconds) to provide time-based key evolution.

**See also**: Forward Secrecy

### PoP (Proof-of-Possession)
An ML-DSA-65 signature proving device key ownership. Every anchor includes a PoP signature from the publisher.

**See also**: ML-DSA, Publisher

### Publisher
The device that creates and signs an anchor. Can be:
- The joining member (self-join in open groups)
- An admin (controlled groups)
- An existing member (merge operations)

**Blindness**: Server validates publisher's proofs without learning epoch secrets

---

## R

### RLWE-HPS
Ring Learning With Errors - Hash Proof System. The instantiation of SPHF used in City-G for computing hp values.

**Parameters**:
- Ring degree: 256
- Modulus: q = 3329
- Distribution: Centered binomial

**Security**: Module-LWE hardness (~96-bit quantum security)

### Rollup
See **Checkpoint**

---

## S

### Server-Blindness
Cryptographic property ensuring the server cannot decrypt messages or derive epoch keys, even if the server is compromised. Enforced through:
1. ML-KEM-768 IND-CCA2 (KBROAD encryption)
2. ZK-VRF output-hiding
3. Code separation (no decryption functions in server path)
4. Automated verification (`verify_no_secrets.sh`)

**Important**: Server-blindness refers to **encryption key confidentiality** (server cannot learn hp, Y*, E_k, or eid). This does NOT mean sender anonymity — the server **CAN identify devices** via public keys (ML-DSA-65, ~2KB) transmitted in field #108 (HDR_POP_PK) during join/merge operations.

**See also**: [Security Model](./protocol/10-security-model.md)

### SPHF (Smooth Projective Hash Function)
Hash functions where evaluation depends on language membership. Members of the group can compute the same Y* deterministically; non-members get computationally indistinguishable randomness.

**Application**: All valid devices compute identical Y* from their hp values without interaction

**See also**: [SPHF & ME-OR](./protocol/05-sphf-meor.md)

### SRX (Structured Relational Witness)
The witness validation system providing Merkle proofs of membership/non-membership with canonical encoding.

**Modes**: `srx/v1-complete` (full witnesses)
**Size**: O(log N) for N members

**See also**: [Witness Validation](./protocol/04-witness-validation.md)

---

## T

### TOFU (Trust-On-First-Use)
Security model where the first encountered public key for an identity is trusted, with warnings on subsequent key changes.

**City-G Usage**: Optional identity binding with ML-DSA-65 PoP; alias→key mappings stored locally

### tswe/msphf-we/fs-hybrid + prs-barrier
The City-G protocol profile name (v0.1.2):
- **tswe**: Time-Stamped Witness Extraction
- **msphf-we**: Masked SPHF with Witness Extraction
- **fs-hybrid**: Forward Secrecy with hybrid pivot rotation
- **prs-barrier**: Post-Revocation Secrecy via KEM-tree barrier

---

## W

### WE-epoch
Witness Extraction epoch. See **Epoch**.

### WID (Window Identifier)
A deterministic identifier for a Multi-Head Window, computed as:
```
WID = H_L("mhw/window", [gid, parent_root, seed_ctx_hash])
```

**Properties**: Public (not derived from secrets), unique per window state

### Witness
Cryptographic proof that a leaf ID is (or is not) a member of the Merkle tree at a specific root. Witnesses are canonical and grow O(log N).

**See also**: [Witness Validation](./protocol/04-witness-validation.md)

---

## X

### xk_hash
A 32-byte commitment to the anchor context (group ID, roots, public parameters). Used for challenge binding in proofs.

**Computation**: `H("msphf/xk", [gid, parent_root, join_delta_root, ...])`

---

## Y

### Y* (VRF Output)
The unique epoch digest computed via ME-OR from SPHF evaluation. Used to derive the epoch key E_k.

**Properties**:
- Deterministic for valid group members
- Output-hiding (server never learns Y*)
- Unique per epoch
- 32 bytes

**Derivation**: In v0.1.2, message keys are bound to `K_barrier` via HKDF-BLAKE3 (spec S8.3).

**See also**: [SPHF & ME-OR](./protocol/05-sphf-meor.md)

---

## Z

### ZK-VRF (Zero-Knowledge Verifiable Random Function)
A proof system demonstrating that Y* was computed correctly without revealing it. Based on LB-VRF with output-hiding property.

**Proof Size**: ≤8KB
**Field**: `95: zk_vrf_proof` in anchor headers

**See also**: [Proof Systems](./protocol/06-proof-systems.md)

---

## Numeric & Symbols

### 16 KB
Maximum size for CAPSS Smallwood proofs (`fs_capss_max_bytes`)

### 8 KB
Maximum size for ZK-VRF proofs (`max_vrf_proof_bytes`)

### 32 bytes
Standard size for:
- Hash outputs (BLAKE3)
- Epoch IDs
- Leaf IDs
- Merkle roots
- Y* outputs

---

## Common Abbreviations

| Abbreviation | Full Term |
|--------------|-----------|
| AEAD | Authenticated Encryption with Associated Data |
| CAPSS | A Framework for SNARK-Friendly Post-Quantum Signatures |
| CBOR | Concise Binary Object Representation |
| DECS | Distributed Encrypted Commitment Scheme |
| FS | Forward Secrecy |
| HP | Hash Projection |
| HPS | Hash Proof System |
| KEK | Key Encryption Key |
| LB-VRF | Lattice-Based Verifiable Random Function |
| LVCS | Linear Verifiable Commitment Scheme |
| ME-OR | Masked-Equality OR |
| MHW | Multi-Head Window |
| ML-DSA | Module Lattice Digital Signature Algorithm |
| ML-KEM | Module Lattice Key Encapsulation Mechanism |
| PACS | Polynomial Algebraic Constraint System |
| PoP | Proof-of-Possession |
| RLWE | Ring Learning With Errors |
| ROM | Random Oracle Model |
| SPHF | Smooth Projective Hash Function |
| SRX | Structured Relational Witness |
| TOFU | Trust-On-First-Use |
| VRF | Verifiable Random Function |
| WE | Witness Extraction |
| ZK | Zero-Knowledge |

---

## See Also

- **[Protocol Overview](./protocol/01-overview.md)** - High-level protocol architecture
- **[FAQ](./protocol/17-faq.md)** - Frequently asked questions
- **[Label Registry](./protocol/15-label-registry.md)** - Domain separation labels
- **[Data Structures](./protocol/03-data-structures.md)** - CBOR encodings

---

**Last Updated**: 2026-02-25
**Note**: This glossary consolidates terminology from across City-G documentation. For formal definitions, see the [specification](./specs.md).
