# 06 — Proof Systems (CAPSS Smallwood & ZK-VRF-for-ME-OR)

> [!IMPORTANT]
> This chapter is a legacy companion document. For `tswe/msphf-we/fs-hybrid`, the normative source is [`../specs.md`](../specs.md).
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and implementation.


**Blueprint**: Alpha (0.1.0) §11, §12.2, Annexes L & V (unified spec)
**Implementation**: [`crates/msphf-orchestrator/src/proofs/`](../../crates/msphf-orchestrator/src/proofs/)

---

## Table of Contents

1. [Overview](#1-overview)
2. [CAPSS Smallwood Proof](#2-capss-smallwood-proof)
   - 2.1 [Transcript Layout](#21-transcript-layout)
   - 2.2 [Deterministic Seeding](#22-deterministic-seeding)
   - 2.3 [Binding Digest & Header Field 146](#23-binding-digest--header-field-146)
3. [ZK-VRF-for-ME-OR (Output-Hiding VRF)](#3-zk-vrf-for-me-or-output-hiding-vrf)
4. [Proof Binding & Hash Labels](#4-proof-binding--hash-labels)
5. [Verification Pipeline](#5-verification-pipeline)
6. [Security Properties](#6-security-properties)

---

## 1. Overview

Every City-G join anchor carries two zero-knowledge proofs:

1. **CAPSS Smallwood** — a deterministically seeded Smallwood/DECS transcript that binds the
   forward-secrecy tuple `(fs_epoch_commit, fs_ec, fs_dev_commit)` to the published `hp_commit`
   without revealing any secret Material.
2. **ZK-VRF-for-ME-OR** — an output-hiding VRF proof that shows both branches derive the same
   epoch digest **Y\*** from `hp`, again without revealing **Y\*** itself.

The proofs are non-interactive (Fiat–Shamir) and fully publisher-blind: the server can replay them,
validate integrity, and short-circuit acceptance on any failure, but never learns the secret seeds,
hash projections, or epoch keys.

---

## 2. CAPSS Smallwood Proof

### Goal

Prove that:
- `hp` was derived deterministically from the public tuple (PoP-derived seeds + context) using the
  RLWE-HPS KGen.
- The forward-secrecy commitments (`fs_epoch_commit`, `fs_ec`, `fs_dev_commit`) are consistent with
  the same seeds.
- No information about the seeds, τₑ, or `epoch_sk` leaks.

### 2.1 Transcript Layout

The orchestrator serializes the proof as a `CapssSignature` (bincode) that wraps a
`SmallwoodProof`:

```rust
pub struct SmallwoodProof {
    pub config: SmallwoodConfig,
    pub transcript: SmallwoodTranscript,
}

pub struct SmallwoodTranscript {
    pub commitments: Vec<RoundCommitment>, // length = repetitions (default 1)
    pub challenge: Vec<u8>,                // Fiat–Shamir challenge
    pub responses: Vec<RoundResponse>,     // one per opened round
}

pub struct RoundCommitment {
    pub commitment: Vec<u8>,  // DECS Merkle root
    pub metadata: Vec<u8>,    // salt derived from round seed
}

pub struct RoundResponse {
    pub evaluations: Vec<u8>,     // serialized LVCS evaluations
    pub opening_proof: Vec<u8>,   // DECS opening proof (masks + Merkle path)
}
```

**Encoding Notes**
- `SmallwoodConfig` stores the negotiated parameters (security level, `nb_queries`, `rho`, etc.).
- All byte arrays are fixed-length in practice (commitments 32 bytes, salts 16 bytes) but remain as
  owned `Vec<u8>` for bincode compatibility.
- The canonical fixture (see `crates/capss/tests/fixtures/*.json`) reveals the exact byte counts.

### 2.2 Deterministic Seeding

Both prover and verifier derive round material from a shared `SmallwoodSeeder` (BLAKE3-based):

- **Master seed** is published in the fixture to enable Sage/Rust cross-checks, but never transmitted
  in production.
- For each repetition `i`:
  - `round_seed = seeder.round(i)`
  - `salt = round_seed.derive(b"round/salt", b"", 16)` (stored in `RoundCommitment.metadata`)
  - Witness/mask polynomials are generated deterministically from the same seed segments.

This guarantees the verifier can replay the exact LVCS/DECS commitments from the transcript plus the
public tuple.

### 2.3 Binding Digest & Header Field 146

Field **#146** (`fs_capss`) stores `CapssSignature::proof.bytes` — the serialized `SmallwoodProof`
shown above. The Fiat–Shamir challenge is still derived with the legacy label
`"msphf/lin_fs/chal"`:

```rust
let challenge = H_L(
    "msphf/lin_fs/chal",
    [statement_bytes, commitment_bytes, evaluations_bytes, opening_proof_bytes],
);
```

The same label intentionally remains to preserve backward compatibility with existing label
registries and tooling. `HDR_PROOFS_COMMIT` hashes `[vrf_proof, fs_capss]` so any tampering with the
transcript or recomputed digest (field #125) causes a deterministic freeze.

### 2.4 Parameter set & sample vector

| Parameter | Value |
|-----------|-------|
| Field modulus (`p`) | `21888242871839275222246405745257275088548364400416034343698204186575808495617` |
| Generator | `5` |
| Fiat–Shamir domain | `"msphf/srx_smallwood"` |
| Label | `"capss-srx-smallwood"` |
| Repetitions | `1` |
| Polynomial degree | `4` |
| `nb_queries` | `1` |
| `rho` | `1` |

**Sample SRX shadow roots (for testing/documentation)**

Inputs: `parent = 0x11…11`, `join = 0x22…22`, `revoked_since = 0x33…33`, `revoked_root = 0x44…44`, `srx_commit = 0x55…55`, `payload_digest = 0x66…66`.

| Case | `compute_shadow_root(...)` |
|------|--------------------------------------------|
| Before (no SRX commit/payload) | `105f267feee1dd25e661d46839c7cba1a5e82207222e1b2857a9be58bf2047c0` |
| After (with commit + payload)  | `eda7afb92a88b83c8c3eb346d6ff1f1cf9ed7f9bf34b155a496a3168b6b1dfbc` |

Implementations MUST reproduce the values above for the given inputs before shipping; the corresponding unit test (`shadow_root_sample_vector`) asserts them.

### 2.4 Parameter set (normative) + sample vector

| Parameter | Value | Notes |
|-----------|-------|-------|
| Field modulus (`p`) | `21888242871839275222246405745257275088548364400416034343698204186575808495617` | BN254-compatible (see `capss::field::FieldElement`) |
| Generator | `5` | Matches Arkworks defaults |
| Label | `"capss-srx-smallwood"` | Included in `CapssConfig` |
| Fiat–Shamir domain | `"msphf/srx_smallwood"` | Bound to SRX shadow roots |
| Repetitions | `1` | Soundness parameter |
| Polynomial degree | `4` | Matches MSPHF witness size |
| Queries per repetition (`nb_queries`) | `1` | |
| ρ (mask polynomials) | `1` | |

All digests inside `encode_statement_payload` (payload, hint counts, hint sizes) use unkeyed BLAKE3; the CAPSS public key (`iv`, `y`) is the BLAKE3 hash `compute_shadow_root(...)` interpreted as a field element via little-endian reduction.

**Sample SRX shadow roots**

For the canonical test tuple (`parent = 0x11…11`, `join = 0x22…22`, `revoked_since = 0x33…33`, `revoked_root = 0x44…44`, `srx_commit = 0x55…55`, `payload_digest = 0x66…66`), the deterministic hash yields:

```
shadow_root_before = 105f 267f eee1 dd25 e661 d468 39c7 cba1
                     a5e8 2207 222e 1b28 57a9 be58 bf20 47c0
shadow_root_after  = eda7 afb9 2a88 b83c 8c3e b346 d6ff 1f1c
                     f9ed 7f9b f34b 155a 496a 3168 b6b1 dfbc
```

Any implementation of `compute_shadow_root` MUST reproduce the bytes above for the sample inputs before shipping.

---

## 3. ZK-VRF-for-ME-OR (Output-Hiding VRF)

The ZK-VRF module is unchanged: it proves that both branches produce the same **Y\*** under the
challenge context without revealing **Y\***. See [`crates/msphf-orchestrator/src/proofs/zk_vrf/`](../../crates/msphf-orchestrator/src/proofs/zk_vrf/)
for the Rust implementation. Key properties:

- Output hiding (server never learns **Y\***).
- Deterministic seeding via transcript transcripts to prevent grinding.
- Runs before SRX so acceptance can fail fast on VRF inconsistency.

---

## 4. Proof Binding & Hash Labels

| Label | Purpose | Notes |
|-------|---------|-------|
| `"msphf/lin_fs/chal"` | CAPSS Smallwood Fiat–Shamir challenge | Legacy label retained for compatibility |
| `"msphf/proofs"` | Commitment over `[vrf_proof, fs_capss]` | Field #125 (`HDR_PROOFS_COMMIT`) |
| `"msphf/hp/commit"` | Hash projection commitment | Field #99 |
| `"fs/epoch/commit"` | Forward-secrecy epoch commit | Field #142 |

A verifier recomputes the challenge, replays each round from deterministic seeds, checks the DECS
Merkle openings, and finally ensures the transcript bytes match the hashed commitment in field #125.

---

## 5. Verification Pipeline

The orchestrator follows this sequence (see [`accept::stages`](../../crates/msphf-orchestrator/src/accept/stages.rs)):

1. Extract `fs_capss` (field 146) and enforce the size bound (`≤ 16,384` bytes).
2. Deserialize `CapssSignature` → `SmallwoodProof`.
3. Rebuild the CAPSS context using the public tuple (same CBOR as the client) and run
   `smallwood_verifier.verify(...)`.
4. Extract the ZK-VRF proof (field 95) and verify output-hiding VRF constraints.
5. Only if both proofs succeed do we continue with SRX witness validation.

Any failure freezes the anchor with `944.2 fs_capss_invalid`.

---

## 6. Security Properties

- **Soundness**: Based on the Smallwood/DECS polynomial commitment security (random oracle model)
  plus RLWE hardness for the underlying witness polynomials.
- **Zero-knowledge**: Verifier learns only the public tuple; seeds and forward-secrecy secrets remain
  hidden.
- **Determinism**: Shared seeding ensures replayability and unique challenge derivation.
- **Composability**: The CAPSS and ZK-VRF proofs feed into the same `proofs_commit` binding, so the
  server cannot mix-and-match transcripts from different anchors.
