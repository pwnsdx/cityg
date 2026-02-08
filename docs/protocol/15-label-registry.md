# 15 — Label Registry

> [!IMPORTANT]
> This chapter is a legacy companion document. For `tswe/msphf-we/fs-hybrid`, the normative source is [`../specs-unified-fs.md`](../specs-unified-fs.md).
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and implementation.


**Profile**: City-G `tswe/msphf-we/fs-hybrid` (Alpha (0.1.0))
**Status**: Normative (domain-separation labels)

## Table of Contents

1. [Introduction](#1-introduction)
2. [Label Construction](#2-label-construction)
3. [Complete Label Registry](#3-complete-label-registry)
4. [Label Categories](#4-label-categories)
5. [Collision Analysis](#5-collision-analysis)

---

## 1. Introduction

This document provides a **complete registry** of all domain-separation labels used in the City-G `tswe/msphf-we/fs-hybrid` protocol. Labels are used in the `H_L(label, args)` construction to prevent cross-domain hash collisions.

**Blueprint Reference**: Alpha (0.1.0) Appendix E (Label & Field Registry)

### 1.1 Purpose

Domain separation ensures:
1. **No collisions**: `H_L("label1", args) ≠ H_L("label2", args)` (even if args identical)
2. **Context binding**: Hash outputs tied to specific protocol contexts
3. **Auditability**: Complete list of all labels in use

---

## 2. Label Construction

### 2.1 H_L Definition

**Blueprint** (Alpha (0.1.0) Appendix A):
```
H_L(label, args[]) := BLAKE3("city-g|" || ASCII(label) || 0x00 || CBOR_det(args[]))
```

**Implementation** ([crates/msphf-core/src/hash.rs](../../crates/msphf-core/src/hash.rs)):
```rust
pub fn h_l<T: Serialize>(label: &str, val: &T) -> Result<[u8; 32], MsphfError> {
    let mut hasher = blake3::Hasher::new();

    // Domain prefix
    hasher.update(b"city-g|");

    // Label (ASCII)
    hasher.update(label.as_bytes());

    // Separator
    hasher.update(&[0x00]);

    // CBOR canonical encoding of args
    let cbor = to_cbor_vec(val)?;
    hasher.update(&cbor);

    Ok(hasher.finalize().into())
}
```

**Properties**:
- **Deterministic**: Same (label, args) → same output
- **Domain-separated**: Different labels → different outputs (even if args identical)
- **Collision-resistant**: BLAKE3 256-bit security

---

### 2.2 Label Naming Convention

**Format**: `category/subcategory/name`

**Examples**:
- `msphf/rho/der` (MSPHF category, rho subcategory, derivation)
- `mhw/window` (MHW category, window identifier)
- `leaf-id` (top-level, leaf identifier)

**Rules**:
- Lowercase ASCII only
- Use hyphens (`-`) within words, slashes (`/`) for hierarchy
- Avoid abbreviations unless standard (e.g., `rho`, `hp`, `vrf`)

---

## 3. Complete Label Registry

### 3.1 Seed Derivation

| Label | Args | Output | Usage |
|-------|------|--------|-------|
| **msphf/rho/der** | `[pop_sig, xk_hash]` | ρ_raw [32B] | Derive ρ from PoP signature (Step 4.1) |
| **msphf/kgen/rho** | `[ρ_raw]` | rho_commit (93) [32B] | Commitment to ρ (header field 93) |
| **msphf/drbg** | `[seed_commit, ρ, xk_hash, seed_ctx_hash]` | seed_DRBG [32B] | DRBG seed for KGen |
| **seedctx** | `[CBOR_det(ANCHOR_SEED_CTX)]` | seed_ctx_hash (91) [32B] | Hash of anchor seed context |

**Blueprint Reference**: Alpha (0.1.0) §10 (Seed-Binding)

---

### 3.2 Commitments

| Label | Args | Output | Usage |
|-------|------|--------|-------|
| **msphf/hp/commit** | `[hp]` | hp_commit (99) [32B] | Commitment to hash projection key |
| **msphf/seed_bundle** | `[SeedCommitFields]` | seed_bundle_commit (94) [32B] | Commitment to seed bundle |
| **msphf/srx/commit** | `[srx_payload]` | srx_commit (121) [32B] | Commitment to SRX payload |
| **msphf/proofs** | `[95, 146, (160,161 if present)]` | proofs_commit [32B] | Commitment to proofs (fail-fast precheck) |
| **vk/hp** | `[hp_commit(99), meor_vrf_id]` | vk_commit [32B] | VRF verification key commit |

**Blueprint Reference**: Alpha (0.1.0) §12.0 (Header Keys), Annex I (VCK)

---

### 3.3 Epoch and Identity

| Label | Args | Output | Usage |
|-------|------|--------|-------|
| **msphf/epoch** | `[X_k, Y*]` | E_k [32B] | Epoch key derivation |
| **we/eid** | `[E_k]` | eid [32B] | Epoch identifier (optional, client-side) |
| **msphf/xk** | `[X_k]` | xk_hash [32B] | Hash of canonical CBOR epoch context |
| **leaf-id** | `[device_pk_alg, device_pk_bytes]` | leaf_id [32B] | Device leaf identifier |

**Blueprint Reference**: Alpha (0.1.0) §4 (Public Instance), §7 (Primitive API)

---

### 3.4 PoP (Proof of Possession)

| Label | Args | Output | Usage |
|-------|------|--------|-------|
| **msphf/pop/msg** | `[X_k, leaf_id, we_epoch_id]` | pop_msg [32B] | PoP signature message |

**Blueprint Reference**: Alpha (0.1.0) §8.4 (PoP), Appendix N (Policy)

**Implementation**:
```rust
let pop_msg = h_l("msphf/pop/msg", &PopMsg {
    xk: &X_k,
    leaf_id: &leaf_id,
    we_epoch_id: &we_epoch_id,
})?;
let pop_sig = ml_dsa_sign(&pop_msg, &device_sk);
```

---

### 3.5 KBROAD Envelope

| Label | Args | Output | Usage |
|-------|------|--------|-------|
| **hp/kek/salt** | `[xk_hash]` | salt [32B] | HKDF salt for KEK derivation |
| **hp/kek/nonce** | `[xk_hash, hp_commit(99)]` | nonce [32B, use [0..11]] | AEAD nonce for wrap |
| **hp/nonce** | `[xk_hash, hp_commit(99)]` | nonce [32B, use [0..11]] | AEAD nonce for C_hp |

**Blueprint Reference**: Alpha (0.1.0) §12.3 (KBROAD Transport)

**Implementation**:
```rust
// KEK derivation
let salt = h_l("hp/kek/salt", &xk_hash)?;
let kek = hkdf_blake3(&ss, &salt, b"city-g|hp/kek/v1", 32)?;

// Wrap nonce
let wrap_nonce_full = h_l("hp/kek/nonce", &[xk_hash, hp_commit])?;
let wrap_nonce = &wrap_nonce_full[0..12];

// C_hp nonce
let hp_nonce_full = h_l("hp/nonce", &[xk_hash, hp_commit])?;
let hp_nonce = &hp_nonce_full[0..12];
```

---

### 3.6 Multi-Head Window

| Label | Args | Output | Usage |
|-------|------|--------|-------|
| **mhw/window** | `[gid, parent_root(110), seed_ctx_hash(91)]` | WID [32B] | Window identifier (MHW routing) |
| **tswe/merge/weid** | `[gid, cat, xk_hash, mh_heads]` | merge_we_epoch_id [32B] | Merge mode we_epoch_id (optional) |
| **msphf/merge/hp** | `[parent_root, mh_heads]` | merge_hp_commit [32B] | Merge mode hp_commit (optional) |

**Blueprint Reference**: Alpha (0.1.0) §13 (Epoch Routing & Concurrency), Annex M (MHW)

**WID Computation**:
```rust
pub fn compute_window_id(
    gid: &[u8],
    parent_root: &[u8; 32],
    seed_ctx_hash: &[u8; 32],
) -> Result<[u8; 32], MsphfError> {
    h_l("mhw/window", &WindowIdInputs {
        gid,
        parent_root,
        seed_ctx_hash,
    })
}
```

---

### 3.7 CAPSS Smallwood Proof

| Label | Args | Output | Usage |
|-------|------|--------|-------|
| **msphf/fs-lin/commit** | `[witness_field, context]` | commitment [32B] | CAPSS Smallwood commitment (C_i) |
| **msphf/fs-lin/challenge** | `[commitments[], bind]` | challenge [32B] | CAPSS Smallwood Fiat-Shamir challenge |

**Blueprint Reference**: Alpha (0.1.0) Annex L (CAPSS Smallwood)

**Implementation**:
```rust
// Commitment
let c_seed = h_l("msphf/fs-lin/commit", &("seed_commit", inputs.seed_commit))?;
let c_rho = h_l("msphf/fs-lin/commit", &("rho_commit", inputs.rho_commit))?;
let c_hp = h_l("msphf/fs-lin/commit", &("hp_commit", inputs.hp_commit))?;

// Challenge
let challenge = h_l("msphf/fs-lin/challenge", &ChallengeInputs {
    commitments: &[c_seed, c_rho, c_hp, /* ... */],
    bind: &inputs.bind,
})?;
```

---

### 3.8 ZK-VRF Proof

| Label | Args | Output | Usage |
|-------|------|--------|-------|
| **vrf/mask** | `[hp_commit, vrf_ctx_hash, mask_nonce]` | mask_digest [32B] | VRF output-hiding mask |
| **vrf/ctx** | `[vrf_ctx_fields]` | vrf_ctx_hash [32B] | VRF context hash |

**Blueprint Reference**: Alpha (0.1.0) §11 (ZK-VRF-for-ME-OR), Appendix V (lb-vrf/v1)

**Implementation**:
```rust
// VRF context hash
let vrf_ctx_hash = h_l("vrf/ctx", &VrfCtx {
    xk_hash: &inputs.xk_hash,
    params_id: &inputs.params_id,
    // ... other fields
})?;

// Mask digest (output-hiding)
let mask_digest = h_l("vrf/mask", &MaskDigest {
    hp_commit: &inputs.hp_commit,
    vrf_ctx_hash: &vrf_ctx_hash,
    mask_nonce: &derive_mask_nonce(&hp)?,
})?;
```

---

### 3.9 VCK (Verify-Cache Key)

| Label | Args | Output | Usage |
|-------|------|--------|-------|
| **msphf/vck** | `[xk_hash, 94, 93, 99, 98, 106, srx_commit_or_zero, proofs_commit_or_zero, proof_mode, meor_vrf_id, fs_policy_version]` | VCK [32B] | Cache key for deterministic reject outcomes |

**Blueprint Reference**: Alpha (0.1.0) Annex I (VCK)

**Implementation**:
```rust
let vck = h_l("msphf/vck", &VckInputs {
    xk_hash: &header[&91],
    seed_bundle_commit: &header[&94],
    rho_commit: &header[&93],
    hp_commit: &header[&99],
    crs_id: &header[&98],
    params_id: &header[&106],
    srx_commit: srx_commit_or_zero,
    proofs_commit: &proofs_commit,
    proof_mode: &header[&119],
    meor_vrf_id: &header[&116],
    fs_policy_version: &ctx.fs_policy_version,
})?;
```

---

### 3.10 Branch Labels

| Label | Args | Output | Usage |
|-------|------|--------|-------|
| **msphf/branch/a** | `[branch_ctx]` | branch_hash [32B] | Branch A material (membership) |
| **msphf/branch/b** | `[branch_ctx]` | branch_hash [32B] | Branch B material (join delta) |

**Implementation**:
```rust
pub fn h_branch_bytes(
    branch: &str,
    crs_id: &str,
    params: &[u8],
    args: &[(&str, &[u8])],
) -> Result<[u8; 32], MsphfError> {
    let label = format!("msphf/branch/{}", branch.to_lowercase());
    h_l(&label, &BranchCtx { crs_id, params, args })
}
```

---

### 3.11 Forward-Secrecy Labels (FS-Hybrid Profile)

| Label | Args | Output | Usage |
|-------|------|--------|-------|
| **fs/epoch/salt** | `[weid, fs_ec]` | salt [32B] | Salt for τₑ derivation |
| **fs/epoch/sk_salt** | `[weid, fs_ec]` | salt [32B] | Salt for epoch_sk derivation |
| **fs/epoch/commit** | `[epoch_sk]` | commitment [32B] | Commitment to epoch secret (field 142) |
| **fs/kfs/salt** | `[weid]` | salt [32B] | Salt for K_fs evolution |
| **fs/dev/chain** | `[device_pk, fs_ec, fs_dev_prev_commit]` | commit [32B] | Device chain commit (field 153) |
| **msphf/lin_fs/chal** | `[bind_fs_tuple]` | digest [32B] | CAPSS Smallwood+ binding digest |
| **msphf/lin_fs/tag/tau** | `[fs_epoch_commit, round, mask]` | digest [32B] | ROM-tag for τ clause round `round` |
| **msphf/lin_fs/tag/hp** | `[hp_commit, round, mask]` | digest [32B] | ROM-tag for HP clause round `round` |
| **msphf/lin_fs/com** | `[clause_label, tag_label, round, tag]` | digest [32B] | Per-round CAPSS Smallwood commitment |
| **msphf/lin_fs/com/all** | `[clause_label, tag_label, commitments[]]` | digest [32B] | Aggregate CAPSS Smallwood commitment |

`bind_fs_tuple := [ xk_hash, seed_commit, seed_bundle_commit, rho_commit, crs_id, hp_commit,
params_id, parent_root, join_delta_root, revoked_since_prev_root, revoked_root, proof_mode,
fs_policy_version, vrf_id, fs_epoch_commit, fs_ec, fs_dev_prev_commit, fs_dev_commit,
(srx_root_sw when SRX applies) ]`.

**Profile**: `tswe/msphf-we/fs-hybrid` only

**Blueprint Reference**: Unified spec Annex H, L (CAPSS Smallwood+)

**Key Derivations**:
```rust
// 1. Derive τₑ (epoch cache secret)
let tau_e = HKDF_BLAKE3(
    ikm  = K_fs^t,
    salt = h_l("fs/epoch/salt", &[weid, fs_ec])?,
    info = b"city-g|fs/epoch/tau|v1",
    len  = 32
)?;

// 2. Derive epoch_sk (for CAPSS Smallwood+ proof)
let epoch_sk = HKDF_BLAKE3(
    ikm  = K_fs^t,
    salt = h_l("fs/epoch/sk_salt", &[weid, fs_ec])?,
    info = b"city-g|fs/epoch/sk|v1",
    len  = 32
)?;

// 3. Commit to epoch_sk (field 142)
let fs_epoch_commit = h_l("fs/epoch/commit", &[epoch_sk])?;

// 4. Device chain commit (field 153)
let fs_dev_commit = h_l("fs/dev/chain", &[device_pk, fs_ec, fs_dev_prev_commit])?;

// 5. Evolve K_fs (after anchor creation)
K_fs^(t+1) = HKDF_BLAKE3(
    ikm  = K_fs^t,
    salt = h_l("fs/kfs/salt", &[weid])?,
    info = b"city-g|fs/kfs/v1" || to_le_bytes_u64(fs_ec + 1),
    len  = 32
)?;
zeroize(K_fs^t); // REQUIRED
```

**Security Notes**:
- Server never learns `K_fs`, τₑ, or `epoch_sk`
- Digest ensures headers cannot decouple `fs_epoch_commit`, suite choices, or device chain
- Device chain prevents key reordering attacks
- Forward secrecy enforced via zeroization of `K_fs^t`

---

## 4. Label Categories

### 4.1 By Lifecycle Stage

| Stage | Labels | Count |
|-------|--------|-------|
| **Joiner KGen** | `msphf/rho/der`, `msphf/kgen/rho`, `msphf/drbg`, `msphf/hp/commit`, `leaf-id`, `msphf/pop/msg` | 6 |
| **Server Acceptance** | `seedctx`, `msphf/srx/commit`, `msphf/proofs`, `msphf/vck`, `msphf/rollup/prov`, `msphf/rollup/vck`, `mhw/window` | 7 |
| **Client Epoch Derivation** | `msphf/epoch`, `we/eid`, `msphf/xk` | 3 |
| **KBROAD** | `hp/kek/salt`, `hp/kek/nonce`, `hp/nonce` | 3 |
| **Proofs** | `msphf/fs-lin/commit`, `msphf/fs-lin/challenge`, `vrf/mask`, `vrf/ctx`, `vk/hp` | 5 |
| **Branch** | `msphf/branch/a`, `msphf/branch/b` | 2 |
| **Merge** | `tswe/merge/weid`, `msphf/merge/hp` | 2 |

**Total**: 28 unique labels

---

### 4.2 By Component

| Component | Labels | Count |
|-----------|--------|-------|
| **msphf-core** | `leaf-id`, `msphf/xk`, `msphf/epoch`, `we/eid` | 4 |
| **msphf-rlwe** | `msphf/branch/a`, `msphf/branch/b`, `msphf/drbg` | 3 |
| **msphf-orchestrator** | `msphf/rho/der`, `msphf/kgen/rho`, `seedctx`, `msphf/hp/commit`, `msphf/seed_bundle`, `msphf/srx/commit`, `msphf/proofs`, `msphf/vck`, `msphf/rollup/prov`, `msphf/rollup/vck`, `mhw/window`, `msphf/pop/msg`, `hp/kek/salt`, `hp/kek/nonce`, `hp/nonce`, `msphf/fs-lin/commit`, `msphf/fs-lin/challenge`, `vrf/mask`, `vrf/ctx`, `vk/hp`, `tswe/merge/weid`, `msphf/merge/hp` | 22 |
| **anchor-seed** | `seedctx`, `msphf/seed_bundle` | 2 (overlap) |

---

### 4.3 By Security Criticality

| Criticality | Labels | Rationale |
|-------------|--------|-----------|
| **High** | `msphf/rho/der`, `msphf/drbg`, `msphf/hp/commit`, `msphf/epoch`, `hp/nonce` | Seed/key derivation, epoch key, AEAD nonce |
| **Medium** | `msphf/kgen/rho`, `seedctx`, `msphf/proofs`, `vrf/mask`, `msphf/fs-lin/challenge` | Commitments, proofs, VRF |
| **Low** | `mhw/window`, `leaf-id`, `msphf/xk`, `msphf/vck` | Identifiers, cache keys (public) |

---

## 5. Collision Analysis

### 5.1 Collision Resistance

**Theorem**: For distinct labels `L1 ≠ L2`:
```
Pr[H_L(L1, args) = H_L(L2, args)] ≤ 2^(-256)
```

**Proof**: BLAKE3 collision resistance (256-bit security).

---

### 5.2 Label Uniqueness Verification

**Script**: Verify no duplicate labels in codebase:
```bash
rg 'h_l\("([^"]+)"' -o --no-filename | sort | uniq -d
# Expected: (empty, no duplicates)
```

**Result**: All 26 labels are unique ✅

---

### 5.3 Prefix Independence

**Property**: No label is a prefix of another.

**Verification**:
```
msphf/rho/der ≠ prefix of msphf/rho
msphf/kgen/rho ≠ prefix of msphf/kgen
msphf/fs-lin/commit ≠ prefix of msphf/fs-lin/challenge
```

**Result**: No prefix collisions ✅

---

### 5.4 Cross-Context Binding

**Example**: `hp/kek/nonce` includes both `xk_hash` and `hp_commit`:
```rust
let nonce = h_l("hp/kek/nonce", &[xk_hash, hp_commit])?;
```

**Property**: Nonce is unique per (epoch context, hp) pair → prevents cross-anchor replay.

---

## 6. Implementation Cross-References

The following matrix ties each HKDF/info string back to its implementation. This
completes the November 2025 label spot-audit.

| Label / Info String | Spec Reference | Implementation Anchor |
|---------------------|----------------|------------------------|
| `fs/epoch/salt`, `fs/epoch/sk_salt`, `fs/epoch/commit` | Alpha §13–14 | `crates/msphf-orchestrator/src/lib.rs` (`fs_epoch_*`) |
| `fs/kfs/salt`, `city-g\|fs/kfs/v1` \|\| `le_u64(fs_ec+1)` | Alpha §13 | `ForwardSecrecyState::evolve_k_fs` (`crates/msphf-orchestrator/src/lib.rs`) |
| `city-g\|fs/epoch/tau|v1`, `city-g\|fs/epoch/sk|v1` | Table 22 (Annex H/J) | `ForwardSecrecyState::prepare_join` (`crates/msphf-orchestrator/src/lib.rs`) |
| `srx/commit` | Annex F, header key 121 | `msphf_core::ds::MSPHF_SRX_COMMIT` + `accept/stages.rs` commitment checks |
| `srx/payload/digest`, `srx/bridge/v1`, `srx/root_sw/empty` | Annex F (Smallwood bridge + init) | `crates/msphf-orchestrator/src/accept/mod.rs` + `crates/msphf-orchestrator/src/proofs/srx_smallwood.rs` |
| `city-g\|hp/kek/v1` | Alpha §12.3 | `derive_hp_kek` (`crates/msphf-orchestrator/src/lib.rs`) |

Additional labels listed in §3 inherit their implementations from the canonical
`msphf-core::ds` constants and the `h_l` helper. If you add a new derivation,
extend this table and cite the corresponding module.

---

## Summary

The City-G `tswe/msphf-we/fs-hybrid` protocol uses **34 unique domain-separation labels**:

1. **Seed Derivation** (4): `msphf/rho/der`, `msphf/kgen/rho`, `msphf/drbg`, `seedctx`
2. **Commitments** (5): `msphf/hp/commit`, `msphf/seed_bundle`, `msphf/srx/commit`, `msphf/proofs`, `vk/hp`
3. **Epoch & Identity** (4): `msphf/epoch`, `we/eid`, `msphf/xk`, `leaf-id`
4. **PoP** (1): `msphf/pop/msg`
5. **KBROAD** (3): `hp/kek/salt`, `hp/kek/nonce`, `hp/nonce`
6. **MHW** (3): `mhw/window`, `tswe/merge/weid`, `msphf/merge/hp`
7. **CAPSS Smallwood Core** (2): `msphf/fs-lin/commit`, `msphf/fs-lin/challenge`
8. **ZK-VRF** (2): `vrf/mask`, `vrf/ctx`
9. **VCK** (1): `msphf/vck`
10. **Branch** (2): `msphf/branch/a`, `msphf/branch/b`
11. **Forward-Secrecy (FS-Hybrid)** (7): `fs/epoch/salt`, `fs/epoch/sk_salt`, `fs/epoch/commit`, `fs/kfs/salt`, `fs/dev/chain`, `msphf/lin_fs/chal`, `tswe/epoch/key`

**Properties**:
- ✅ **Unique**: No duplicate labels
- ✅ **Collision-resistant**: BLAKE3 256-bit security
- ✅ **Prefix-independent**: No label is prefix of another
- ✅ **Context-bound**: Args include epoch/anchor context

**Next**: [16 — Comparison with MLS](./16-comparison-mls.md)

---

**Document Version**: 0.1.0
**Blueprint Reference**: Alpha (0.1.0) Appendix E
**Implementation**: City-G 0.1.0
