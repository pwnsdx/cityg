# 07 — Server Acceptance Pipeline

**Blueprint**: Alpha (0.1.0) §12.2, §12.3, §15
**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Step 0: Pre-Filters & Maxima](#step-0-pre-filters--maxima)
3. [Step 1: Structure & Presence](#step-1-structure--presence)
4. [Step 2: Gates & Policy](#step-2-gates--policy)
5. [Step 3: PoP Validation (Join Only)](#step-3-pop-validation-join-only)
6. [Step 4: ρ Determinism & Seed-Bundle](#step-4-ρ-determinism--seed-bundle)
7. [Step 5: KBROAD Binding (Public, No Decrypt)](#step-5-kbroad-binding-public-no-decrypt)
8. [Step 6: SRX Validation](#step-6-srx-validation)
9. [Step 7: Proofs (Join Only)](#step-7-proofs-join-only)
10. [Step 8: Defense-in-Depth](#step-8-defense-in-depth)
11. [Step 9: Cache & Window Management](#step-9-cache--window-management)
12. [Merge Mode](#12-merge-mode)
    1. [Revocation & Reinstatement](#121-revocation--reinstatement)
13. [Error Semantics](#13-error-semantics)

---

## 1. Overview

The **acceptance pipeline** is the server-side validation sequence that determines whether to accept or reject an epoch anchor. It enforces cryptographic correctness, DoS hygiene, and policy compliance **without learning secrets**.

### Key Properties

- **Publisher-blind**: Server never decrypts KBROAD envelope (no KEM/AEAD operations)
- **Deterministic**: Same inputs always produce same outcome (Freeze errors are cacheable)
- **Defensive**: Multiple layers of validation prevent malformed/malicious anchors
- **Efficient**: Most checks are O(1) or O(log N); SRX is the only O(N) step

### Modes

- **Join mode**: New anchor (requires PoP, SRX, proofs)
- **Merge mode**: Consolidates multiple heads (no PoP/SRX/proofs, validates head references)

### Canonical constants & encodings

- `ZERO` denotes the 32-byte all-zero string `0x00…00`. Any comparison against “zero” commits (e.g., device-chain fields 152/153) MUST treat the value as a 32-byte byte string and compare bytewise.
- Unless otherwise noted, integer header fields use canonical CBOR unsigned integers (big-endian, no leading zero bytes). When hashed via `H_L`, the canonical CBOR encoding is hashed directly—implementations MUST NOT re-encode integers in ad-hoc formats.
- CBOR maps MUST be encoded in canonical key order (ascending numeric keys); every `H_L` invocation in this document assumes canonical CBOR.

### Device key rotation semantics

Rotating the device signing key (`108/109`) is modeled as onboarding a new device. The first anchor after rotation MUST present `fs_dev_prev_commit == ZERO`, satisfy the `D_first_device` bound, and rebuild its `fs_dev_commit` chain from scratch. The acceptance layer does **not** track historical key continuity; any policy (e.g., “admin devices may rotate once per day”) belongs at Tier 3. Deployments that require explicit continuity MUST publish a merge/rotation anchor that rebinds membership to the new key before accepting further joins.

**Blueprint**: Alpha (0.1.0) §12.2

---

## Time-Blind Acceptance & Logical Clock

CityG's acceptance pipeline is **time-blind**: it never consults wall-clock timestamps when validating anchors. Instead, it uses a **logical acceptance clock** that advances deterministically based on accepted anchors.

### Logical Clock Architecture

**Implementation**: [`crates/msphf-orchestrator/src/time.rs`](../../crates/msphf-orchestrator/src/time.rs)

The logical clock provides two key types:

#### `AcceptInstant`
A logical timestamp represented as a tick counter:
```rust
pub struct AcceptInstant {
    ticks: u64,
}
```

- Each tick represents one accepted anchor
- Ticks are monotonically increasing
- Independent of wall-clock time or time zones
- Prevents server from manipulating acceptance timing

#### `AcceptClock`
The deterministic clock that advances on each acceptance:
```rust
pub struct AcceptClock {
    next_tick: u64,
    last: AcceptInstant,
}
```

**Key methods:**
- `now()` - Returns current logical timestamp
- `tick()` - Advances clock by one tick (called after each anchor acceptance)

### Why Time-Blind Acceptance?

**Security properties:**
1. **Server cannot widen FS window**: Without access to wall-clock, server cannot manipulate forward-secrecy boundaries
2. **Deterministic replay**: Crash recovery produces identical state when replaying journal
3. **No clock skew attacks**: Clients use local monotonic counters for FS evolution
4. **Time zone independence**: Protocol works identically regardless of server location

**Client-side time management:**
- Clients compute `ec_local(now)` using their own monotonic clock (Annex H)
- Clients enforce FS boundaries locally using `τₑ cache` retention windows
- Server validates FS metadata (field 141: `fs_ec`, field 142: `fs_epoch_commit`) but never checks wall-clock consistency

**Forward-secrecy guarantee:**
The server validates that:
- Device chains are monotonic (fields 152/153)
- FS epoch counters don't violate forward/backward caps
- CAPSS Smallwood binds `fs_epoch_commit` to the header

But the server **cannot**:
- Determine absolute wall-clock time of anchor creation
- Backdateor fast-forward FS evolution
- Correlate logical ticks with real-world timestamps

**See also:**
- [Annex H](../specs-unified-fs.md#annex-h) - Local Boundary Counter (client-side time-grid)
- [Annex J](../specs-unified-fs.md#annex-j) - τₑ Caching & Offline Decryption

---

## Policy vs. Cryptography: Three-Tier Model

City-G separates **cryptographic validation** (protocol-enforced) from **policy enforcement** (application-layer). Understanding this distinction is critical for implementing City-G correctly.

### Three Tiers

```
┌─────────────────────────────────────────────────────────────────┐
│ Tier 3: Fine-Grained Policy (Application Code)                  │
├─────────────────────────────────────────────────────────────────┤
│ Examines accepted anchor BEFORE persisting:                     │
│                                                                 │
│ Group: "city-announcements"                                     │
│   ✓ join_leaf_ids.len() == 1?      ← Only 1 member per anchor   │
│   ✓ PoP signer not in blocklist?   ← Check against allow list   │
│   ✓ Rate limit check?              ← Join once per hour         │
│   → Accept self-joins              ← Open policy                │
│                                                                 │
│ Group: "executive-team"                                         │
│   ✓ PoP signer in admin_list?      ← Check Alice's leaf_id      │
│   ✓ join_leaf_ids.len() <= 10?     ← Bulk adds allowed          │
│   → Reject self-joins              ← Admin-only policy          │
│                                                                 │
│ NOTE: This is YOUR code, not in accept_anchor()                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Tier 2: Coarse Policy (AcceptanceOptions)                       │
├─────────────────────────────────────────────────────────────────┤
│ Deployment-wide configuration:                                  │
│   • allowed_srx_modes: ["srx/v1-complete"]                      │
│   • allowed_params_ids: [A1, A2]                                │
│   • bootstrap_policy: genesis anchor rules                      │
│   • allowed_proof_modes: ["lin+zkvrf"]                          │
│                                                                 │
│ Applied during accept_anchor() via AcceptanceOptions            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Tier 1: Cryptographic Validation (accept_anchor)                │
├─────────────────────────────────────────────────────────────────┤
│ Protocol-enforced checks (ALWAYS run):                          │
│   ✓ PoP signature valid?                                        │
│   ✓ CAPSS SmallWood proof verifies?                              │
│   ✓ ZK-VRF proof verifies?                                      │
│   ✓ SRX witnesses canonical?                                    │
│   ✓ KBROAD envelope structurally valid?                         │
│   ✓ rho determinism enforced?                                   │
│   ✓ Merkle roots consistent?                                    │
│                                                                 │
│ This is the accept_anchor() function - policy-agnostic          │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation Pattern

```rust
// Tier 1: Cryptographic validation (accept_anchor does this)
let accepted_anchor = accept_anchor(&parts, we_epoch_id, &header_map, now)?;

// Tier 2: Coarse policy (already applied via AcceptanceOptions)
// (nothing to do here - already happened in accept_anchor)

// Tier 3: Fine-grained policy (YOUR application code)
match group_id {
    "city-announcements" => {
        // Only allow self-joins (1 member at a time)
        if accepted_anchor.join_leaf_ids.len() != 1 {
            return Err("bulk joins not allowed in announcements");
        }

        // Check blocklist
        let signer = accepted_anchor.pop_signer_leaf_id;
        if blocklist.contains(&signer) {
            return Err("signer is blocked");
        }

        // Rate limiting
        if !rate_limiter.allow(signer, Duration::from_hours(1)) {
            return Err("rate limit exceeded");
        }
    }

    "executive-team" => {
        // Only admins can create join anchors
        let signer = accepted_anchor.pop_signer_leaf_id;
        if !admin_list.contains(&signer) {
            return Err("only admins can add members");
        }

        // Allow bulk adds (up to 10)
        if accepted_anchor.join_leaf_ids.len() > 10 {
            return Err("too many members in one anchor");
        }
    }

    _ => return Err("unknown group"),
}

// Persist accepted anchor
db.store_anchor(&accepted_anchor)?;
```

### Key Points

1. **accept_anchor() is policy-agnostic**: It validates cryptography, not group-specific rules
2. **AcceptanceOptions**: Deployment-wide coarse policy (algorithm allowlists, suite gates)
3. **Application layer**: Group-specific fine-grained policy (who can join which groups)
4. **Server sees metadata**: `join_leaf_ids`, `pop_signer_leaf_id` are PUBLIC (you can examine them)
5. **Server is blind to secrets**: `hp`, `Y*`, `E_k` are NEVER revealed to server

**Important**: "Server blind to secrets" means **encryption key confidentiality** (server cannot decrypt messages or derive epoch keys). However, the server **CAN identify devices** via public keys (ML-DSA-65, ~2KB) transmitted in field #108 (HDR_POP_PK). This is NOT sender anonymity.

**See also**: Main README §"Policy vs Cryptography" for visual diagrams

---

## Step 0: Size & Policy Checks

**Purpose**: Apply coarse limits before running the expensive proof verifiers.

The acceptance context defines the following guards:

```rust
const MAX_HP_PROOF_BYTES: usize = 512 * 1024;     // Field 97 (coarse guard)
const MAX_VRF_PROOF_BYTES: usize = 8 * 1024;      // Field 95
const FS_CAPSS_MAX_BYTES: usize = 16_384;      // Field 146 (after decoding)
const DEFAULT_SRX_MAX_BYTES: usize = 1024 * 1024; // Field 122 (policy-tunable)
const KBROAD_BYTES_MAX: usize = 262_144;          // Field 97
```

- Field #146 (CAPSS Smallwood proof) is first checked against the coarse `MAX_HP_PROOF_BYTES`
  bound and then against `FS_CAPSS_MAX_BYTES` before the witness is parsed.
- Field #95 (VRF proof) must be ≤ `MAX_VRF_PROOF_BYTES`; exceeding the limit
  raises `FREEZE_VRF_INVALID`.
- Field #97 (KBROAD envelope) enforces: `ct_kem.len() == 1,088`, `wrap.len() == 48`,
  and total serialized bytes `≤ KBROAD_BYTES_MAX` (262 144). Any mismatch raises
  `FREEZE_KBROAD_PARENT_MISMATCH`.
- Field #122 (SRX payload) must stay within the configured `srx_max_bytes`
  budget (default 1 MB, with a minimum of 256 KB enforced by policy updates).

Suite deprecation and SRX allow-lists are enforced in later steps. Canonical
headers are required; unknown or duplicate keys immediately freeze with
`cbor_malformed`.

---

## Step 1: Structure & Presence

**Purpose**: Validate CBOR canonical encoding and required field presence.

### Decoding

The server decodes and re-encodes the header into canonical CBOR. Any missing,
duplicate, or unknown key, as well as type mismatches, causes
`Freeze(907.1, "cbor_malformed")`. Builders must emit RFC 8949 canonical CBOR on
the first attempt because the resulting freeze is cacheable.

### Required Fields (Join Mode)

| Field | Key | Type   | Constraint |
|-------|-----|--------|------------|
| `tswe_alg` | 90 | `uint` | MUST == 31 |
| `msphf_seed_ctx_hash` | 91 | `bstr` | 32 bytes |
| `merkle_ds_id` | 92 | `tstr` | "rpo-256/v1" |
| `msphf_kgen_rho_commit` | 93 | `bstr` | 32 bytes |
| `seed_bundle_commit` | 94 | `bstr` | 32 bytes |
| `msphf_hp` | 97 | `bstr` | KBROAD envelope |
| `msphf_crs_id` | 98 | `tstr` | "rlwe-merkle/v1" |
| `msphf_hp_commit` | 99 | `bstr` | 32 bytes |
| `kbroad_pub` | 104 | `bstr` | 1,184 bytes (ML-KEM-768) |
| `kbroad_alg` | 105 | `tstr` | "ml-kem-768" |
| `msphf_params_id` | 106 | `bstr` | 32 bytes |
| `pop_device_pk_alg` | 107 | `tstr` | "ML-DSA-65" |
| `pop_device_pk_bytes` | 108 | `bstr` | 1952 bytes |
| `pop_sig` | 109 | `bstr` | 4595 bytes |
| `parent_root` | 110 | `bstr` | 32 bytes |
| `join_delta_root` | 111 | `bstr` | 32 bytes |
| `revoked_since_prev_root` | 112 | `bstr` | 32 bytes |
| `revoked_root` | 113 | `bstr` | 32 bytes |
| `meor_vrf_id` | 116 | `tstr` | "lb-vrf/v1" |
| `fs_capss` | 146 | `bstr` | CAPSS Smallwood proof |
| `proof_mode` | 119 | `tstr` | "lin+zkvrf" |
| `srx_mode` | 120 | `tstr` | "srx/v1-complete" |
| `srx_commit` | 121 | `bstr` | 32 bytes |
| `srx_payload` | 122 | `bstr` | SRX bundle |

Lengths shown are normative for clients. The acceptance path binds most fields
via commitments and proofs rather than direct length checks; only the VRF
proof, CAPSS Smallwood transcript, KBROAD envelope, and SRX payload have explicit byte limits
enforced in code per the specification.

### Merge Mode: Canonical Lists & Join-Only Gate

- A merge anchor **must** carry `mh_heads` (130). When present the server:
  1. **Decodes** the array, verifies each element is a 32-byte `we_epoch_id`,
     and enforces strict **ascending lexicographic order** with no duplicates.
     Non-canonical input freezes `FREEZE_HASH_CBOR (907.1)`.
  2. Treats the presence of `mh_heads` as the merge signal and forbids join-only
     material (PoP, HP envelope, bootstrap profile). The implementation rejects
     header keys {97, 107, 108, 109, 137–139}. Violations raise
     `FREEZE_MERGE_JOIN_KEYS (921)`.
- Rollup metadata uses deterministic CBOR arrays:
  - `pivot_weid` (131) must reference one of the retiring heads; its `93`
    becomes the merge parity.
  - `rollup_provenance_commit` (132), `epoch_replay` (133), optional
    `vck_rollup_commit` (134), and `kbroad_replay` (136) are each canonically
    re-encoded (sorted by `weid`, no duplicates) before the server hashes them.
    Any non-canonical encoding freezes `FREEZE_HASH_CBOR (907.1)`.
  - `merge_delegation_sig` (135) is optional policy surface; if present it is
    verified outside the acceptance core.

**Blueprint**: Alpha (0.1.0) §12.2 step 1 plus the rollup deltas

**Implementation**: [`accept/` module (structure stage)](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Error codes**:
- `907.1` (`FREEZE_HASH_CBOR`): malformed/canonical failure
- `921` (`FREEZE_MERGE_JOIN_KEYS`): join-only material leaked into merge
- `927` (`FREEZE_MH_HEADS_INVALID`): missing/duplicate/unknown heads or pivot

---

## Step 2: Gates & Policy

**Purpose**: Enforce algorithmic gates and policy constraints.

### Algorithmic Gates

```rust
fn ensure_tswe_alg(header: &BTreeMap<u64, Value>) -> Result<(), AcceptanceError> {
    let alg = extract_uint(header, HDR_TSWE_ALG)?;
    if alg != 31 {
        return Err(FREEZE_TSWE_ALG_INVALID);
    }
    Ok(())
}

fn ensure_merkle_suite(header: &BTreeMap<u64, Value>) -> Result<(), AcceptanceError> {
    let merkle_ds_id = extract_text(header, HDR_MERKLE_DS_ID)?;
    if merkle_ds_id != MERKLE_DS_ID {  // "rpo-256/v1"
        return Err(FREEZE_MERKLE_SUITE_INVALID);
    }
    Ok(())
}

fn ensure_kbroad_alg(header: &BTreeMap<u64, Value>) -> Result<(), AcceptanceError> {
    let alg = extract_text(header, HDR_KBROAD_ALG)?;
    if alg != "ml-kem-768" {
        return Err(FREEZE_KBROAD_ALG_INVALID);
    }
    Ok(())
}
```

**Blueprint**: Alpha (0.1.0) §12.1 (Algorithm gates)

### Policy Enforcement

```rust
// 1. CRS ID allow-list
if let Some(allowed_crs_ids) = &ctx.allowed_crs_ids {
    if !allowed_crs_ids.contains(&crs_id) {
        return Freeze(921, "msphf_crs_untrusted");
    }
}

// 2. Params ID allow-list
if let Some(allowed_params_ids) = &ctx.allowed_params_ids {
    if !allowed_params_ids.contains(&params_id) {
        return Freeze(921, "params_id_invalid");
    }
}

// 3. VRF ID allow-list
if let Some(allowed_vrf_ids) = &ctx.allowed_vrf_ids {
    if !allowed_vrf_ids.contains(&vrf_id) {
        return Freeze(923, "vrf_invalid");
    }
}

// 4. Proof mode allow-list
if let Some(allowed_proof_modes) = &ctx.allowed_proof_modes {
    if !allowed_proof_modes.contains(&proof_mode) {
        return Freeze(923, "proof_invalid");
    }
}

// 5. SRX mode allow-list
if let Some(allowed_srx_modes) = &ctx.allowed_srx_modes {
    if !allowed_srx_modes.contains(&srx_mode) {
        return Freeze(930, "srx_invalid");
    }
}

// 6. Policy version monotonicity
if policy_version < ctx.min_policy_version {
    return Freeze(921, "policy_version_stale");
}

// 7. VCK invalidation on policy change
if policy_version != ctx.current_policy_version {
    ctx.vck_cache.invalidate();
}
```

**Blueprint**: Alpha (0.1.0) §12.2 step 2, Annex N (Suite & policy)

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Error codes**:
- `921`: CRS/params/policy untrusted
- `923`: Proof mode invalid
- `930`: SRX mode invalid
- `934`: Suite deprecated

---

## Step 3: PoP Validation (Join Only)

**Purpose**: Verify proof-of-possession of ML-DSA-65 keypair and bind to leaf_id.

### Pipeline

```rust
// 1. Extract PoP fields
let pop_alg = extract_text(header, HDR_POP_DEVICE_PK_ALG)?;  // "ML-DSA-65"
let pop_pk = extract_bytes(header, HDR_POP_DEVICE_PK_BYTES)?; // 1952 bytes
let pop_sig = extract_bytes(header, HDR_POP_SIG)?;           // 4595 bytes

// 2. Compute leaf_id
let leaf_id = H_L("msphf/leaf/id", &LeafBinding { public_key: pop_pk })?;

// 3. Stream-parse SRX to check leaf_id ∈ join_leaf_ids (syntactic)
let srx_payload = extract_bytes(header, HDR_SRX_PAYLOAD)?;
let join_leaf_ids = parse_join_leaf_ids(&srx_payload)?;
if !join_leaf_ids.contains(&leaf_id) {
    return Freeze(907.3, "leaf_bind_mismatch");
}

// 4. Compute PoP message
let xk_bytes = to_cbor_vec(&anchor_instance)?;
let pop_msg = H_L("msphf/pop/msg", &PopMsg {
    xk: &xk_bytes,
    leaf_id: &leaf_id,
    epoch: &we_epoch_id,
})?;

// 5. Verify ML-DSA-65 signature (deterministic, canonical)
let pk = MlDsaPublicKey::from_bytes(&pop_pk)?;
let sig = MlDsaDetachedSignature::from_bytes(&pop_sig)?;
verify_ml_dsa(&sig, &pop_msg, &pk)?;
```

**Validation checks**:
- PoP algorithm MUST be "ML-DSA-65"
- Public key MUST be 1952 bytes
- Signature MUST be 4595 bytes (deterministic encoding)
- `leaf_id` MUST appear in SRX `join_leaf_ids`
- Signature MUST verify under `pop_msg`

**Blueprint**: Alpha (0.1.0) §12.2 step 3

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Error codes**:
- `907.3`: Leaf binding mismatch (leaf_id not in SRX)
- `921`: PoP invalid (signature verification failed)

---

## Step 4: ρ Determinism & Seed-Bundle

**Purpose**: Enforce deterministic seed derivation and cross-check epoch-scope invariants.

### 4.1: ρ Determinism (Join Only)

```rust
// 1. Derive ρ from PoP signature
let rho_raw = H_L("msphf/rho/der", [pop_sig, xk_hash])?;

// 2. Compute rho_commit
let rho_commit_computed = H_L("msphf/kgen/rho", [rho_raw])?;

// 3. Extract claimed rho_commit from header
let rho_commit_claimed = extract_bytes32(header, HDR_KGEN_RHO_COMMIT)?;

// 4. Compare
if rho_commit_computed != rho_commit_claimed {
    return Freeze(924, "msphf_rho_parity");
}

// 5. Anti-grind: ρ uniqueness per (gid, parent_root)
if !ctx.rho_guard.record(gid, parent_root, &rho_commit_claimed) {
    return Freeze(924, "msphf_rho_parity");
}
```

**Purpose**: Prevents grinding attacks where joiner tries multiple PoP signatures to manipulate derived seeds.

**Blueprint**: Alpha (0.1.0) §10 (Seed-binding), §12.2 step 4.1

### 4.2: Seed-Bundle Validation

```rust
// 1. Build ANCHOR_SEED_CTX (header minus excluded fields)
let anchor_seed_ctx = build_anchor_seed_ctx(header)?;

// 2. Compute seed_ctx_hash
let seed_ctx_hash = H_L("seedctx", [CBOR_det(anchor_seed_ctx)])?;

// 3. Compare with claimed value (field 91)
let seed_ctx_hash_claimed = extract_bytes32(header, HDR_SEED_CTX_HASH)?;
if seed_ctx_hash != seed_ctx_hash_claimed {
    return Freeze(922, "msphf_seedctx_mismatch");
}

// 4. Compute seed_bundle_commit
let seed_bundle_commit = compute_seed_bundle_commit(
    &anchor_seed_ctx,
    &rho_commit,
    gid,
    cat,
    &parent_root,
)?;

// 5. Compare with claimed value (field 94)
let seed_bundle_claimed = extract_bytes32(header, HDR_SEED_BUNDLE_COMMIT)?;
if seed_bundle_commit != seed_bundle_claimed {
    return Freeze(922, "msphf_seedctx_mismatch");
}
```

**ANCHOR_SEED_CTX exclusions** (fields NOT included):
- 93-100: KGen/hp fields (derived, not input)
- 107-109: PoP fields (bound via ρ, not seed_ctx)
- 116: meor_vrf_id (bound separately)
- 120-125, 146: Proof/SRX fields (outputs, not inputs)
- 130-136: Merge/telemetry fields

**Blueprint**: Alpha (0.1.0) §12.0-bis (ANCHOR_SEED_CTX), §12.2 step 4.2

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Error codes**:
- `922`: Seed context mismatch
- `924`: ρ parity violation (grinding detected)
- `928`: Epoch ID mismatch

---

## Step 5: KBROAD Binding (Public, No Decrypt)

**Purpose**: Validate KBROAD envelope structure **without decrypting** it.

### Envelope Validation

1. Decode field #97 into a five-element array; enforce index 0 = `"kbroad-v1"`.
2. Validate element types and lengths:
   - `ct_kem` must be a byte string of length 1,088 (`ml_kem_ciphertext_bytes()`).
   - `kbroad_alg` (field 105) MUST equal `"ml-kem-768"` (or another identifier explicitly whitelisted by policy); `kbroad_pub` (field 104) must be a 1,184-byte ML-KEM-768 public key.
   - `wrap` must be a 48-byte AEAD ciphertext (32-byte KEK + 16-byte tag).
   - `C_hp` must be a byte string with `16 ≤ len ≤ 16,400` (`MAX_HP_BYTES + AEAD_TAG_LEN`).
   - index 4 must equal `"chacha20-poly1305"`.
3. Reject any mismatch with `FREEZE_KBROAD_PARENT_MISMATCH`; incorrect AEAD → `FREEZE_SUITE_DEPRECATED`.
4. Do **not** decapsulate or decrypt—publisher blindness is preserved.

**Key principle**: Server validates envelope **shape** and **bindings** but never learns the plaintext.

**Blueprint**: Alpha (0.1.0) §12.2 step 5, §12.3 (hp transport, KBROAD only)

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Error codes**:
- `921`: KBROAD parent mismatch (wrong shape/type)
- `934`: Suite deprecated (wrong AEAD)
- `907.1`: CBOR malformed (non-canonical envelope)

---

## Step 6: SRX Validation

**Purpose**: Validate SRX payload for completeness, anchored adjacency, and canonicity.

**When executed**

- **Joins**: Always. SRX (`mode`, `payload`, `hints`, `commit`) must be present and valid on every
  join anchor.
- **Merges**: Triggered when any of `111/112/113` differ from the pivot antecedent. In that case the
  merge **must** carry SRX (120–124) and run Step 6; absence freezes with `929 (srx_required)`. If
  the roots match the pivot exactly, the merge must omit SRX entirely; any stray SRX field yields
  `930 (srx_invalid)`.

### Validation Steps

```rust
// 1. Decode SRX payload (field 122)
let srx_bytes = extract_bytes(header, HDR_SRX_PAYLOAD)?;
if srx_bytes.len() > ctx.srx_max_bytes {
    return Freeze(930, "srx_invalid");
}

let srx: SrxPayload = from_reader(srx_bytes.as_slice())?;

// 2. Validate mode
if let Some(allowed_srx_modes) = &ctx.allowed_srx_modes {
    if !allowed_srx_modes.contains(&srx.mode) {
        return Freeze(930, "srx_invalid");
    }
}

// 3. Completeness: recompute roots
let join_delta_root_computed = canonical_set_root(&srx.join_leaf_ids)?;
if join_delta_root_computed != expected_join_delta_root {
    return Freeze(930, "srx_anchor_mismatch");
}

let revoked_since_root_computed = canonical_set_root(&srx.since_leaf_ids)?;
if revoked_since_root_computed != expected_revoked_since_root {
    return Freeze(930, "srx_anchor_mismatch");
}

// 4. Anchored adjacency: non-membership witnesses
for nonmem in &srx.join_nonmem_parent {
    // 4a. Dereference left/right anchors
    let left_anchor = if let Some(ref_idx) = nonmem.left_ref {
        &srx.anchor_mem_pool[ref_idx as usize]
    } else {
        None
    };

    let right_anchor = if let Some(ref_idx) = nonmem.right_ref {
        &srx.anchor_mem_pool[ref_idx as usize]
    } else {
        None
    };

    // 4b. Validate non-membership witness
    let validated = CanonicalWitness::validate_nonmembership_witness(
        &nonmem.witness,
        &expected_parent_root,
    )?;

    // 4c. Check adjacency: witness.left == left_anchor.leaf_id
    if let Some(anchor) = left_anchor {
        if validated.left != Some(anchor.leaf_id) {
            return Freeze(930, "srx_anchor_mismatch");
        }
    }

    // 4d. Check adjacency: witness.right == right_anchor.leaf_id
    if let Some(anchor) = right_anchor {
        if validated.right != Some(anchor.leaf_id) {
            return Freeze(930, "srx_anchor_mismatch");
        }
    }

    // 4e. Canonicity: depth ≤ 64, sorted order, NMINT binding
    validate_canonicity(&validated)?;
}

**Error codes**:
- `929`: SRX required (merge touched membership roots but omitted SRX)
- `930`: SRX invalid (format, coverage, or commit mismatch)
- `907.1`: CBOR malformed / canonicalisation failure

// 5. Cumulative revoked: membership witnesses
for mem_witness in &srx.since_mem_revoked {
    CanonicalWitness::validate_membership_witness(
        mem_witness,
        &expected_revoked_root,
    )?;
}

// 6. Recompute srx_commit and compare
let srx_commit_computed = H_L("msphf/srx/commit", &srx)?;
let srx_commit_claimed = extract_bytes32(header, HDR_SRX_COMMIT)?;
if srx_commit_computed != srx_commit_claimed {
    return Freeze(930, "srx_commit_mismatch");
}
```

**Blueprint**: Alpha (0.1.0) §12.2 step 6, Appendix F (SRX modes)

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Error codes**:
- `907.2`: Non-membership non-canonical
- `907.5`: Path oversize (depth > 64)
- `907.6`: Set conflict (unsorted)
- `930`: SRX invalid (see sub-codes in [04-witness-validation.md](./04-witness-validation.md#9-error-mapping))

---

## Rollup Provenance & KBROAD Replay

When `mh_heads` is present the merge path performs additional rollup-specific checks after SRX:

1. **Pivot parity** — `pivot_weid` (131) must reference one of the retiring heads and its `ρ` is
   inherited. Acceptance compares header `93/94` against the pivot snapshot.
2. **Provenance commit (132)** — the server rebuilds `[[weid, vck, xk_hash], …]` in canonical order
   using the cached parity store, hashes it with `H_L("msphf/rollup/prov", …)` and compares. Missing
   VCK entries or mismatched hashes freeze `FREEZE_MH_HEADS_INVALID (927)`.
3. **Epoch replay table (133)** — each entry must exactly match the stored parity metadata
   (`weid`, `xk_hash`, `parent_root`, `join_delta_root`, `revoked_*`, join flag). The array must be
   sorted by `weid` with no duplicates. Violations freeze `FREEZE_HASH_CBOR (907.1)` or
   `FREEZE_MH_HEADS_INVALID`.
4. **KBROAD replay (136)** — for every join epoch (`is_join=true`) the merge carries a byte-perfect
   KBROAD envelope clone. Shape errors map to `FREEZE_KBROAD_PARENT_MISMATCH (921)` or
   `FREEZE_SUITE_DEPRECATED (934)`; missing/mismatched clones freeze `FREEZE_MH_HEADS_INVALID`.
5. **Optional VCK commit (134)** — if provided the server recomputes
   `H_L("msphf/rollup/vck", [vck_1,…])`. A mismatch freezes `FREEZE_MH_HEADS_INVALID`.

**Operational note**: implementations must persist `(weid → VCK snapshot, KBROAD envelope)` for
accepted join heads. Rollups fail closed with `FREEZE_MH_HEADS_INVALID` when provenance material is
missing (cache eviction, restart).

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

## Step 7: Proofs (Join Only)

### 7.1: CAPSS Smallwood Verification

```rust
// 1. Extract proof (field 146)
let fs_capss_bytes = extract_bytes(header, HDR_FS_CAPSS)?;
if fs_capss_bytes.len() > FS_CAPSS_MAX_BYTES {
    return Freeze(923, "msphf_lin_invalid");
}

// 2. Decode proof
let fs_capss_proof = capss::Proof::from_bytes(fs_capss_bytes)?;

// 3. Build public tuple inputs
let fs_inputs = capss::Inputs {
    seed_commit: &seed_commit,
    seed_bundle_commit: &seed_bundle_commit,
    rho_commit: &rho_commit,
    hp_commit: &hp_commit,
    bind: capss::BindingInputs {
        xk_hash,
        crs_id,
        params_id,
        proof_mode,
        policy_version,
        vrf_id: meor_vrf_id,
        parent_root: anchor_instance.parent_root,
        join_delta_root: anchor_instance.join_delta_root,
        revoked_since_prev_root: anchor_instance.revoked_since_prev_root,
        revoked_root: anchor_instance.revoked_root,
        fs_epoch_commit,
        fs_ec,
        fs_dev_prev_commit,
        fs_dev_commit,
    },
};

// 4. Verify proof + binding
capss::verify(&fs_inputs, &fs_capss_proof)?;
```

`capss::verify` rebuilds the CAPSS context, deserializes the Smallwood transcript, and
recomputes the challenge commitments. Any failure freezes the anchor with
`FREEZE_CAPSS_INVALID (944.2 fs_capss_invalid)`.

**Blueprint**: Alpha (0.1.0) §12.2 step 7.1, Annex L

### 7.2: ZK-VRF-ME-OR Verification

```rust
// 1. Extract VRF proof (field 95)
let vrf_pi_bytes = extract_bytes(header, HDR_VRF_PI)?;
if vrf_pi_bytes.len() > MAX_VRF_PROOF_BYTES {
    return Freeze(923, "vrf_invalid");
}

// 2. Construct VRF context
let vrf_ctx = VrfCtx {
    xk_hash,
    meor_vrf_id,
    we_epoch_id,
};

// 3. Extract masks from header (pre-hashed commitments)
let mask_a = extract_bytes32(header, HDR_VRF_MASK_A)?;
let mask_b = extract_bytes32(header, HDR_VRF_MASK_B)?;

// 4. Verify VRF proof
let vrf_proof = VrfProof { bytes: vrf_pi_bytes };
if !zk_vrf::verify(&vrf_pk_payload, &vrf_ctx, (&mask_a, &mask_b), &vrf_proof) {
    return Freeze(923, "vrf_invalid");
}
```

**Blueprint**: Alpha (0.1.0) §12.2 step 7.2, Appendix V

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Error codes**:
- `923`: Proof invalid ("msphf_lin_invalid" or "vrf_invalid")

---

## Step 8: Defense-in-Depth

**Purpose**: Cross-check header fields against proof bindings to prevent proof substitution.

```rust
// Extract from header
let header_93 = extract_bytes32(header, HDR_KGEN_RHO_COMMIT)?;
let header_94 = extract_bytes32(header, HDR_SEED_BUNDLE_COMMIT)?;
let header_98 = extract_text(header, HDR_CRS_ID)?;
let header_99 = extract_bytes32(header, HDR_HP_COMMIT)?;
let header_106 = extract_bytes32(header, HDR_PARAMS_ID)?;
let header_110 = extract_bytes32(header, 110)?;  // parent_root
let header_111 = extract_bytes32(header, 111)?;  // join_delta_root
let header_112 = extract_bytes32(header, 112)?;  // revoked_since_root
let header_113 = extract_bytes32(header, 113)?;  // revoked_root
let header_116 = extract_text(header, HDR_MEOR_VRF_ID)?;

// Extract from proof transcript (CAPSS Smallwood commitments)
let proof_93 = lin_proof.commitments[1];  // rho_commit
let proof_94 = lin_proof.commitments[0];  // seed_commit (indirect)
let proof_99 = lin_proof.commitments[2];  // hp_commit

// Cross-check
if header_93 != proof_93 {
    return Freeze(921, "msphf_crs_untrusted");
}

if header_99 != proof_99 {
    return Freeze(921, "msphf_crs_untrusted");
}

// ... (check all 13 fields)
```

**Purpose**: Prevents joiner from using proofs generated for different commitments/contexts.

**Blueprint**: Alpha (0.1.0) §12.2 step 8 (Defense-in-depth)

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Error code**:
- `921`: CRS untrusted (binding mismatch)

---

## Step 9: Cache & Window Management

### VCK (Verification Cache Key)

```rust
let vck = H_L("msphf/vck", [
    xk_hash,
    seed_bundle_commit,
    rho_commit,
    hp_commit,
    crs_id,
    params_id,
    srx_commit,
    proofs_commit,
    policy_version,
    meor_vrf_id,
])?;

// Check cache
if ctx.vck_cache.contains(&vck, now) {
    return Freeze(925, "mh_window_full");  // Duplicate head
}

// Record verified head
ctx.vck_cache.insert(vck, TTL = T_window, now);
```

**Purpose**: Prevent replay attacks and reduce verification cost for duplicate anchors.

### Window Management

```rust
// Compute WID (window identifier)
let wid = H_L("mhw/window", [gid, parent_root, seed_ctx_hash])?;

// Create head record
let record = HeadRecord::new(
    we_epoch_id,
    hp_commit,
    seed_ctx_hash,
    rho_commit,
    seed_commit,
    xk_hash,
    join_delta_root,
    revoked_since_prev_root,
    revoked_root,
    accept_seq,
    now,
);

// Accept into multi-head window
ctx.mh_window.accept_head(&wid, record, now)?;
```

**Blueprint**: Alpha (0.1.0) §12.2 step 9, §13 (MHW), Annex M

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Error codes**:
- `925`: Window full (H_MAX exceeded)
- `927`: MH heads invalid (merge mode)

The pivot parity stored alongside the head now keeps `join_delta_root`,
`revoked_since_prev_root`, and `revoked_root`. Merge anchors compare those snapshots with the
incoming header to determine whether SRX must be supplied and to enforce ρ-parity across heads.

### Pre-commit TOCTOU guard (REQUIRED)

Because multiple joins can run concurrently, the server MUST re-check the time-blind predicates that depend on `A := GroupState.last_accepted_ec` immediately before the atomic commit. The implementation follows this logic:

```rust
// Snapshot used during gating
let a_snapshot = ctx.last_accepted_ec;
enforce_fs_bounds(fs_ec, a_snapshot, device_state)?;

// ... proofs, SRX, etc ...

// TOCTOU guard immediately before commit
let a_now = ctx.last_accepted_ec;
if a_now > a_snapshot {
    enforce_fs_bounds(fs_ec, a_now, device_state)?;
}

ctx.commit_head(fs_ec, device_state, record);
```

`enforce_fs_bounds` re-evaluates the anchor-, device-, and first-device forward-leap guards using the current `last_accepted_ec`. If any predicate fails during the re-check, the anchor MUST be frozen with the same code as in Step 2c. This guard prevents races where a join admitted under an older `A` would have been rejected if evaluated against the contemporaneous state.

---

## 12. Merge Mode

**Purpose**: Consolidate multiple heads into a single anchor without re-validating proofs.

### Pipeline

```rust
// 1. Extract mh_heads (field 130)
let mh_heads = extract_array(header, HDR_MH_HEADS)?;
if mh_heads.is_empty() || mh_heads.len() > ctx.h_max {
    return Freeze(927, "mh_heads_invalid");
}

// 2. Validate all heads exist in window
for head_weid in &mh_heads {
    if !ctx.mh_window.contains(&wid, head_weid) {
        return Freeze(927, "mh_heads_invalid");
    }
}

// 3. Derive new we_epoch_id from merged set
let merge_we_epoch_id = H_L("tswe/merge/weid", [gid, cat, xk_hash, mh_heads])?;

// 4. Compute new hp_commit (merged)
let merge_hp_commit = H_L("msphf/merge/hp", [parent_root, mh_heads])?;

// 5. Accept merge (retires old heads)
ctx.mh_window.accept_merge(&wid_old, &wid_new, &mh_heads, new_record, now)?;
```

**Skipped steps** (merge mode):
- Step 3: PoP validation (no new device joining)
- Step 6: SRX validation (required if roots/deltas change)
- Step 7: Proofs (already validated in constituent heads)

**Blueprint**: Alpha (0.1.0) §13 (MHW), Annex M

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Error codes**:
- `927`: MH heads invalid (missing/expired heads)

### 12.1 Revocation & Reinstatement

The **publisher** (the entity that holds the ML-DSA signature key and orchestrates joins) is
responsible for banning or reinstating members by publishing merge anchors. The acceptance
server only validates the submitted anchor; it never creates the anchor itself.

1. **Retrieve the pivots**: Call `pivot_parities_for(gid, parent_root, now)` while keeping the
   same `parent_root` as the active heads in the Multi-Head Window (the window's anchor root).
2. **Build the new state**: Prepare a consistent `AnchorInstanceParts`/`SrxInputs`:
   - `join_delta_root` points to the root of the *join delta* (often `0` when there are no
     new members in a revocation merge);
   - `revoked_since_prev_root` and `revoked_root` are recomputed from the banned leaves;
   - `SrxInputs` carries `revoked_since_leaves` and the corresponding membership proofs
     (`since_mem_revoked`) in the new `revoked_root` set.
3. **Create the merge anchor**: Use
   `joiner_kgen_merge_or(header_map, retired_parities, note, parts, params, witness_bytes)`.
   This function automatically removes the "join-only" fields (95, 97, 107‑109, 116, 119, 120‑125, 146) and
   installs the pivot parity (ρ, seed bundle, etc.).
4. **Submit for acceptance**: Sign if necessary (bootstrap), then call
   `accept_anchor(&parts, merge_we_epoch_id, &header_map, now)`. During this step, the server:
   - Computes `wid_new = H_L("mhw/window", [gid, parent_root, seed_ctx_hash])` for the merge,
   - Locates the heads to retire in the old window (`wid_old`) relying on the pivot parities
     retrieved in step 1,
   - Retires the heads under `wid_old` then, if `wid_new ≠ wid_old`, inserts the new record
     into the target window before updating telemetry.
   - Copies the KBROAD envelope from the pivot (if the merge header doesn't carry one) so that
     subsequent merges can always verify payload consistency.

   When `wid_new == wid_old`, the window is updated in place; otherwise, the old window is
   emptied if necessary, then the new one is filled with the merged head.

To reinstate a member, publish another merge by reversing the operation: put their leaf
back in `join_delta_root` and clear the `revoked_*` roots.

> Complete example: The `ban_and_reinstate_member_flow` test
> ([`crates/msphf-orchestrator/tests/end_to_end.rs`](../../crates/msphf-orchestrator/tests/end_to_end.rs))
> shows "Alice" banning then reinstating "Bob" through two successive merges.

## 13. Error Semantics

### Freeze vs. Reject

- **Freeze(code, reason)**: Deterministic failure, cacheable, binding to anchor hash
- **Reject**: Stateless failure, not cacheable (e.g., transient network error)

### Freeze Caching

```rust
struct FreezeCache {
    entries: BTreeMap<[u8; 32], (FreezeError, Instant)>,
    ttl: Duration,
}

impl FreezeCache {
    pub fn record(&mut self, anchor_hash: &[u8; 32], error: FreezeError, now: Instant) {
        self.entries.insert(*anchor_hash, (error, now));
    }

    pub fn lookup(&self, anchor_hash: &[u8; 32], now: Instant) -> Option<FreezeError> {
        self.entries.get(anchor_hash).and_then(|(err, ts)| {
            if now.duration_since(*ts) <= self.ttl {
                Some(*err)
            } else {
                None
            }
        })
    }
}
```

**Purpose**: Prevent DoS by re-validation of known-bad anchors.

**Blueprint**: Alpha (0.1.0) §15 (Error semantics)

**Implementation**: [`crates/msphf-orchestrator/src/mhw.rs`](../../crates/msphf-orchestrator/src/mhw.rs)

---

## Summary

The **9-step acceptance pipeline** enforces cryptographic correctness and DoS hygiene while maintaining **publisher-blindness**. The server validates envelope structure, seed determinism, witness canonicity, and proof correctness **without decrypting the KBROAD envelope or learning Y\***. Defense-in-depth cross-checks prevent proof-witness malleability. Freeze errors are deterministic and cacheable, preventing replay attacks. Merge mode consolidates heads without re-validating proofs, enabling efficient epoch progression.

**Next**: [08 — Client Operations](./08-client-operations.md)
**VRF identifier registry**

| `meor_vrf_id` | Algorithm | Proof transcript | Notes |
|---------------|-----------|------------------|-------|
| `lb-vrf/v1`   | LB-VRF over Ring-LWE masks (see [`crates/msphf-lb-vrf`](../../crates/msphf-lb-vrf)) | Output-hiding ZK proof bundled in field 95 (`proof_mode = "lin+zkvrf"`) | Required identifier for the Alpha 0.1.0 profile |

Servers MUST reject anchors whose `meor_vrf_id` is not listed in their `AcceptanceOptions.allow.meor_vrf_id` set using `FREEZE_SUITE_DEPRECATED (934)`. Additional identifiers MUST normatively define the curve/field, hash-to-input domain, transcript encoding, and failure codes before deployment.
