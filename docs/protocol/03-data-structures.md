# Data Structures & Wire Formats

> [!IMPORTANT]
> This chapter is a legacy companion document. For `tswe/msphf-we/fs-hybrid`, the normative source is [`../specs-unified-fs.md`](../specs-unified-fs.md).
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and implementation.


**Specification:** Alpha (0.1.0)
**Blueprint:** §12.0, Appendix A, D, E

---

## Table of Contents

1. [CBOR Encoding](#1-cbor-encoding)
2. [Header Field Registry](#2-header-field-registry)
3. [ANCHOR_SEED_CTX](#3-anchor_seed_ctx)
4. [MSPHF_HP Envelope](#4-msphf_hp-envelope)
5. [Anchor Instance (X_k)](#5-anchor-instance-xk)
6. [SRX Payloads](#6-srx-payloads)
7. [Proof Structures](#7-proof-structures)
8. [Size Limits](#8-size-limits)
9. [Wire Format Examples](#9-wire-format-examples)

---

## 1. CBOR Encoding

**Standard:** RFC 8949 (Canonical CBOR)
**Blueprint:** Appendix A

### 1.1 Canonical Encoding Rules

City-G headers use **deterministic CBOR** (CBOR_det). Clients **MUST**:

1. Emit map keys in ascending numeric order
2. Avoid duplicate keys (last-write-wins behaviour is non-compliant)
3. Use shortest-length encodings (no indefinite-length strings or arrays)
4. Restrict values to integers, byte strings, text strings, arrays, and maps
5. Encode booleans as simple values (`true = 0xF5`, `false = 0xF4`)

### 1.2 Server Handling

The acceptance pipeline re-encodes the header into canonical CBOR and freezes on
any malformed input: unknown keys, duplicate keys, and non-canonical encodings
all trigger `Freeze(907.1, "cbor_malformed")` per the specification. Clients
must therefore emit fully deterministic CBOR, and builders should treat any
validation failure as cacheable.

**Implementation:** [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

### 1.3 CBOR Types Used

| CBOR Type | Major Type | Usage |
|-----------|------------|-------|
| **Unsigned Integer** | 0 | Field keys, algorithm IDs (e.g., tswe_alg=31) |
| **Byte String** | 2 | Cryptographic material (keys, sigs, commits, proofs) |
| **Text String** | 3 | Algorithm identifiers, mode strings |
| **Array** | 4 | KBROAD envelope, proof arrays, witness paths |
| **Map** | 5 | Header map (anchor metadata) |

**No floats, bignums, or tags used** (simplifies parsing, prevents ambiguity).

### 1.4 Byte String Encoding

**All cryptographic data encoded as CBOR byte strings (major type 2):**

```
# 32-byte hash (e.g., hp_commit)
CBOR: 0x58 0x20 [32 bytes]
      ^    ^    ^-- Data
      |    |------- Length (32)
      |----------- Major type 2 (byte string), length follows

# Variable-length (e.g., proof)
CBOR: 0x59 [len_hi] [len_lo] [data...]
      ^    ^--Length (16-bit)
      |------- Major type 2, 2-byte length
```

**Implementation Detail:** `serde_bytes` crate ensures efficient binary serialization.

---

## 2. Header Field Registry

**Blueprint:** §12.0 (Header-key registry)
**Implementation:** [`crates/msphf-orchestrator/src/hdr.rs`](../../crates/msphf-orchestrator/src/hdr.rs)

### 2.1 Complete Field List

| Key | Constant | Type | Presence | Max Size | Value Constraints |
|-----|----------|------|----------|----------|-------------------|
| **90** | `HDR_TSWE_ALG` | uint | MUST (join/merge) | - | MUST = 31 |
| **91** | `HDR_SEED_CTX_HASH` | bstr32 | MUST (join/merge) | 32B | `H_L("seedctx", [ANCHOR_SEED_CTX])` |
| **92** | `HDR_MERKLE_SUITE` | tstr | MUST (join/merge) | - | MUST = "rpo-256/v1" |
| **93** | `HDR_RHO_COMMIT` | bstr32 | MUST (join/merge) | 32B | `H_L("msphf/kgen/rho", [ρ])` |
| **94** | `HDR_SEED_BUNDLE_COMMIT` | bstr32 | MUST (join/merge) | 32B | Computed from ANCHOR_SEED_CTX |
| **95** | `HDR_VRF_PROOF` | bstr | MUST (join) | ≤ 8,192B | ZK-VRF proof (lb-vrf/v1) |
| **96** | `HDR_TSWE_STMT_COMMIT` | bstr32 | OPTIONAL | 32B | Statement commitment (builder use) |
| **97** | `HDR_HP_BYTES` | bstr/array | MUST (join) | ≤ 262,144B | KBROAD envelope (5-element array) |
| **98** | `HDR_CRS_ID` | tstr | MUST (join/merge) | - | "rlwe-merkle/v1" or "sigma-merkle/v1" |
| **99** | `HDR_HP_COMMIT` | bstr32 | MUST (join) | 32B | `H_L("msphf/hp/commit", [hp])` |
| **104** | `HDR_KBROAD_PUB` | bstr | MUST (join/merge) | 1,184B | ML-KEM-768 public key |
| **105** | `HDR_KBROAD_ALG` | tstr | MUST (join/merge) | - | MUST = "ml-kem-768" |
| **106** | `HDR_PARAMS_ID` | bstr32 | MUST (join/merge) | 32B | RLWE parameter pack hash |
| **107** | `HDR_POP_ALG` | tstr | MUST (join) | - | MUST = "ML-DSA-65" |
| **108** | `HDR_POP_PK` | bstr | MUST (join) | 2,592B | ML-DSA-65 public key |
| **109** | `HDR_POP_SIG` | bstr | MUST (join) | 4,595B | ML-DSA-65 signature (deterministic) |
| **110** | `parent_root` | bstr32 | MUST (join/merge) | 32B | Parent membership set root |
| **111** | `join_delta_root` | bstr32 | MUST (join/merge) | 32B | New membership set root |
| **112** | `revoked_since_prev_root` | bstr32 | MUST (join/merge) | 32B | Revoked set root (or empty) |
| **113** | `HDR_REVOKED_ROOT` | bstr32 | MUST (join/merge) | 32B | Total revoked set root |
| **116** | `HDR_VRF_ID` | tstr | MUST (join) | - | MUST = "lb-vrf/v1" |
| **119** | `HDR_PROOF_MODE` | tstr | MUST (join) | - | MUST = "lin+zkvrf" |
| **120** | `HDR_SRX_MODE` | tstr | MUST (join) | - | "srx/v1-complete" |
| **121** | `HDR_SRX_COMMIT` | bstr32 | MUST (join) | 32B | `H_L("srx/commit", [srx_payload])` |
| **122** | `HDR_SRX_PAYLOAD` | bstr | MUST (join) | 1,048,576B | SRX witness payload (v1-complete) |
| **123** | `HDR_SRX_HINT_COUNTS` | bstr | MUST (join) | - | CBOR array of hint counts |
| **124** | `HDR_SRX_HINT_SIZES` | bstr | MUST (join) | - | CBOR array of hint sizes |
| **125** | `HDR_PROOFS_COMMIT` | bstr32 | MUST (join) | 32B | `H_L("msphf/proofs", [vrf_proof, fs_capss])` |
| **130** | `HDR_MH_HEADS` | array | Merge only | K×32B | Retired head list |
| **131** | `HDR_ROLLUP_PIVOT_WEID` | bstr32 | Merge only | 32B | Pivot antecedent (`93` inherited) |
| **132** | `HDR_ROLLUP_PROVENANCE_COMMIT` | bstr32 | Merge (rollup) | 32B | `H_L("msphf/rollup/prov", …)` |
| **133** | `HDR_ROLLUP_EPOCH_REPLAY` | array | Merge (rollup) | - | Epoch replay table |
| **134** | `HDR_ROLLUP_VCK_COMMIT` | bstr32 | OPTIONAL | 32B | `H_L("msphf/rollup/vck", …)` |
| **135** | `HDR_MERGE_DELEGATION_SIG` | bstr | OPTIONAL | - | Service authorization signature |
| **136** | `HDR_KBROAD_REPLAY` | array | Merge (rollup) | - | KBROAD envelope clones |
| **138** | `HDR_ROLLUP_FS_MODE` | tstr | Merge (rollup) | - | FS mode identifier |
| **139** | `HDR_FS_POLICY_VERSION` | tstr | MUST (FS profiles) | - | FS policy version string |
| **140** | `HDR_POLICY_VERSION` | tstr | Legacy | - | Pre-FS policy version (deprecated) |
| **141** | `HDR_FS_EC` | uint | MUST (FS profiles) | - | Forward-secrecy epoch counter |
| **142** | `HDR_FS_EPOCH_COMMIT` | bstr32 | MUST (FS profiles) | 32B | `H_L("fs/epoch/commit", [epoch_sk])` |
| **143** | `HDR_FS_EPOCH_BASE_TS` | uint64 | MUST (FS profiles) | 8B | Epoch base timestamp (monotonic) |
| **144** | `HDR_FS_EVOLUTION_BOUNDARY` | uint | OPTIONAL | - | Evolution boundary marker |
| **145** | `HDR_FS_PURGE_TIMES` | array | OPTIONAL | - | τₑ cache purge timestamps |
| **146** | `HDR_FS_CAPSS` | bstr32 | MUST (FS profiles, join) | 32B | `H_L("msphf/lin_fs/chal", […])` CAPSS Smallwood binding digest |
| **152** | `HDR_FS_DEV_PREV_COMMIT` | bstr32 | MUST (FS profiles) | 32B | Previous device chain commit |
| **153** | `HDR_FS_DEV_COMMIT` | bstr32 | MUST (FS profiles) | 32B | `H_L("fs/dev/chain", [device_pk, fs_ec, fs_dev_prev])` |
| **154** | `HDR_VRF_MASK_A` | bstr32 | Internal | 32B | VRF mask for branch A (debugging) |
| **155** | `HDR_VRF_MASK_B` | bstr32 | Internal | 32B | VRF mask for branch B (debugging) |

> `fs_capss` binds the public tuple `[xk_hash, seed_commit, seed_bundle_commit, rho_commit,
> crs_id, hp_commit, params_id, parent_root, join_delta_root, revoked_since_prev_root,
> revoked_root, proof_mode, policy_version, vrf_id, fs_epoch_commit, fs_ec,
> fs_dev_prev_commit, fs_dev_commit]` via `H_L("msphf/lin_fs/chal", …)`.

### 2.2 Field Categories

**Join-Only Fields** (MUST NOT appear in merge anchors):
- 95, 96, 97, 99, 107, 108, 109 (PoP & proof encapsulation)
- 116, 119, 125 (Proof suite metadata)
- 146 (CAPSS Smallwood binding digest - FS profiles only)
- 120, 121, 122, 123, 124 (SRX)

**Join & Merge Fields** (MUST appear in both):
- 90, 91, 92, 93, 94 (Algorithms & seeds)
- 98, 104, 105, 106 (CRS & KBROAD)
- 110, 111, 112, 113 (Membership roots)

**FS Profile Fields** (MUST appear when using `tswe/msphf-we/fs-hybrid`):
- 139 (`fs_policy_version`)
- 141 (`fs_ec` - forward-secrecy epoch counter)
- 142 (`fs_epoch_commit`)
- 143 (`fs_epoch_base_ts`)
- 146 (`fs_capss` binding digest - join only)
- 152 (`fs_dev_prev_commit`)
- 153 (`fs_dev_commit`)

**Optional Fields:**
- 96, 134, 135 (builder/cap policy surfaces)
- 144, 145 (FS evolution/purge metadata)

### 2.3 Validation Rules

**Server rejects the following conditions:**

1. **Malformed or non-canonical CBOR** (missing/duplicate/unknown keys, wrong types) → Freeze(907.1, "cbor_malformed")
2. **Join-only field present in merge mode** → Freeze(921, "msphf_crs_untrusted")
3. **Algorithm mismatch** (e.g., `tswe_alg` ≠ 31) → Freeze(934, "suite_deprecated")
4. **Proof/SRX payload exceeds limits** → Freeze(923) or Freeze(930)

**Implementation:** [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

## 3. ANCHOR_SEED_CTX

**Blueprint:** §12.0-bis
**Implementation:** [`crates/anchor-seed/src/lib.rs`](../../crates/anchor-seed/src/lib.rs)

### 3.1 Definition

```
ANCHOR_SEED_CTX := CBOR_det(header minus volatile and forbidden keys)

Excluded Keys:
- 93-99 (seed/HP commitments)
- 107-109 (PoP material)
- 120-124 (SRX payload)
- 130-136 (merge/rollup telemetry)
```

**Rationale:** ANCHOR_SEED_CTX contains only stable, semantically meaningful fields. Proofs, SRX, and PoP are excluded because they vary per joiner.

### 3.2 Construction

```rust
// crates/anchor-seed/src/lib.rs
pub fn build_anchor_seed_ctx(
    header_map: &BTreeMap<u64, Value>
) -> Result<Vec<u8>, MsphfError> {
    let mut filtered = BTreeMap::new();
    for (key, value) in header_map.iter() {
        if VOLATILE_KEYS.contains(key) || FORBIDDEN_SEED_CTX_KEYS.contains(key) {
            continue;  // Exclude
        }
        filtered.insert(*key, value.clone());
    }

    // Canonical CBOR encoding
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&filtered, &mut buf)?;
    Ok(buf)
}
```

**Result:** Deterministic byte sequence representing anchor's stable context.

### 3.3 Seed Context Hash (Field #91)

```
msphf_seed_ctx_hash := H_L("seedctx", [CBOR_det(ANCHOR_SEED_CTX)])
```

**Validation:**
```rust
// Server recomputes and verifies
let seed_ctx_bytes = build_anchor_seed_ctx(&header_map)?;
let expected = compute_seed_ctx_hash(&seed_ctx_bytes)?;

if expected != header[91] {
    return Freeze(922, "msphf_seedctx_mismatch");
}
```

**Purpose:** Binds all cryptographic operations to anchor's stable context.

### 3.4 Seed Bundle Commit (Field #94)

```
seed_bundle_commit := H_L("msphf/seed/bundle", [
    ANCHOR_SEED_CTX,
    rho_commit,
    gid,
    cat,
    parent_root
])
```

**Implementation:**
```rust
// crates/anchor-seed/src/lib.rs
pub fn compute_seed_bundle_commit(
    anchor_seed_ctx: &[u8],
    rho_commit: &[u8; 32],
    gid: &[u8],
    cat: &[u8],
    parent_root: &[u8; 32],
) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct SeedBundle<'a> {
        #[serde(with = "serde_bytes")] anchor_seed_ctx: &'a [u8],
        #[serde(with = "serde_bytes")] rho_commit: &'a [u8],
        #[serde(with = "serde_bytes")] gid: &'a [u8],
        #[serde(with = "serde_bytes")] cat: &'a [u8],
        #[serde(with = "serde_bytes")] parent_root: &'a [u8],
    }

    hash::h_l("msphf/seed/bundle", &SeedBundle { ... })
}
```

**Validation:**
```rust
// Server verifies field #94
let expected = compute_seed_bundle_commit(
    &seed_ctx_bytes,
    &header[93],  // rho_commit
    gid,
    cat,
    &header[110],  // parent_root
)?;

if expected != header[94] {
    return Freeze(922, "msphf_seedctx_mismatch");
}
```

---

## 4. MSPHF_HP Envelope

**Blueprint:** Appendix D (MSPHF_HP tuple & envelope)

### 4.1 MSPHF_HP Tuple (Internal)

```
MSPHF_HP := [
    0:  uint (MUST = 1),          // Format version
    1:  hp_A:bstr,                 // Branch A hash projection
    2:  hp_B:bstr,                 // Branch B hash projection
    3:  M_A:bstr (32 bytes),       // Branch A mask
    4:  M_B:bstr (32 bytes),       // Branch B mask
    5:  params_id:bstr (32 bytes)  // Parameter pack commitment
]
```

**Size:** Typically ~6-8 KB (depends on RLWE parameters)

**Example:**
```rust
let hp_tuple = vec![
    Value::Integer(1.into()),           // version
    Value::Bytes(hp_a_bytes),           // ~2KB
    Value::Bytes(hp_b_bytes),           // ~2KB
    Value::Bytes(mask_a.to_vec()),      // 32B
    Value::Bytes(mask_b.to_vec()),      // 32B
    Value::Bytes(params_id.to_vec()),   // 32B
];
```

### 4.2 KBROAD Envelope (Field #97)

**Blueprint:** §12.3, Appendix D

```
KBROAD_V1 := [
    0:  "kbroad-v1",               // Envelope type (text string)
    1:  ct_kem:bstr,               // ML-KEM-768 ciphertext (byte string)
    2:  wrap:bstr,                 // Wrapped K_HP (AEAD ciphertext)
    3:  C_hp:bstr,                 // Encrypted MSPHF_HP tuple (AEAD ciphertext)
    4:  "chacha20-poly1305"        // AEAD algorithm (text string)
]
```

**Construction (Joiner Side):**

```rust
// 1. KEM Encapsulation
let (ss, ct_kem) = ml_kem_768::encapsulate(&kbroad_pub);

// 2. Derive KEK
let salt = h_l("hp/kek/salt", &xk_hash)?;
let info = b"city-g|hp/kek/v1";
let kek = hkdf_blake3_extract_expand(&ss, &salt, info, &hp_commit, 32)?;

// 3. Generate K_HP (random AEAD key)
let k_hp: [u8; 32] = random_bytes();

// 4. Wrap K_HP
let nonce_wrap = h_l("hp/kek/nonce", &(&xk_hash, &hp_commit))?;
let wrap = aead_encrypt(&kek, &nonce_wrap[..12], &hp_commit, &k_hp)?;

// 5. Encrypt MSPHF_HP tuple
let hp_k_bytes = to_cbor_vec(&msphf_hp_tuple)?;
let nonce_hp = h_l("hp/nonce", &(&xk_hash, &hp_commit))?;
let c_hp = aead_encrypt(&k_hp, &nonce_hp[..12], &hp_commit, &hp_k_bytes)?;

// 6. Build envelope
let envelope = vec![
    Value::Text("kbroad-v1".to_string()),
    Value::Bytes(ct_kem.to_vec()),
    Value::Bytes(wrap),
    Value::Bytes(c_hp),
    Value::Text("chacha20-poly1305".to_string()),
];
```

**Server Validation (Structure & Length):**

- **Shape**: value must be a 5-element array; index 0 must equal `"kbroad-v1"` or the server raises `FREEZE_HASH_CBOR`/`FREEZE_PARENT_EID_FORBIDDEN`.
- **Element 1 (`ct_kem`)**: byte string, length = `ml_kem_ciphertext_bytes()` = **1,088 bytes**.
- **Element 2 (`wrap`)**: byte string, length = **48 bytes** (32-byte KEK + 16-byte tag).
- **Element 3 (`C_hp`)**: byte string, length between **16 bytes** (tag-only minimum) and **16,400 bytes** (`MAX_HP_BYTES + AEAD_TAG_LEN`).
- **Element 4 (`aead`)**: text string equal to `"chacha20-poly1305"`.

Any length/type mismatch yields `FREEZE_KBROAD_PARENT_MISMATCH` (code 921); wrong AEAD suite yields `FREEZE_SUITE_DEPRECATED`.

**Implementation:** [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

**Server MUST NOT:**
- Decrypt ct_kem (no KEM decapsulation)
- Decrypt wrap or C_hp (no AEAD decryption)
- Access MSPHF_HP tuple contents

**Receiver Decryption:**

```rust
// 1. KEM Decapsulation
let ss = ml_kem_768::decapsulate(&ct_kem, &kbroad_secret);

// 2. Derive KEK
let salt = h_l("hp/kek/salt", &xk_hash)?;
let info = b"city-g|hp/kek/v1";
let kek = hkdf_blake3_extract_expand(&ss, &salt, info, &hp_commit, 32)?;

// 3. Unwrap K_HP
let nonce_wrap = h_l("hp/kek/nonce", &(&xk_hash, &hp_commit))?;
let k_hp = aead_decrypt(&kek, &nonce_wrap[..12], &hp_commit, &wrap)?;

// 4. Decrypt MSPHF_HP
let nonce_hp = h_l("hp/nonce", &(&xk_hash, &hp_commit))?;
let hp_k_bytes = aead_decrypt(&k_hp, &nonce_hp[..12], &hp_commit, &c_hp)?;

// 5. Decode MSPHF_HP tuple
let msphf_hp: Vec<Value> = ciborium::de::from_reader(&hp_k_bytes[..])?;

// Extract components
let hp_a = msphf_hp[1].as_bytes()?;
let hp_b = msphf_hp[2].as_bytes()?;
let mask_a = msphf_hp[3].as_bytes()?;
let mask_b = msphf_hp[4].as_bytes()?;
```

### 4.3 HP Commit (Field #99)

```
hp_commit := H_L("msphf/hp/commit", [hp_k_bytes])
```

**Where:** `hp_k_bytes = CBOR_det(MSPHF_HP)`

**Validation:**
- Joiner: Computes hp_commit, includes in header #99
- Server: Verifies CAPSS Smallwood proof binds to hp_commit (in-proof check)
- Receiver: Recomputes hp_commit from decrypted MSPHF_HP, verifies match

---

## 5. Anchor Instance (X_k)

**Blueprint:** §4 (Public Instance & NP Language)
**Implementation:** [`crates/msphf-core/src/instance.rs`](../../crates/msphf-core/src/instance.rs)

### 5.1 Structure

```rust
pub struct AnchorInstance<'a> {
    pub gid: &'a [u8],                     // Group identifier
    pub cat: &'a [u8],                     // Category/domain
    pub we_epoch_id: [u8; 32],             // Window-epoch identifier
    pub anchor_hdr_ctx: &'a [u8],          // ANCHOR_SEED_CTX bytes
    pub tswe_salt_hash: &'a [u8],          // TSWE salt binding
    pub parent_root: &'a [u8],             // Field #110
    pub join_delta_root: &'a [u8],         // Field #111
    pub revoked_since_prev_root: &'a [u8], // Field #112
    pub revoked_root: &'a [u8],            // Field #113
    pub pox_r_commit: Option<&'a [u8]>,    // Optional: PoX commitment
    pub msphf_hp_commit: Option<&'a [u8]>, // Optional: Field #99 (join only)
}
```

### 5.2 CBOR Encoding

**Canonical Tuple:**
```
X_k := [
    gid,
    cat,
    we_epoch_id,
    anchor_hdr_ctx,
    tswe_salt_hash,
    parent_root,
    join_delta_root,
    revoked_since_prev_root,
    revoked_root,
    pox_r_commit  // null for standard anchors
]
```

**Example (Genesis):**
```json
[
    b"my-group-id",              // gid
    b"default",                  // cat
    [0xAA; 32],                  // we_epoch_id
    b"...",                      // anchor_hdr_ctx (ANCHOR_SEED_CTX)
    [0xBB; 32],                  // tswe_salt_hash
    [0x00; 32],                  // parent_root (empty for genesis)
    [0xCC; 32],                  // join_delta_root (founder's leaf)
    [0x00; 32],                  // revoked_since_prev_root (empty)
    [0x00; 32],                  // revoked_root (empty)
    null                         // pox_r_commit
]
```

### 5.3 xk_hash Derivation

```
xk_hash := H_L("msphf/xk", [CBOR_det(X_k)])
```

**Implementation:**
```rust
// crates/msphf-core/src/instance.rs
pub fn xk_hash(&self) -> Result<[u8; 32], MsphfError> {
    hash::h_l(ds::MSPHF_XK, &self.as_cbor_tuple())
}
```

**Usage:**
- Binds proofs to epoch context
- Feeds into ρ derivation: `ρ := H_L("msphf/rho/der", [pop_sig, xk_hash])`
- Part of VRF context

### 5.4 Epoch Key Derivation

```
E_k := H_epoch(X_k, Y*) = H_L("msphf/epoch", [CBOR_det((X_k, Y*))])
```

**Implementation:**
```rust
// crates/msphf-core/src/instance.rs
pub fn epoch_key(instance: &AnchorInstance, y_star: &[u8]) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct Y<'a>(#[serde(with = "serde_bytes")] &'a [u8]);
    hash::h_epoch(&instance.as_cbor_tuple(), &Y(y_star))
}
```

**Properties:**
- Unique per epoch (X_k changes)
- Same for all valid members (Y* is deterministic for valid hp)
- Unpredictable to server (Y* hidden by ZK-VRF)

---

## 6. SRX Payloads

**Blueprint:** Appendix F (SRX Modes)

### 6.1 SRX/v1-complete (Required)

Field #122 (`HDR_SRX_PAYLOAD`) is the canonical CBOR encoding of the tuple below. Each
element uses the same witness encodings as `RawNonMembershipWitness` and
`RawMembershipWitness` in the Rust implementation.

```
srx_payload := [
    0: join_nonmem_parent:      [AnchoredNonMembership, ...],
    1: join_nonmem_revoked:     [AnchoredNonMembership, ...],
    2: revoked_since_mem:       [MembershipWitness, ...],
    3: meta: {
         "join_count": uint,
         "since_count": uint,
         "join_frontier_size": uint,
         "since_frontier_size": uint
       },
    4: join_leaf_ids:           [bstr32, ...],
    5: join_frontier:           [bstr32, ...] / null,
    6: since_leaf_ids:          [bstr32, ...],
    7: since_frontier:          [bstr32, ...] / null,
    8: anchor_mem_pool:         [MembershipWitness, ...]
]
```

**AnchoredNonMembership** entries carry the anchor index references produced by the
joiner. The verifier remaps those indices into the canonical anchor pool before
checking each witness. Membership witnesses are standard Merkle proofs over the
revoked-set root.

**Constraints:**
- `|srx_payload| ≤ SRX_MAX = 1,048,576 bytes`
- `meta.join_count == |join_leaf_ids|`
- `meta.since_count == |since_leaf_ids|`
- Anchor pool entries MUST be sorted by `(root, leaf_id)`
- Merkle path depth ≤ 64 for every witness

### 6.2 Hint Fields

**Field #123 (srx_hint_counts):**
```
hint_counts := CBOR_det([
    num_cimp:uint,
    num_mmp:uint,
    num_join_leaf_ids:uint,
    num_since_leaf_ids:uint,
    num_anchors:uint
])
```

**Field #124 (srx_hint_sizes):**
```
hint_sizes := CBOR_det([
    total_cimp_bytes:uint,
    total_mmp_bytes:uint,
    total_join_ids_bytes:uint,
    total_since_ids_bytes:uint,
    total_anchors_bytes:uint
])
```

**Validation:**
```rust
// Server checks hints match actual payload
let (cimp, mmp, join_ids, since_ids, anchors) = parse_srx_payload(&payload)?;

let actual_counts = [
    cimp.len(), mmp.len(), join_ids.len(), since_ids.len(), anchors.len()
];

if actual_counts != expected_counts {
    return Freeze(930, "srx_hint_under");
}

// Size check
if total_payload_bytes != sum(hint_sizes) {
    return Freeze(930, "srx_oversize_hint");
}
```

### 6.3 SRX Commit (Field #121)

```
srx_commit := H_L("srx/commit", [srx_payload])
```

**Validation:**
```rust
let expected = h_l("srx/commit", &srx_payload_bytes)?;

if expected != header[121] {
    return Freeze(930, "srx_commit_mismatch");
}
```

---

## 7. Proof Structures

### 7.1 CAPSS Smallwood Proof (Field #146)

**Size:** ≤ 16,384 bytes (`FS_CAPSS_MAX_BYTES`)

**Structure:** CBOR map containing:
- Seven commitments (`seed_commit`, `rho_commit`, `hp_commit`, branch artifacts, context tags)
- Four response bundles (noise bounds, determinism checks)
- Public witness (`CapssWitnessBundle`)
- Binding digest `H_L("msphf/lin_fs/chal", bind_tuple)`

**bind_tuple Includes:**  
`[xk_hash, seed_commit, seed_bundle_commit, rho_commit, crs_id, hp_commit, params_id, parent_root, join_delta_root, revoked_since_prev_root, revoked_root, proof_mode, policy_version, vrf_id, fs_epoch_commit, fs_ec, fs_dev_prev_commit, fs_dev_commit]`

**Validation:** [`crates/msphf-orchestrator/src/proofs/capss.rs`](../../crates/msphf-orchestrator/src/proofs/capss.rs)

### 7.2 ZK-VRF Proof (Field #95)

**Size:** ≤ 8,192 bytes (`MAX_VRF_PROOF_BYTES`)

**lb-vrf/v1 Structure:**
```
vrf_proof := {
    "commitment": bstr32,       // Commitment to VRF evaluation
    "challenge": bstr32,        // Fiat-Shamir challenge
    "response_s": bstr,         // Response polynomial (s component)
    "response_e": bstr,         // Response polynomial (e component)
    "mask_opening": bstr32,     // Mask opening value
    ...                         // Additional lb-vrf components
}
```

**Binding:**
```
bind := CBOR_det([
    xk_hash,
    rho_commit,
    seed_bundle_commit,
    crs_id,
    hp_commit,
    params_id,
    parent_root,
    join_delta_root,
    revoked_since_prev_root,
    revoked_root,
    proof_mode,
    policy_version,
    meor_vrf_id
])
```

**Validation:** Verifies that Y* was correctly computed from hp (without revealing Y*).

### 7.3 Proofs Commit (Field #125)

```
proofs_commit := H_L("msphf/proofs", [vrf_proof, fs_capss])
```

**Purpose:** Single commitment to both proofs for VCK caching.

---

## 8. Size Limits

**Blueprint:** §12.0 (Maxima)

| Field | Enforced Limit | Constant | Comment |
|-------|----------------|----------|---------|
| **#95 (VRF proof)** | 8,192 bytes | `MAX_VRF_PROOF_BYTES` | Hard limit enforced inside the `accept/` module |
| **#97 (KBROAD envelope)** | 16,400 bytes | `KBROAD_HP_MAX_CIPHERTEXT_BYTES` | `C_hp` ciphertext bound (includes 16-byte tag) |
| **#146 (CAPSS Smallwood proof)** | 16,384 bytes | `FS_CAPSS_MAX_BYTES` | Binding digest + transcript |
| **#122 (SRX payload)** | Configurable (`srx_max_bytes`, default 1,048,576) | `DEFAULT_SRX_MAX_BYTES` | Tunable via policy |

Field #97 (KBROAD envelope) is now validated for both structure and length (≤ 16,400 bytes for `C_hp`). Oversize envelopes trigger `FREEZE_KBROAD_PARENT_MISMATCH` before any decryption attempt.

---

## 9. Wire Format Examples

### 9.1 Minimal Join Anchor (Genesis)

**CBOR Diagnostic Notation:**
```
{
    90: 31,                           // tswe_alg
    91: h'AA...AA',                   // seed_ctx_hash (32 bytes)
    92: "rpo-256/v1",                 // merkle_ds_id
    93: h'BB...BB',                   // rho_commit (32 bytes)
    94: h'CC...CC',                   // seed_bundle_commit (32 bytes)
    95: h'DD...',                     // vrf_proof (≤ 8KB)
    97: [                             // KBROAD envelope
        "kbroad-v1",
        h'...',                       // ct_kem (ML-KEM-768 ciphertext)
        h'...',                       // wrap (~48 bytes)
        h'...',                       // C_hp (~6-8KB)
        "chacha20-poly1305"
    ],
    98: "rlwe-merkle/v1",             // crs_id
    99: h'EE...EE',                   // hp_commit (32 bytes)
    104: h'...',                      // kbroad_pub (ML-KEM-768 public key)
    105: "ml-kem-768",                // kbroad_alg
    106: h'FF...FF',                  // params_id (32 bytes)
    107: "ML-DSA-65",                 // pop_device_pk_alg
    108: h'...',                      // pop_device_pk_bytes (2592 bytes)
    109: h'...',                      // pop_sig (4595 bytes)
    110: h'00...00',                  // parent_root (empty, 32 bytes)
    111: h'11...11',                  // join_delta_root (founder's leaf, 32 bytes)
    112: h'00...00',                  // revoked_since_prev_root (empty)
    113: h'00...00',                  // revoked_root (empty)
    116: "lb-vrf/v1",                 // meor_vrf_id
    119: "lin+zkvrf",                 // proof_mode
    146: h'...',                      // fs_capss (≤16KB, typically ~12KB)
    120: "srx/v1-complete",           // srx_mode
    121: h'22...22',                  // srx_commit (32 bytes)
    122: h'...',                      // srx_payload (~1KB for genesis)
    123: h'...',                      // srx_hint_counts (CBOR array)
    124: h'...',                      // srx_hint_sizes (CBOR array)
    125: h'33...33',                  // proofs_commit (32 bytes)
    130: "self-ml-dsa-65",            // bootstrap_alg (genesis only)
    131: h'...',                      // bootstrap_sig (4595 bytes)
    132: h'...'                       // bootstrap_pk (2592 bytes)
}
```

**Total Size:** ~50-60 KB for genesis anchor

### 9.2 Merge Anchor

**CBOR Diagnostic Notation:**
```
{
    90: 31,
    91: h'AA...AA',                   // seed_ctx_hash
    92: "rpo-256/v1",
    93: h'BB...BB',                   // rho_commit
    94: h'CC...CC',                   // seed_bundle_commit
    98: "rlwe-merkle/v1",
    104: h'...',                      // kbroad_pub
    105: "ml-kem-768",
    106: h'FF...FF',                  // params_id
    110: h'DD...DD',                  // parent_root (previous epoch)
    111: h'EE...EE',                  // join_delta_root (merged result)
    112: h'00...00',                  // revoked_since_prev_root
    113: h'00...00',                  // revoked_root
    140: "v0.1.0",                    // policy_version (optional)
    // NO fields 95-97, 99, 107-109, 116, 119, 120-125, 146 (join-only)
    // NO fields 130-132 (bootstrap)
}
```

**Total Size:** ~2-3 KB (much smaller than join anchors)

### 9.3 Binary Encoding

**Example: Field #99 (hp_commit)**
```
Hex dump:
  18 63    -- Key 99 (unsigned int, 1-byte value)
  58 20    -- Byte string, 32 bytes follow
  AA AA AA AA AA AA AA AA  -- hp_commit[0..8]
  AA AA AA AA AA AA AA AA  -- hp_commit[8..16]
  AA AA AA AA AA AA AA AA  -- hp_commit[16..24]
  AA AA AA AA AA AA AA AA  -- hp_commit[24..32]
```

**Decoding:**
```
0x18 = major type 0 (uint), additional info 24 (1-byte value follows)
0x63 = 99 (key)
0x58 = major type 2 (bstr), additional info 24 (1-byte length follows)
0x20 = 32 (length)
[32 bytes] = data
```

---

## 10. Validation Checklist

**Server MUST validate:**

1. **CBOR Structure:**
   - ✅ Clients MUST emit canonical CBOR (sorted keys, shortest encoding)
   - ✅ Required keys present for the selected mode
   - ✅ Values use the expected types (uint, bstr, tstr, array)
   - ℹ️ Unknown or duplicate keys are ignored by the current implementation (last value wins); clients should avoid sending them.

2. **Size Limits:**
   - ✅ Field #95 ≤ MAX_VRF_PROOF_BYTES (8 KB)
   - ✅ Field #122 ≤ configured `srx_max_bytes`

3. **Algorithm Gates:**
   - ✅ Field #90 = 31 (tswe_alg)
   - ✅ Field #92 = "rpo-256/v1" (merkle_ds_id)
   - ✅ Field #105 = "ml-kem-768" (kbroad_alg)
   - ✅ Field #107 = "ML-DSA-65" (pop_device_pk_alg)
   - ✅ Field #119 = "lin+zkvrf" (proof_mode)

4. **KBROAD Envelope:**
   - ✅ 5-element array
   - ✅ Element 0 = "kbroad-v1"
   - ✅ Element 1 = 1088-byte ct_kem
   - ✅ Element 4 = "chacha20-poly1305"

5. **Commitments:**
   - ✅ Field #91 = H_L("seedctx", [ANCHOR_SEED_CTX])
   - ✅ Field #94 = compute_seed_bundle_commit(...)
   - ✅ Field #121 = H_L("srx/commit", [srx_payload])
   - ✅ Field #125 = H_L("msphf/proofs", [vrf_proof, fs_capss])

---

**Next Steps:**
- For witness validation details → [04-witness-validation.md](04-witness-validation.md)
- For SRX/CIMP/MMP algorithms → [04-witness-validation.md](04-witness-validation.md) §3
- For proof verification → [06-proof-systems.md](06-proof-systems.md)
- For complete acceptance pipeline → [07-server-acceptance.md](07-server-acceptance.md)
