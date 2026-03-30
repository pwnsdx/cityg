# 04 — Canonical Witness Validation & SRX Modes

> [!IMPORTANT]
> This chapter is companion material, not the normative specification.
> For the current `tswe/msphf-we/fs-hybrid + prs-barrier` profile, the normative source is [`../specs.md`](../specs.md).
> Inline references below to `Alpha (0.1.0)` are historical blueprint citations only.
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and live code/tests.


**Historical blueprint reference**: Alpha (0.1.0) §5, §12.2, Appendices B & F
**Implementation**: [`crates/msphf-core/src/witness.rs`](../../crates/msphf-core/src/witness.rs), [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Witness Modes](#2-witness-modes)
3. [Canonical Membership Witnesses](#3-canonical-membership-witnesses)
4. [Canonical Non-Membership Witnesses](#4-canonical-non-membership-witnesses)
5. [Proof-of-Possession (PoP)](#5-proof-of-possession-pop)
6. [SRX Modes](#6-srx-modes)
7. [Canonical Interval Binding](#7-canonical-interval-binding)
8. [Validation Pipeline](#8-validation-pipeline)
9. [Error Mapping](#9-error-mapping)
10. [Implementation Details](#10-implementation-details)

---

## 1. Overview

City-G uses **canonical Merkle witnesses** to prove membership or non-membership in the four root sets that constitute the NP language instance **X_k**:

- **`parent_root`**: Merkle root of active members before this anchor
- **`join_delta_root`**: Merkle root of newly joining members in this anchor
- **`revoked_since_prev_root`**: Merkle root of members revoked since the previous anchor
- **`revoked_root`**: Merkle root of all revoked members (cumulative)

Witnesses are encoded in **CBOR canonical form** (RFC 8949 §4.2) and validated using the **rpo-256/v1** hash function. The protocol enforces strict **canonicity rules** to prevent proof malleability and ensure deterministic verification.

### Key Invariants

- **Depth limit**: All Merkle paths MUST have depth ≤ 64
- **Sorted order**: Leaf sets MUST be strictly increasing in byte-lexicographic order
- **Canonical encoding**: All witnesses MUST use deterministic CBOR encoding
- **Anchored adjacency**: Non-membership intervals MUST prove adjacency with binding hashes

---

## 2. Witness Modes

The protocol defines two witness modes corresponding to the exclusive-OR NP language:

```rust
pub enum WitnessMode {
    A,  // Branch A: Membership in parent_root
    B,  // Branch B: Membership in join_delta_root + Non-membership in revoked_root
}
```

### Mode A (Existing Member)

- **Usage**: Existing members rejoining after parent anchor
- **Proves**: `leaf_id ∈ parent_root`
- **Structure**:
  ```cbor
  {
    "mode": "a",
    "witness": <MembershipWitness>,
    "pop": <PopWitness>  # OPTIONAL
  }
  ```

### Mode B (New Joiner)

- **Usage**: New members joining for the first time
- **Proves**:
  1. `leaf_id ∈ join_delta_root` (membership)
  2. `query ∉ revoked_root` (non-membership)
- **Structure**:
  ```cbor
  {
    "mode": "b",
    "witness": <MembershipWitness>,
    "nonmem": <NonMembershipWitness>,  # OPTIONAL if revoked_root is empty
    "pop": <PopWitness>  # OPTIONAL
  }
  ```

---

## 3. Canonical Membership Witnesses

### Wire Format

```cbor
{
  "leaf_id": h'<32 bytes>',  # Leaf identifier (hashed public key)
  "root": h'<32 bytes>',     # Expected Merkle root
  "path": [                  # Path from leaf to root
    {"sibling": h'<32 bytes>', "dir": 0/1},
    ...
  ]
}
```

### Field Definitions

| Field     | Type          | Size  | Description |
|-----------|---------------|-------|-------------|
| `leaf_id` | `bstr`        | 32 B  | `H_L("msphf/leaf/id", [pk_bytes])` where `pk_bytes` is ML-DSA-65 public key |
| `root`    | `bstr`        | 32 B  | Merkle root to validate against (MUST match expected root from `X_k`) |
| `path`    | `[PathEntry]` | ≤64   | Path from leaf to root (depth ≤ 64) |

### PathEntry Structure

```rust
pub struct RawPathEntry {
    pub sibling: Vec<u8>,  // 32 bytes
    pub dir: u8,           // 0 or 1
}
```

- **`dir = 0`**: Current node is left child, sibling is right (`hash_node(current, sibling)`)
- **`dir = 1`**: Current node is right child, sibling is left (`hash_node(sibling, current)`)

### Leaf Identifier Derivation

```rust
// Normative construction (specification §12.2 step 3)
#[derive(Serialize)]
struct LeafBinding {
    #[serde(with = "serde_bytes")]
    public_key: &[u8],  // ML-DSA-65 public key (1952 bytes)
}

leaf_id := H_L("msphf/leaf/id", &LeafBinding { public_key: pk_bytes })
```

**Implementation**: [`crates/msphf-core/src/witness.rs`](../../crates/msphf-core/src/witness.rs)

### Path Evaluation Algorithm

```rust
fn validate_membership_path(leaf: &[u8; 32], path: &[(u8, [u8; 32])]) -> [u8; 32] {
    let mut acc = *leaf;
    for (dir, sibling) in path {
        acc = if *dir == 0 {
            hash_node(&acc, sibling)  // Current is left
        } else {
            hash_node(sibling, &acc)  // Current is right
        };
    }
    acc
}
```

**Validation**:
1. Compute `computed_root := validate_membership_path(leaf_id, path)`
2. Require `computed_root == expected_root` (from `X_k`)
3. Require `path.len() ≤ 64`
4. Require all `dir` values are 0 or 1

**Implementation**: [`crates/msphf-core/src/merkle.rs`](../../crates/msphf-core/src/merkle.rs)

---

## 4. Canonical Non-Membership Witnesses

Non-membership witnesses prove that a query value falls within an interval `(left, right)` where `left` and `right` are adjacent leaves in the Merkle tree (or boundary sentinels).

### Wire Format (Alpha (0.1.0) Canonical)

```cbor
{
  "query": h'<32 bytes>',               # Value to prove not in set
  "root": h'<32 bytes>',                # Expected Merkle root
  "left": h'<32 bytes>' / null,         # Left boundary (or null if open)
  "right": h'<32 bytes>' / null,        # Right boundary (or null if open)
  "path": [],                           # MUST be empty for interval proofs
  "left_below": [<PathEntry>, ...],     # Path from left anchor to LCA
  "right_below": [<PathEntry>, ...],    # Path from right anchor to LCA
  "above": [<PathEntry>, ...],          # Shared path from LCA to root
  "nmint": h'<32 bytes>',               # Interval binding hash (MT_NMBIN)
  "lca_left_height": uint,              # Height of left anchor at LCA
  "lca_right_height": uint              # Height of right anchor at LCA
}
```

### Field Definitions

| Field              | Type          | Required | Description |
|--------------------|---------------|----------|-------------|
| `query`            | `bstr`        | ✓        | 32-byte value to prove ∉ set |
| `root`             | `bstr`        | ✓        | 32-byte Merkle root |
| `left`             | `bstr/null`   | ✓        | Left boundary leaf ID (null if empty/open) |
| `right`            | `bstr/null`   | ✓        | Right boundary leaf ID (null if empty/open) |
| `path`             | `[PathEntry]` | ✓        | MUST be `[]` for interval proofs |
| `left_below`       | `[PathEntry]` | If left  | Path from left leaf to LCA (all `dir=0`) |
| `right_below`      | `[PathEntry]` | If right | Path from right leaf to LCA (all `dir=1`) |
| `above`            | `[PathEntry]` | If left & right | Shared path from LCA to root |
| `nmint`            | `bstr`        | If left & right | 32-byte interval binding hash |
| `lca_left_height`  | `uint`        | If left & right | `left_below.len() + 1` |
| `lca_right_height` | `uint`        | If left & right | `right_below.len() + 1` |

### Canonicity Rules

1. **Ordering constraint**: `left < query < right` (byte-lexicographic)
2. **Directional anchor invariant**:
   - All `left_below` entries MUST have `dir = 0` (climbing right siblings)
   - All `right_below` entries MUST have `dir = 1` (climbing left siblings)
3. **Height consistency**:
   - `lca_left_height == left_below.len() + 1`
   - `lca_right_height == right_below.len() + 1`
4. **Depth limit**: `left_below.len() + right_below.len() + above.len() ≤ 64`
5. **Legacy path rejection**: `path` MUST be empty `[]`
6. **NMINT binding**: MUST match recomputed `hash_interval_binding()`

### Special Cases

#### Empty Set (Both Bounds Null)

```cbor
{
  "query": h'<32 bytes>',
  "root": h'0000...0000',  # All zeros
  "left": null,
  "right": null,
  "path": [],
  "left_below": [],
  "right_below": [],
  "above": [],
  "nmint": null,
  "lca_left_height": null,
  "lca_right_height": null
}
```

**Validation**:
- `left == null && right == null`
- `root == [0u8; 32]` (zero sentinel)
- `path.is_empty()`

#### Single-Leaf Tree (One Bound Null)

```cbor
{
  "query": h'<32 bytes>',
  "root": h'<32 bytes>',
  "left": h'<32 bytes>',   # OR null
  "right": null,           # OR h'<32 bytes>'
  "path": [<optional witness path>],
  "left_below": [],
  "right_below": [],
  "above": [],
  "nmint": null,
  "lca_left_height": null,
  "lca_right_height": null
}
```

**Validation**:
- Compute `base := left` (if right is null) or `base := right` (if left is null)
- Compute `computed_root := apply_path_from(base, path)`
- Require `computed_root == expected_root`

**Implementation**: [`crates/msphf-core/src/witness.rs`](../../crates/msphf-core/src/witness.rs)

---

## 5. Proof-of-Possession (PoP)

PoP witnesses bind the device's ML-DSA-65 keypair to the anchor instance **X_k** and prove possession of the private key.

### Wire Format

```cbor
{
  "public_key": h'<1952 bytes>',  # ML-DSA-65 public key
  "signature": h'<4595 bytes>'    # ML-DSA-65 detached signature
}
```

### Message Construction

```rust
#[derive(Serialize)]
struct PopMsg {
    #[serde(with = "serde_bytes")]
    xk: &[u8],         // CBOR_det(X_k)
    #[serde(with = "serde_bytes")]
    leaf_id: &[u8],    // 32-byte leaf identifier
    #[serde(with = "serde_bytes")]
    epoch: &[u8],      // 32-byte we_epoch_id
}

pop_msg := H_L("msphf/pop/msg", &PopMsg { xk, leaf_id, epoch })
```

**Blueprint**: Alpha (0.1.0) §12.2 step 3

### Validation Steps

1. **Size check**:
   - `public_key.len() == 1952` (ML-DSA-65 public key size)
   - `signature.len() == 4595` (ML-DSA-65 signature size)

2. **Leaf binding check**:
   ```rust
   computed_leaf := H_L("msphf/leaf/id", &LeafBinding { public_key })
   require computed_leaf == membership.leaf_id
   ```

3. **Signature verification**:
   ```rust
   pop_msg := H_L("msphf/pop/msg", &PopMsg { xk, leaf_id, epoch })
   verify_ml_dsa(signature, pop_msg, public_key)
   ```

4. **Error mapping**:
   - Leaf mismatch → `Freeze(907.3, "leaf_bind_mismatch")`
   - Signature invalid → `Freeze(921, "pop_invalid")`

**Implementation**: [`crates/msphf-core/src/witness.rs`](../../crates/msphf-core/src/witness.rs)

---

## 6. SRX Modes

## 6. SRX Mode

**SRX** (Succinct Root eXtraction) payloads bundle all Merkle witnesses for a join anchor into a single CBOR blob. City-G ships a single mode, `srx/v1-complete`.

### 6.1. v1-complete (REQUIRED)

**Structure** (canonical CBOR array)

```cbor
srx_payload := [
  0: join_nonmem_parent,        // [AnchoredNonMembership, ...]
  1: join_nonmem_revoked_since, // [AnchoredNonMembership, ...]
  2: since_mem_revoked,         // [MembershipWitness, ...]
  3: meta,                      // {"join_count", "since_count", "join_frontier_size", "since_frontier_size"}
  4: join_leaf_ids,             // [bstr32, ...]
  5: join_frontier,             // [bstr32, ...] / null
  6: since_leaf_ids,            // [bstr32, ...]
  7: since_frontier,            // [bstr32, ...] / null
  8: anchor_mem_pool            // [MembershipWitness, ...]
]
```

For readability we refer to the numbered entries by the field names above. Each `AnchoredNonMembership` and `MembershipWitness` uses the same encoding as the corresponding Rust structs (`RawNonMembershipWitness` and `RawMembershipWitness`).

#### Field Overview

| Entry (name)               | Type                  | Description |
|----------------------------|-----------------------|-------------|
| 0 `join_nonmem_parent`     | `[NonMemAnchor]`      | Non-membership witnesses anchored to `parent_root` |
| 1 `join_nonmem_revoked_since` | `[NonMemAnchor]`   | Non-membership witnesses anchored to `revoked_since_prev_root` |
| 2 `since_mem_revoked`      | `[MembershipWitness]` | Membership witnesses into `revoked_root` |
| 3 `meta`                   | `map`                 | Counts and frontier sizes (`join_count`, `since_count`, …) |
| 4 `join_leaf_ids`          | `[bstr32]`            | Sorted leaves comprising `join_delta_root` |
| 5 `join_frontier`          | `[bstr32]` / `null`   | Optional canonical frontier for `join_delta_root` |
| 6 `since_leaf_ids`         | `[bstr32]`            | Sorted leaves comprising `revoked_since_prev_root` |
| 7 `since_frontier`         | `[bstr32]` / `null`   | Optional canonical frontier for `revoked_since_prev_root` |
| 8 `anchor_mem_pool`        | `[MembershipWitness]` | Membership witness pool referenced by non-mem anchors |

`meta.join_count` **must** equal `|join_leaf_ids|`, and `meta.since_count` **must** equal `|since_leaf_ids|`. Frontier sizes must match the optional frontier arrays when present.

#### Anchored Non-Membership

```rust
pub struct SrxNonMembershipAnchor {
    pub witness: RawNonMembershipWitness,
    pub left_ref: Option<u32>,
    pub right_ref: Option<u32>,
}
```

If `left_ref`/`right_ref` are present the verifier resolves them against `anchor_mem_pool` and checks that the referenced membership witness shares the same leaf ID as the non-membership witness boundary.

#### Validation Checklist

1. **Leaf ID sorting**
   - `join_leaf_ids` and `since_leaf_ids` MUST be strictly increasing.

2. **Meta consistency**
   - `meta.join_count == join_leaf_ids.len()` and `meta.since_count == since_leaf_ids.len()`.
   - `meta.join_frontier_size` / `meta.since_frontier_size` must match the lengths of the optional frontier arrays when present.

3. **Root recomputation**
   ```rust
   require canonical_set_root(&join_leaf_ids) == X_k.join_delta_root
   require canonical_set_root(&since_leaf_ids) == X_k.revoked_since_prev_root
   ```

4. **Frontier verification**
   ```rust
   if join_frontier.is_some() {
       require canonical_frontier(&join_leaf_ids) == join_frontier
   }
   if since_frontier.is_some() {
       require canonical_frontier(&since_leaf_ids) == since_frontier
   }
   ```

5. **Anchored adjacency**
   - Resolve `left_ref`/`right_ref` into `anchor_mem_pool`.
   - Validate each non-membership witness against the appropriate root (`parent_root` / `revoked_since_prev_root`).

6. **Revoked membership**
   - Each `since_mem_revoked` witness must validate against `revoked_root`.

7. **Size limits**
   - Payload length ≤ `SRX_MAX` (1 MiB).
   - Hint count budgets enforced via `HDR_SRX_HINT_COUNTS`.

**Implementation**: [`crates/msphf-orchestrator/src/accept`](../../crates/msphf-orchestrator/src/accept)

## 7. Canonical Interval Binding

The **interval binding hash** (`nmint`) prevents replay attacks by cryptographically binding the non-membership witness to its specific anchor leaves and tree structure.

### NMINT Construction

```rust
pub fn hash_interval_binding(
    left_id: &[u8; 32],         // Left anchor leaf ID
    left_leaf: &[u8; 32],       // Left anchor leaf hash
    right_id: &[u8; 32],        // Right anchor leaf ID
    right_leaf: &[u8; 32],      // Right anchor leaf hash
    lca_left_height: u8,        // Height from left leaf to LCA
    lca_right_height: u8,       // Height from right leaf to LCA
) -> [u8; 32] {
    rpo256::interval_binding(
        left_id,
        left_leaf,
        right_id,
        right_leaf,
        lca_left_height,
        lca_right_height,
    )
}
```

**Blueprint**: Alpha (0.1.0) Appendix B (CanonicalInterval)

### RPO-256 Domain Separation

The `rpo256::interval_binding` function uses a dedicated Rescue-Prime-Optimized permutation with domain label **`MT_NMBIN`**:

```rust
// Pseudo-code (RPO-256/v1 specification)
fn interval_binding(
    left_id: &[u8; 32],
    left_leaf: &[u8; 32],
    right_id: &[u8; 32],
    right_leaf: &[u8; 32],
    lca_left_height: u8,
    lca_right_height: u8,
) -> [u8; 32] {
    let input = [
        left_id,
        left_leaf,
        right_id,
        right_leaf,
        &[lca_left_height],
        &[lca_right_height],
    ].concat();

    rpo256_hash("MT_NMBIN", input)
}
```

**Implementation**: [`crates/msphf-core/src/rpo256.rs`](../../crates/msphf-core/src/rpo256.rs) (via `miden-crypto` crate)

### Validation Logic

```rust
// Recompute anchors
let left_anchor = fold_extended_anchor(left_leaf_hash, &left_below)?;
let right_anchor = fold_extended_anchor(right_leaf_hash, &right_below)?;

// Merge at LCA
let mut acc = hash_node(&left_anchor, &right_anchor);

// Climb shared suffix
for entry in &above {
    acc = fold_step(acc, entry)?;
}

// Verify root
require acc == expected_root;

// Verify NMINT
let expected_nmint = hash_interval_binding(
    left_id,
    &left_leaf_hash,
    right_id,
    &right_leaf_hash,
    lca_left_height,
    lca_right_height,
);
require nmint == expected_nmint;
```

**Implementation**: [`crates/msphf-core/src/witness.rs`](../../crates/msphf-core/src/witness.rs)

---

## 8. Validation Pipeline

The acceptance pipeline validates witnesses in the following order (specification §12.2):

### Step 3: PoP Validation (Join Only)

1. Stream-parse `HDR_SRX_PAYLOAD` (field 122) to extract `join_leaf_ids`
2. For the joiner's witness (mode A or B):
   - Extract `pop` field
   - Compute `leaf_id := H_L("msphf/leaf/id", [pk_bytes])`
   - Require `leaf_id ∈ join_leaf_ids` (syntactic check)
3. Compute `pop_msg := H_L("msphf/pop/msg", [xk, leaf_id, we_epoch_id])`
4. Verify ML-DSA-65 signature deterministically
5. On failure → `Freeze(921, "pop_invalid")`

### Step 6: SRX Validation (Join Only)

1. Decode `HDR_SRX_PAYLOAD` (field 122) into `SrxPayload`
2. Validate `srx_mode` (field 120) is `"srx/v1-complete"` and allowed by policy
3. **Completeness checks**:
   - Recompute `join_delta_root` from `join_leaf_ids` and verify match
   - Recompute `revoked_since_prev_root` from `since_leaf_ids` and verify match
4. **Anchored adjacency**:
   - For each `join_nonmem_parent[i]`:
     - Dereference `left_ref`/`right_ref` into `anchor_mem_pool`
     - Validate non-membership witness against `X_k.parent_root`
     - Verify NMINT binding
   - For each `join_nonmem_revoked_since[i]`: same logic vs. `revoked_since_prev_root`
5. **Cumulative revoked**:
   - For each `since_mem_revoked[i]`: validate membership witness against `X_k.revoked_root`
6. **Canonicity**:
   - All Merkle paths depth ≤ 64
   - All leaf sets strictly increasing
   - All NMINT bindings match
7. **Error mapping** (see §9 below)

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

## 9. Error Mapping

Witness validation errors map to **Freeze** codes (deterministic, cacheable):

| Code    | Reason                      | Cause |
|---------|-----------------------------|-------|
| 907.1   | `cbor_malformed`            | Invalid CBOR encoding, missing fields, wrong types |
| 907.2   | `nonmem_noncanonical`       | Non-membership witness violates canonicity rules |
| 907.21  | `mem_malformed`             | Membership witness has invalid structure |
| 907.3   | `leaf_bind_mismatch`        | PoP public key does not hash to claimed `leaf_id` |
| 907.4   | `proj_eval_fail`            | Merkle path evaluation does not match expected root |
| 907.5   | `path_oversize`             | Merkle path depth > 64 |
| 907.6   | `set_conflict`              | Leaf set not strictly increasing |
| 921     | `pop_invalid`               | ML-DSA-65 signature verification failed |
| 929     | `srx_required`              | SRX payload missing when required |
| 930     | `srx_invalid`               | SRX validation failed (see sub-reasons below) |

### SRX Sub-Errors (Code 930)

| Sub-Reason                  | Cause |
|-----------------------------|-------|
| `srx_oversize_hint`         | Hint counts exceed budget |
| `srx_hint_under`            | Hint counts below actual witness count |
| `srx_frontier_mismatch`     | Provided frontier does not match computed frontier |
| `srx_anchor_missing`        | Referenced `anchor_mem_pool` index out of bounds |
| `srx_anchor_mismatch`       | Dereferenced anchor `leaf_id` does not match non-mem `left`/`right` |
| `srx_anchor_oob`            | Anchor reference exceeds pool size |
| `srx_anchor_pool_unsorted`  | Anchor pool not sorted |
| `srx_anchors_overbudget`    | Total anchor count exceeds limit |
| `srx_commit_mismatch`       | Recomputed `srx_commit` does not match header field 121 |

**Blueprint**: Alpha (0.1.0) §15

### Rust Error Enum Mapping

```rust
impl From<WitnessValidationError> for FreezeError {
    fn from(err: WitnessValidationError) -> Self {
        match err {
            WitnessValidationError::CborMalformed => FREEZE_HASH_CBOR,
            WitnessValidationError::NonCanonical => FREEZE_HASH_NONCANONICAL,
            WitnessValidationError::LeafBindMismatch => FREEZE_HASH_LEAF_BIND,
            WitnessValidationError::ProjEvalFail => FREEZE_HASH_PROJ_FAIL,
            WitnessValidationError::PathOversize => FREEZE_HASH_PATH_OVERSIZE,
            WitnessValidationError::MemMalformed => FREEZE_HASH_MEM_MALFORMED,
        }
    }
}
```

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

## 10. Implementation Details

### 10.1. Canonical Set Root

```rust
pub fn canonical_set_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], MsphfError> {
    if leaves.is_empty() {
        return Ok([0u8; 32]);  // Empty set sentinel
    }
    if leaves.len() == 1 {
        return Ok(leaves[0]);  // Single leaf
    }

    // Verify strict ordering
    if leaves.windows(2).any(|w| w[0] >= w[1]) {
        return Err(MsphfError::invalid_input("set must be strictly increasing"));
    }

    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks_exact(2) {
            next.push(hash_node(&pair[0], &pair[1]));
        }
        // Carry rule: propagate last digest if odd
        if level.len() % 2 == 1 {
            next.push(*level.last().unwrap());
        }
        level = next;
    }
    Ok(level[0])
}
```

**Blueprint**: Alpha (0.1.0) Appendix F (canonical Merkle set root with carry rule)
**Implementation**: [`crates/msphf-core/src/merkle.rs`](../../crates/msphf-core/src/merkle.rs)

### 10.2. Canonical Frontier

```rust
pub fn canonical_frontier(leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, MsphfError> {
    if leaves.is_empty() {
        return Ok(Vec::new());
    }

    // Verify strict ordering
    if leaves.windows(2).any(|w| w[0] >= w[1]) {
        return Err(MsphfError::invalid_input("set must be strictly increasing"));
    }

    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut frontier = Vec::new();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks_exact(2) {
            next.push(hash_node(&pair[0], &pair[1]));
        }
        if level.len() % 2 == 1 {
            let carry = *level.last().unwrap();
            frontier.push(carry);  // Record carried digest
            next.push(carry);
        }
        level = next;
    }
    Ok(frontier)
}
```

**Purpose**: The frontier is the multiset of carried digests encountered while ascending the tree. It allows incremental Merkle root updates without recomputing the entire tree.

**Implementation**: [`crates/msphf-core/src/merkle.rs`](../../crates/msphf-core/src/merkle.rs)

### 10.3. Hash Functions

All Merkle operations use **rpo-256/v1** (Rescue-Prime-Optimized):

```rust
pub fn hash_leaf(leaf: &[u8]) -> [u8; 32] {
    crate::rpo256::leaf(leaf)
}

pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    crate::rpo256::node(left, right)
}

pub fn hash_interval(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    crate::rpo256::interval_node(left, right)
}
```

**Domain labels**:
- Leaf hashing: `MT_LEAF_32`
- Internal nodes: `MT_NODE_32`
- Interval nodes: `MT_INTERVAL_32`
- Interval binding: `MT_NMBIN`

**Implementation**: [`crates/msphf-core/src/rpo256.rs`](../../crates/msphf-core/src/rpo256.rs)

### 10.4. Witness Digest

Each validated witness is hashed to produce a **witness commit** for binding into proofs:

```rust
impl ValidatedWitness {
    pub fn digest(&self) -> Result<[u8; 32], MsphfError> {
        hash::h_l(ds::MSPHF_WITNESS_COMMIT, self)
    }
}
```

**Label**: `"msphf/witness/commit"`
**Purpose**: Binds the witness structure into the proof transcript, preventing proof-witness malleability.

**Implementation**: [`crates/msphf-core/src/witness.rs`](../../crates/msphf-core/src/witness.rs)

---

## Summary

City-G's canonical witness validation enforces strict **depth limits** (≤64), **sorted order**, and **anchored adjacency** to ensure deterministic verification and prevent proof malleability. The **SRX/v1-complete** mode bundles all join witnesses into a single payload with shared anchor pools, enabling efficient batch validation. **PoP** witnesses bind ML-DSA-65 keypairs to the epoch context, and **NMINT** bindings prevent interval witness replay. All errors map to deterministic **Freeze** codes for caching and DoS mitigation.

**Next**: [05 — SPHF & ME-OR](./05-sphf-meor.md)
