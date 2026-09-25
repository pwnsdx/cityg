# 09 — Multi-Head Window (MHW)

> [!IMPORTANT]
> This chapter is companion material, not the normative specification.
> For the current `tswe/msphf-we/fs-hybrid + prs-barrier` profile, the normative source is [`../specs.md`](../specs.md).
> Inline references below to `Alpha (0.1.0)` are historical blueprint citations only.
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and live code/tests.


**Historical blueprint reference**: Alpha (0.1.0) §13, Annex M
**Implementation**: [`crates/msphf-orchestrator/src/mhw.rs`](../../crates/msphf-orchestrator/src/mhw.rs)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Window Identifier (WID)](#2-window-identifier-wid)
3. [Multi-Head Window Structure](#3-multi-head-window-structure)
4. [Join Mode (Non-Merge)](#4-join-mode-non-merge)
5. [Merge Mode](#5-merge-mode)
6. [Anti-Grind Mechanisms](#6-anti-grind-mechanisms)
7. [Concurrency Control](#7-concurrency-control)
8. [Window Management](#8-window-management)

---

## 1. Overview

The **Multi-Head Window (MHW)** enables **parallel join capability** where multiple devices can simultaneously join the same parent anchor, creating concurrent "heads" that can later be merged into a single consolidated anchor.

### Key Properties

- **Concurrency**: Up to **H_MAX** (default: 16) concurrent heads per parent root
- **Time-bounded**: Heads expire after **T_WINDOW** (default: 120 seconds)
- **Deterministic routing**: All heads for the same parent root share the same **WID**
- **DoS protection**: Window limits prevent unbounded head proliferation
- **Publisher-blind**: WID is derived from public header fields, not secrets

**Blueprint**: Alpha (0.1.0) §13, Annex M

---

## 2. Window Identifier (WID)

### Definition

```rust
WID := H_L("mhw/window", [gid, parent_root, seed_ctx_hash])
```

**Components**:
- `gid`: Group identifier (variable length bytes)
- `parent_root`: 32-byte Merkle root (field 110)
- `seed_ctx_hash`: 32-byte ANCHOR_SEED_CTX hash (field 91)

**Label**: `"mhw/window"`

**Output**: 32 bytes

### Implementation

```rust
#[derive(Serialize)]
struct WindowIdInputs<'a> {
    #[serde(with = "serde_bytes")]
    gid: &'a [u8],
    #[serde(with = "serde_bytes")]
    parent_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    seed_ctx_hash: &'a [u8; 32],
}

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

**Implementation**: [`crates/msphf-orchestrator/src/lib.rs`](../../crates/msphf-orchestrator/src/lib.rs)

### Properties

1. **Deterministic**: Same (gid, parent_root, seed_ctx_hash) → same WID
2. **Public**: Derivable from header without secrets
3. **Collision-resistant**: BLAKE3 output (32 bytes)
4. **Scope**: Each WID represents a unique "join window" for a parent anchor

**Key insight**: WID is **not derived from Y\*** or **E_k**, maintaining server blindness while enabling routing.

**Blueprint**: Alpha (0.1.0) §13 (WID definition), Annex M

---

## 3. Multi-Head Window Structure

### Data Structure

```rust
pub struct MultiHeadWindow {
    h_max: usize,                              // Maximum heads per WID
    ttl: Duration,                             // Time-to-live for heads
    heads: BTreeMap<Vec<u8>, Vec<HeadRecord>>, // WID → list of active heads
}

pub struct HeadRecord {
    pub we_epoch_id: [u8; 32],        // Unique epoch ID for this head
    pub msphf_hp_commit: [u8; 32],    // HP commitment (field 99)
    pub seed_ctx_hash: [u8; 32],      // Seed context hash (field 91)
    pub rho_commit: [u8; 32],         // ρ commitment (field 93)
    pub seed_commit: [u8; 32],        // Seed commitment (field 94)
    pub xk_hash: [u8; 32],            // X_k hash
    pub accept_seq: u64,              // Monotonic sequence number
    accept_ts: Instant,               // Acceptance timestamp (internal)
}
```

**Key**: WID (32 bytes, stored as `Vec<u8>` for BTreeMap)
**Value**: List of `HeadRecord` (up to `h_max` entries)

**Implementation**: [`crates/msphf-orchestrator/src/mhw.rs`](../../crates/msphf-orchestrator/src/mhw.rs)

### Parameters

```rust
pub const DEFAULT_H_MAX: usize = 16;                  // Up to 16 concurrent heads
pub const DEFAULT_T_WINDOW: Duration = Duration::from_secs(120); // 2-minute window
```

**Rationale**:
- **H_MAX = 16**: Balances concurrency with DoS protection
- **T_WINDOW = 120s**: Absorbs typical client jitter while bounding memory and freeze exposure

> **Operational note:** Doubling `T_WINDOW` roughly doubles in-memory head retention and extends the freeze window attackers can try to exhaust. Only raise it when measurements show honest clients frequently exceed 2 minutes between anchor submissions.

**Blueprint**: Annex M (Multi-Head Windows & anti-grind telemetry)

---

## 4. Join Mode (Non-Merge)

### Accept Head

```rust
pub fn accept_head(
    &mut self,
    wid: &[u8],
    record: HeadRecord,
    now: Instant,
) -> Result<(), FreezeError>
```

**Algorithm**:

1. **Prune expired heads**:
   ```rust
   let entry = self.prune(wid, now);
   // Removes all heads where: now - accept_ts > ttl
   ```

2. **Check capacity**:
   ```rust
   if entry.len() >= self.h_max {
       return Err(FreezeError::WINDOW_FULL);  // Code 925
   }
   ```

3. **Insert new head**:
   ```rust
   entry.push(record);
   Ok(())
   ```

**Pruning logic**:
```rust
fn prune(&mut self, wid: &[u8], now: Instant) -> &mut Vec<HeadRecord> {
    let ttl = self.ttl;
    let entry = self.heads.entry(wid.to_vec()).or_default();
    entry.retain(|record| now.duration_since(record.accept_ts) <= ttl);
    entry
}
```

**Implementation**: [`crates/msphf-orchestrator/src/mhw.rs`](../../crates/msphf-orchestrator/src/mhw.rs)

### Example Timeline

````
┌─────────────────────────────────────────────────────────────────┐
│ Multi-Head Window Timeline (H_MAX=16, TTL=120s)                 │
└─────────────────────────────────────────────────────────────────┘

Time   │ Event                   │ Active Heads in WID=0x1234...
───────┼─────────────────────────┼──────────────────────────────────
t=0s   │ Device A joins          │ [Head 1: 0xAA...]
       │ (same parent_root)      │
       │                         │
t=30s  │ Device B joins          │ [Head 1: 0xAA...,
       │ (same parent_root)      │  Head 2: 0xBB...]
       │                         │
t=80s  │ Device C joins          │ [Head 1: 0xAA...,
       │ (same parent_root)      │  Head 2: 0xBB...,
       │                         │  Head 3: 0xCC...]
       │                         │
t=130s │ Head 1 expires          │ [Head 2: 0xBB...,
       │ now - 0s > 120s TTL     │  Head 3: 0xCC...]
       │ Auto-pruned             │
       │                         │
t=135s │ Device D joins          │ [Head 2: 0xBB...,
       │ (same parent_root)      │  Head 3: 0xCC...,
       │                         │  Head 4: 0xDD...]
```

---

## 5. Merge Mode

### Accept Merge

```rust
pub fn accept_merge(
    &mut self,
    wid_old: &[u8],
    wid_new: &[u8],
    mh_heads: &[[u8; 32]],
    new_record: HeadRecord,
    now: Instant,
) -> Result<(), FreezeError>
```

**Inputs**:
- `wid_old`: Window identifier that currently owns the heads being retired
- `wid_new`: Window identifier for the merged head (often identical to `wid_old`, but
  merges are allowed to land in a new window when the seed context changes)
- `mh_heads`: Sorted, unique list of `we_epoch_id` values to retire
- `new_record`: New merged head record
- `now`: Current timestamp

**Algorithm**:

1. **Validate mh_heads**:
   ```rust
   if !is_sorted_unique(mh_heads) {
       return Err(FreezeError::MERGE_INVALID);  // Code 927
   }

   fn is_sorted_unique(list: &[[u8; 32]]) -> bool {
       if list.is_empty() { return false; }
       for window in list.windows(2) {
           if window[0] >= window[1] { return false; }
       }
       true
   }
   ```

2. **Prune expired heads in the source window**:
   ```rust
   let entry_old = self.prune(wid_old, now);
   ```

3. **Retire specified heads**:
   ```rust
   for head_weid in mh_heads {
       if let Some(pos) = entry_old.iter().position(|rec| &rec.we_epoch_id == head_weid) {
           entry_old.remove(pos);
       } else {
           return Err(FreezeError::MERGE_INVALID);  // Head not found
       }
   }
   ```

4. **Handle window transition** (`accept_merge(wid_old, wid_new, …)`):
   ```rust
   if wid_old == wid_new {
       if entry_old.len() >= self.h_max {
           return Err(FreezeError::WINDOW_FULL);
       }
       entry_old.push(new_record);
       return Ok(());
   }

   let remove_empty = entry_old.is_empty();
   if remove_empty {
       self.heads.remove(&wid_old.to_vec());
   }

   let entry_new = self.prune(wid_new, now);
   if entry_new.len() >= self.h_max {
       return Err(FreezeError::WINDOW_FULL);
   }
   entry_new.push(new_record);
   Ok(())
   ```

**Implementation**: [`crates/msphf-orchestrator/src/mhw.rs`](../../crates/msphf-orchestrator/src/mhw.rs)

### Merge Semantics

**Header field 130** (`mh_heads`):
```cbor
[
  h'<32 bytes>',  # we_epoch_id of head 1 to retire
  h'<32 bytes>',  # we_epoch_id of head 2 to retire
  ...
]
```

**Constraints**:
- MUST be sorted in ascending byte-lexicographic order
- MUST contain no duplicates
- All `we_epoch_id` values MUST exist in the window
- Merged head inherits consolidated state from retired heads

**Derived we_epoch_id**:
```rust
we_epoch_id := H_L("tswe/merge/weid", [gid, cat, xk_hash, mh_heads])
```

**Blueprint**: Alpha (0.1.0) §13, Annex M (extended by the rollup metadata additions)

**Rollup extensions (fields 131–136)**:

- `pivot_weid` (131) — indicates which antecedent provides the inherited `ρ` (key 93) and the
  reference roots for SRX.
- `rollup_provenance_commit` (132) — `H_L("msphf/rollup/prov", [[weid, vck, xk_hash], …])`.
- `epoch_replay` (133) — sorted table mapping `weid` → `(xk_hash, roots, is_join)` for absorbed
  epochs.
- `vck_rollup_commit` (134, optional) — `H_L("msphf/rollup/vck", [vck_1,…,vck_K])`.
- `merge_delegation_sig` (135, optional) — policy-level authorization.
- `kbroad_replay` (136) — KBROAD clones for join epochs (`is_join=true`).

All lists are canonicalised (sorted by `weid`, no duplicates) and excluded from `ANCHOR_SEED_CTX`
so they do not perturb key derivation.

### Example Merge

```
┌─────────────────────────────────────────────────────────────────┐
│                       Before Merge                              │
└─────────────────────────────────────────────────────────────────┘

    WID = 0x1234...
         ↓
    ┌─────────────────────────────────────┐
    │  Active Heads (3/16)                │
    ├─────────────────────────────────────┤
    │  0xAA... (Head 1, Device A)         │ ← Will be retired
    │  0xBB... (Head 2, Device B)         │ ← Will be retired
    │  0xCC... (Head 3, Device C)         │ ← Remains active
    └─────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────┐
│                       Merge Operation                           │
└─────────────────────────────────────────────────────────────────┘

    Merger creates anchor with:
      mh_heads = [0xAA..., 0xBB...]  (sorted, no duplicates)
      pivot_weid = 0xAA...           (choose parity source)
      new_weid = H_L("tswe/merge/weid", [gid, cat, xk_hash, mh_heads])
                = 0xDD...


┌─────────────────────────────────────────────────────────────────┐
│                       After Merge                               │
└─────────────────────────────────────────────────────────────────┘

    WID = 0x1234...  (same window, wid_old == wid_new)
         ↓
    ┌─────────────────────────────────────┐
    │  Active Heads (2/16)                │
    ├─────────────────────────────────────┤
    │  0xCC... (Head 3, Device C)         │ ← Unchanged
    │  0xDD... (Merged, A+B)              │ ← New consolidated head
    └─────────────────────────────────────┘

    Retired heads: [0xAA..., 0xBB...]
    All members can now derive E_k from merged state


┌─────────────────────────────────────────────────────────────────┐
│ Note: Window Transition (when seed_ctx changes)                 │
└─────────────────────────────────────────────────────────────────┘

If the merge updates seed_ctx_hash:
  1. Compute new WID: wid_new = H_L("mhw/window", [gid, parent_root, new_seed_ctx])
  2. Prune heads from wid_old (retire [0xAA..., 0xBB...])
  3. Prune/create wid_new
  4. Insert merged head (0xDD...) into wid_new
  5. If wid_old is now empty, remove it entirely
```

---

## 6. Anti-Grind Mechanisms

### ρ Determinism

**Purpose**: Prevent joiners from grinding PoP signatures to manipulate derived seeds.

**Mechanism**:
```rust
// 1. Server maintains ρ guard per (gid, parent_root)
struct RhoGuard {
    seen: BTreeMap<(Vec<u8>, [u8; 32]), BTreeSet<[u8; 32]>>,
    capacity: usize,
}

// 2. On each join, check ρ uniqueness
let key = (gid.to_vec(), parent_root);
if !rho_guard.record(key, rho_commit) {
    return Freeze(924, "msphf_rho_parity");
}

// 3. record() returns false if rho_commit already seen
impl RhoGuard {
    fn record(&mut self, key: (Vec<u8>, [u8; 32]), rho: [u8; 32]) -> bool {
        let set = self.seen.entry(key).or_insert_with(BTreeSet::new);
        if set.len() >= self.capacity {
            return false;  // Guard capacity exceeded
        }
        set.insert(rho)  // Returns false if already present
    }
}
```

**Rationale**: Since `rho := H_L("msphf/rho/der", [pop_sig, xk_hash])`, the joiner could theoretically generate many PoP signatures until they find one that produces a favorable `rho`. The guard prevents this by rejecting duplicate `rho_commit` values.

**Blueprint**: Alpha (0.1.0) §10 (Seed-binding), §13 (Anti-grind)

**Implementation**: [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

### SRX Completeness

**Purpose**: Prevent joiners from omitting witnesses to create invalid anchors.

**Mechanism**:
- Server recomputes `join_delta_root` from SRX `join_leaf_ids` and verifies match
- Server validates all non-membership witnesses have anchored adjacency
- Any missing/malformed witness → `Freeze(930, "srx_invalid")`

**Blueprint**: Alpha (0.1.0) §12.2 step 6 (SRX validation)

---

## 7. Concurrency Control

### Window Limits

**H_MAX** (Maximum heads):
- Prevents unbounded head proliferation
- Typical value: 16 (configurable)
- When exceeded: deterministic code `925` (`mh_window_full`)

**T_WINDOW** (Time-to-live):
- Automatically prunes stale heads
- Typical value: 120 seconds (configurable)
- Pruning occurs on every `accept_head` / `accept_merge` call

### Head Expiration

```rust
pub fn set_ttl(&mut self, ttl: Duration, now: Instant) {
    self.ttl = ttl;
    let ttl_bound = self.ttl;
    self.heads.retain(|_, records| {
        records.retain(|record| now.duration_since(record.accept_ts) <= ttl_bound);
        !records.is_empty()
    });
}
```

**Pruning strategy**: Lazy (on-demand during accept operations)

**Implementation**: [`crates/msphf-orchestrator/src/mhw.rs`](../../crates/msphf-orchestrator/src/mhw.rs)

### Race Conditions

**Scenario**: Two devices join simultaneously with the same parent root.

**Resolution**:
1. Both derive the same WID (deterministic from public fields)
2. Both generate different `we_epoch_id` (unique from `rho_commit` / `seed_commit`)
3. Server accepts both if `active_heads < h_max`
4. Later merge consolidates both heads

**No locking required**: Server processes sequentially; MHW state is single-threaded.

---

## 8. Window Management

### Query Operations

```rust
// Get active head count
pub fn active_heads(&self, wid: &[u8]) -> usize;

// Iterate all heads for a WID
pub fn iter_heads(&self, wid: &[u8]) -> impl Iterator<Item = &HeadRecord>;

// Find specific head by we_epoch_id
pub fn find_head(&self, wid: &[u8], we_epoch_id: &[u8; 32]) -> Option<&HeadRecord>;

// Check if head exists
pub fn contains(&self, wid: &[u8], we_epoch_id: &[u8; 32]) -> bool {
    self.find_head(wid, we_epoch_id).is_some()
}
```

**Implementation**: [`crates/msphf-orchestrator/src/mhw.rs`](../../crates/msphf-orchestrator/src/mhw.rs)

### Snapshot

```rust
pub fn snapshot(&self) -> Vec<(Vec<u8>, Vec<HeadRecord>)> {
    self.heads
        .iter()
        .map(|(wid, records)| (wid.clone(), records.clone()))
        .collect()
}
```

**Purpose**: Export full window state for telemetry/debugging.

**Implementation**: [`crates/msphf-orchestrator/src/mhw.rs`](../../crates/msphf-orchestrator/src/mhw.rs)

### Configuration

```rust
// Set maximum heads
pub fn set_h_max(&mut self, h_max: usize);

// Set TTL (prunes existing heads)
pub fn set_ttl(&mut self, ttl: Duration, now: Instant);

// Get current limits
pub fn h_max(&self) -> usize;
pub fn ttl(&self) -> Duration;
```

**Dynamic reconfiguration**: Supports runtime changes to `h_max` and `ttl`.

---

## Summary

The **Multi-Head Window (MHW)** enables concurrent join operations by maintaining time-bounded, capacity-limited head lists keyed by **WID**. The WID is deterministically derived from public header fields (gid, parent_root, seed_ctx_hash), ensuring server blindness while enabling efficient routing. Anti-grind mechanisms (ρ determinism, SRX completeness) prevent manipulation, and automatic head expiration (T_WINDOW) prevents stale state accumulation. Merge operations consolidate multiple heads by retiring specified `we_epoch_id` values and inserting a new merged head. The system supports up to **H_MAX** (default: 16) concurrent heads per parent root, with **T_WINDOW** (default: 120s) for automatic cleanup.

**Next**: [10 — Security Model](./10-security-model.md)
