# 07 — Server Acceptance Pipeline

**Blueprint:** Alpha (0.1.0) §12.2, §22, §23
**Normative Source:** [`../specs.md`](../specs.md)
**Implementation:** [`../../crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)

---

## 1. Scope

This chapter describes the acceptance path implemented in `accept/` for
`tswe/msphf-we/fs-hybrid`.

Key profile facts:

- Time-blind acceptance (no server wall-clock checks for FS progression).
- Merge-linearized SRX model.
- Closed-world header validation.
- Fail-fast proof commit before expensive proof verification.

---

## 2. Pipeline Order

## Step 0 — Canonical Decode + Maxima

- Decode canonical CBOR header.
- Reject malformed/unknown/duplicate keys (`907.1`).
- Enforce byte caps before heavy work:
  - `95 <= 8192`
  - `97 <= 262144` (with structural checks)
  - `146 <= 16384`
  - `161 <= 16384`
  - `122 <= configured srx_max_bytes` (min floor enforced)

## Step 1 — Structure / Presence / Mode

- Require FS fields: `139,141,142,143,146`.
- Require device-chain fields: `152,153`.
- Derive merge mode from merge-only keys (`130,131,132,133,134,135,136,138,144,145,148`).

### Join mode

- Must include join-only keys (`97,99,107,108,109`).
- Must exclude merge-only keys.
- Must exclude SRX-only keys (`121,122,160,161`).
- Must exclude legacy SRX keys (`120,123,124`).

### Merge mode

- Must exclude join-only keys (`97,107,108,109,170,171,172`).
- SRX symmetry:
  - required case: require all `121,122,160,161`
  - forbidden case: require all absent
- Legacy SRX keys (`120,123,124`) are rejected.

## Step 2 — Gates + FS Policy Version

- Enforce suite/algorithm allow-lists (`tswe_alg`, merkle suite, kbroad alg, proof mode, vrf id).
- Validate `fs_policy_version` from `139`.
- Legacy `140` handling:
  - if present: must be `uint`
  - must equal `139` after canonical conversion
  - otherwise `FREEZE_FS_POLICY_VERSION_UNSUPPORTED` (`944.6` mapping)

## Step 3 — FS Base + Device Chain + FLG

- Enforce fixed FS base: `143 == GroupState.fs_epoch_base_ts` (`945.0` on mismatch).
- Device-chain checks:
  - recompute `153 == H_L("fs/dev/chain/v2", [108,141,152,176,barrier_update_digest])`
  - verify `152` continuity from stored device state
- FLG checks against stored group/device counters:
  - global forward jump guard
  - first-device forward guard
  - per-device forward guard

## Step 4 — Join-Only PoP + KBROAD Structure

Join path performs:

- PoP verification (`107/108/109` and signature over `msphf/pop/msg`).
- KBROAD envelope validation only (shape/types/lengths/AEAD label).
- No decapsulation/decryption on acceptance path.

## Step 5 — Proof Commit + Proof Verification

- Always verify `125` first (fail-fast).
- Proof order is deterministic:
  1. CAPSS Smallwood (`146`)
  2. ZK-VRF (`95`) over `bind_fs`
  3. SRX Smallwood (`161`) when SRX applies
- `bind_fs` includes FS fields and appends `160` when SRX applies.

## Step 6 — SRX (Merge-Only, Linearized)

When SRX applies in merge mode:

- `121` must be `bstr32`, `122` must be `bstr`.
- Recompute/validate `srx_commit` from payload.
- Verify SRX relation consistency with roots and payload-derived context.
- Verifier sources `srx_root_sw_before` from durable group state; prover cannot choose it.

When SRX is forbidden:

- Any SRX-only key presence is `930`.

## Step 7 — Atomic Commit

On acceptance:

- Update per-device chain state (`last_commit=153`, `last_ec=141`).
- Advance group `A := max(A,141)`.
- If SRX applies, CAS-update durable `GroupState.srx_root_sw`:
  - require stored value equals verified `srx_root_sw_before`
  - then set `GroupState.srx_root_sw := 160`
  - CAS mismatch is `930` (concurrent SRX update)

---

## 3. Merge-Specific Rules

Merge acceptance also enforces:

- `mh_heads` canonical sorted/unique.
- Pivot parity checks (pivot lineage consistency).
- Rollup provenance replay checks.
- Checkpoint monotonicity and checkpoint-ec constraints.

---

## 4. Error Families

Common families in this pipeline:

- `907.1` malformed/unknown key/canonical CBOR failure
- `921` suite/structure/policy gate violations
- `923` proof commit/proof failures
- `925` window-full / replay outcomes
- `929` SRX required but incomplete
- `930` SRX invalid/forbidden/concurrent-SRX-CAS
- `934` suite/config/startup constraints
- `945-948` FS base/policy/device-chain/FLG failures

See full catalog: [`./12-error-reference.md`](./12-error-reference.md)

---

## 5. Code Pointers

- Shared stage helpers: [`../../crates/msphf-orchestrator/src/accept/stages.rs`](../../crates/msphf-orchestrator/src/accept/stages.rs)
- Join path: [`../../crates/msphf-orchestrator/src/accept/join.rs`](../../crates/msphf-orchestrator/src/accept/join.rs)
- Merge path: [`../../crates/msphf-orchestrator/src/accept/merge.rs`](../../crates/msphf-orchestrator/src/accept/merge.rs)
- Core acceptance orchestration: [`../../crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)
