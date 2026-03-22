# Data Structures & Wire Formats

**Specification:** Alpha (0.1.0)
**Normative Source:** [`../specs.md`](../specs.md)
**Implementation:** [`../../crates/msphf-orchestrator/src/hdr.rs`](../../crates/msphf-orchestrator/src/hdr.rs)

---

## 1. Canonical CBOR Requirements

All headers are deterministic CBOR maps with:

- Canonical RFC 8949 encoding.
- Unique keys (no duplicates).
- Closed-world key policy for this profile.
- Reject malformed type/shape before expensive proof work.

Unknown/duplicate/malformed keys map to `907.1` (`cbor_malformed`).

---

## 2. Header-Key Registry (Unified FS-Hybrid)

### 2.1 Join + Merge Core

| Key | Constant | Type | Notes |
|---|---|---|---|
| 90 | `HDR_TSWE_ALG` | uint | `31` |
| 91 | `HDR_SEED_CTX_HASH` | bstr32 | `H_L("seedctx", [ANCHOR_SEED_CTX])` |
| 92 | `HDR_MERKLE_SUITE` | tstr | `rpo-256/v1` |
| 93 | `HDR_RHO_COMMIT` | bstr32 | `H_L("msphf/kgen/rho", [rho_raw])` |
| 94 | `HDR_SEED_BUNDLE_COMMIT` | bstr32 | deterministic seed bundle commit |
| 95 | `HDR_VRF_PROOF` | bstr | ZK-VRF proof blob |
| 98 | `HDR_CRS_ID` | tstr/bstr | allow-listed by policy |
| 104 | `HDR_KBROAD_ALG` | tstr | `ml-kem-768` |
| 105 | `HDR_KBROAD_PUB` | bstr | ML-KEM-768 public key |
| 106 | `HDR_PARAMS_ID` | tstr/bstr | allow-listed by policy |
| 110 | `parent_root` | bstr32 | parent membership root |
| 111 | `join_delta_root` | bstr32 | resulting membership root |
| 112 | `revoked_since_prev_root` | bstr32 | delta revoked root |
| 113 | `HDR_REVOKED_ROOT` | bstr32 | cumulative revoked root |
| 116 | `HDR_VRF_ID` | tstr | proof suite id |
| 119 | `HDR_PROOF_MODE` | tstr | proof mode id |
| 125 | `HDR_PROOFS_COMMIT` | bstr32 | proof commit digest |

### 2.2 Join-Only Keys

| Key | Constant | Type | Notes |
|---|---|---|---|
| 97 | `HDR_HP_BYTES` | bstr/array | KBROAD envelope |
| 99 | `HDR_HP_COMMIT` | bstr32 | `H_L("msphf/hp/commit", [hp])` |
| 107 | `HDR_POP_ALG` | tstr | `ML-DSA-65` |
| 108 | `HDR_POP_PK` | bstr | ML-DSA-65 public key |
| 109 | `HDR_POP_SIG` | bstr | PoP signature |
| 170 | `HDR_BOOTSTRAP_ALG` | tstr | bootstrap only |
| 171 | `HDR_BOOTSTRAP_SIG` | bstr | bootstrap only |
| 172 | `HDR_BOOTSTRAP_PK` | bstr | bootstrap only |

### 2.3 FS + Device-Chain Keys (Required)

| Key | Constant | Type | Notes |
|---|---|---|---|
| 139 | `HDR_FS_POLICY_VERSION` | uint | authoritative FS policy version (legacy text/bytes may be normalized by compatibility code paths) |
| 141 | `HDR_FS_EC` | uint | FS epoch counter |
| 142 | `HDR_FS_EPOCH_COMMIT` | bstr32 | epoch commitment |
| 143 | `HDR_FS_EPOCH_BASE_TS` | uint64 | fixed group FS base timestamp |
| 146 | `HDR_FS_CAPSS` | bstr | CAPSS Smallwood transcript |
| 152 | `HDR_FS_DEV_PREV_COMMIT` | bstr32 | previous device-chain commit |
| 153 | `HDR_FS_DEV_COMMIT` | bstr32 | `H_L("fs/dev/chain/v2", [108,141,152,176,barrier_update_digest])` |

### 2.4 Merge-Only Keys

| Key | Constant |
|---|---|
| 130 | `HDR_MH_HEADS` |
| 131 | `HDR_ROLLUP_PIVOT_WEID` |
| 132 | `HDR_ROLLUP_PROVENANCE_COMMIT` |
| 133 | `HDR_ROLLUP_EPOCH_REPLAY` |
| 134 | `HDR_ROLLUP_VCK_COMMIT` |
| 135 | `HDR_MERGE_DELEGATION_SIG` |
| 136 | `HDR_KBROAD_REPLAY` |
| 138 | `HDR_ROLLUP_FS_MODE` |
| 144 | `HDR_FS_EVOLUTION_BOUNDARY` |
| 145 | `HDR_FS_PURGE_TIMES` |
| 148 | `HDR_FS_CHECKPOINT_EC` |

### 2.5 SRX Keys (Merge-Only Carve-Out)

SRX is merge-linearized under this profile:

- Join mode: SRX keys must be absent.
- Merge mode:
  - SRX required: all SRX-only keys must be present.
  - SRX forbidden: all SRX-only keys must be absent.

| Key | Constant | Type |
|---|---|---|
| 121 | `HDR_SRX_COMMIT` | bstr32 |
| 122 | `HDR_SRX_PAYLOAD` | bstr |
| 160 | `HDR_SRX_ROOT_SW` | bstr32 |
| 161 | `HDR_SRX_SMALLWOOD` | bstr |

Legacy SRX keys are forbidden in this profile:

- `120` (`HDR_SRX_MODE`)
- `123` (`HDR_SRX_HINT_COUNTS`)
- `124` (`HDR_SRX_HINT_SIZES`)

### 2.6 Legacy Policy Key (140)

`140` (`HDR_POLICY_VERSION`) is legacy-only under FS-hybrid:

- Optional for migration/interoperability checks only.
- If present, it must be `uint` and equal to `139` after canonical conversion.
- Non-`uint` or mismatch fails with `944.6` (`fs_policy_version_unsupported`).

---

## 3. Deterministic Commitments and Bind Tuples

### 3.1 Proofs Commit

`125` is always recomputed before expensive proof verification:

- No SRX: `H_L("msphf/proofs", [95, 146])`
- With SRX: `H_L("msphf/proofs", [95, 146, 160, 161])`

### 3.2 FS/VRF Bind Tuple (`bind_fs`)

ZK-VRF binding includes:

`[xk_hash, 93, 94, 98, 99, 106, 110, 111, 112, 113, proof_mode, fs_policy_version, vrf_id, fs_epoch_commit, fs_ec, fs_dev_prev_commit, fs_dev_commit, (160 when SRX applies)]`

### 3.3 VCK Preimage (`msphf/vck`)

`msphf/vck` binds:

`[xk_hash, seed_commit, rho_commit, hp_commit, crs_id, params_id, srx_commit_or_zero, proofs_commit_or_zero, proof_mode, vrf_id, fs_policy_version]`

---

## 4. ANCHOR_SEED_CTX (`91`)

`ANCHOR_SEED_CTX` is derived from the header after removing volatile/forbidden keys.

Inclusion/exclusion follows [`../../crates/anchor-seed/src/lib.rs`](../../crates/anchor-seed/src/lib.rs):

- Excludes seed/proof/materialization keys and PoP keys (`93`, `94`, `95`, `99`, `107-109`, proof suite keys).
- Excludes legacy SRX keys (`120-124`) and merge/bootstrap telemetry keys.
- Retains FS metadata and device-chain keys (`139`, `141`, `142`, `143`, `152`, `153`).
- Includes `160` when SRX applies, per unified-spec binding rules.

---

## 5. Size Limits

| Field | Limit |
|---|---|
| `95` (VRF proof) | `<= 8,192` bytes |
| `97` (KBROAD envelope) | `<= 262,144` bytes |
| `146` (CAPSS Smallwood) | `<= 16,384` bytes |
| `161` (SRX Smallwood) | `<= 16,384` bytes |
| `122` (SRX payload) | `<= 1,048,576` bytes |

---

## 6. Mode Summary

### Join Mode

- Must include join-only keys (`97`, `99`, `107-109`) plus FS/device keys.
- Must not include merge-only keys.
- Must not include SRX-only keys (`121`, `122`, `160`, `161`) or legacy SRX keys (`120`, `123`, `124`).

### Merge Mode

- Must include merge-only keys and FS/device keys.
- Must not include join-only keys.
- SRX keys are conditional and symmetric:
  - required together when SRX applies,
  - forbidden together when SRX is not required.

---

## 7. Implementation Pointers

- Header constants: [`../../crates/msphf-orchestrator/src/hdr.rs`](../../crates/msphf-orchestrator/src/hdr.rs)
- Presence/gate checks: [`../../crates/msphf-orchestrator/src/accept/stages.rs`](../../crates/msphf-orchestrator/src/accept/stages.rs)
- Acceptance orchestration: [`../../crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs)
