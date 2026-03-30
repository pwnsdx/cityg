# 08 — Client Operations (Joiner + Merge Builder)

> [!IMPORTANT]
> This chapter is companion material, not the normative specification.
> For the current `tswe/msphf-we/fs-hybrid + prs-barrier` profile, the normative source is [`../specs.md`](../specs.md).
> Inline references below to `Alpha (0.1.0)` are historical blueprint citations only.
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and live code/tests.

**Historical blueprint reference:** Alpha (0.1.0) §10, §12.3, Annex I
**Normative Source:** [`../specs.md`](../specs.md)
**Implementation:** [`../../crates/cityg-client/src/lib.rs`](../../crates/cityg-client/src/lib.rs), [`../../crates/msphf-orchestrator/src/lib.rs`](../../crates/msphf-orchestrator/src/lib.rs)

---

## 1. Join Workflow

Client joiners build an anchor with:

1. Canonical roots (`110/111/112/113`).
2. PoP (`107/108/109`).
3. KBROAD envelope (`97`) + `hp_commit` (`99`).
4. FS headers (`139/141/142/143/146/152/153`).
5. Proof material (`95`, `116`, `119`, `125`).

Under unified merge-linearized SRX:

- Join anchors must not carry SRX-only keys (`121/122/160/161`).
- Join anchors must not carry legacy SRX keys (`120/123/124`).

---

## 2. Join Header Assembly (Aligned)

```rust
let mut header_map = BTreeMap::new();

// Core + commitments
header_map.insert(90, Value::Integer(31.into()));
header_map.insert(91, Value::Bytes(seed_ctx_hash.to_vec()));
header_map.insert(92, Value::Text("rpo-256/v1".to_string()));
header_map.insert(93, Value::Bytes(rho_commit.to_vec()));
header_map.insert(94, Value::Bytes(seed_bundle_commit.to_vec()));

// KBROAD + hp commit
header_map.insert(97, kbroad_envelope_value);
header_map.insert(98, Value::Text(params.msphf_crs_id.to_string()));
header_map.insert(99, Value::Bytes(hp_commit.to_vec()));
header_map.insert(104, Value::Text("ml-kem-768".to_string()));
header_map.insert(105, Value::Bytes(kbroad_pub.to_vec()));
header_map.insert(106, Value::Bytes(params.params_id.to_vec()));

// PoP
header_map.insert(107, Value::Text("ML-DSA-65".to_string()));
header_map.insert(108, Value::Bytes(pop_pk.to_vec()));
header_map.insert(109, Value::Bytes(pop_sig.to_vec()));

// Roots
header_map.insert(110, Value::Bytes(parent_root.to_vec()));
header_map.insert(111, Value::Bytes(join_delta_root.to_vec()));
header_map.insert(112, Value::Bytes(revoked_since_root.to_vec()));
header_map.insert(113, Value::Bytes(revoked_root.to_vec()));

// Proof suite + proofs
header_map.insert(95, Value::Bytes(vrf_proof_bytes));
header_map.insert(116, Value::Text(params.vrf_id.to_string()));
header_map.insert(119, Value::Text(params.proof_mode.to_string()));
header_map.insert(146, Value::Bytes(fs_capss_bytes));
header_map.insert(125, Value::Bytes(proofs_commit.to_vec()));

// FS / device chain
header_map.insert(139, Value::Integer(params.fs_policy_version.into()));
header_map.insert(141, Value::Integer(fs_ec.into()));
header_map.insert(142, Value::Bytes(fs_epoch_commit.to_vec()));
header_map.insert(143, Value::Integer(fs_epoch_base_ts.into()));
header_map.insert(152, Value::Bytes(fs_dev_prev_commit.to_vec()));
header_map.insert(153, Value::Bytes(fs_dev_commit.to_vec()));

// Legacy optional compatibility key (strict): if emitted, must be uint and equal to 139.
// header_map.insert(140, Value::Integer(params.fs_policy_version.into()));
```

---

## 3. Merge Workflow

Merge builders:

- Collect retired heads (`130`) and pivot metadata (`131-135`).
- Carry merge FS/checkpoint metadata (`138`, `144`, `145`, `148`) as required.
- Keep FS/device-chain continuity (`139/141/142/143/152/153`).

SRX behavior in merge mode:

- SRX required case: include all `121/122/160/161`.
- SRX forbidden case: include none of `121/122/160/161`.
- Never include legacy SRX keys (`120/123/124`).

`125` must commit to SRX proof material when present:

- without SRX: `H_L("msphf/proofs", [95,146])`
- with SRX: `H_L("msphf/proofs", [95,146,160,161])`

---

## 4. Receiver Side (Epoch Extraction)

Receivers validate accepted anchor material and derive epoch secrets from accepted
state. They do not need SRX on joins in this profile.

- Validate/parse anchor instance and bind tuple consistency.
- Recover/decrypt HP payload using local KBROAD material.
- Verify commitments and derive epoch key deterministically.

---

## 5. Do/Don’t Checklist

Do:

- Use canonical CBOR for all header data.
- Emit `139` as authoritative FS policy version.
- Keep `140` absent by default; if present, emit as equal `uint` only.
- Keep join anchors SRX-free.
- Keep merge SRX presence symmetric (all-or-none on `121/122/160/161`).

Don’t:

- Emit `140` as text/bytes.
- Emit legacy SRX keys `120/123/124`.
- Emit partial SRX sets in merge mode.

---

## 6. Code Pointers

- Join/merge generation: [`../../crates/msphf-orchestrator/src/lib.rs`](../../crates/msphf-orchestrator/src/lib.rs)
- Client bundle helpers: [`../../crates/cityg-client/src/lib.rs`](../../crates/cityg-client/src/lib.rs)
- Join/merge acceptance: [`../../crates/msphf-orchestrator/src/accept/`](../../crates/msphf-orchestrator/src/accept/)
