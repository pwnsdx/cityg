# City-G Fingerprints

City-G surfaces two complementary fingerprints that let members confirm they
see the same group state without exposing any plaintext:

| Name | Definition | When it changes | Purpose |
|------|------------|-----------------|---------|
| **Seed-context (regular) fingerprint** | `seed_ctx_hash` (header **91**) = `H_L("seedctx", ANCHOR_SEED_CTX)` where `ANCHOR_SEED_CTX` **includes** the canonical non-merge header fields (notably `{110–113, 98, 104–106, 139, 141, 142, 143, 152–153, 160 when SRX applies}`) and **excludes** merge-only `{130–136, 138, 144–148}` | **On most accepted heads.** It changes when epochs advance (`141/142`), when membership/policy/suite IDs change, when SRX applies (`160`), and—on join heads—when the device-chain steps (`152/153`). | Proves canonical state equivalence: both devices see the same roster, policy/suite IDs, FS base, and device-chain step. |
| **Epoch (FS) fingerprint** | `fs_fp := H_L("fs/fingerprint", [fs_policy_version (139), fs_ec (141), fs_epoch_commit (142), fs_epoch_base_ts (143)])` *(computed locally; not a protocol header)* | Every time the FS epoch advances or when the FS policy is re-keyed | Proves epoch/caps equivalence: devices are in lock-step on the current FS epoch. Device-agnostic (excludes 152/153). |

Both digests are 32 bytes. For human comparison, display at least 16 hex
characters (≈64 bits, e.g. `abcd-1234 ef56-7890 …`) or an equivalent Base32
string. Comparing 64 bits leaves a ~1 in 2⁶⁴ false-match chance while remaining
easy to read aloud; provide a “copy full value” affordance for the entire hash,
and recommend 32 hex characters (~128 bits) for higher-assurance checks.

---

## Seed-context (Regular) Fingerprint Details

* `ANCHOR_SEED_CTX` is the deterministic CBOR snapshot defined in §3 of
  `docs/protocol/03-data-structures.md`.
  * **Included keys:** membership roots (110–113), CRS/params/policy IDs (98,
    104–106), FS policy/counters (139, 141, 142, 143), device-chain commits
    (152–153), SRX shadow root (`hdr::HDR_SRX_ROOT_SW` = 160) when SRX applies,
    and the other canonical header fields.
* **Excluded keys:** merge-only telemetry (130–136, 138) and frontier hints
  (144–148). These volatile structures would change between siblings and are
  deliberately omitted.
* **Also excluded (construction order):** proof artifacts and their commit
  (`95 vrf_proof`, `146 smallwood`, `161 srx_smallwood`, `125 proofs_commit`);
  proofs are produced *after* seed binding and therefore MUST NOT feed
  `seed_ctx_hash (91)`.
  * **Policy-version note:** Under FS-Hybrid, `fs_policy_version` (139) carries
    the authoritative policy string; the legacy `policy_version` (140) applies
    only to non-FS profiles and MUST NOT collide.
* The server returns `seed_ctx_hash` with every accepted anchor and via
  `/v1/window` snapshots, so any device can compare it against peers.
* Window IDs use `WID := H_L("mhw/window", [gid, parent_root (110),
  seed_ctx_hash (91)])`, so matching `seed_ctx_hash` implies the same multi-head
  window context.
* Use case: out-of-band verification (“Read me the first 16 hex characters of
  the seed-context fingerprint”) to ensure structural parity.

---

## Epoch (FS) Fingerprint Details

```
fs_fp := H_L("fs/fingerprint", [
  fs_policy_version (139),
  fs_ec             (141),
  fs_epoch_commit   (142),
  fs_epoch_base_ts  (143)
])
```

* Rotates whenever `fs_ec` advances (minutes-grade; default `H=300` seconds) or
  when the FS policy (`fs_policy_version`, 139) is re-keyed. `fs_epoch_base_ts`
  (143) is an immutable genesis constant.
* Device-agnostic by design: it intentionally excludes
  `fs_dev_prev_commit`/`fs_dev_commit` (152/153), so two honest devices on the
  same epoch show the same digest even if their device-chain step differs.
* Field **146** is the Smallwood proof object (label `"msphf/smallwood/chal"`)
  and *not* a fingerprint; its bytes may differ for each anchor.
* Use case: ensure everyone has adopted the latest FS epoch/caps. If `fs_fp`
  differs, a client is lagging on epoch adoption.

---

## How to Obtain the Fingerprints

| Surface | Seed-context fingerprint | Epoch fingerprint |
|---------|-------------------------|-------------------|
| **GUI (`cityg-gui`)** | Displayed in the “Regular fingerprint” row (preview + copy). | Displayed in the “FS fingerprint” row; computed locally from fields 139/141/142/143 and shown alongside `fs_ec`. |
| **API** | Header field **91** or `/v1/window`. | Derive locally from a **join head** by hashing 139/141/142/143. For merges that omit 141/142, use the **pivot join** referenced via `130 mh_heads` / `131 pivot_weid`. *(UI helper; not a registered on-wire field.)* |
| **CLI / SDKs** | `cityg-client::ClientEpochBundle` exposes `hp_binding.seed_ctx_hash`. | The helper in `crates/cityg-gui/src/bin/join_leave.rs` (or four-field hash above) computes `fs_fp` for logging/A/B checks. |

When transmitting fingerprints verbally or via chat, compare at least 64 bits
(e.g., 16 hex characters or Base32 Crockford digits—case-insensitive and
designed to avoid `0/O` and `1/I`) and note which head (join vs merge) you’re
referencing. The GUI displays a 64-bit preview with an ellipsis and copies the
full 32-byte value on demand; use 32 hex characters (~128 bits) when you need
higher assurance.

---

## Comparison Workflow

> **Note.** If `seed_ctx_hash (91)` matches, `fs_fp` must also match because
> `91` already includes `139/141/142/143`. The workflow therefore checks the
> fast-moving epoch fingerprint first.

1. **Epoch fingerprint matches?**  
   If not, devices disagree on the current FS epoch/caps. Ask the lagging client
   to fetch and adopt newer heads or checkpoints; adoption is time-blind with
   respect to the server and follows each client’s local boundary counter per
   Annex H (derived from local monotonic + wall clocks), not any server clocks.

2. **Seed-context fingerprint matches?**  
   If `fs_fp` matches but `seed_ctx_hash` differs, the disagreement is
   structural (membership/policy/SRX/device-chain). Because merge-only fields
   are excluded from `ANCHOR_SEED_CTX`, merge heads SHOULD share the pivot’s
   `seed_ctx_hash`; City‑G copies the pivot value into the merge header to make
   that equality explicit. If another implementation recomputes instead, compare
   against the pivot (`131 pivot_weid`) and provenance (`132`), remembering that
   `148 fs_checkpoint_ec` is merge-only.

3. **Checkpointing context.**  
   Checkpoints set `fs_checkpoint_ec` (148) to the max epoch absorbed; clients
   adopt when their local counter reaches that value and their forward-leap caps
   allow it. Once every client advances to the same `fs_ec`, the epoch
   fingerprints align automatically.

4. **Advanced cross-checks.**  
   * `proofs_commit` (125) hashes the VRF proof (95), the Smallwood proof (146),
     and SRX payload commits—useful as a “proof bundle handle” for auditors.
   * Merge artefacts (`130 mh_heads`, `131 pivot_weid`, `132 rollup_provenance_commit`,
     `133 epoch_replay`, `148 fs_checkpoint_ec`) expose the history a
     merge consumed; power users can compare their `seed_ctx_hash`/`fs_fp`
     against those records when auditing rollups.
   * Parity reminder: header **93** (pivot parity / `rho_commit`) is inherited
     from the pivot join; matching it alongside `131/132/133/148` provides a
     quick sanity check.

---

## Implementation Notes

* Store the raw 32-byte digests and expose a copy-to-clipboard action so users
  can share the full value even if the UI shows a short preview.
* Compute `fs_fp` locally from the four fields above; do **not** treat header
  146 (Smallwood proof) as a fingerprint.
* When persisting sessions (e.g., in `cityg-gui`), store the seed-context
  fingerprint and recompute the epoch fingerprint from the persisted FS fields.
* Treat missing fingerprints as “unknown” and prompt the user to
  re-synchronize; do not display stale values without labeling them.
