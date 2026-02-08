# City‑G Protocol Specifications

**Profile identifier:** `tswe/msphf‑we/fs‑hybrid`
**Date:** 2025‑11‑10
**Status:** Alpha (0.1.0)

### Conformance language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as in **RFC 2119** and **RFC 8174** when, and only when, they appear in all capitals.

---

## Contents

1. Motivation & Fit *(informative)*
2. Delivered Capabilities *(informative)*
3. Threat Model *(informative)*
4. Public Instance & NP Language *(normative)*
5. Canonical Merkle Witnesses *(normative)*
6. Crypto, Domains, and Labels *(normative)*
7. Primitive API *(normative)*
8. ME‑OR with Forward‑Evolving Secrets & **Smallwood** *(normative)*
9. Instantiations *(normative; σ‑Merkle OPTIONAL)*
10. Seed‑Binding & Construction Order *(normative)*
11. ZK‑VRF (FS Bind Context) *(normative)*
12. Header Keys, SRX, Size Limits, Acceptance *(normative; **time‑blind + auto‑FLG**)*
13. Epoch Routing; Client Autonomic Evolution & Adoption *(normative)*
14. Offline Decryption Window *(normative)*
15. Security Properties *(informative)*
16. Error Semantics & Codes *(normative)*
17. Implementation Guidance *(normative)*
18. Benchmarks & Budgets *(informative)*
19. Known‑Answer Tests (KATs) *(normative)*

**Merges & Checkpoints (integrated, normative)**
20. Goals & Invariants (**FS‑only**, time‑blind)
21. Merge‑Only Fields & Determinism
22. SRX Carve‑Out on Merges
23. Acceptance Deltas (Merge Mode; time‑blind)
24. Client Behavior & FS‑Equivalence
25. Scheduling & Sizing (incl. adaptive trigger)
26. Acceptance Patch‑Set & Test Plan

**Annexes**
A. Canonical CBOR & Hashes *(normative)*
B. rpo‑256/v1 *(normative)*
C. RLWE‑HPS Parameters *(normative)*
D. `MSPHF_HP` & KBROAD *(normative; transport & derivations)*
E. Label & Field Registry *(normative)*
F. **SRX/Smallwood‑v1 (ZK)** *(normative; ROM‑sound)*
G. Bootstrap & Genesis FS Base *(normative)*
H. Local Boundary Counter (Time‑Grid, time‑blind) *(normative)*
J. τₑ Caching & Offline Decryption *(normative)*
L. **Smallwood** *(normative)*
V. ZK‑VRF (FS Bind) *(normative)*
M. MHW & Metadata Surface *(normative)*
N. Suite & Policy Journal *(normative; minutes‑grade presets; synthesized caps)*
I. Implementation Binding (Server/Client) *(normative)*
**Q. Membership Representation & Cryptographic Verification** *(informative)*
R. Formalization Plan *(informative)*
P. Personal‑Inbox (Singleton‑Group) Pattern *(informative)*
X. MLS Mapping & Why City‑G Avoids KeyPackage Reuse *(informative)*
Z. System‑Level Constraints *(informative)*

> **Editorial note (unification):** This document integrates the full protocol, SRX, MHW, and **mandatory** FS‑Hybrid (time‑blind) features. Merge/rollup semantics are updated to the **FS‑purge** model (no `kbroad_replay` on merges). HP/KBROAD transport details from the original core spec are retained intact (nonces/salts/AAD).

---

## 1) Motivation & Fit *(informative)*

City‑G provides publisher‑blind E2EE for massive groups. In v0.1.0 (alpha), the profile delivers **minutes‑grade FS** without trusting server clocks, **synthesizes Forward‑Leap Guard (FLG) caps** from policy (eliminating deadlock‑inducing misconfig), and adds an **adaptive, time‑blind checkpoint trigger** to keep merges small under bursty load. Proof verification order is optimized to **fail fast**, presets make the effective FS window explicit, and **SRX uses Smallwood ZK** so revocation deltas need not be revealed on wire. 

---

## 2) Delivered Capabilities *(informative)*

* **Minutes‑grade FS** (`H` seconds; 5 min typical).
* **Time‑blind** acceptance/checkpoints (no server wall clock).
* **Publisher‑blindness** (server never decrypts KBROAD).
* **Auto‑synthesized FLG caps** (`W` + slack) with fail‑fast invariants.
* **Adaptive checkpoints** (time‑blind).
* **DoS‑hardened** (FLG + bounded queues + early proof abort).
* **Offline‑friendly** (τₑ cache bounds exposure).
* **Deterministic acceptance** at scale (MHW concurrency; canonicality).
* **SRX privacy by default** with **Smallwood** (ROM‑sound ZK; compact proofs in the ~9–15.5 KB band at 128‑bit security when tuned via arity/γ_MT).  

---

## 3) Threat Model *(informative)*

Adversary controls networks/publishers; excluded devices may collude; devices may be compromised; adversary is PQ‑capable; **store‑now‑decrypt‑later** in scope; DoS/grinding in scope. Security goals: confidentiality of `hp`/`Y*`/`E_k`; **time‑blind FS**; set‑relation correctness; liveness; publisher‑blindness. Assumptions: **ML‑KEM‑768**, **ML‑DSA‑65**, **rpo‑256**, **BLAKE3/HKDF‑BLAKE3**, **chacha20‑poly1305**, **ZK‑VRF in QROM**, **Smallwood‑based FS proof in ROM**, and **SRX/Smallwood‑v1 in ROM** (Smallwood‑ARK straightline‑extractable in the Random‑Oracle Model). The acceptance server is assumed **keyless for KBROAD** (no `kbroad_sk`, recovered `K_HP`, or `hp_k_bytes` provisioning); if this assumption is violated, publisher‑blindness is out of scope.

---

## 4) Public Instance & NP Language *(normative)*

The public language is `MEM ⊕ NONMEM`. FS parameters (`H`, `T_base`) are public and appear in `X_k`.
`xk_hash := H_L("msphf/xk",[X_k])` where `X_k` is a canonical CBOR data item.

---

## 5) Canonical Merkle Witnesses *(normative)*

Witnesses are canonical; depth ≤ 64; **CanonicalInterval** with anchored adjacency; deterministic error mapping at acceptance.

---

## 6) Crypto, Domains, and Labels *(normative)*

* All digests: 32 B.
* Domain‑sep hash: `H_L(label,args[]) := BLAKE3("city-g|" || ASCII(label) || 0x00 || CBOR_det(args[])) → 32 B`.
* KDFs: HKDF‑BLAKE3 (defined below).
* Set‑hash: `rpo‑256/v1`.
* AEAD: `chacha20‑poly1305`.
* FS labels include: `"fs/epoch/salt"`, `"fs/epoch/sk_salt"`, `"fs/kfs/salt"`, `"fs/epoch/commit"`, `"fs/timegrid/base"`, `"fs/dev/chain"`.
* WID label: `"mhw/window"`.

**HKDF‑BLAKE3 definition (normative).**

```text
Extract: PRK := BLAKE3_keyed(salt_32, IKM)
Expand : OKM_i := BLAKE3_keyed(PRK, info || counter_i), counter_i in {0x01,0x02,...}
```

For this profile, all specified invocations use `L=32` and therefore a single block (`i=1`).
`salt_32` is a 32‑byte value (typically from `H_L(...)`); `info` is byte-string domain separated and profile scoped.
`BLAKE3_keyed(k, m)` denotes BLAKE3 keyed-hash mode with 32-byte output.
`counter_i` is a single byte (`0x01`, `0x02`, ...).
Requests for `L != 32` are outside this profile and MUST be rejected as suite/config mismatch.

---

## 7) Primitive API *(normative)*

Devices compute `Y*` via ME‑OR using an **epoch secret** from a forward‑evolving key `K_fs^t`.
`E_k := H_epoch(X_k, Y*)` is **local**; the server remains blind to `hp`/`Y*`/`E_k`.

---

## 8) ME‑OR with Forward‑Evolving Secrets & **Smallwood** *(normative)*

**Epoch secret & commit**

```text
epoch_sk := HKDF‑BLAKE3(
  ikm  = K_fs^t,
  salt = H_L("fs/epoch/sk_salt",[weid, fs_ec=t]),
  info = "city-g|fs/epoch/sk|v1", L=32)

τ_e := HKDF‑BLAKE3(
  ikm  = K_fs^t,
  salt = H_L("fs/epoch/salt",[weid, t]),
  info = "city-g|fs/epoch/tau|v1", L=32)

fs_epoch_commit := H_L("fs/epoch/commit",[epoch_sk])
```

**Evolution (local)**

```text
K_fs^(t+1) := HKDF‑BLAKE3(
  ikm  = K_fs^t,
  salt = H_L("fs/kfs/salt",[weid]),
  info = "city-g|fs/kfs/v1" || to_le_bytes_u64(t+1), L=32)
fs_ec := t+1
zeroize(K_fs^t)
```

**Epoch lifecycle (normative).**

* To construct an anchor carrying `141 = t`, the device MUST derive `epoch_sk(t)` and `τ_e(t)` from `K_fs^t`.
* Devices MUST evolve from `K_fs^t` to `K_fs^(t+1)` when the local epoch boundary advances (`t -> t+1`) per Annex H, and MUST zeroize `K_fs^t` after evolution.
* `141` is an epoch index, not a total ordering key; cross-device anchors with equal `141` are unordered unless additional sequencing is applied.

**Smallwood** (Annex L) binds `epoch_sk`/`fs_epoch_commit` to `99/xk_hash` in zero‑knowledge; verifier learns neither `hp` nor τₑ. *(Knowledge soundness in ROM.)* 

---

## 9) Instantiations *(normative; σ‑Merkle OPTIONAL)*

Default **RLWE‑HPS** suite **A1**; **σ‑Merkle** MAY be enabled via allow‑list. Proof binds the public tuple:

```text
[xk_hash,93,94,98,99,106,110,111,112,113,
 proof_mode, fs_policy_version /*139*/, meor_vrf_id,
 fs_epoch_commit, fs_ec, fs_dev_prev_commit, fs_dev_commit]
```

---

## 10) Seed‑Binding & Construction Order *(normative)*

```text
ρ := H_L("msphf/rho/der",[pop_sig, xk_hash])
93 := H_L("msphf/kgen/rho",[ρ])
seed_DRBG := H_L("msphf/drbg",[seed_commit, ρ, xk_hash, 91])
```

**Order:** PoP → ρ → 93/94 → DRBG → KGen → masks → 99 → **Smallwood** → ZK‑VRF → **SRX/Smallwood‑v1**.

---

## 11) ZK‑VRF (FS Bind Context) *(normative)*

`bind_fs := CBOR_det([ xk_hash,93,94,98,99,106,110,111,112,113, proof_mode, fs_policy_version /*139*/, meor_vrf_id, fs_epoch_commit, fs_ec, fs_dev_prev_commit, fs_dev_commit ])`.
**When SRX applies**, include the SRX shadow root:

```text
bind_fs := CBOR_det([...above..., srx_root_sw /*160*/])
```

Legacy key `140 policy_version` MUST NOT be used for bind tuples in this profile.

The VRF is **output‑hiding**; the server learns no message secrets.

---

## 12) Header Keys, SRX, Size Limits, Acceptance *(normative; **time‑blind + auto‑FLG**)*

### 12.0 Header‑Key Registry (join; **REQUIRED**)

**Core (join & merge):**
`90,91,92,93,94,95,96,97,98,99,104,105,106,107,108,109,110,111,112,113,116,119,120,121,122,123,124,125,160,161`.

**Reserved (legacy pre‑FS transcript):**
`118 proofs_blob:bstr` (MUST NOT appear under `tswe/msphf-we/fs-hybrid`; retained for interoperability notes).

**FS fields (join; **REQUIRED**):**
`139 fs_policy_version:uint`, `141 fs_ec:uint`, `142 fs_epoch_commit:bstr32`, `143 fs_epoch_base_ts:uint64`, `146 smallwood:bstr`.
Key `140` remains legacy `policy_version` (non‑FS profiles). Under this profile, `140` is OPTIONAL only for migration and, if present, MUST be `uint` and MUST equal `139`; mismatch → `944.6`.

**Device‑chain fields (join; **REQUIRED**):**
`152 fs_dev_prev_commit:bstr32`, `153 fs_dev_commit:bstr32`, with
`fs_dev_commit := H_L("fs/dev/chain",[108 /*device pk*/, 141 /*fs_ec*/, 152])`.

**SRX (Smallwood) fields (when SRX applies; **REQUIRED**):**
`160 srx_root_sw:bstr32`, `161 srx_smallwood:bstr`.

**Proof material & commits:**
`95 vrf_proof:bstr`, `146 smallwood:bstr`,
`125 proofs_commit:bstr32 := H_L("msphf/proofs",[95,146,(160,161 if present)])`.

**Closed-world key policy (REQUIRED):** headers using keys outside this profile registry (plus merge-only keys in §21 when in merge mode) MUST be rejected with `907.1`.

**Maxima:** `|97|≤262144`, `|95|≤8192`, `|146|≤16384`, `|161|≤16384`, `|122|≤1048576`.
*(CAPSS reports ~9–15.5 KB proofs at 128‑bit security for Anemoi‑family instances; a 16 KB cap provides headroom.)* 

**ANCHOR_SEED_CTX for `91` (normative):** include FS keys **139,141,142,143**, device‑chain **152–153**, and **160** when SRX applies; exclude **merge‑only** keys `130–136, 138, 144–148`.
*(Supersedes the previous exclusion list by adding FS+device‑chain, the SRX shadow root, and widening merge exclusions.)*

### 12.1 Algorithm & Policy Gates *(auto‑synthesis & fail‑fast)*

At startup and on policy change:

```text
W := ceil(checkpoint_interval / H)             // REQUIRED
D_anchor_max := W + S_anchor                   // REQUIRED
D_first_device := W + S_first                  // REQUIRED
D_device_max := W + S_device                   // REQUIRED
```

**Startup invariants (REQUIRED):**

1. `H > 0`. 2) `checkpoint_interval ≥ H`.
2. `D_anchor_max ≥ W` and `D_first_device ≥ W`.
   Fail → **do not** admit joins; raise **`948.0 fs_policy_window_incompatible`**.

### 12.2 Acceptance Pipeline *(publisher‑blind, **time‑blind**, DoS‑hardened)*

Maintain `A := GroupState.last_accepted_ec` (monotone; init: `last_checkpoint_ec`).

0. **Pre‑filters & maxima** — canonical CBOR, no duplicate keys, no unknown keys, respect size limits.
1. **Structure/presence** — require FS (`139,141,142,143,146`) and device‑chain (`152–153`) fields; **if SRX applies**, require `160,161`.
2. **Gates** — suite & `fs_policy_version` MUST be allow‑listed (Annex N).

**(2a) FS base constant (join & merge; REQUIRED):**
Fetch canonical `T_base := GroupState.fs_epoch_base_ts` (immutable, Annex G).
Require `header[143] == T_base`; else **`945.0 fs_base_mismatch`**.
**No server clocks** may be consulted.

**(2b) Device‑chain integrity (REQUIRED):**
Lookup `(stored_last_commit, stored_last_ec)` by device key `108`.

* New device: `152 == ZERO`.
* Known device: `152 == stored_last_commit` **and** `141 ≥ stored_last_ec`.
  Violation → **`947.0 fs_dev_chain_break`**.
* For both cases: `153 == H_L("fs/dev/chain",[108,141,152])`.
  Violation → **`947.2 fs_dev_chain_bind_mismatch`**.

**(2c) Forward‑Leap Guards (REQUIRED; derived caps):**

* **Per‑device (known):** `141 ≤ stored_last_ec + D_device_max` → else **`947.4 fs_forward_jump_device`**.
* **First‑anchor (new device):** `141 ≤ A + D_first_device` → else **`947.5 fs_forward_jump_first`**.
* **Global (all joins):** `141 ≤ A + D_anchor_max` → else **`947.6 fs_forward_jump_group`**.

> **Ordering.** Accepted `fs_ec = t+1` cannot precede `t`; within an epoch ciphertexts are unordered. Combine `fs_ec` with per‑device sequence if total order is required.

3. **Proof commit & proofs (REQUIRED; fail‑fast):**
   1. Verify `125 == H_L("msphf/proofs",[95,146,(160,161 if present)])` **before** expensive proof verification.
   2. Verify proofs in order: **Smallwood (FS)** → **ZK‑VRF** (bind_fs, include `160` if present) → **SRX/Smallwood‑v1** (Annex F, if SRX applies).
4. **Defense‑in‑depth** — cross‑field binds across `93/94/98/99/106/110–113/116/139/141/142/143/152/153/(160 if present)`.
5. **Atomic commit (REQUIRED):**

```text
DeviceState[(gid, device_pk)] := (last_commit := 153, last_ec := 141)
A := max(A, 141)
```

Atomicity failure → no ack/visibility. Persist `last_checkpoint_ec`, `last_accepted_ec (A)`, and per‑device map.

### 12.3 HP Transport (KBROAD only; Parent‑EID forbidden) *(normative)*

**Transport shape (KBROAD_V1):**
`["kbroad-v1", ct_kem:bstr, wrap:bstr, C_hp:bstr, "chacha20-poly1305"]`.

**Derivations (joiners):**

```text
KEM.Encap(kbroad_pub) → (ct_kem, ss)
hp_commit := header[99]  // raw bstr32 bytes
KEK := HKDF‑BLAKE3(ss,  salt=H_L("hp/kek/salt",[xk_hash]),
                   info="city-g|hp/kek/v1"||hp_commit,  L=32)
K_HP := random(32)       // MUST be fresh per KBROAD envelope
wrap := AEAD_chacha20poly1305(KEK, 
         nonce=H_L("hp/kek/nonce",[xk_hash,hp_commit])[0..11], aad=hp_commit, pt=K_HP)
C_hp := AEAD_chacha20poly1305(K_HP, 
         nonce=H_L("hp/nonce",[xk_hash,hp_commit])[0..11], aad=hp_commit, pt=hp_k_bytes)
```

`aad` is the raw 32-byte `hp_commit` value (field `99`), not the integer key ID.
Deterministic nonces are safe only under one-time key usage (`KEK` from fresh KEM encapsulation and fresh `K_HP` per envelope).
`random(32)` MUST be generated by a CSPRNG suitable for key generation.

**Publisher‑blindness guardrails:**
* *(normative)* Servers MUST NOT be provisioned with any secret (e.g., `kbroad_sk`, recovered `K_HP`, or `hp_k_bytes`) that would allow recovery of `K_HP`/`hp`/`Y*`, and MUST NOT invoke KEM decapsulation on `ct_kem` or AEAD decryption on `wrap`/`C_hp`.
* *(informative)* Because conforming servers have neither the secret material nor the code path above, they therefore cannot decrypt KBROAD or learn `hp`/`Y*`. See Annex D for mirrored constraints.

> **Note (informative).** Group membership is not a decryption gate: honest devices derive `Y*` via the **projected** hash and a witness, while anyone who learns `K_HP`/`hp_k_bytes` could run the **full** hash (no witness needed) on the public instance and recover `Y*`. Preventing provisioning/decapsulation is therefore mandatory to preserve publisher‑blindness.

Parent‑EID and non‑KBROAD envelopes are **FORBIDDEN**.

---

## 13) Epoch Routing; Client Autonomic Evolution & Adoption *(normative)*

**WID:** `WID := H_L("mhw/window",[gid, parent_root(110), 91])`.
**Autonomic evolution (REQUIRED).** Clients evolve at local boundaries per Annex H using a **monotonic** clock, zeroizing old `K_fs` and incrementing `fs_ec`.
**Adoption (REQUIRED).** Let `ec := ec_local(now)`. Enforce device‑chain monotonicity; apply local forward/back caps; validate proofs; decrypt if current or τₑ‑cached (Annex J). **Checkpoint adoption:** when `ec ≥ 148` and within `D_ckpt_client_max`; otherwise defer. **Queues:** bound per‑device and global pending.

---

## 14) Offline Decryption Window *(normative)*

Pre‑boundary epochs decrypt **only** via cached τₑ (Annex J). Misses are **irrecoverable**.
**Effective FS bound:** `FS_window = max(H, tau_cache_retention)`.

---

## 15) Security Properties *(informative)*

* Server cannot enlarge FS window (acceptance time‑blind; clients use local monotone counters + τₑ cache bounds).
* DoS‑hardened: FLG caps, early proof abort.
* Rollback/replay prevented by per‑device chains.
* Checkpoints are time‑blind; no backdating; `148 == max(fs_ec)` across absorbed heads.
* WID partitions concurrency via public roots/seed context only—no `hp`/`Y*`/`E_k` leakage.
* **SRX privacy by default:** SRX correctness is proven via **Smallwood ZK** (ROM) without revealing changed leaves on wire. 
* **Liveness tradeoff (time‑blind FLG):** if no anchor is accepted for more than `D_anchor_max` epochs, honest devices may be blocked by group forward caps until recovery logic or operator action advances `A`. Deployments SHOULD keep at least one heartbeat publisher active per group.

---

## 16) Error Semantics & Codes *(normative)*

**Action model (normative).**

* `REJECT(code)`: reject this input, do not mutate acceptance state, continue processing later inputs.
* `DROP`: ignore without a structured code (rate-limit/anti-spam path).
* `QUARANTINE(device_pk, code)`: optional operational policy; not required by this profile.
* `FREEZE(group, code)`: reserved for authenticated, persistent state-corruption signals.

All numeric codes listed below are `REJECT(code)` outcomes unless explicitly marked otherwise.
Implementations MAY keep the historical term “freeze code” for the numeric code while preserving these per-message semantics.

**FS‑specific / time‑blind:**

* `945.0 fs_base_mismatch`
* `947.0 fs_dev_chain_break`
* `947.1 fs_checkpoint_backdate`
* `947.2 fs_dev_chain_bind_mismatch`
* `947.3 fs_checkpoint_monotonicity`
* `947.4 fs_forward_jump_device`
* `947.5 fs_forward_jump_first`
* `947.6 fs_forward_jump_group`
* `948.0 fs_policy_window_incompatible`
* `944.1 fs_join_missing`
* `944.2 smallwood_invalid`
* `944.3 vrf_bind_fs_mismatch`
* `944.31 kbroad_present_in_fspurge`
* `944.4 fspurge_before_grace`
* `944.6 fs_policy_version_unsupported`

**General/core (joins/SRX/canonicality):**
`907.1` malformed CBOR/unknown key/duplicate key; `907.2/907.21/907.5/907.6` path/canonicality/set conflicts;
`907.3` leaf_bind_mismatch;
`921` msphf_crs_untrusted (incl. parent_eid_forbidden, pop_invalid);
`922` msphf_seedctx_mismatch;
`923` proof_invalid (smallwood/vrf);
`924` msphf_rho_parity;
`925` mh_window_full;
`927` mh_heads_invalid;
`928` epochid_mismatch;
`929` srx_required;
`930` srx_invalid;
`931/932/934` bootstrap/suite errors.

---

## 17) Implementation Guidance *(normative)*

* **Atomicity (REQUIRED):** acceptance + state update commit atomically; else no ack/visibility.
* **Crash recovery (REQUIRED):** rebuild `last_checkpoint_ec`, `last_accepted_ec (A)`, and `DeviceState` **before** admitting joins; freeze inputs while rehydrating.
* **No server time:** FS decisions MUST NOT consult clocks.
* **Proof path (REQUIRED):** verify `125` first, then **Smallwood (FS) → VRF → SRX/Smallwood‑v1**; keep SRX last so malformed traffic fails before the heaviest SRX checks.
* **τₑ cache:** encrypt at rest; wipe on eviction; purge per Annex J.
* **Policy changes:** recompute `W` & derived `D_*` immediately; adaptive checkpoint logic uses the **current** `W`.
* **AEAD interop/side‑channels:** fix AEAD to `chacha20‑poly1305`; constant‑time ops; no secret‑dependent indexing.
* **SRX tuning:** verification cost/size are tuned via **Merkle arity** (higher near the top) and **γ_MT** trimmed paths per CAPSS. 

---

## 18) Benchmarks & Budgets *(informative)*

Per‑join on mobile (typical): **Smallwood (FS)** ≲ ~10 ms; **ZK‑VRF** ≲ ~6 ms.
**SRX/Smallwood‑v1**: proofs typically **~9–15.5 KB** at 128‑bit security for Anemoi‑family instances when tuned via higher arity near the root + `γ_MT` path trimming; set `|161|≤16 KB`. 
State: ~64 B per active device; group state maintains two counters.

---

## 19) Known‑Answer Tests (KATs) *(normative)*

* **Device chain:** forward ok / break (`947.0`) / bind mismatch (`947.2`).
* **FLG (group keyed to `A`):** device jump (`947.4`), first‑anchor jump (`947.5`), group jump (`947.6`).
* **Checkpoint rules:** max‑rule ok; backdate (`947.1`); monotonicity (`947.3`).
* **Policy synthesis:** `H=300`, `checkpoint_interval=3600` ⇒ `W=12`, `D_anchor_max=D_first_device=12` when `S_anchor=S_first=0`.
* **Adaptive checkpoint:** publish when `A − last_checkpoint_ec ≥ W` (using **current** `W`) or head count ≥ `K`.
* **τₑ cache:** hit/miss; at‑rest encryption; checkpoint purge.
* **SRX/Smallwood‑v1:**
  – Missing `160/161` when SRX is required → `929`.
  – `125` mismatch when `160/161` present → `923`.
  – VRF bind mismatch (tamper `160`) → `944.3`.
  – Invalid SRX proof → `930`.
* **Publisher‑blindness negative:** Supplying `kbroad_sk` (or any KBROAD private material) in server config MUST fail at startup with `934`.

---

# Merges & Checkpoints — Time‑Blind (Normative)

## 20) Goals & Invariants (**FS‑only**)

Maintain publisher‑blindness and parity (`93` inherited from pivot). **No `kbroad_replay`.** Checkpoints are **time‑blind**; server applies **no forward caps** to checkpoints (clients keep adoption caps).

## 21) Merge‑Only Fields & Determinism *(normative)*

Merge‑only keys (excluded from `ANCHOR_SEED_CTX`): `130–136, 138, 144–148`.

* `130 mh_heads` — sorted unique `weid[]` (exist‑now enforced).
* `131 pivot_weid` — **REQUIRED**; must be in `130`.
* `132 rollup_provenance_commit` — **REQUIRED**:
  `H_L("msphf/rollup/prov",[[weid,vck,xk_hash],…])`.
* `133 epoch_replay` — **REQUIRED**: `[[weid,xk_hash,[110,111,112,113],is_join],…]`.
* `134 vck_rollup_commit` — OPTIONAL.
* `135 merge_delegation_sig` — OPTIONAL.
* `136 kbroad_replay` — **FORBIDDEN**.
* `138 rollup_fs_mode` — **REQUIRED** literal `"fs-purge"`.
* `144 fs_evolution_boundary` — **REQUIRED** `true`.
* `145 fs_purge_times` — OPTIONAL liveness metadata.
* `148 fs_checkpoint_ec` — **REQUIRED**.

Arrays (132/133/134) are canonical CBOR, sorted by `weid`, no duplicates.

## 22) SRX Carve‑Out on Merges *(normative)*

**SRX is REQUIRED** iff revocation roots differ from the pivot (`112` or `113` differ); otherwise SRX is **FORBIDDEN**.
When SRX is required, the merge MUST carry `160 srx_root_sw` and `161 srx_smallwood` and satisfy Annex F.

## 23) Acceptance Deltas (Merge Mode; time‑blind) *(normative)*

* **FS base:** `143 == T_base` (else **`945.0`**).
* **Parity & mode:** `93` equals pivot; `138 == "fs-purge"`; absence of `136` (else **`944.31`**).
* **Time‑blind checkpoint rule:**

```text
max_ec := max( fs_ec(h) for h in mh_heads )
require 148 == max_ec                        // 947.1
require 148 ≥ GroupState.last_checkpoint_ec  // 947.3
require 148 ≤ GroupState.last_accepted_ec    // implied by definition of max_ec
```

* **SRX/Smallwood‑v1 (if required):** verify `161` under the Annex F statement (including `srx_bridge_ctx` derived from `110–113`, `121`, `122`, and `160`); `125` must include `160/161`.
* **Atomic commit:** persist merge and set `last_checkpoint_ec := 148`.

## 24) Client Behavior & FS‑Equivalence *(normative)*

Clients adopt the checkpoint when the local counter reaches `148` and the forward adoption cap allows it (`D_ckpt_client_max`). Consuming only the checkpoint yields the same **latest** `E_k` as raw replay; **no `kbroad_replay`** is involved.

## 25) Scheduling & Sizing *(normative; adaptive trigger)*

**Option A (lock‑step):** `checkpoint_interval = H` (`W=1`).
**Option B (batched):** `checkpoint_interval = k·H`, `k≥2`. Auto‑synthesis ensures `D_first_device ≥ k` and `D_anchor_max ≥ k`.

**Adaptive trigger (SHOULD):** publish when either

1. `A − last_checkpoint_ec ≥ W_current(policy)`, or
2. `|mh_heads| ≥ K` (head‑count threshold).
   Prefer (1) for predictability.

## 26) Acceptance Patch‑Set & Test Plan *(normative)*

Acceptance integrates: canonicality, parity, SRX carve‑out, provenance recompute, **group‑FLG keyed to `A`**, **auto‑synthesized caps**, and **adaptive checkpoint** tests per § 19.

---

## Annex A — Canonical CBOR & Hashes *(normative)*

RFC 8949 canonical CBOR; duplicated keys rejected.
`H_L(label,args[]) := BLAKE3("city-g|" || ASCII(label) || 0x00 || CBOR_det(args[])) → 32 B`.

---

## Annex B — rpo‑256/v1 *(normative)*

Canonical set‑hash used to ensure completeness/dedup independent of element order for set‑like fields.

---

## Annex C — RLWE‑HPS Parameters *(normative)*

Use the **A1** parameter pack of the RLWE‑HPS suite; constants are taken from the suite registry (allow‑list in Annex N).

---

## Annex D — `MSPHF_HP` & KBROAD *(normative; transport & derivations)*

```
MSPHF_HP := [0:uint.eq1, 1:hp_A:bstr, 2:hp_B:bstr, 3:M_A:32B, 4:M_B:32B, 5:params_id:32B].
KBROAD_V1 := ["kbroad-v1", ct_kem:bstr, wrap:bstr, C_hp:bstr, "chacha20-poly1305"].
```

Transport derivations/forbidden Parent‑EID as in § 12.3.
**Publisher‑blindness guardrails:** *(normative)* servers MUST NOT be provisioned with KBROAD private material nor call KEM decapsulation/AEAD decryption on KBROAD artifacts; *(informative)* consequently, conforming deployments cannot decrypt KBROAD or learn `hp`/`Y*`.

---

## Annex E — Label & Field Registry *(normative)*

Labels include `"msphf/xk"`, `"hp/kek/salt"`, `"hp/kek/nonce"`, `"hp/nonce"`, `"msphf/hp/commit"`, `"msphf/proofs"`, `"msphf/smallwood/chal"`, `"mhw/window"`, `"msphf/drbg"`, `"msphf/kgen/rho"`, `"msphf/rho/der"`, `"seedctx"`, `"fs/epoch/salt"`, `"fs/epoch/sk_salt"`, `"fs/kfs/salt"`, `"fs/epoch/commit"`, `"fs/timegrid/base"`, `"fs/dev/chain"`, `"srx/root_sw"`, and rollup labels as applicable.

---

## Annex F — **SRX/Smallwood‑v1 (ZK)** *(normative; ROM‑sound)*

**Purpose.** Provide a **zero‑knowledge** proof that a hidden SRX delta is valid under the field‑friendly SRX Merkle relation, while binding that proof transcript to the on‑wire canonical roots (`110/111/112/113`) and SRX payload material.

**Fields (REQUIRED when SRX applies):**

* `160 srx_root_sw:bstr32` — field‑friendly **shadow** SRX root (Anemoi/Poseidon‑family permutation; Jive compression for Merkle). 
* `161 srx_smallwood:bstr` — Smallwood proof object for the SRX statement.

**Bindings (REQUIRED):**

* Include `160/161` in `125 := H_L("msphf/proofs",[95,146,(160,161)])`.
* Include `160` in the **VRF bind tuple** (see § 11) whenever SRX applies.
* On‑wire roots `112/113` remain canonical and normative.
* Define bridge inputs and context:

```text
srx_payload_digest := H_L("srx/payload/digest",[raw_srx_payload_bytes(122)])
srx_bridge_ctx := H_L("srx/bridge/v1",[
  parent_root(110), join_delta_root(111),
  revoked_since_root(112), revoked_root(113),
  srx_commit(121), srx_payload_digest, srx_root_sw(160)
])
```

* Verifier MUST recompute `srx_bridge_ctx` and pass it as a public input to SRX/Smallwood verification.
* `srx_bridge_ctx` provides transcript binding without arithmetizing rpo‑256 in-circuit; by itself it is not a claim that canonical rpo‑256 roots are derivable from `160`.

**Statement (public inputs):**
`(srx_root_sw_before, srx_root_sw_after /*=160*/, parent_root /*110*/, join_delta_root /*111*/, revoked_since_root /*112*/, revoked_root /*113*/, srx_commit /*121*/, srx_payload_digest, srx_bridge_ctx, policy_flags, …)`.

**Witness (hidden):**
Structured SRX delta (adds/removes; metadata needed for no‑dup and label‑class checks) encoded in a field‑friendly format.

**Constraints (PACS, verified by Smallwood):**

1. Applying the delta transforms `srx_root_sw_before` → `srx_root_sw_after` under a Merkle scheme with **Jive** compression over an Anemoi‑family permutation. 
2. **No duplicates**; **allowed label classes only**; other SRX invariants as specified by policy.
3. `srx_root_sw_after` in the verified statement MUST equal header field `160`.
4. Verifier recomputes `srx_payload_digest` and `srx_bridge_ctx` from `110–113`, `121`, `122`, and `160`; statement values MUST match or verification fails.

**Security model.** Smallwood‑ARK provides **straightline‑extractable knowledge soundness in the ROM**; SRX ZK claims adopt this model. 

**Sizing & parameters.** Proof sizes in the **~9–15.5 KB** range at 128‑bit security are attainable with Anemoi‑family permutations when tuned via **higher‑arity near the top** and **`γ_MT`** authentication‑path trimming; set `|161|≤16384`. 

---

## Annex G — Bootstrap & Genesis FS Base *(normative)*

`T_base := fs_epoch_base_ts` is set at genesis and **aligned** to `H` (integer seconds since Unix epoch). Anchors **MUST** echo `143 == T_base`; mismatch → **`945.0`**. `T_base` is immutable.

---

## Annex H — Local Boundary Counter (time‑blind) *(normative)*

**State:** `(ec_local, t0_wall, t0_mono)`; `ec0 := floor((t0_wall − T_base)/H)`.
**Update (monotonic):**

```text
ec_pred := ec0 + floor( (now_mono − t0_mono) / H )
ec_wall := floor( (now_wall − T_base) / H )
ec_new  := max(ec_local, min(ec_wall + C_forward, ec_pred))  // RECOMMENDED C_forward=0
ec_local := ec_new
```

Skew affects only local liveness; it cannot widen FS exposure.

---

## Annex J — τₑ Caching & Offline Decryption *(normative)*

Keyed by `(weid, fs_ec)`; entries store `(τ_e, created_at)`.
Policy: `tau_cache_retention`, `tau_cache_max_entries`, `retention_periods := ⌊tau_cache_retention / H⌋`.
Security: encrypt at rest; wipe on eviction; purge on evolution/checkpoint as specified.

---

## Annex L — **Smallwood** *(normative)*

Uses a Smallwood (hash‑based) zero‑knowledge argument to bind `epoch_sk` to `fs_epoch_commit`. Public inputs include `fs_epoch_commit`; challenge label `"msphf/smallwood/chal"`. Knowledge soundness is established in the **Random‑Oracle Model** (straightline‑extractable). Verifier learns neither `hp` nor τₑ/`epoch_sk`. 

---

## Annex V — ZK‑VRF (FS Bind) *(normative)*

Verify under `bind_fs` (includes device‑chain and FS commits, and `srx_root_sw` when SRX applies). Output‑hiding. Budgets per § 18.

---

## Annex M — MHW & Metadata Surface *(normative)*

`WID := H_L("mhw/window",[gid, parent_root(110), 91])`. WID reveals concurrency partitioning only; it leaks neither `hp`, `Y*`, nor `E_k`.

---

## Annex N — Suite & Policy Journal *(normative; minutes‑grade presets; synthesized caps)*

**Core parameters (REQUIRED unless noted):**

```yaml
H: 300                         # 5 minutes
T_base: <uint64>               # immutable, aligned to H

checkpoint_interval: 3600      # 60 minutes
checkpoint_head_threshold: 24  # K; adaptive trigger Head-count
tau_cache_retention: 600       # 10 minutes (Balanced-10m)
tau_cache_max_entries: 2000

# Synthesis
W: ceil(checkpoint_interval / H)

# Slack knobs (non-negative)
S_anchor: 0                    # group cap extra headroom
S_first:  0                    # first-anchor extra headroom
S_device: 4                    # per-device extra headroom (offline catch-up)

# Derived caps (MUST be used)
D_anchor_max:     W + S_anchor
D_first_device:   W + S_first
D_device_max:     W + S_device

# Client adoption/queues (CLIENT-SIDE enforcement only; not validated by server)
D_ckpt_client_max: 12
D_future_drop: 12
P_device_max: 64         # Per-device pending queue bound (client local)
P_total_max: 4096        # Global pending queue bound (client local)
D_local: 12              # Local forward cap for adoption

# Suites & versions
allow_suites: ["rlwe-merkle/v1"]
fs_policy_version: 7
```

**Presets:**

* **Tight‑5m:** `tau_cache_retention=300`, `S_device=0` → FS ≤ 5 min; minimal offline grace.
* **Balanced‑10m (default):** `tau_cache_retention=600`, `S_device=4` → FS ≤ 10 min.

**Smallwood profile (FS bind; REQUIRED for `proof_mode="smallwood/v1"`):**

```yaml
smallwood_profile: sw-anemoi-128
smallwood:
  security: 128
  permutation: anemoi
  N: 8192              # Merkle leaves / DECS domain
  l: 64                # openings
  beta: 4              # LVCS stacking layers
  mu: 8                # LVCS row packing
  merkle_arity: [8, 8, 8]
  gamma_mt: 2          # trimmed path depth
```

*(Parameters mirror CAPSS tuning: higher arity near the top + `γ_MT` path trimming to keep proofs compact and verification light.)* 

**SRX/Smallwood profile (REQUIRED when SRX applies):**

```yaml
srx_smallwood_profile: srx-anemoi-128
srx_smallwood:
  security: 128
  permutation: anemoi
  N: 8192          # PCS/DECS domain
  l: 64            # openings
  beta: 4
  mu: 8
  merkle_arity: [8, 8, 8]
  gamma_mt: 2
max_proof_bytes_for_161: 16384
```

*(These knobs track CAPSS for ~9–15.5 KB proofs at 128‑bit security and reduced verifier work.)* 

**Merkle-arity interpretation (normative).**

Given `N` and `merkle_arity = [a0,a1,...,ak]` (`k>=0`), the effective schedule is:
`a_eff(i) := a[min(i,k)]` for level `i` from root to leaves.
Depth `d` is the smallest integer such that `Π_{i=0}^{d-1} a_eff(i) >= N`.
Leaves are filled left-to-right; any missing right siblings at the last populated layer use deterministic padding as defined by the proof system.

`gamma_mt` defines how many top authentication levels MAY be trimmed by the profile; verifier reconstruction MUST use the same `a_eff` schedule.

**Operational liveness note (REQUIRED to document in deployment policy).**
For time-blind FLG, deployments MUST specify how `A` is advanced after long idle periods (for example, heartbeat publishers or an explicit recovery procedure) so groups do not stall when `ec_local - A > D_anchor_max`.

**Invariant check (REQUIRED):** compute `W`; verify `H>0`, `checkpoint_interval ≥ H`, `D_anchor_max ≥ W`, `D_first_device ≥ W`; else **`948.0`** and do not admit joins. Policy changes take effect immediately in acceptance and adaptive checkpoint logic.

---

## Annex I — Implementation Binding (Server/Client) *(normative)*

**Server (REQUIRED):** Enforce FS base (`143`), device chain (`152/153`), FLG vs `A`, **SRX/Smallwood‑v1** carve‑outs, Smallwood & VRF binds (incl. `160`), parity, **no `kbroad_replay`**, time‑blind checkpoint rule; maintain durable `last_checkpoint_ec`, `A`, per‑device map; atomicity; crash‑rehydration. Server MUST fail closed (return `934 suite/config error`) if any KBROAD private material (e.g., `kbroad_sk`, injected `K_HP`) is supplied at startup, and SHOULD NOT link a KEM decapsulation entry point on the acceptance path.
**Client (REQUIRED):** Maintain `K_fs^t`, `fs_ec`, encrypted τₑ cache; device‑chain LRU; bounded queues; compute `ec_local(now)` (Annex H); evolve on boundary; zeroize old `K_fs`; enforce device‑chain monotonicity; mirror FLG at **adoption**; adopt checkpoints only when local counter is ready and forward cap allows.

---

## Annex Q — Membership Representation & Cryptographic Verification *(informative)*

Anchors carry commitments (`110–113`) and a delta witness payload; service maintains full membership state keyed by roots, while clients fetch witnesses and verify incrementally. rpo‑256 canonical set‑hash ensures completeness/no duplicates; **SRX/Smallwood‑v1** adds **zero‑knowledge (ROM)** defense‑in‑depth; bindings across `93/94/98/99/106/110–113/160/VRF` prevent tampering. 

---

## Annex R — Formalization Plan *(informative)*

TLA+ acceptance & merge state machines with invariants:
**I1:** `last_checkpoint_ec ≤ last_accepted_ec` (monotone).
**I2:** per‑device chain monotonicity.
**I3:** all accepted heads satisfy FLG bounds.
**I4:** checkpoint `148` equals `max(fs_ec)` over absorbed heads.
Crypto artifacts for Smallwood binds and VRF; SRX lemma: Smallwood proof implies correct root transition and invariant checks under ROM. 

---

## Annex P — Personal‑Inbox (Singleton‑Group) Pattern *(informative)*

A 1‑member “inbox group” lets any sender post a **join anchor** (policy‑permitting) and encrypt immediately via KBROAD; recipient decrypts later with A‑branch. Include an **Inbox Descriptor** (gid, parent root, KBROAD key, suite IDs) and abuse controls (quotas/revocations).

---

## Annex X — MLS Mapping & Why City‑G Avoids KeyPackage Reuse *(informative)*

City‑G has no reusable invite object; each join anchor is one‑time and context‑bound (`xk_hash`, `99`, AEAD nonces/labels, PoP). Reuse across contexts fails proof/binding checks; avoids MLS KeyPackage pitfalls.

---

## Annex Z — System‑Level Constraints *(informative)*

No server‑resident message secrets; immediate send; high concurrency; PQ‑resistant; deterministic acceptance; **minutes‑grade FS** at scale; time‑blind & witness‑free & publisher‑blind.

---

### Clarifications (concise)

* **Time‑blind vs time‑based:** Server acceptance & checkpoint validity never inspect clocks. Clients use **local monotonic** counters only to schedule evolution/adoption; skew cannot widen FS exposure.
* **Network partitions:** Offline devices evolve locally and, on reconnect, catch up via **stair‑steps** bounded by `D_device_max`; the group guard is keyed to `A`.
* **`T_base`/time zones:** `T_base` is an absolute Unix‑seconds multiple of `H` (time zones irrelevant).
* **Adaptive checkpoint uses current `W`:** Triggers evaluate `A − last_checkpoint_ec ≥ W_current(policy)`.
* **SRX ZK privacy:** deltas are not revealed on wire; SRX correctness is proven via **Smallwood** (ROM). 

---

**Citations:** SRX ZK design and sizing/tuning draw on CAPSS (Merkle with Jive, higher‑arity layers, γ_MT trimming; 9–15.5 KB at 128‑bit) and Smallwood (ROM straightline‑extractable knowledge soundness).  
