# 08 — Client Operations (Joiner Workflow & Key Derivation)

> [!IMPORTANT]
> This chapter is a legacy companion document. For `tswe/msphf-we/fs-hybrid`, the normative source is [`../specs-unified-fs.md`](../specs-unified-fs.md).
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and implementation.


**Blueprint**: Alpha (0.1.0) §10, §12.3, Annex I (Client)
**Implementation**: [`crates/cityg-client/src/lib.rs`](../../crates/cityg-client/src/lib.rs), [`crates/msphf-orchestrator/src/lib.rs`](../../crates/msphf-orchestrator/src/lib.rs)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Joiner KGen Pipeline](#2-joiner-kgen-pipeline)
3. [Seed Derivation Hierarchy](#3-seed-derivation-hierarchy)
4. [KBROAD Envelope Construction](#4-kbroad-envelope-construction)
5. [Proof Generation](#5-proof-generation)
6. [Header Assembly](#6-header-assembly)
7. [Epoch Key Extraction (Receiver)](#7-epoch-key-extraction-receiver)
8. [Merge Operations](#8-merge-operations)
9. [Client API](#9-client-api)
10. [Message Ordering & Timeline Considerations](#10-message-ordering--timeline-considerations)

---

## 1. Overview

The **client (joiner)** is responsible for:
1. Generating RLWE hashing parameters (hp_A, hp_B)
2. Constructing the KBROAD envelope
3. Generating CAPSS Smallwood and ZK-VRF proofs
4. Assembling the complete anchor header
5. Deriving the epoch key **E_k** locally

**Key principle**: Client derives all secrets from deterministic seeds and never reveals **Y\*** or **hp_k_bytes** to the server.

**Blueprint**: Alpha (0.1.0) §10 (Seed-binding and construction order), Annex I (Client implementation binding)

---

## 2. Joiner KGen Pipeline

### Entry Point

```rust
pub fn joiner_kgen_or<'a>(
    header_map: BTreeMap<u64, Value>,
    parts: AnchorInstanceParts<'a>,
    params: OrchestrationParams<'a>,
    witness_bytes: Option<&[u8]>,
) -> Result<JoinerKGenResult, MsphfError>
```

**Input**:
- `header_map`: Initial header (may be incomplete, will be populated)
- `parts`: Anchor identity (gid, cat, roots)
- `params`: Cryptographic profile (CRS, params, VRF ID)
- `witness_bytes`: Optional canonical witness (for SRX)

**Output**: `JoinerKGenResult` containing:
- `hp_k`: Secret RLWE hashing key bytes
- `hp_commit`: Commitment to MSPHF_HP
- `seed_ctx_hash`: ANCHOR_SEED_CTX hash (field 91)
- `seed_commit`: Seed commitment (field 94)
- `rho_commit`: ρ commitment (field 93)
- `xk_hash`: X_k hash
- `we_epoch_id`: Epoch identifier
- `epoch_key`: Derived epoch key **E_k**
- `eid`: Epoch ID (short identifier)
- `hp_proof`: CAPSS Smallwood + ZK-VRF proofs
- `header_map`: Complete header with all fields
- `capss_witness`: Branch artifacts for verification
- `hp_ciphertext`: KBROAD envelope (field 97)
- `hp_aead_key`: K_HP (32-byte symmetric key)

**Implementation**: [`crates/msphf-orchestrator/src/lib.rs`](../../crates/msphf-orchestrator/src/lib.rs)

### Construction Order

**Blueprint**: Alpha (0.1.0) §10 (Construction order)

```
PoP → ρ → 93/94 → seed_DRBG → KGen → masks → 99 → CAPSS Smallwood → ZK-VRF → SRX
```

Detailed steps:

1. **PoP** (Proof-of-Possession):
   - Generate or load ML-DSA-65 keypair
   - Compute `leaf_id := H_L("msphf/leaf/id", [pk_bytes])`
   - Sign PoP message: `pop_sig := ML-DSA-65.Sign(sk, pop_msg)`

2. **ρ** (Randomness):
   - Derive `rho_raw := H_L("msphf/rho/der", [pop_sig, xk_hash])`
   - Commit `rho_commit := H_L("msphf/kgen/rho", [rho_raw])`

3. **93/94** (Commitments):
   - Field 93 = `rho_commit`
   - Compute `seed_bundle_commit` (field 94)

4. **seed_DRBG**:
   - Derive `seed_DRBG := H_L("msphf/drbg", [seed_commit, rho_raw, xk_hash, seed_ctx_hash])`

5. **KGen** (Key Generation):
   - Derive branch seeds: `seed_A := H_L("msphf/kgen/a", [seed_DRBG])`, `seed_B := H_L("msphf/kgen/b", [seed_DRBG])`
   - Build branch artifacts (hp_A, hp_B) via RLWE-HPS

6. **Masks**:
   - Compute `Y_full_A`, `Y_full_B` from full hash
   - Derive masks: `M_A := H_L("msphf/mask/a", [Y_full_A, hp_commit])`, `M_B := H_L("msphf/mask/b", [Y_full_B, hp_commit])`

7. **99** (HP Commit):
   - Construct `MSPHF_HP := [1, hp_A, hp_B, M_A, M_B, params_id]`
   - Commit `hp_commit := H_L("msphf/hp/commit", [MSPHF_HP])`

8. **CAPSS Smallwood**:
   - Generate CAPSS Smallwood proof (binds seed→hp determinism)

9. **ZK-VRF**:
   - Generate ZK-VRF proof (proves Y\* correctness without revealing it)

10. **SRX**:
    - Assemble SRX payload with witnesses

---

## 3. Seed Derivation Hierarchy

### Diagram

```
                    ML-DSA-65 keypair
                            |
                    pop_sig (signing PoP message)
                            |
                            +-------------------+
                            |                   |
                    pop_sig + xk_hash           |
                            |                   |
                    H_L("msphf/rho/der")        |
                            ↓                   |
                          rho_raw               |
                            |                   |
                    H_L("msphf/kgen/rho")       |
                            ↓                   |
                       rho_commit (field 93)    |
                            |                   |
        +-------------------+-------------------+
        |                                       |
   rho_raw + seed_commit                  seed_commit
   + xk_hash + seed_ctx_hash                   |
        |                            H_L("msphf/seed/commit")
 H_L("msphf/drbg")                             ↓
        ↓                              seed_bundle_commit (field 94)
   seed_DRBG (32 bytes)
        |
        +-----------------------------------+
        |                                   |
   H_L("msphf/kgen/a")              H_L("msphf/kgen/b")
        ↓                                   ↓
     seed_A (32 bytes)                  seed_B (32 bytes)
        |                                   |
   hash_full("A")                      hash_full("B")
        ↓                                   ↓
     Y_full_A                            Y_full_B
```

### Code

```rust
// 1. Derive ρ from PoP signature
let rho_raw = h_l("msphf/rho/der", &RhoSig { pop_sig, xk_hash })?;
let rho_commit = h_l("msphf/kgen/rho", &RhoCommit(&rho_raw))?;

// 2. Compute seed_DRBG
let seed_drbg = h_l("msphf/drbg", &Drbg {
    seed_commit: &seed_commit,
    rho: &rho_raw,
    xk_hash: &xk_hash,
    seed_ctx_hash: &seed_ctx_hash,
})?;

// 3. Derive branch seeds
let seed_a = h_l("msphf/kgen/a", &SeedRef(&seed_drbg))?;
let seed_b = h_l("msphf/kgen/b", &SeedRef(&seed_drbg))?;

// 4. Generate branch artifacts
let full_a = hash_full(&RlweSecretKey::new(seed_a), "A", crs_id, params_id, xk_hash)?;
let full_b = hash_full(&RlweSecretKey::new(seed_b), "B", crs_id, params_id, xk_hash)?;

// 5. Extract outputs
let Y_full_A = full_a.y_full;
let Y_full_B = full_b.y_full;
let hp_A = full_a.projective.into_bytes();
let hp_B = full_b.projective.into_bytes();
```

**Implementation**: [`crates/msphf-orchestrator/src/lib.rs`](../../crates/msphf-orchestrator/src/lib.rs)

---

## 4. KBROAD Envelope Construction

### Overview

The **KBROAD** (Key Broadcast) envelope encrypts the MSPHF_HP tuple using ML-KEM-768 and ChaCha20-Poly1305.

**Blueprint**: Alpha (0.1.0) §12.3 (hp transport, KBROAD only)

### Step-by-Step Construction

#### Step 1: KEM Encapsulation

```rust
// 1. Obtain group's KBROAD public key (from policy registry)
let kbroad_pub: &[u8; 1184] = get_kbroad_public_key(gid)?;

// 2. Encapsulate (deterministic from random seed)
let mut rng = ChaCha20Rng::from_seed(kem_seed);
let (ct_kem, ss) = ml_kem_768::encapsulate(kbroad_pub, &mut rng)?;

// ct_kem: ~1088 bytes (ML-KEM-768 ciphertext)
// ss: 32 bytes (shared secret)
```

#### Step 2: KEK Derivation

```rust
// Derive KEK (Key Encryption Key) from shared secret
let salt = h_l("hp/kek/salt", [xk_hash])?;
let info = b"city-g|hp/kek/v1".iter().chain(hp_commit.iter()).copied().collect::<Vec<u8>>();

let kek = hkdf_blake3(
    &ss,           // Input key material (32 bytes)
    &salt,         // Salt (32 bytes)
    &info,         // Info (~50 bytes)
    32             // Output length
)?;
```

**HKDF-BLAKE3**:
```rust
fn hkdf_blake3(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, MsphfError> {
    // Extract
    let prk = blake3::keyed_hash(blake3::hash(salt).as_bytes(), ikm);

    // Expand
    let mut okm = Vec::new();
    let mut t = Vec::new();
    let mut counter = 1u8;

    while okm.len() < len {
        let mut hasher = blake3::Hasher::new_keyed(prk.as_bytes());
        hasher.update(&t);
        hasher.update(info);
        hasher.update(&[counter]);
        t = hasher.finalize().as_bytes().to_vec();
        okm.extend_from_slice(&t[..len.saturating_sub(okm.len()).min(32)]);
        counter += 1;
    }

    Ok(okm[..len].to_vec())
}
```

#### Step 3: Generate K_HP

```rust
// Generate random K_HP (32-byte symmetric key for encrypting MSPHF_HP)
let mut k_hp = [0u8; 32];
let mut rng = ChaCha20Rng::from_seed(hp_key_seed);
rng.fill_bytes(&mut k_hp);
```

#### Step 4: Wrap K_HP

```rust
// Encrypt K_HP with KEK
let kek_nonce = h_l("hp/kek/nonce", [xk_hash, hp_commit])?;
let nonce_12 = &kek_nonce[0..12];

let wrap = chacha20poly1305_encrypt(
    &kek,           // Key (32 bytes)
    nonce_12,       // Nonce (12 bytes)
    &hp_commit,     // AAD (32 bytes)
    &k_hp           // Plaintext (32 bytes)
)?;

// wrap: 48 bytes (32-byte K_HP + 16-byte Poly1305 tag)
```

#### Step 5: Encrypt MSPHF_HP

```rust
// Construct MSPHF_HP tuple
let msphf_hp = to_cbor_vec(&[
    Value::Integer(1.into()),                  // Version
    Value::Bytes(hp_a),                        // Branch A artifact
    Value::Bytes(hp_b),                        // Branch B artifact
    Value::Bytes(mask_a.to_vec()),             // Mask A
    Value::Bytes(mask_b.to_vec()),             // Mask B
    Value::Bytes(params_id.to_vec()),          // Params ID
])?;

// Encrypt with K_HP
let hp_nonce = h_l("hp/nonce", [xk_hash, hp_commit])?;
let nonce_12 = &hp_nonce[0..12];

let c_hp = chacha20poly1305_encrypt(
    &k_hp,          // Key (32 bytes)
    nonce_12,       // Nonce (12 bytes)
    &hp_commit,     // AAD (32 bytes)
    &msphf_hp       // Plaintext (~9.2 KB)
)?;

// C_hp: ~9.5 KB (MSPHF_HP + 16-byte tag)
```

#### Step 6: Assemble Envelope

```rust
let kbroad_envelope = to_cbor_vec(&[
    Value::Text("kbroad-v1".to_string()),
    Value::Bytes(ct_kem.to_vec()),
    Value::Bytes(wrap.to_vec()),
    Value::Bytes(c_hp),
    Value::Text("chacha20-poly1305".to_string()),
])?;

// Total size: ~10.6 KB
```

**Implementation**: [`crates/msphf-orchestrator/src/lib.rs`](../../crates/msphf-orchestrator/src/lib.rs)

---

## 5. Proof Generation

### CAPSS Smallwood Proof

```rust
// 1. Prepare inputs
let lin_inputs = capss::Inputs {
    seed_commit: &seed_commit,
    rho_commit: &rho_commit,
    hp_commit: &hp_commit,
};

// 2. Prepare witness
let capss_witness = CapssWitnessBundle {
    branch_a: full_a.capss_witness,
    branch_b: full_b.capss_witness,
};

// 3. Generate proof
let lin_proof = capss::prove(&lin_inputs, &capss_witness)?;
let lin_proof_bytes = lin_proof.as_bytes().to_vec();

// Size: typically 10-15 KB (≤ LIN_PI_MAX = 24 KB)
```

**Implementation**: [`crates/msphf-orchestrator/src/proofs/capss.rs`](../../crates/msphf-orchestrator/src/proofs/capss.rs)

### ZK-VRF Proof

```rust
// 1. Construct VRF context
let vrf_ctx = VrfCtx {
    xk_hash: &xk_hash,
    meor_vrf_id: params.vrf_id,
    we_epoch_id: &we_epoch_id,
};

// 2. Derive masks
let mask_a = h_l("msphf/mask/a", [&Y_full_A, &hp_commit])?;
let mask_b = h_l("msphf/mask/b", [&Y_full_B, &hp_commit])?;

// 3. Generate proof
let vrf_secret_key = params.vrf_secret_key
    .ok_or_else(|| MsphfError::invalid_input("missing vrf_secret_key"))?;

let vrf_proof = zk_vrf::zk_vrf_impl::prove(
    vrf_secret_key,
    &vrf_ctx,
    (&mask_a, &mask_b),
)?;

// Size: typically 3-5 KB (server limit: 6 KB)
```

**Implementation**: [`crates/msphf-orchestrator/src/proofs/zk_vrf/lb.rs`](../../crates/msphf-orchestrator/src/proofs/zk_vrf/lb.rs)

---

## 6. Header Assembly

### Complete Header Map

```rust
let mut header_map = BTreeMap::new();

// Algorithm gates
header_map.insert(90, Value::Integer(31.into()));                    // tswe_alg
header_map.insert(91, Value::Bytes(seed_ctx_hash.to_vec()));         // msphf_seed_ctx_hash
header_map.insert(92, Value::Text("rpo-256/v1".to_string()));        // merkle_ds_id
header_map.insert(93, Value::Bytes(rho_commit.to_vec()));            // msphf_kgen_rho_commit
header_map.insert(94, Value::Bytes(seed_bundle_commit.to_vec()));    // seed_bundle_commit

// KBROAD envelope
header_map.insert(97, kbroad_envelope_value);                        // msphf_hp

// CRS and params
header_map.insert(98, Value::Text(params.msphf_crs_id.to_string())); // msphf_crs_id
header_map.insert(99, Value::Bytes(hp_commit.to_vec()));             // msphf_hp_commit
header_map.insert(104, Value::Bytes(kbroad_pub.to_vec()));           // kbroad_pub
header_map.insert(105, Value::Text("ml-kem-768".to_string()));       // kbroad_alg
header_map.insert(106, Value::Text(params.params_id.to_string()));   // msphf_params_id

// PoP (join only)
header_map.insert(107, Value::Text("ML-DSA-65".to_string()));        // pop_device_pk_alg
header_map.insert(108, Value::Bytes(pop_pk.to_vec()));               // pop_device_pk_bytes
header_map.insert(109, Value::Bytes(pop_sig.to_vec()));              // pop_sig

// Roots
header_map.insert(110, Value::Bytes(parent_root.to_vec()));          // parent_root
header_map.insert(111, Value::Bytes(join_delta_root.to_vec()));      // join_delta_root
header_map.insert(112, Value::Bytes(revoked_since_root.to_vec()));   // revoked_since_prev_root
header_map.insert(113, Value::Bytes(revoked_root.to_vec()));         // revoked_root

// Proofs
header_map.insert(95, Value::Bytes(vrf_proof_bytes));                // vrf_pi (ZK-VRF)
header_map.insert(116, Value::Text(params.vrf_id.to_string()));      // meor_vrf_id
header_map.insert(146, Value::Bytes(fs_capss_bytes));            // fs_capss (CAPSS Smallwood transcript)
header_map.insert(119, Value::Text(params.proof_mode.to_string()));  // proof_mode

// SRX
header_map.insert(120, Value::Text("srx/v1-complete".to_string()));  // srx_mode
header_map.insert(121, Value::Bytes(srx_commit.to_vec()));           // srx_commit
header_map.insert(122, Value::Bytes(srx_payload));                   // srx_payload
header_map.insert(123, Value::Bytes(srx_hint_counts));               // srx_hint_counts
header_map.insert(124, Value::Bytes(srx_hint_sizes));                // srx_hint_sizes
header_map.insert(125, Value::Bytes(proofs_commit.to_vec()));        // proofs_commit

// Policy
header_map.insert(140, Value::Text(params.policy_version.to_string())); // policy_version
```

**Implementation**: [`crates/msphf-orchestrator/src/lib.rs`](../../crates/msphf-orchestrator/src/lib.rs)

---

## 7. Epoch Key Extraction (Receiver)

Other group members (receivers) extract the epoch key from the accepted anchor.

### Pipeline

```rust
pub fn extract_epoch_msphf_or<'a>(
    instance: &AnchorInstance<'a>,
    expected_xk_hash: &[u8; 32],
    hp_ciphertext: &[u8],
    hp_key: &[u8; 32],
    proof: &HpProof,
    binding_inputs: &HpBindingInputs<'_>,
    witness: &[u8],
) -> Result<[u8; 32], MsphfError>
```

**Inputs**:
- `instance`: Anchor instance (X_k)
- `expected_xk_hash`: Expected X_k hash
- `hp_ciphertext`: KBROAD envelope (field 97)
- `hp_key`: K_HP (obtained by decrypting KBROAD)
- `proof`: HP binding proof
- `binding_inputs`: Seed/rho/hp commitments
- `witness`: Canonical witness for this receiver

**Steps**:

#### 1. Verify XK Hash

```rust
let computed_xk_hash = instance.xk_hash()?;
if &computed_xk_hash != expected_xk_hash {
    return Err(MsphfError::invalid_input("xk_hash mismatch"));
}
```

#### 2. Decrypt HP

```rust
let hp_commit = instance.msphf_hp_commit.ok_or(...)?;
let hp_plain = decrypt_hp_bytes(hp_ciphertext, expected_xk_hash, hp_commit, hp_key)?;

// Verify commitment
let computed_commit = H_L("msphf/hp/commit", &hp_plain)?;
if &computed_commit != hp_commit {
    return Err(MsphfError::invalid_input("msphf_hp_commit mismatch"));
}
```

#### 3. Decode MSPHF_HP

```rust
let artifact: HpArtifactOwned = from_reader(hp_plain.as_slice())?;

// Extract components
let hp_a = artifact.hp_a;
let hp_b = artifact.hp_b;
let mask_a: [u8; 32] = artifact.m_a.try_into()?;
let mask_b: [u8; 32] = artifact.m_b.try_into()?;
```

#### 4. Validate Witness

```rust
let validated_witness = if witness.is_empty() {
    None
} else {
    let canonical: CanonicalWitness = from_reader(witness)?;
    Some(canonical.validate_against(instance)?)
};

let mode = validated_witness.as_ref().map(|w| w.mode).unwrap_or(WitnessMode::A);
```

#### 5. Compute Y_proj

```rust
// Select branch based on witness mode
let (branch, mask_bytes, hp_params) = match mode {
    WitnessMode::A => ("A", &mask_a, &RlweProjectiveParams::new(hp_a)),
    WitnessMode::B => ("B", &mask_b, &RlweProjectiveParams::new(hp_b)),
};

// Compute projective hash
let y_proj = hash_proj(
    hp_params,
    branch,
    crs_id,
    params_id,
    instance,
    validated_witness.as_ref(),
)?;
```

#### 6. Unmask to Get Y\*

```rust
// Compute mask material
let mask_material = h_branch_bytes(
    "msphf/mask",
    branch,
    crs_id,
    params_id,
    &[y_proj.as_ref()],
)?;

// Unmask: Y* = mask_bytes ⊕ mask_material
let mut y_star = [0u8; 32];
for i in 0..32 {
    y_star[i] = mask_bytes[i] ^ mask_material[i];
}
```

#### 7. Derive Epoch Key

```rust
fn epoch_key(instance: &AnchorInstance<'_>, y_star: &[u8; 32]) -> Result<[u8; 32], MsphfError> {
    h_l("tswe/epoch/key", &EpochKey {
        xk: &instance.to_cbor_bytes()?,
        y_star,
    })
}

let epoch_key = epoch_key(instance, &y_star)?;
```

**Implementation**: [`crates/msphf-orchestrator/src/lib.rs`](../../crates/msphf-orchestrator/src/lib.rs)

---

## 8. Merge Operations

### Merge KGen

```rust
pub fn joiner_kgen_merge_or<'a>(
    header_map: BTreeMap<u64, Value>,
    parts: AnchorInstanceParts<'a>,
    params: OrchestrationParams<'a>,
    mh_heads: Vec<[u8; 32]>,
) -> Result<JoinerKGenResult, MsphfError>
```

**Differences from join mode**:
- No PoP signature (no new device joining)
- No SRX payload (no new witnesses)
- No CAPSS Smallwood/ZK-VRF proofs (already validated in constituent heads)
- Derives new `we_epoch_id` from merged set: `H_L("tswe/merge/weid", [gid, cat, xk_hash, mh_heads])`
- Derives new `hp_commit` from merged set: `H_L("msphf/merge/hp", [parent_root, mh_heads])`

**Implementation**: [`crates/msphf-orchestrator/src/lib.rs`](../../crates/msphf-orchestrator/src/lib.rs)

---

## 9. Client API

### High-Level Facade

Client applications retain a `ForwardSecrecyState` per device, seeded with the
current `K_fs`. The facade mutates that state on each successful join.

```rust
use cityg_client::CityGClient;
use msphf_orchestrator::ForwardSecrecyState;

let mut fs_state = ForwardSecrecyState::new(initial_k_fs);

let bundle = CityGClient::generate_epoch(
    header_map,
    parts,
    params,
    &mut fs_state,
    witness_bytes,
)?;

// Bundle contains:
// - header_map: Complete anchor header (ready to submit)
// - epoch_key: Derived E_k
// - eid: Epoch ID
// - hp_ciphertext: KBROAD envelope
// - hp_aead_key: K_HP
// - capss_witness: For verification
// - fs_epoch_secret: Optional epoch secret (K_fs^t binding)
// - fs_tau: Optional τₑ cache key
```

**Implementation**: [`crates/cityg-client/src/lib.rs`](../../crates/cityg-client/src/lib.rs)

### Receiver Workflow

```rust
// 1. Server accepts anchor and broadcasts header

// 2. Receiver obtains KBROAD secret key
let kbroad_sk = get_kbroad_secret_key(gid)?;

// 3. Decrypt KBROAD envelope
let (ss, ct_kem) = extract_kbroad_components(header)?;
let shared_secret = ml_kem_768::decapsulate(kbroad_sk, &ct_kem)?;

// 4. Derive KEK
let kek = derive_kek(&shared_secret, &xk_hash, &hp_commit)?;

// 5. Unwrap K_HP
let k_hp = decrypt_k_hp(&kek, &wrap, &xk_hash, &hp_commit)?;

// 6. Extract epoch key
let epoch_key = extract_epoch_msphf_or(
    &anchor_instance,
    &xk_hash,
    &hp_ciphertext,
    &k_hp,
    &hp_proof,
    &binding_inputs,
    witness_bytes,
)?;

// 7. Derive EID
let eid = eid_from_epoch(&epoch_key)?;
```

---

### Rollup Consumption

Clients that receive a rollup merge use the additional metadata to recover past epochs:

1. Locate the ciphertext’s `weid` in `epoch_replay` (133) → obtain `xk_hash` and committed roots.
2. If `is_join=true`, fetch the matching KBROAD clone from `kbroad_replay` (136), validate its
   structure, and decrypt hp locally. (The server never decapsulates.)
3. Request a membership witness for the historical `parent_root` (110). Without membership the
   device cannot derive `E_k` for that epoch.
4. Run ME-OR as usual to derive the historic epoch key; `E_k` matches the original anchor’s output.

Rollups do not grant new decryption rights: the membership witness check enforces that only members
of the historical epoch can recover its key.

---

## 10. Message Ordering & Timeline Considerations

Forward-secrecy (FS) epochs induce a **partial order** over anchors and the ciphertexts derived from
them. Understanding what is (and isn’t) guaranteed helps avoid over-interpreting the metadata.

### What FS gives you “for free”

- **Strict ordering across epochs.** Deriving \(K_{fs}^{t+1}\) requires evolving from \(K_{fs}^{t}\)
  (Annex H). Any ciphertext that decrypts under an epoch key for `fs_ec = t+1` must have been created
  after the sender evolved past `t`. Anchors inherit this guarantee: the server enforces monotonic
  device chains and FLG bounds (`FREEZE_FS_DEV_CHAIN_*`, `FREEZE_FS_FORWARD_JUMP_*`).
- **Anchor auditability.** Acceptance records (`PivotParity`, checkpoints) freeze the epoch counter
  and device-chain commits, giving a verifiable timeline for join/merge events without relying on a
  wall clock.

### What FS does *not* guarantee

- **No total order inside an epoch.** Two messages encrypted under the same `fs_ec` remain
  unordered. Applications that need per-device FIFO semantics must add their own sequencing
  (e.g. a lightweight hash chain similar to `fs_dev_prev/commit`).
- **Late posts within the τₑ window.** Devices may retain τₑ for offline decryption (Annex J). While
  the spec requires zeroizing \(K_{fs}^{t}\) after evolution, an implementation that caches τₑ can
  still emit a ciphertext “from” a recent epoch until the retention window expires. The effective
  FS bound is `max(H, tau_cache_retention)`.
- **No mandated message header.** The protocol keeps ciphertext metadata minimal to preserve
  publisher-blindness. Clients TRY decryption under recent epochs; there is no standard field that
  exposes `fs_ec` at the transport level.

### Recommended application practices

- **Expose helpful metadata when safe.** Including `weid` (already needed for routing) and optionally
  `fs_ec` in an authenticated but public header lets clients sort without trial decryption. This
  does not leak hp/Y*/E_k.
- **Chain messages per device if you need total order.** A simple commit such as  
  `msg_commit := H_L("msg/chain",[device_pk, fs_ec, msg_prev_commit, msg_seq])` mirrors the anchor
  dev-chain and gives every recipient a verifiable per-sender order.
- **Tune τₑ retention consciously.** Short retention → tighter ordering guarantees (good for chat).
  Longer retention → better offline UX (forums, slow-moving discussions) but weaker “anti-backdate”
  properties.
- **Sort client-side by (`fs_ec`, local seq/commit, receipt time).** This reflects the guarantees
  above without inventing an artificial total order that the cryptography does not enforce.

---

## Summary

The **client workflow** follows a deterministic seed hierarchy from PoP signature to epoch key derivation. The joiner constructs the KBROAD envelope using ML-KEM-768 and ChaCha20-Poly1305, generates CAPSS Smallwood and ZK-VRF proofs, and assembles the complete anchor header. Receivers decrypt the KBROAD envelope (using the group's KEM secret key), compute the projective hash with their witness, unmask to recover **Y\***, and derive the epoch key **E_k**. The server never learns **Y\*** or **E_k** due to publisher-blindness.

**Next**: [09 — Multi-Head Window (MHW)](./09-multi-head-window.md)
