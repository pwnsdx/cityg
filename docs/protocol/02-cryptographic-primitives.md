# Cryptographic Primitives

> [!IMPORTANT]
> This chapter is a legacy companion document. For `tswe/msphf-we/fs-hybrid`, the normative source is [`../specs.md`](../specs.md).
> If this chapter conflicts with the unified spec or implementation behavior/tests, follow the unified spec and implementation.


**Specification:** Alpha (0.1.0)
**Blueprint:** §6, §9, Appendices A, B, C

---

## Table of Contents

1. [Overview](#1-overview)
2. [Hash Functions](#2-hash-functions)
3. [Post-Quantum Cryptography](#3-post-quantum-cryptography)
4. [RPO-256/v1 (Rescue-Prime-Optimized)](#4-rpo-256v1-rescue-prime-optimized)
5. [RLWE-HPS Construction](#5-rlwe-hps-construction)
6. [AEAD (Authenticated Encryption)](#6-aead-authenticated-encryption)
7. [Key Derivation Functions](#7-key-derivation-functions)
8. [Domain Separation](#8-domain-separation)
9. [Security Parameters](#9-security-parameters)

---

## 1. Overview

**Blueprint:** §6 (Crypto, Domains, and Labels)

City-G `tswe/msphf-we/fs-hybrid` uses a carefully selected suite of cryptographic primitives optimized for:
- **Post-quantum security** (NIST-approved algorithms)
- **Server blindness** (no decryption capability)
- **Determinism** (reproducible from seeds)
- **Performance** (battery-friendly mobile execution)

### 1.1 Primitive Stack

```
┌─────────────────────────────────────────────────────────┐
│                 Application Layer                       │
│              (Messages encrypted with E_k)              │
└─────────────────────────────────────────────────────────┘
                         ↓  ↑
┌─────────────────────────────────────────────────────────┐
│               ChaCha20-Poly1305 (AEAD)                  │
│          Nonces: deterministic from context             │
└─────────────────────────────────────────────────────────┘
                         ↓  ↑
┌─────────────────────────────────────────────────────────┐
│                  HKDF-BLAKE3 (KDF)                      │
│       KEK derivation, seed expansion, nonces            │
└─────────────────────────────────────────────────────────┘
                         ↓  ↑
┌─────────────────────────────────────────────────────────┐
│       BLAKE3 (Domain-Separated Hash)                    │
│   H_L(label, args) - All commitments and bindings       │
│   XOF mode - Deterministic randomness generation        │
└─────────────────────────────────────────────────────────┘
                         ↓  ↑
┌───────────────────────┬─────────────────────────────────┐
│   RPO-256/v1          │     RLWE-HPS (A1 Pack)         │
│  (Merkle Hashing)     │   N=256, Q=3329, K=3            │
│  Goldilocks field     │   Smooth Projective Hashing     │
└───────────────────────┴─────────────────────────────────┘
                         ↓  ↑
┌───────────────────────┬─────────────────────────────────┐
│   ML-DSA-65           │     ML-KEM-768                  │
│  (Dilithium Sigs)     │    (Kyber KEM)                  │
│  PoP, Bootstrap       │    KBROAD Envelope              │
└───────────────────────┴─────────────────────────────────┘
```

### 1.2 Security Levels

| Primitive | Classical | Quantum | NIST Category |
|-----------|-----------|---------|---------------|
| **BLAKE3** | 256-bit | 128-bit | - |
| **RPO-256** | 256-bit | 128-bit | - |
| **ML-KEM-768** | 256-bit | 192-bit | NIST Level 3 |
| **ML-DSA-65** | 256-bit | 192-bit | NIST Level 3 |
| **ChaCha20-Poly1305** | 256-bit | 128-bit | IETF RFC 8439 |

**All primitives provide at least 128-bit quantum security.**

### 1.3 Primitive Registry (Normative)

| Identifier | Primitive | Usage | Notes |
|------------|-----------|-------|-------|
| `ml-kem-768` | ML-KEM-768 (Kyber) | KBROAD envelope (`ct_kem`, KEK derivation) | FIPS 203 |
| `rlwe-merkle/a1` | RLWE-HPS (N=256,Q=3329,K=3) | MSPHF ME-OR derivations (`hp_k`) | Annex C |
| `hkdf/blake3` | City-G HKDF-BLAKE3 (see §7.1) | KEK, τₑ, epoch-sk, AEAD nonces | Deterministic extract/expand |
| `hash/blake3` | BLAKE3 (`H_L`) | All commitments, domain separation | Section 2 |
| `hash/rpo-256/v1` | Rescue-Prime-Optimized | Merkle/SRX roots, payload hashes | Section 4 |
| `aead/chacha20poly1305` | ChaCha20-Poly1305 | `wrap`, `C_hp`, application AEAD | Nonce derivation in §6 |
| `vrf/lb-vrf/v1` (`meor_vrf_id`) | LB-VRF with ZK proof | Device binding (`bind_fs`, acceptance) | Appendix V |
| `smallwood/v1` | CAPSS Smallwood proof | Seed determinism + SRX shadow roots | Config in §5 / Annex F |

Every reference to a primitive in the rest of the specification MUST use one of the identifiers above. Additional identifiers MAY be added only if their parameters, encodings, and failure codes are defined with the same level of specificity.

---

## 2. Hash Functions

### 2.1 BLAKE3 (Primary Hash)

**Implementation:** [`crates/msphf-core/src/hash.rs`](../../crates/msphf-core/src/hash.rs)
**Specification:** https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf

**Properties:**
- **Output:** 256-bit (32 bytes)
- **Speed:** ~5 GB/s (single-threaded), parallelizable
- **Security:** 256-bit preimage, 128-bit collision resistance
- **Modes:** Hash, Keyed hash, Key derivation, XOF (extendable output)

#### 2.1.1 H_L Construction (Labeled Hash)

**Blueprint:** Appendix A

**Definition:**
```
H_L(label, args[]) := BLAKE3("city-g|" || ASCII(label) || 0x00 || CBOR_det(args[]))
```

**Components:**
1. **Prefix:** `b"city-g|"` (7 bytes) — namespace separation
2. **Label:** ASCII string (e.g., `"msphf/hp/commit"`)
3. **Separator:** `0x00` (1 byte) — prevents label extension attacks
4. **Payload:** Canonical CBOR encoding of arguments (RFC 8949)

**Implementation:**
```rust
// crates/msphf-core/src/hash.rs
use blake3::Hasher;
use std::io::{self, Write};

pub fn h_l<T: Serialize>(label: &str, args: &T) -> Result<[u8; 32], MsphfError> {
    hash_serialized(CITY_G_PREFIX, label, args)
}

fn hash_serialized<T: Serialize>(
    prefix: &[u8],
    label: &str,
    value: &T,
) -> Result<[u8; 32], MsphfError> {
    let mut hasher = Hasher::new();
    hasher.update(prefix);            // "city-g|"
    hasher.update(label.as_bytes());  // label
    hasher.update(&[0u8]);            // separator
    {
        let mut writer = HasherWriter { hasher: &mut hasher };
        ciborium::ser::into_writer(value, &mut writer).map_err(MsphfError::serialization)?;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    Ok(out)
}

struct HasherWriter<'a> {
    hasher: &'a mut blake3::Hasher,
}

impl Write for HasherWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
```

**Security Rationale:**
- **Prefix:** Prevents cross-protocol attacks (won't collide with other BLAKE3 uses)
- **Separator:** Prevents `label="foo"` + `payload=b"bar"` from colliding with `label="foobar"` + `payload=b""`
- **Canonical CBOR:** Ensures deterministic encoding (no key ordering ambiguity)

**Example:**
```rust
// Compute hp_commit := H_L("msphf/hp/commit", [hp])
let hp: Vec<u8> = vec![0xAA; 128];
let commit = h_l("msphf/hp/commit", &hp)?;
// commit = BLAKE3("city-g|msphf/hp/commit\0" || CBOR([hp]))
```

#### 2.1.2 H_branch (Branch-Bound Hash)

**Blueprint:** §10 (Seed-Binding)

**Definition:**
```
H_branch(label, branch, crs_id, params_id, args[]) :=
    H_L(label, {
        "branch": branch,
        "crs": crs_id,
        "params": params_id,
        "args": [args...]
    })
```

**Purpose:** Binds hash computation to specific cryptographic parameters.

**Implementation:**
```rust
// crates/msphf-core/src/hash.rs
pub fn h_branch_bytes(
    label: &str,
    branch: &str,        // "A" or "B"
    crs_id: &str,        // "rlwe-merkle/v1"
    params_id: &str,     // params_id commitment
    args: &[&[u8]],
) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct Branch<'a> {
        branch: &'a str,
        crs: &'a str,
        params: &'a str,
        args: Vec<ByteSlice<'a>>,
    }
    h_l(label, &Branch { branch, crs, params, args })
}
```

**Example:**
```rust
// Compute branch A seed
let seed_A = h_branch_bytes(
    "msphf/kgen/A",
    "A",                    // branch identifier
    "rlwe-merkle/v1",       // CRS identifier
    params_id_hex,          // parameter pack hash
    &[&ρ, &xk_hash],        // additional binding
)?;
```

#### 2.1.3 XOF Mode (Extendable Output)

**Purpose:** Generate deterministic randomness from seeds.

**Implementation:**
```rust
// crates/msphf-core/src/hash.rs
pub fn xof32(ctx: &str, seed: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"city-g|xof|");  // XOF-specific prefix
    hasher.update(ctx.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();  // XOF mode
    let mut out = [0u8; 32];
    reader.fill(&mut out);  // Extract 32 bytes
    out
}
```

**Usage:** Noise sampling, matrix expansion (where more than 32 bytes needed, use SHAKE128 instead).

#### 2.1.4 H_epoch (Epoch Key Derivation)

**Blueprint:** §6

**Definition:**
```
E_k := H_epoch(X_k, Y*) = H_L("msphf/epoch", [CBOR_det((X_k, Y*))])
```

**Implementation:**
```rust
// crates/msphf-core/src/hash.rs
pub fn h_epoch<X: Serialize, Y: Serialize>(
    xk: &X,    // Public epoch context
    y: &Y      // VRF output (Y*)
) -> Result<[u8; 32], MsphfError> {
    let payload = to_cbor_vec(&(xk, y))?;
    Ok(hash_internal(CITY_G_PREFIX, ds::MSPHF_EPOCH, &payload))
}
```

**Security:** Binds epoch key to both public context (X_k) and unique VRF output (Y*).

---

## 3. Post-Quantum Cryptography

### 3.1 ML-KEM-768 (Key Encapsulation Mechanism)

**Standard:** FIPS 203 (NIST PQC Standard)
**Implementation:** `pqcrypto_kyber::kyber768` (via `pqcrypto-traits`)
**Blueprint:** §12.1 (Algorithm Gates)

**Parameters:**
- **Security Level:** NIST Level 3 (~192-bit quantum security)
- **Public Key Size:** 1,184 bytes
- **Ciphertext Size:** 1,088 bytes
- **Shared Secret:** 32 bytes

**Usage in City-G:** KBROAD envelope group key distribution

```rust
// Key encapsulation (joiner side)
use pqcrypto_kyber::kyber768::{encapsulate, PublicKey};

let kbroad_pub = PublicKey::from_bytes(&pub_bytes)?;
let (ss, ct_kem) = encapsulate(&kbroad_pub);
// ss: 32-byte shared secret
// ct_kem: 1,088-byte ciphertext

// Key decapsulation (receiver side)
use pqcrypto_kyber::kyber768::{decapsulate, SecretKey};

let receiver_secret = SecretKey::from_bytes(&sk_bytes)?;
let ss = decapsulate(&ct_kem, &receiver_secret);
```

**Server Constraint:** Server MUST NOT have client decapsulation keys or call `decapsulate()`.

**Implementation:** [`crates/msphf-orchestrator/src/accept/mod.rs`](../../crates/msphf-orchestrator/src/accept/mod.rs) (validation only, no decapsulation)

### 3.2 ML-DSA-65 (Digital Signatures)

**Standard:** FIPS 204 (NIST PQC Standard)
**Implementation:** `pqcrypto_dilithium::dilithium5` (Dilithium5 ≈ ML-DSA-65)
**Blueprint:** §12.1

**Parameters:**
- **Security Level:** NIST Level 3 (~192-bit quantum security)
- **Public Key Size:** 2,592 bytes
- **Signature Size:** 4,595 bytes
- **Deterministic:** Yes (for PoP signatures)

**Usage in City-G:**

1. **Proof-of-Possession (PoP):** Binds device to anchor
2. **Bootstrap Signatures:** Genesis anchors (CA-signed or self-signed)

**PoP Construction:**
```rust
// Blueprint §12.2.3
// msg := H_L("msphf/pop/msg", [gid, leaf_id, xk_hash])

use pqcrypto_dilithium::dilithium5::{keypair, detached_sign};

let (pop_pk, pop_sk) = keypair();  // Device key pair

// Compute leaf_id
let leaf_id = h_l("leaf-id", &pop_pk_bytes)?;

// Compute PoP message
let pop_msg = h_l("msphf/pop/msg", &(gid, &leaf_id, &xk_hash))?;

// Sign deterministically
let pop_sig = detached_sign(&pop_msg, &pop_sk);
```

**Deterministic ρ Derivation:**
```rust
// Blueprint §10, §12.2.4
// ρ := H_L("msphf/rho/der", [pop_sig, xk_hash])

let ρ = h_l("msphf/rho/der", &(&pop_sig_bytes, &xk_hash))?;

// Server verifies: H_L("msphf/kgen/rho", [ρ]) == field #93
let rho_commit = h_l("msphf/kgen/rho", &ρ)?;
assert_eq!(rho_commit, header[93]);
```

**Anti-Grind Property:** Joiner cannot choose favorable ρ because it's derived from PoP signature, which commits to device public key.

**Implementation:** [`crates/msphf-core/src/witness.rs`](../../crates/msphf-core/src/witness.rs)

---

## 4. RPO-256/v1 (Rescue-Prime-Optimized)

**Implementation:** [`crates/msphf-core/src/rpo256.rs`](../../crates/msphf-core/src/rpo256.rs)
**Specification:** Appendix B
**External:** Miden/Winterfell (Rescue-Prime permutation)

**Purpose:** Merkle tree hashing for membership witnesses.

### 4.1 Construction

**Algebraic Structure:**
- **Field:** Goldilocks (p = 2^64 - 2^32 + 1)
- **State Width:** 12 field elements
- **Rate:** 8 field elements (sponge mode)
- **Capacity:** 4 field elements
- **Rounds:** 7 (Rescue-Prime-Optimized)

**Sponge Parameters:**
```rust
const STATE_WIDTH: usize = 12;
const RATE_WIDTH: usize = 8;
const RATE_OFFSET: usize = 4;  // First 4 elements = capacity
```

### 4.2 Domain Separation Tags

**Blueprint:** Appendix B

| Tag | ASCII | Hex (BE u64) | Usage |
|-----|-------|--------------|-------|
| **MT_LEAF** | `"MT_LEAF\0"` | `0x4D545F4C45414600` | Merkle leaf hash |
| **MT_NODE** | `"MT_NODE\0"` | `0x4D545F4E4F444500` | Merkle internal node |
| **MT_NMINT** | `"MT_NMINT"` | `0x4D545F4E4D494E54` | Non-membership interval node |
| **MT_NMBIN** | `"MT_NMBIN"` | `0x4D545F4E4D42494E` | Non-membership binding |
| **SET_HASH** | `"SET_HASH"` | `0x5345545F48415348` | Canonical set hash |

### 4.3 Hash Operations

#### 4.3.1 Leaf Hash

```rust
// crates/msphf-core/src/rpo256.rs
pub fn leaf(data: &[u8]) -> [u8; 32] {
    hash_with_tag(DS_MT_LEAF_U64, data)
}
```

**Process:**
1. Initialize state: `[0; 12]` (Goldilocks field elements)
2. Absorb tag: `MT_LEAF` (64-bit BE)
3. Absorb length: number of field words
4. Absorb data: convert bytes → field elements (8-byte BE chunks)
5. Apply permutation: Rescue-Prime-Optimized (7 rounds)
6. Squeeze: Extract first 4 rate elements → 32 bytes (BE)

#### 4.3.2 Node Hash

```rust
// crates/msphf-core/src/rpo256.rs
pub fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(left);
    payload[32..].copy_from_slice(right);
    hash_with_tag(DS_MT_NODE_U64, &payload)
}
```

**Merkle Tree Construction:**
```
        root = node(h1, h2)
       /                  \
   h1 = node(L1, L2)    h2 = node(L3, carry)
     /      \             /       \
   L1       L2          L3       L3 (carry for odd count)
```

**Carry Rule:** If level has odd count, last element carries to next level unchanged (see Appendix F of the unified spec).

**Implementation:** [`crates/msphf-core/src/merkle.rs`](../../crates/msphf-core/src/merkle.rs)

#### 4.3.3 Canonical Set Hash

```rust
// crates/msphf-core/src/rpo256.rs
pub fn set_hash(items: &[[u8; 32]]) -> Result<[u8; 32], MsphfError> {
    // Requires strict lexicographic ordering
    if items.windows(2).any(|w| w[0] >= w[1]) {
        return Err(MsphfError::invalid_input("set must be strict-sorted"));
    }
    let mut payload = Vec::with_capacity(items.len() * 32);
    for item in items {
        payload.extend_from_slice(item);
    }
    Ok(hash_with_tag(DS_SET_HASH_U64, &payload))
}
```

**Usage:** Deterministic commitment to membership sets (order-independent up to sorting).

### 4.4 Byte-to-Field Mapping

**Blueprint:** Appendix B

**Process:**
1. Split bytes into 8-byte chunks (big-endian)
2. Interpret as u64
3. Convert to Goldilocks field element (modulo p = 2^64 - 2^32 + 1)
4. Pad last chunk if needed

```rust
// crates/msphf-core/src/rpo256.rs
fn bytes_to_field_elements(bytes: &[u8]) -> Vec<BaseElement> {
    let mut result = Vec::new();
    for chunk in bytes.chunks(8) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let val = u64::from_be_bytes(buf);  // Big-endian
        result.push(BaseElement::new(val));
    }
    result
}
```

### 4.5 Security Properties

- **Preimage Resistance:** 256-bit (Rescue-Prime security proof)
- **Collision Resistance:** 128-bit (birthday bound for 256-bit output)
- **Second-Preimage Resistance:** 256-bit
- **Quantum Security:** 128-bit (Grover's algorithm speedup)

**Note:** Merkle tree depth limited to 64 (specification §5), so collision attacks infeasible.

---

## 5. RLWE-HPS Construction

**Implementation:** [`crates/msphf-core/src/rlwe/`](../../crates/msphf-core/src/rlwe/), [`crates/msphf-rlwe/src/lib.rs`](../../crates/msphf-rlwe/src/lib.rs)
**Specification:** §9, Appendix C

**Purpose:** Smooth Projective Hash Function (SPHF) for publisher-blind epoch key derivation.

### 5.1 Parameter Pack A1

**Specification:** Annex C (A1 Pack)

```rust
// crates/msphf-core/src/rlwe/constants.rs
pub const N: usize = 256;       // Polynomial degree
pub const Q: i16 = 3329;        // Modulus (prime)
pub const K: usize = 3;         // Number of polynomials in vector
```

**Ring:** `R_q = Z_q[X] / (X^N + 1)` where N=256, Q=3329

**Verification:**
- Q=3329 is prime ✓
- N=256 is power of 2 ✓
- Q ≡ 1 (mod 2N) → 3329 = 1 + 13*256 ✓ (NTT-friendly)

### 5.2 Modular Arithmetic

#### 5.2.1 Montgomery Reduction

**Purpose:** Efficient modular multiplication.

**Montgomery Form:** `a·R mod Q` where R = 2^16

**Implementation:**
```rust
// crates/msphf-core/src/rlwe/arithmetic.rs
pub fn montgomery_reduce(a: i32) -> i16 {
    let u = ((a as i64 * QINV as i64) as i32) & 0xFFFF;
    let t = u * Q as i32;
    let mut res = (a - t) >> 16;
    res += (res >> 31) & Q as i32;  // Constant-time conditional add
    res as i16
}
```

**Constants:**
```rust
pub const QINV: i32 = 62209;  // Q^{-1} mod 2^16 (positive inverse)
pub const MONT_R: i16 = 2285;  // R mod Q = 2^16 mod 3329
pub const R2_MOD_Q: i16 = 1353;  // R^2 mod Q
```

**Verification:**
```
Q * QINV mod 2^16 = 1  ✓
(3329 * 62209) & 0xFFFF = 1  ✓
```

**Security:** ✅ Constant-time (no data-dependent branches after fix)

#### 5.2.2 Barrett Reduction

**Purpose:** Reduce arbitrary i32 to range [0, Q).

**Implementation:**
```rust
// crates/msphf-core/src/rlwe/arithmetic.rs
pub fn barrett_reduce(mut a: i32) -> i16 {
    debug_assert!(a.abs() < (Q as i32) * (Q as i32));  // Input bound check
    let t = ((BARRETT_MU * a + (1 << 25)) >> 26) * Q as i32;
    a -= t;
    let mut r = a - Q as i32;
    r += (r >> 31) & Q as i32;  // Constant-time conditional add
    r as i16
}
```

**Constant:**
```rust
pub const BARRETT_MU: i32 = 20159;  // floor((2^26)/Q + 0.5)
```

**Verification:**
```
(2^26 / 3329) + 0.5 = 20159.14...
floor(20159.14) = 20159  ✓
```

**Security:** ✅ Constant-time, with debug assertion for input bounds

#### 5.2.3 Montgomery Add/Sub

**Implementation:**
```rust
// Add (constant-time)
pub fn montgomery_add(a: i16, b: i16) -> i16 {
    let mut res = a as i32 + b as i32 - Q as i32;
    res += (res >> 31) & Q as i32;  // Conditional add if negative
    res as i16
}

// Subtract (constant-time)
pub fn montgomery_sub(a: i16, b: i16) -> i16 {
    let mut res = a as i32 - b as i32;
    res += (res >> 31) & Q as i32;  // Conditional add if negative
    res as i16
}
```

**Security:** ✅ Both are constant-time (fixed in security audit)

### 5.3 Number Theoretic Transform (NTT)

**Purpose:** Fast polynomial multiplication in R_q.

**Algorithm:** Cooley-Tukey decimation-in-time (DIT)

**Implementation:**
```rust
// crates/msphf-core/src/rlwe/ntt.rs
pub fn ntt(a: &mut [i16; N]) {
    let mut len = 128usize;
    let mut k = 1usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS_FWD[k];  // Twiddle factor
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, a[j + len]);  // Montgomery mul
                let tmp = a[j];
                let sum = tmp as i32 + t as i32;
                let diff = tmp as i32 - t as i32;
                a[j + len] = diff as i16;
                a[j] = sum as i16;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}
```

**Twiddle Factors:**
```rust
// 128 precomputed roots of unity in Montgomery form
pub const ZETAS_FWD: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, ...
];
```

**Inverse NTT:**
```rust
pub fn inv_ntt(a: &mut [i16; N]) {
    // Similar structure, but iterates ZETAS in reverse
    // Final step: multiply by N^{-1} * R^2 mod Q
    for coeff in a.iter_mut() {
        *coeff = fqmul(*coeff, F_INV_NTT);
    }
}

pub const F_INV_NTT: i16 = 1441;  // N^{-1} * R^2 mod Q
```

**Security:** ✅ Constant-time (fixed loop counts, no data-dependent branches)

**Test Coverage:** [`crates/msphf-core/src/rlwe/ntt.rs`](../../crates/msphf-core/src/rlwe/ntt.rs) (roundtrip test)

### 5.4 Noise Sampling (CBD-η₂)

**Purpose:** Generate small error polynomials for RLWE.

**Algorithm:** Centered Binomial Distribution with η=2

**Implementation:**
```rust
// crates/msphf-core/src/rlwe/noise.rs
pub fn cbd_eta2_poly(buf: &[u8]) -> [i16; N] {
    assert!(buf.len() * 2 >= N);  // Need 128 bytes for 256 coefficients

    let mut poly = [0i16; N];
    let mut byte_offset = 0;
    let mut bit_offset = 0;

    for coeff in &mut poly {
        let mut a = 0u16;
        let mut b = 0u16;
        // Extract 4 bits: 2 for 'a', 2 for 'b'
        for _ in 0..2 {
            let bit = (buf[byte_offset] >> bit_offset) & 1;
            a += bit as u16;
            bit_offset += 1;
            if bit_offset == 8 {
                bit_offset = 0;
                byte_offset += 1;
            }
        }
        for _ in 0..2 {
            let bit = (buf[byte_offset] >> bit_offset) & 1;
            b += bit as u16;
            bit_offset += 1;
            if bit_offset == 8 {
                bit_offset = 0;
                byte_offset += 1;
            }
        }
        *coeff = (a as i16) - (b as i16);  // Result in range [-2, 2]
    }
    poly
}
```

**Distribution:** Pr[X = k] = (η choose (η+k)/2) / 2^η for |k| ≤ η

**For η=2:**
- Pr[X = -2] = 1/16
- Pr[X = -1] = 4/16
- Pr[X =  0] = 6/16
- Pr[X =  1] = 4/16
- Pr[X =  2] = 1/16

**Security:** Deterministic timing (no rejection sampling, all inputs produce valid output)

### 5.5 Matrix Expansion (SHAKE-128)

**Purpose:** Generate public matrix **A** from seed deterministically.

**Implementation:**
```rust
// crates/msphf-core/src/rlwe/matrix.rs
pub fn expand_a(seed: &[u8]) -> [[i16; N]; K] {
    use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};

    let mut a = [[0i16; N]; K];
    for (i, row) in a.iter_mut().enumerate() {
        let mut xof = Shake128::default();
        xof.update(seed);
        xof.update(&[i as u8]);  // Row index for domain separation
        let mut reader = xof.finalize_xof();

        let mut coeffs = Vec::with_capacity(N);
        let mut buf = [0u8; 3];

        // Rejection sampling: only accept values < Q
        while coeffs.len() < N {
            reader.read(&mut buf);
            let t0 = ((buf[0] as u16) | ((buf[1] as u16) << 8)) & 0x0FFF;
            let t1 = ((buf[1] as u16 >> 4) | ((buf[2] as u16) << 4)) & 0x0FFF;

            if t0 < Q as u16 {
                coeffs.push(montgomery_reduce((t0 as i32) * R2_MOD_Q as i32));
                if coeffs.len() == N { break; }
            }
            if t1 < Q as u16 && coeffs.len() < N {
                coeffs.push(montgomery_reduce((t1 as i32) * R2_MOD_Q as i32));
            }
        }
        row.copy_from_slice(&coeffs);
    }
    a
}
```

**Security Note:** Rejection sampling causes variable timing (not constant-time). This is acceptable because:
1. Seed is public (derived from CRS and public parameters)
2. Matrix **A** is public
3. No secret information leaked

**Determinism:** Same seed always produces same matrix **A** (required for verification).

### 5.6 Key Generation (RLWE-HPS)

**Blueprint:** §10 (Seed-Binding & Construction Order)

**Process:**

```
1. PoP → ρ
   ρ := H_L("msphf/rho/der", [pop_sig, xk_hash])

2. Seed Commitment
   seed_commit := H_L("msphf/kgen/seed", [user-provided or default])

3. DRBG Seed
   seed_DRBG := H_L("msphf/drbg", [seed_commit, ρ, xk_hash, seed_ctx_hash])

4. Branch Seeds
   seed_A := H_branch("msphf/kgen/A", "A", crs_id, params_id, [seed_DRBG, ...])
   seed_B := H_branch("msphf/kgen/B", "B", crs_id, params_id, [seed_DRBG, ...])

5. Component Seeds (for each branch)
   s_seed   := XOF("hps/s", seed_branch)
   eB_seed  := XOF("hps/eB", seed_branch)
   r_seed   := XOF("hps/r", seed_branch)
   e1_seed  := XOF("hps/e1", seed_branch)
   e2_seed  := XOF("hps/e2", seed_branch)
   A_seed   := XOF("hps/A-seed", seed_branch)

6. Polynomial Generation
   s  := CBD-η₂(s_seed)    // Secret polynomial
   eB := CBD-η₂(eB_seed)   // Error for B component
   r  := CBD-η₂(r_seed)    // Randomness
   e1 := CBD-η₂(e1_seed)   // Error 1
   e2 := CBD-η₂(e2_seed)   // Error 2
   A  := SHAKE128-expand(A_seed)  // Public matrix

7. NTT Domain
   s_ntt  := NTT(s)
   r_ntt  := NTT(r)
   e1_ntt := NTT(e1)

8. RLWE Samples
   hp_A := A·s + e1  (in NTT domain)
   hp_B := A·r + e2  (in NTT domain)

9. Mask Generation
   M_A := H_L("msphf/mask", [branch="A", ...])
   M_B := H_L("msphf/mask", [branch="B", ...])
```

**Output:** `(hp_A, hp_B, M_A, M_B, params_id)` — the MSPHF_HP tuple

**Implementation:** [`crates/msphf-rlwe/src/lib.rs`](../../crates/msphf-rlwe/src/lib.rs)

### 5.7 ME-OR Construction (Masked-Equality OR)

**Blueprint:** §8 (ME-OR)

**Goal:** Both branch A and branch B members compute the same Y*.

**Construction:**

```
For member in set A:
    Y*_A = SPHF_A(hp_A) ⊕ M_A

For member in set B:
    Y*_B = SPHF_B(hp_B) ⊕ M_B

Constraint: M_A and M_B chosen such that Y*_A = Y*_B for valid members
```

**Implementation:**
```rust
// Joiner computes both branches
let (y_star_A, y_star_B) = compute_meor_branches(hp_A, hp_B, M_A, M_B, ...);

// Masks adjusted so:
assert_eq!(y_star_A, y_star_B);  // Enforced by construction

// Final Y*
let y_star = y_star_A;  // = y_star_B
```

**Security:** Server never learns hp (encrypted in KBROAD), so server cannot compute Y*.

---

## 6. AEAD (Authenticated Encryption)

**Standard:** ChaCha20-Poly1305 (RFC 8439)
**Implementation:** `chacha20poly1305` crate
**Blueprint:** §12.3

### 6.1 ChaCha20-Poly1305

**Properties:**
- **Key Size:** 256 bits (32 bytes)
- **Nonce Size:** 96 bits (12 bytes)
- **Authentication Tag:** 128 bits (16 bytes)
- **Speed:** ~4 GB/s (software, single-core)
- **Quantum Security:** 128 bits (Grover's algorithm)

**API:**
```rust
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce
};

let key = ChaCha20Poly1305::new(&key_bytes.into());
let nonce = Nonce::from_slice(&nonce_bytes[..12]);
let ciphertext = key.encrypt(nonce, plaintext.as_ref())?;
let plaintext = key.decrypt(nonce, ciphertext.as_ref())?;
```

### 6.2 KBROAD Envelope Usage

**Blueprint:** §12.3 (hp transport)

**Three-Layer Encryption:**

```
1. KEK Derivation (HKDF-BLAKE3)
   ss := KEM.Encap(kbroad_pub)  // ML-KEM-768
   salt := H_L("hp/kek/salt", [xk_hash])
   info := "city-g|hp/kek/v1" || hp_commit
   KEK := HKDF-BLAKE3-Extract-Expand(ss, salt, info, L=32)

2. K_HP Wrapping
   nonce_wrap := H_L("hp/kek/nonce", [xk_hash, hp_commit])[0..12]
   wrap := AEAD(KEK, nonce_wrap, aad=hp_commit, plaintext=K_HP)

3. HP Encryption
   nonce_hp := H_L("hp/nonce", [xk_hash, hp_commit])[0..12]
   C_hp := AEAD(K_HP, nonce_hp, aad=hp_commit, plaintext=hp_k_bytes)
```

**Nonce uniqueness (REQUIRED).** The pairs `(xk_hash, hp_commit)` and `(hp_commit, aad)` are unique per anchor because `hp_commit (99)` binds the gid, parent root, SRX commits, and deterministic MSPHF transcript. Therefore the truncated 96-bit `nonce_wrap` and `nonce_hp` values are guaranteed to be unique across the entire deployment. Implementations MUST derive nonces exactly as shown above and MUST treat them as deterministic (never random or reused under different contexts).

**Example (xk_hash = 0xAA…AA, hp_commit = 0xBB…BB)**

| Label (`H_L`) | 32-byte digest | Nonce (first 12 bytes) |
|---------------|----------------|------------------------|
| `"hp/kek/nonce"` | `3e292f176a4d936907ff598f49e47ca41e385661975059c46b96d7b117409424` | `3e292f176a4d936907ff598f` |
| `"hp/nonce"`      | `877c755076d1f436280ec251c3ad22c24284e82877a3aff3dd19532fd6cc5d0d` | `877c755076d1f436280ec251` |

Both client and server MUST derive the same digests for a given `(xk_hash, hp_commit)` pair and truncate to 96 bits for AEAD nonces.

**Envelope Structure:**
```
BARRIER_HP_V1 := ["barrier-sealed-v1", hp_ciphertext, "chacha20-poly1305"]
```

**Server Validation:**
```rust
// Server checks structure only (no decryption)
if envelope[0] != "barrier-sealed-v1" {
    return Freeze(921, "parent_eid_forbidden");
}
if envelope[2] != "chacha20-poly1305" {
    return Freeze(934, "suite_deprecated");
}
// Validate sizes: hp_ciphertext only
```

**Client Decryption:**
```rust
// 1. Derive the barrier-scoped HP AEAD key
let hp_key = derive_barrier_hp_key(&k_barrier, barrier_version, &xk_hash, &hp_commit)?;

// 2. Decrypt hp
let nonce_hp = h_l("hp/nonce", &(&xk_hash, &hp_commit))?;
let hp_k_bytes = aead_decrypt(&hp_key, &nonce_hp[..12], &hp_commit, &hp_ciphertext)?;
```

**Security:** Three-layer defense:
1. Authenticated barrier state
2. Barrier-scoped HP key derivation with transcript binding
3. ChaCha20-Poly1305 (AEAD with unique nonces)

---

## 7. Key Derivation Functions

### 7.1 HKDF-BLAKE3

**Identifier:** `hkdf/blake3`

**Definition (normative)**  
City‑G uses HKDF as in RFC 5869 with the following fixed instantiation:

1. **Extract:** `PRK := BLAKE3_Keyed(salt_32, IKM)` where `salt_32` is the 32-byte salt (HKDF salt is zero-padded/truncated to 32 bytes).
2. **Expand:** `OKM := BLAKE3_Keyed(PRK, info || 0x01)` for single-block outputs. For multi-block outputs, standard HKDF counter chaining applies (`info || counter` with `counter = 0x01,0x02,…`).
3. **Output length:** All protocol invocations request exactly 32 bytes (KEKs, τₑ, epoch-sk, AEAD nonces). Larger outputs MUST re-run Expand with subsequent counters rather than re-keying.

This is equivalent to HKDF-HMAC with HMAC replaced by keyed BLAKE3. Because the keyed mode already provides PRF guarantees, no additional XOR with the previous block (`T(i-1)`) is required; the counter byte is appended directly to the `info` string.

**Usage constraints**
- `salt` MUST be the 32-byte output of an `H_L` invocation (e.g., `"hp/kek/salt"`, `"fs/epoch/salt"`).
- `info` MUST begin with the ASCII domain tag `b"city-g|"` followed by the context string (e.g., `b"city-g|hp/kek/v1"`).
- `IKM` is either the ML-KEM shared secret (`wrap`/`C_hp`) or a 32-byte derived secret (`K_fs`).

**Test vectors (32-byte outputs)**

| Context | Salt (hex) | IKM (hex) | Info (ASCII) | OKM (hex) |
|---------|------------|-----------|--------------|-----------|
| KEK (`hp/kek`) | `5c1e461b3ac3a6bb7f1c668e7d44a681cbf079dbd1be4e8f641fcbff1b84f5e5` | `3333…33` (32 bytes) | `city-g|hp/kek/v1` ‖ `hp_commit=0x22…22` | `bb67b4e885abfcd171b1be95b27f0dc86f303c19317c171d59e6d8b8e2b86657` |
| τₑ (`fs/epoch/tau`) | `dd640e893b6dd62a371915113d8ae4d7676ff5a9f68cfe5fcbba6140d722351b` | `5555…55` (32 bytes) | `city-g|fs/epoch/tau|v1` | `9b1f09bf75f12c042f7b0b967824220b8f839000ee6dcac0e72e1221c15d048f` |
| Epoch SK (`fs/epoch/sk`) | `35f11e891aa40ef379cc35b065b098f9df7b3000b17f395107b1281b4af43d41` | `5555…55` (32 bytes) | `city-g|fs/epoch/sk|v1` | `9dbeb1b2f8445d61e6f7f9186cd84008fa338a71d002ffbab44aabb4bcc26b9a` |

*(Salts shown above are the output of the corresponding `H_L` labels with sample inputs described in the msphf-core HKDF tests.)*

Implementations MUST produce the exact outputs above when supplied with the listed inputs.

### 7.2 Seed Derivation Chains

**Purpose:** Hierarchical key derivation from master seed.

**Tree Structure:**
```
                ρ (from PoP signature)
                 │
                 ├─→ rho_commit (field #93)
                 │
                 ├─→ seed_DRBG
                      │
                      ├─→ seed_A (branch A)
                      │    ├─→ s_seed
                      │    ├─→ eB_seed
                      │    ├─→ r_seed
                      │    ├─→ e1_seed
                      │    ├─→ e2_seed
                      │    └─→ A_seed
                      │
                      └─→ seed_B (branch B)
                           ├─→ s_seed
                           ├─→ eB_seed
                           ├─→ r_seed
                           ├─→ e1_seed
                           ├─→ e2_seed
                           └─→ A_seed
```

**Properties:**
- **One-way:** Cannot derive parent from child
- **Independence:** Sibling seeds computationally independent
- **Binding:** Changes to ρ change all descendant seeds
- **Determinism:** Same ρ always produces same tree

---

## 8. Domain Separation

**Blueprint:** Appendix E (Label & Field Registry)
**Implementation:** [`crates/msphf-core/src/ds.rs`](../../crates/msphf-core/src/ds.rs)

### 8.1 Complete Label Registry

| Label | Hex Field | Usage | Output |
|-------|-----------|-------|--------|
| `"msphf/hash"` | - | Branch-bound hash | 32B |
| `"msphf/ystar"` | - | Epoch target Y* | 32B |
| `"msphf/mask"` | - | ME-OR mask | 32B |
| `"msphf/hp/commit"` | #99 | HP commitment | 32B |
| `"seedctx"` | #91 | Seed context hash | 32B |
| `"msphf/kgen/seed"` | - | Seed commitment | 32B |
| `"msphf/kgen/rho"` | #93 | Rho commitment | 32B |
| `"msphf/rho/der"` | - | Derive ρ from PoP | 32B |
| `"msphf/kgen/A"` | - | Branch A seed | 32B |
| `"msphf/kgen/B"` | - | Branch B seed | 32B |
| `"msphf/drbg"` | - | DRBG seed | 32B |
| `"weid"` | - | WE epoch ID | 32B |
| `"msphf/xk"` | - | Epoch context hash | 32B |
| `"msphf/epoch"` | - | Epoch key E_k | 32B |
| `"eid"` | - | Epoch identifier | 32B |
| `"leaf-id"` | - | Device leaf binding | 32B |
| `"msphf/pop/msg"` | - | PoP message | 32B |
| `"tswe/salt"` | - | TSWE salt hash | 32B |
| `"srx/commit"` | #121 | SRX commitment | 32B |
| `"msphf/params"` | #106 | Params commitment | 32B |
| `"msphf/proofs"` | #125 | Proofs commitment | 32B |
| `"msphf/vck"` | - | VCK cache key | 32B |
| `"vk/hp"` | - | VRF key commit | 32B |
| `"vrf/seed"` | - | VRF seed | 32B |
| `"vrf/ctx"` | - | VRF context | 32B |
| `"mhw/window"` | - | Window ID (WID) | 32B |
| `"hp/kek/salt"` | - | KEK salt | 32B |
| `"hp/kek/nonce"` | - | KEK AEAD nonce | 32B |
| `"hp/nonce"` | - | HP AEAD nonce | 32B |
| `"msphf/lin/chal"` | - | CAPSS Smallwood challenge | 32B |

**XOF Labels (used with BLAKE3 XOF mode):**
- `"hps/A-seed"` - Matrix A seed generation
- `"hps/salt"` - Salt generation
- `"hps/s"` - Secret polynomial seed
- `"hps/eB"` - Error B polynomial seed
- `"hps/r"` - Randomness polynomial seed
- `"hps/e1"` - Error 1 polynomial seed
- `"hps/e2"` - Error 2 polynomial seed

### 8.2 RPO-256 Tags

| Tag | ASCII | Usage |
|-----|-------|-------|
| `rpo-256/leaf` | `"MT_LEAF\0"` | Merkle leaf hash |
| `rpo-256/node` | `"MT_NODE\0"` | Merkle internal node |
| `rpo-256/nonmem` | `"MT_NMINT"` | Non-membership interval |

### 8.3 Design Rationale

**Why Domain Separation?**
1. **Prevent Cross-Protocol Attacks:** City-G hashes won't collide with other BLAKE3 uses
2. **Prevent Purpose Confusion:** Same data hashed for different purposes yields different outputs
3. **Cryptographic Agility:** Can change hash function without breaking label semantics
4. **Formal Analysis:** Domain-separated functions modeled as independent random oracles

**Example Attack Prevented:**
```
Without separation:
  H(X_k || Y*) could equal H(different_data) if formatted identically

With separation:
  H_L("msphf/epoch", [X_k, Y*]) ≠ H_L("other-label", [different_data])
  Even if CBOR encodings collide, labels differ
```

---

## 9. Security Parameters

### 9.1 Summary Table

| Primitive | Classical Sec | Quantum Sec | Standard | Status |
|-----------|---------------|-------------|----------|--------|
| **BLAKE3** | 256-bit | 128-bit | - | ✅ Deployed |
| **RPO-256** | 256-bit | 128-bit | - | ✅ Analyzed |
| **ML-KEM-768** | ≥192-bit (Category 3) | ≥96-bit (Category 3 quantum target) | FIPS 203 | ✅ NIST Std |
| **ML-DSA-65** | ≥192-bit (Category 3) | ≥96-bit (Category 3 quantum target) | FIPS 204 | ✅ NIST Std |
| **ChaCha20-Poly1305** | 256-bit | 128-bit | RFC 8439 | ✅ IETF Std |
| **RLWE-HPS A1** | ≥192-bit (matches ML-KEM-768) | ≈96-bit (quantum sieving ≈2^95 ops) | Annex C | ⚠️ Research |

**Note:** RLWE-HPS security depends on Ring-LWE hardness assumption (lattice-based). Security analysis ongoing.

### 9.2 Quantum Security Analysis

**Grover's Algorithm (Generic Search):**
- Speedup: √N (quadratic)
- Impact on symmetric crypto: Halves effective key length
  - BLAKE3 (256-bit) → 128-bit quantum security ✓
  - ChaCha20 (256-bit key) → 128-bit quantum security ✓

**Shor's Algorithm (Factoring/Discrete Log):**
- Speedup: Exponential
- Impact: Breaks RSA, ECC, DH
- Defense: Use lattice-based crypto (ML-KEM, ML-DSA, RLWE)

**Lattice Attacks (BKZ, LLL):**
- Best known: Exponential in dimension
  - ML-KEM-768: ≥96-bit quantum security target (NIST Category 3)
  - ML-DSA-65: ≥96-bit quantum security target (NIST Category 3)
  - RLWE-HPS A1: ≈96-bit quantum security (Module-LWE instance costs ≈2^95 quantum operations per lattice-estimator)

**Overall System Security:** Meets or exceeds NIST Category 3 targets across all primitives.

**Mitigation:** RLWE-HPS remains under active review; parameters can be raised if future analysis recommends additional margin.

### 9.3 Constant-Time Verification

**Status:** ✅ All critical operations are constant-time after security audit fixes.

**Verified Constant-Time:**
- ✅ Montgomery reduction (arithmetic.rs, 19)
- ✅ Barrett reduction (arithmetic.rs)
- ✅ Montgomery add/sub (arithmetic.rs, 48)
- ✅ NTT forward/inverse (fixed loop counts)
- ✅ CBD noise sampling (deterministic, no rejection)

**Known Variable-Time (Acceptable):**
- ⚠️ Matrix expansion rejection sampling (operates on public seed)
- ⚠️ CBOR parsing (operates on public headers)

**Verification:** [`docs/timing-verification.md`](../timing-verification.md)

---

## 10. Implementation References

### 10.1 Crates

| Crate | Files | Purpose |
|-------|-------|---------|
| **msphf-core** | `hash.rs`, `rpo256.rs`, `rlwe/` | Core crypto primitives |
| **msphf-rlwe** | `lib.rs` | RLWE-HPS construction |
| **pqcrypto_kyber** | External | ML-KEM-768 |
| **pqcrypto_dilithium** | External | ML-DSA-65 |
| **blake3** | External | BLAKE3 hash |
| **chacha20poly1305** | External | AEAD |
| **sha3** | External | SHAKE-128 (matrix expansion) |
| **winter_crypto** | External | Rescue-Prime permutation |

### 10.2 Test Coverage

| Test | File | Purpose |
|------|------|---------|
| **NTT roundtrip** | `rlwe/ntt.rs` | Verify NTT correctness |
| **RPO-256 KATs** | `rpo256.rs` | Known-answer tests |
| **Merkle canonicity** | `merkle.rs` | Canonical tree construction |
| **PoP validation** | `witness.rs` | Signature verification |
| **Arithmetic** | `rlwe/arithmetic.rs` | Montgomery/Barrett tests |

---

**Next Steps:**
- For SPHF/ME-OR details → [05-sphf-meor.md](05-sphf-meor.md)
- For witness validation → [04-witness-validation.md](04-witness-validation.md)
- For proof systems → [06-proof-systems.md](06-proof-systems.md)
- For complete domain labels → [15-label-registry.md](15-label-registry.md)
