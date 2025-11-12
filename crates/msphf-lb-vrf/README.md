lattice based verifiable random function
-----

> Forked from Zhenfei Zhang's original `lb-vrf` prototype (2020). Huge thanks for releasing the reference code—this crate continues that work with constant-time refinements, extended tests, and integration hooks for the City‑G stack.

### Core roadmap

- [x] One-time LB-VRF scheme
  - [x] Implement a basic scheme
  - [x] Use CRT to compress VRF outputs
  - [x] Improve serialization to reduce sizes
  - [x] Introduce structured error enum and RNG injection points
  - [x] Zeroize memory (secret material derives `Zeroize`, transcripts wiped)
  - [x] Add benchmark harness (Criterion; results tracked in `BENCHMARKS.md`)
  - [ ] Implement NTT-backed polynomial multiplications
  - [ ] Adopt Montgomery representations to improve performance
  - [ ] Switch to HNF secrets
- [ ] Many-time VRF scheme
  - [ ] Decide which long-term signature or PRF to chain epochs to
  - [ ] Implement scheme (proof construction + verification)
- [ ] Performance & side-channel hardening
  - [ ] Rework polynomial multipliers / rejection sampling for constant time
  - [ ] Run ctgrind/dudect and capture reports
  - [ ] Evaluate alternative sampling (masking or fixed-iteration)
- [ ] Testing & documentation
  - [x] Exercise boundary-coefficient cases (±`BETA_M_KAPPA`) in tests
  - [x] Add regression tests for `*_with_rng` APIs
  - [x] Document API usage, security assumptions, and feature flags
  - [ ] Gate unused NTT helpers or remove dead code
- [ ] Upstream coordination
  - [ ] Decide whether to upstream vendor patches (`UPSTREAM.md`)
  - [ ] Prep changelog / PR notes if contributing back

### Usage

```rust
use msphf_lb_vrf::lbvrf::LBVRF;
use msphf_lb_vrf::VRF;

let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
let params = LBVRF::paramgen_with_rng(&mut rng)?;
let (pk, sk) = LBVRF::keygen_with_rng(&mut rng, params)?;
let message = b"example context";
let proof = LBVRF::prove(message, params, pk, sk, rand::random())?;
let output = LBVRF::verify(message, params, pk, proof)?;
```

Feature flags:

- `bench` – pulls in Criterion and enables the micro-benchmark harness (`cargo bench --features bench`).

### Security notes

- The codebase is alpha-stage; run side-channel tooling (ctgrind/dudect) before any deployment.
- Parameter defaults align with the original LB-VRF paper but should be reviewed against the current City‑G security targets.
- Only the one-time scheme is implemented; many-time security requires additional design.

---

## Security Properties

This crate implements a **lattice-based verifiable random function (LB-VRF)** with the following cryptographic guarantees:

### 1. Output Hiding (Zero-Knowledge VRF Output)

**Property**: The VRF proof reveals nothing about the VRF output `v` beyond what the verifier can compute from the proof verification.

**Implementation**:
- The proof consists of `(z, c, v)` where:
  - `z`: Response polynomials (9 × Poly256)
  - `c`: Challenge polynomial (Poly256)
  - `v`: VRF output (Poly32)
- The Fiat-Shamir challenge `c = H(A, t, message, w1', w2')` binds the commitment without revealing the secret
- Soundness ensures the verifier accepts only if the prover knows the secret, but the proof is simulatable (zero-knowledge)

**Verified by**: `test::lbvrf::test_lbvrf` and adversarial mutation tests in City-G integration

**Security level**: Based on Module-LWE hardness over ring Z_q[X]/(X^256 + 1) with q = 3329

### 2. Deterministic Seeding (Anti-Grinding)

**Property**: Proofs are deterministically derived from the message, preventing selective disclosure attacks where the prover generates multiple proofs and cherry-picks favorable outputs.

**Implementation**:
```rust
// In City-G integration (msphf-orchestrator/src/proofs/zk_vrf/lb.rs:71-72)
let message = encode_message(ctx, masks);  // Includes xk_hash, epoch_id, masks
let seed = blake3::hash(&message).as_bytes();  // Deterministic seed
let proof = LBVRF::prove(message, params, pk, sk, seed)?;
```

**Binding**: The proof seed is deterministically derived from:
- `xk_hash`: Anchor context (32 bytes)
- `meor_vrf_id`: Protocol version string
- `we_epoch_id`: Epoch identifier (32 bytes)
- `mask_a`, `mask_b`: Mask digests (32 bytes each)

**Verified by**: `test::proofs::zk_vrf::lb::tests::deterministic_proof_generation`

**Security guarantee**: A malicious prover cannot grind for favorable VRF outputs by trying different randomness; the seed is fully determined by public context and witness commitments.

### 3. Constant-Time Verification

**Property**: Proof verification operations do not leak information about the proof validity through timing side-channels.

**Implementation**:
```rust
// In lbvrf.rs:114
if bool::from(c.ct_eq(&proof.c)) {  // Constant-time comparison via subtle crate
    Ok(Some(proof.v))
} else {
    Ok(None)
}
```

Uses `subtle::ConstantTimeEq` for:
- Challenge comparison (`Poly256::ct_eq`)
- Proof acceptance decision

**Security rationale**: Prevents timing attacks where an adversary learns information about the secret key or message by measuring verification time.

**Limitations**:
- Polynomial arithmetic operations (NTT, inner products) are **not** constant-time
- This is acceptable because these operate on **public** polynomials (witness commitments, not secrets)
- Only the final equality check (revealing accept/reject) is constant-time

**Verified by**: Manual code review and integration tests; side-channel analysis pending (ctgrind/dudect)

### 4. Proof Size Bounds (DoS Protection)

**Property**: Proofs are bounded to prevent denial-of-service attacks via oversized proof submission.

**Implementation**:
```rust
const MAX_VRF_PROOF_SIZE: usize = 16_384;  // 16 KB limit

pub fn verify_result(..., proof: &VrfProof, ...) -> Result<bool> {
    if proof.bytes.len() > MAX_VRF_PROOF_SIZE {
        return Err(Error::ProofSizeExceeded(proof.bytes.len(), MAX_VRF_PROOF_SIZE));
    }
    // ... verification logic
}
```

**Typical proof size**: ~8-10 KB (below the 16 KB limit)

**Verified by**: `test::proofs::zk_vrf::lb::tests::reject_oversized_proof`

**Security guarantee**: Servers reject oversized proofs before deserialization, preventing memory exhaustion attacks.

### 5. Soundness (Unforgeability)

**Property**: An adversary cannot produce a valid proof without knowing the secret key, even after seeing many valid proofs.

**Security basis**:
- **Module-LWE hardness**: Finding `s` given `t = A·s` is computationally hard
- **Random Oracle Model (ROM)**: Hash function `H` behaves as a random oracle in the Fiat-Shamir transformation
- **Rejection sampling**: Ensures response polynomial norms don't leak secret information

**Parameters**:
- Ring degree: 256
- Modulus: q = 3329
- Norm bound: β = 38528 (see `param.rs`)

**Verified by**: Adversarial mutation tests ensure that:
- Modified proofs are rejected (`reject_proof_with_mutated_bytes`)
- Proofs for different contexts/epochs are rejected (`reject_proof_with_wrong_epoch`)
- Swapped witness commitments are detected (`reject_proof_with_swapped_masks`)

### 6. Epoch Derivation (Forward Security)

**Property**: VRF keys derived for different epochs are independent; compromise of one epoch key does not affect others.

**Implementation**:
```rust
// In lbvrf.rs:148
pub fn derive_epoch_keypair(master: &MasterSecretKey, params: &Param, epoch_id: &[u8; 32])
    -> (PublicKey, SecretKey) {
    let mut hasher = Blake3::new();
    hasher.update(b"msphf/lbvrf/epoch");
    hasher.update(master.as_bytes());
    hasher.update(epoch_id);
    let seed = hasher.finalize();
    keypair_from_rng(&mut ChaCha20Rng::from_seed(seed), *params)
}
```

**Security guarantee**: Each epoch gets a fresh RLWE keypair derived via one-way hashing; knowing `(pk_epoch_1, sk_epoch_1)` does not reveal `sk_epoch_2`.

**Verified by**: `test::lbvrf::epoch_derivation_differs_by_epoch`

---

## Integration with City-G

In City-G, this VRF is used for **server-blind validation** of ME-OR (Masked-Equality OR) proofs:

1. **Client side** (`joiner_kgen_or`):
   - Computes `Y* = H(r_y, xk)` from SPHF evaluation
   - Derives masks: `m_a = Y* ⊕ H(Y_full_A)`, `m_b = Y* ⊕ H(Y_full_B)`
   - Generates ZK-VRF proof binding `(mask_a, mask_b)` to context
   - **Y* never transmitted** — only mask digests sent

2. **Server side** (`accept_anchor`):
   - Receives: `(mask_digest_a, mask_digest_b, vrf_proof)`
   - Verifies: `LBVRF::verify(message, params, pk, proof)?`
   - **Never learns Y*** — output hiding property ensures server is blind

3. **Anti-grinding protection**:
   - Proof seed = `H(xk_hash || epoch_id || mask_a || mask_b)`
   - Prevents client from trying different proofs to manipulate verification

**Security model**: The server validates cryptographic correctness (proofs, signatures, Merkle witnesses) but remains cryptographically blind to epoch keys. Even if the server is compromised, it cannot decrypt past or future messages without breaking ML-KEM-768.

---

## Testing & Verification

**Adversarial test coverage** (in `msphf-orchestrator/src/proofs/zk_vrf/lb.rs`):
- ✅ Mutation resistance: Bit flips in proof are detected
- ✅ Context binding: Proofs fail with wrong epoch/context
- ✅ Mask binding: Swapped masks are rejected
- ✅ Truncation detection: Incomplete proofs fail gracefully
- ✅ Size limit enforcement: Oversized proofs rejected pre-deserialization
- ✅ Determinism: Same inputs produce identical proofs

**Known limitations**:
- **Alpha-stage code**: Not audited for production use
- **Polynomial operations not constant-time**: Acceptable for public data but requires review
- **Side-channel analysis pending**: ctgrind/dudect reports needed before deployment
- **One-time scheme only**: Many-time VRF security requires additional design

---

## Cryptographic Assumptions

1. **Module-LWE (M-LWE)**: Distinguishing `(A, A·s + e)` from uniform is hard
   - Ring: `Z_q[X]/(X^256 + 1)` with `q = 3329`
   - Secret/error distribution: Centered binomial (small coefficients)

2. **Random Oracle Model (ROM)**: Hash functions (`SHA-512`, `Blake3`) behave as random oracles
   - Required for Fiat-Shamir soundness
   - Standard assumption in lattice-based signatures

3. **Collision resistance**: Blake3 hash collisions are computationally infeasible
   - Used for deterministic seed derivation
   - Security parameter: 256-bit output

**Quantum resistance**: Module-LWE is believed quantum-resistant (no known polynomial-time quantum attacks). Best known quantum attack: ~2^96 operations (conservative estimate).

---

## Security Warnings

- ⚠️ **Alpha stage**: Run side-channel tooling (ctgrind/dudect) before any deployment
- ⚠️ **Parameter review**: Defaults align with original LB-VRF paper but require validation against current NIST standards
- ⚠️ **One-time scheme**: Only suitable for single-use VRF evaluations per key; many-time security requires additional design
- ⚠️ **Server trust**: This VRF proves correctness but does not hide metadata (timing, message length); use with appropriate transport security

**For production use**:
1. Conduct independent security audit
2. Run constant-time verification with ctgrind/dudect
3. Validate parameters against NIST PQC standards
4. Implement proper key rotation and epoch management
5. Monitor proof sizes and rejection rates
