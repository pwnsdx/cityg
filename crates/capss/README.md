# CAPSS: A Framework for SNARK-Friendly Post-Quantum Signatures

This crate implements **CAPSS/Smallwood**, a hash-based polynomial commitment scheme with zero-knowledge proofs used for server-blind validation in City-G's forward secrecy protocol.

## What is CAPSS/Smallwood?

CAPSS provides:
- **Deterministic proof of knowledge**: Proves that `hp` (hash projection key) was derived deterministically from a seed
- **Forward secrecy binding**: Cryptographically binds FS metadata (epoch commit, device chain) to prevent tampering
- **Server-blind validation**: Proofs (~12KB typical, ≤16KB) can be verified without learning secrets

In City-G, CAPSS Smallwood transcripts appear in anchor headers at field `146: fs_capss`, enabling the server to validate that forward secrecy parameters are correctly derived without decrypting the epoch keys.

## Architecture

```
CAPSS (High-level trait interface)
  └── SmallwoodProver/Verifier (Real cryptographic proofs)
       │
       └── Smallwood Protocol (src/smallwood/mod.rs)
            ├── DECS: Distributed Encrypted Commitment Scheme
            │   └── Merkle tree + polynomial commitment
            ├── LVCS: Linear Verifiable Commitment Scheme
            │   └── Layout management + opening proofs
            └── PACS: Polynomial Algebraic Constraint System
                └── ExamplePACS: x^(2^4) = y relation (test system)
```

## Port from Sage/Python Reference

**This is a Rust port of a canonical Sage/Python implementation.**

### Reference Implementations

- **Sage/Python reference**: `vendor/smallwood-python/` (git submodule with the canonical specification)
  - Override the location by setting the `SMALLWOOD_PYTHON_PATH` environment variable
  - Uses SageMath for field arithmetic and polynomial operations
  - Authoritative for mathematical correctness

- **Rust production port**: This crate (`crates/capss`)
  - Performance-oriented implementation
  - Maintains bit-for-bit compatibility via fixture tests
  - Adds production improvements (constant-time operations, no-std support)

### Why Two Implementations?

This dual-reference approach is standard practice for cryptographic protocols:

1. **Sage reference** = Mathematical correctness
   - Easy to verify algebraically
   - Matches paper definitions directly
   - Slower but obviously correct

2. **Rust port** = Production performance
   - Optimized for speed and memory
   - Adds side-channel resistance
   - Suitable for embedded/constrained environments

3. **Cross-language testing** ensures they agree:
   - Python generates JSON fixtures
   - Rust tests validate against fixtures
   - Any divergence is caught immediately

### Reference Implementation Structure

The Python reference at `vendor/smallwood-python/` mirrors this crate's structure:

```
smallwood-python/                      crates/capss/
├── smallwood/                         ├── src/smallwood/
│   ├── commit/                       │   ├── commit.rs
│   │   ├── decs/decs.py             │   ├── decs.rs
│   │   └── merkle/instance.py       │   └── merkle.rs
│   ├── pacs/                         │   └── pacs/
│   │   └── tests/examplepacs.py     │       └── example.rs
│   ├── shake.py                      │   └── (uses sha3 crate)
│   └── smallwood.py                  │   └── mod.rs
└── utils/polynomial.py               └── polynomial.rs
```

## Testing & Verification

### Fixture-Based Regression Testing

The crate uses **cross-language fixture testing** to ensure the Rust port matches the Sage reference:

```
┌─────────────────────────────────────────────────────────────┐
│  Fixture Generation Workflow                                │
└─────────────────────────────────────────────────────────────┘

1. Sage Reference                    2. Rust Implementation
   (vendor/smallwood-python)             (crates/capss)
           │                                    │
           v                                    v
   prove(statement)                     prove(statement)
           │                                    │
           v                                    v
   Python generates JSON            Rust reads JSON fixture
   fixture with proof               and compares outputs
           │                                    │
           v                                    v
   tests/fixtures/                      assert_eq!(
     python_smallwood.json                rust_proof,
                                          python_proof
                                        )
```

### Running the Tests

```bash
# Run all tests (uses checked-in fixtures)
cargo test -p capss

# Specific fixture tests
cargo test -p capss python_fixture
cargo test -p capss smallwood_fixture

# Regenerate fixtures from Sage reference (requires SageMath)
sage -python scripts/export_python_smallwood.py

# Note: The generate_smallwood_fixture example has been removed.
# If you need to regenerate fixtures and the Sage reference is unavailable,
# you can restore it from git history:
# git show 6f8ef39~1:crates/capss/examples/generate_smallwood_fixture.rs > \
#   crates/capss/examples/generate_smallwood_fixture.rs
```

### Fixture Files

- `tests/fixtures/smallwood_fixture.json` - Rust-generated baseline fixture (committed)
- `tests/fixtures/python_smallwood.json` - Sage reference fixture (committed, regenerated via script)
- `tests/fixtures/example_pacs_python.json` - PACS-specific test vectors (committed)

**Note**: Fixture generation examples (`generate_smallwood_fixture`, `dump_smallwood_polys`) have been removed from the codebase as they are development-only tools. The committed fixtures are sufficient for testing. If you need to regenerate fixtures, restore the examples from git history or use the Sage reference via `export_python_smallwood.py`.

The test at `tests/python_fixture.rs:49` ensures:
```rust
assert_eq!(proof_json, proof_python, "python and rust transcripts diverge");
```

This provides **deterministic cross-language verification** - if the Rust port diverges from the mathematical reference, tests fail immediately.

## Key Implementation Details

### DECS (Distributed Encrypted Commitment Scheme)

At `src/smallwood/decs.rs:39`:
- Merkle tree with Shake128 hashing
- Polynomial masking (eta mask polynomials)
- Challenge derivation: Uniform, Powers, or Hybrid modes
- Constant-time index operations (side-channel resistance)

### LVCS (Linear Verifiable Commitment Scheme)

At `src/smallwood/lvcs.rs:19`:
- Layered over DECS with layout management
- Matrix operations for opening verification
- Interpolation-based polynomial reconstruction
- Linear algebra for fullrank column solving

### PACS (Polynomial Algebraic Constraint System)

At `src/smallwood/pacs/example.rs:7`:
- Defines constraint relations for witness data
- Example: "I know x such that x^(2^4) = y"
- Witness matrix: `[[x, x^4], [x^2, x^8], [x^4, x^16]]`
- Used for testing the full proof pipeline

### Proof Sizes

Proof sizes are deterministic and validated:
- Commitment: `digest_bytes + eta*(degree+1)*field_bytes`
- Metadata: `salt_bytes` (typically 16 bytes)
- Evaluations: `nb_queries * nb_polys * 32 bytes`
- Opening proof: Merkle paths + epsilon polynomials + LVCS data

Typical sizes with default config:
- ~12KB for production parameters
- ≤16KB maximum (enforced by protocol)

## Development Workflow

### Making Changes to CAPSS

When modifying the implementation:

1. **Check if it affects correctness**:
   - Does it change proof generation or verification logic?
   - Does it affect serialization or field operations?

2. **If yes, update the Sage reference first**:
   - Modify `vendor/smallwood-python/`
   - Regenerate fixtures: `sage -python scripts/export_python_smallwood.py`
   - Port changes to Rust
   - Verify tests pass

3. **If no (optimization/style only)**:
   - Make Rust changes directly
   - Ensure fixture tests still pass
   - Document the deviation if visible behavior changes

### Adding New PACS Instances

To add a new constraint system beyond ExamplePACS:

1. Implement in Python: `vendor/smallwood-python/smallwood/pacs/`
2. Add fixture generation in `scripts/export_python_example_pacs.py`
3. Port to Rust: `src/smallwood/pacs/your_pacs.rs`
4. Add cross-language fixture test
5. Implement `Pacs` trait

### Code Style

- **Prefer clarity over cleverness**: This is cryptographic code
- **Add mathematical context**: Reference paper sections where applicable
- **Use descriptive names**: `gamma` not `g`, `mask_polys` not `mp`
- **Comment non-obvious invariants**: Especially in LVCS matrix operations

## Integration with City-G

CAPSS is used in City-G's forward secrecy protocol:

```rust
use capss::{CapssContext, CapssConfig, smallwood_prover, smallwood_verifier};

// Create context (client or server)
let config = CapssConfig::default();
let context = CapssContext::new(config, public_key);

// Client: Generate proof
let prover = smallwood_prover(context.clone());
let signature = prover.prove(&statement)?;

// Server: Verify proof (blind - never learns hp, Y*, E_k)
let verifier = smallwood_verifier(context);
verifier.verify(&statement, &signature)?;
```

The server validates the CAPSS Smallwood transcript at `accept_anchor()` without learning:
- `hp` (hash projection key) - encrypted in KBROAD
- `Y*` (VRF output) - hidden by ZK-VRF
- `E_k` (epoch key) - derived client-side

## References

### Academic Background

- **Smallwood**: Hash-based polynomial commitment with linear algebraic opening proofs
- **Fiat-Shamir**: Non-interactive zero-knowledge via challenge hashing
- **DECS**: Merkle commitment with polynomial masking for soundness amplification

### Related Documentation

- City-G protocol spec: `../../docs/specs-unified-fs.md`
- Forward secrecy design: `../../docs/protocol/04-forward-secrecy.md`
- Proof systems overview: `../../docs/protocol/06-proof-systems.md`

### External References

This implementation is compatible with the CAPSS specification used in:
- City-G anchor headers (field 146: `fs_capss`)
- Server acceptance validation (`msphf-orchestrator/src/accept/`)

## Performance

Benchmark support for this crate is still pending upstream integration. Run-time
figures will be published once the benchmarking harness lands.

## Security Considerations

### Soundness

- **ROM (Random Oracle Model)**: Security assumes hash functions behave as random oracles
- **Soundness error**: Configurable via `repetitions` parameter
- **Challenge space**: Determined by `security_level` (default: 128 bits)

### Side-Channel Resistance

- `find_index()` uses constant-time masking (decs.rs:495)
- Field operations depend on `ark-ff` constant-time guarantees
- Polynomial evaluations: not constant-time (acceptable for public polynomials)

### Post-Quantum Security

1. **Post-quantum secure**: Uses quantum-resistant hash functions
   - **BLAKE3**: Based on ChaCha20 core, no known quantum attacks better than Grover's algorithm
   - **SHAKE128**: Part of SHA-3 family, explicitly designed for quantum resistance
   - Security relies on binding properties and Fiat-Shamir transforms, not collision resistance

### Practical Considerations

1. **Proof size**: ~12KB per anchor
   - Acceptable for server-blind validation
   - May be large for bandwidth-constrained clients

2. **Verification cost**: Non-trivial
   - Matrix operations in LVCS opening
   - Multiple Merkle path verifications
   - Consider batching for high-throughput scenarios

## Contributing

Contributions must preserve cross-language compatibility:

1. Run tests: `cargo test -p capss`
2. Verify fixtures: `cargo test -p capss python_fixture`
3. Check formatting: `cargo fmt -p capss`
4. Run clippy: `cargo clippy -p capss`
5. If modifying proof logic, regenerate fixtures and commit

For questions about the Sage reference implementation, see `vendor/smallwood-python/README.md` (if available).

## License

This crate is part of City-G and licensed under the MIT License. See the repository root LICENSE file.

---

**Note**: This is research-grade alpha software (City-G v0.1.0). While the Sage reference provides mathematical confidence, independent security review is required before production use.
> 💡 After cloning the repository, run
> `git submodule update --init --recursive`
> to fetch the reference implementation into `vendor/smallwood-python/`.
