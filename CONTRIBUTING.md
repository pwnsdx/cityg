# Contributing to City-G

Thank you for your interest in contributing to City-G! We welcome contributions from researchers, engineers, and developers.

> Last updated: **12 Nov 2025** (City-G v0.1.0). Need to brush up on terminology such as anchors, epochs, or server-blindness? See the [Glossary](docs/GLOSSARY.md) for quick definitions.

This guide will help you understand our development process, coding standards, and how to submit contributions effectively.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Workflow](#development-workflow)
4. [Contribution Guidelines](#contribution-guidelines)
5. [Testing Requirements](#testing-requirements)
6. [Documentation Standards](#documentation-standards)
7. [Security Considerations](#security-considerations)
8. [Research Contributions](#research-contributions)
9. [Review Process](#review-process)

---

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please:

- Be respectful and constructive in all interactions
- Focus on technical merit and correctness
- Welcome newcomers and help them learn
- Report any concerning behavior to the maintainers

---

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Rust toolchain** (1.70 or newer): [Install Rust](https://rustup.rs/)
- **Git** for version control
- **Basic understanding** of cryptographic protocols (for protocol changes)

### Setup Your Environment

```bash
# Clone the repository
git clone https://github.com/pwnsdx/cityg.git
cd cityg

# Build the project
cargo build --all

# Run tests to verify your setup
cargo test --all

# Run security checks
./scripts/verify_no_secrets.sh
```

### Understanding the Codebase

Before making changes, familiarize yourself with:

1. **[Protocol Overview](docs/protocol/01-overview.md)** - High-level architecture
2. **[Specification](docs/specs.md)** - Normative protocol specification
3. **[Security Model](docs/protocol/10-security-model.md)** - Threat model and guarantees
4. **[Implementation Guide](docs/protocol/11-implementation-guide.md)** - Code structure walkthrough

---

## Development Workflow

### 1. Create a Feature Branch

Always work on a dedicated branch:

```bash
# Create and switch to a new branch
git checkout -b feature/improve-sphf

# Or for bug fixes
git checkout -b fix/merkle-witness-validation
```

**Branch naming convention:**
- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `test/description` - Test improvements

### 2. Make Your Changes

```bash
# Edit source files
vim crates/msphf-core/src/rlwe/mod.rs

# Add corresponding tests
vim crates/msphf-core/tests/rlwe_kat.rs

# Update documentation if needed
vim docs/protocol/02-cryptographic-primitives.md
```

### 3. Verify Compliance

Before committing, run all checks:

```bash
# One-time setup: block pushes unless local CI parity checks pass
./scripts/setup-git-hooks.sh

# Run the same strict checks used by GitHub workflows
./scripts/ci/local-ci.sh

# Optional overrides for constrained environments
CITYG_SKIP_GUI=1 ./scripts/ci/local-ci.sh
CITYG_SKIP_DOCKER=1 ./scripts/ci/local-ci.sh
CITYG_SKIP_NEXTEST=1 ./scripts/ci/local-ci.sh
CITYG_FAST=1 ./scripts/ci/local-ci.sh
CITYG_DISABLE_PARITY_IMAGE_CACHE=1 ./scripts/ci/local-ci.sh
```

Notes:
- The first macOS run now builds a cached Linux parity image (`cityg/local-ci:rust-1.91-bookworm-v1`).
- Subsequent runs reuse that image plus Docker cargo cache volumes, which avoids repeated apt/tool bootstrap.
- `CITYG_FAST=1` runs fmt + strict clippy + cargo check (+ nextest unless skipped), then exits before secret scan/release builds/package tests.

### 4. Commit Your Changes

Write clear, descriptive commit messages:

```bash
# Good commit message
git commit -m "Optimize RLWE NTT implementation (§9, Annex C)

- Use AVX2 intrinsics for polynomial multiplication
- Add benchmark showing 2x speedup
- Maintain constant-time guarantees (verified with dudect)

Refs: docs/protocol/02-cryptographic-primitives.md"

# Reference spec sections for protocol changes
git commit -m "Fix witness validation for empty trees (§5.3)"
```

**Commit message guidelines:**
- First line: <80 characters, imperative mood ("Add", not "Added")
- Reference spec sections for protocol changes (§X.Y)
- Explain **why**, not just **what**
- Include performance impacts for optimizations
- Note security implications if relevant

### 5. Push and Create Pull Request

```bash
# Push your branch
git push origin feature/improve-sphf

# Create pull request on GitHub
# Include:
# - What changed and why
# - Test results
# - Performance impact (if applicable)
# - Breaking changes (if any)
```

---

## Contribution Guidelines

### General Principles

1. **Preserve Security Guarantees**
   - Never add secrets to `AcceptanceContext`
   - Maintain server-blindness properties
   - Run `./scripts/verify_no_secrets.sh` for server-side changes
   - Document any new security assumptions

2. **Maintain Determinism**
   - Use canonical CBOR encoding
   - Document any sources of non-determinism
   - Add tests verifying deterministic behavior

3. **Reference the Specification**
   - Cite spec sections for protocol changes (§X.Y, Annex Z)
   - Update specification if behavior changes
   - Keep code aligned with spec definitions

4. **Add Tests**
   - Known-Answer Tests (KATs) for crypto changes
   - Property-based tests for complex logic
   - Integration tests for API changes
   - Regression tests for bug fixes

5. **Update Documentation**
   - Protocol docs for protocol changes
   - API docs for public APIs
   - CHANGELOG.md for user-facing changes
   - README.md if setup/usage changes

### Specific Contribution Types

#### Cryptographic Changes

If modifying cryptographic code:

- [ ] Add Known-Answer Tests (KATs) from reference implementations
- [ ] Run constant-time verification (dudect/ctgrind)
- [ ] Document security parameters and assumptions
- [ ] Reference academic papers/standards (NIST FIPS, RFCs)
- [ ] Update threat model if applicable

**Example**: See `crates/msphf-lb-vrf/tests/` for KAT structure.

#### Protocol Changes

If modifying the protocol:

- [ ] Update specification: `docs/specs.md`
- [ ] Update protocol docs: `docs/protocol/*.md`
- [ ] Add migration path for breaking changes
- [ ] Consider backwards compatibility
- [ ] Update test vectors

#### Performance Optimizations

If improving performance:

- [ ] Add benchmarks showing improvement
- [ ] Verify correctness (existing tests still pass)
- [ ] Document trade-offs (memory vs. speed, etc.)
- [ ] Ensure constant-time properties preserved (for crypto code)
- [ ] Test on multiple platforms if using SIMD

#### Bug Fixes

If fixing a bug:

- [ ] Add regression test reproducing the bug
- [ ] Explain root cause in commit message
- [ ] Check for similar bugs elsewhere
- [ ] Update error messages if applicable
- [ ] Consider adding validation to prevent recurrence

#### Documentation

If updating documentation:

- [ ] Ensure accuracy (verify against code)
- [ ] Check all links work
- [ ] Use consistent terminology (see [Glossary](docs/GLOSSARY.md))
- [ ] Add examples where helpful
- [ ] Update "Last Updated" date

---

## Testing Requirements

All contributions must include appropriate tests.

### Running Tests

```bash
# Run all tests
cargo test --all

# Run specific crate tests
cargo test -p msphf-core

# Run with verbose output
cargo test --all -- --nocapture

# Run specific test
cargo test test_lbvrf_deterministic

# Run benchmarks (requires nightly for some crates)
cargo bench
```

### Test Types

#### Unit Tests

Test individual functions/modules:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_computation() {
        let leaves = vec![/* ... */];
        let root = compute_merkle_root(&leaves);
        assert_eq!(root, expected_root);
    }
}
```

#### Integration Tests

Test multi-component interactions:

```rust
// tests/integration/join_flow.rs
#[tokio::test]
async fn test_full_join_flow() {
    let server = setup_test_server().await;
    let client = create_test_client();

    let result = client.join_room("test-room").await;
    assert!(result.is_ok());
}
```

#### Known-Answer Tests (KATs)

For cryptographic code:

```rust
#[test]
fn test_lbvrf_kat_vector_1() {
    // Test vectors from reference implementation
    let secret_key = hex!("abcd...");
    let message = b"test message";
    let expected_output = hex!("1234...");

    let proof = LBVRF::prove(message, params, pk, sk, seed).unwrap();
    assert_eq!(proof.output, expected_output);
}
```

#### Property-Based Tests

For complex logic:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_merkle_consistency(leaves in prop::collection::vec(any::<[u8; 32]>(), 1..100)) {
        let root1 = compute_merkle_root(&leaves);
        let root2 = compute_merkle_root(&leaves);
        prop_assert_eq!(root1, root2, "Merkle root must be deterministic");
    }
}
```

### Test Coverage

We aim for:
- **>80% line coverage** for core protocol code
- **100% coverage** for security-critical paths
- **Known-Answer Tests** for all crypto primitives
- **Integration tests** for all API endpoints

---

## Documentation Standards

Good documentation is as important as good code.

### Code Documentation

Use Rust doc comments:

```rust
/// Computes the Merkle root from a list of leaf hashes.
///
/// # Arguments
/// * `leaves` - Vector of 32-byte leaf hashes
///
/// # Security
/// Uses BLAKE3 for hashing. O(n log n) time complexity.
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32]
```

### Protocol Documentation

When updating protocol docs:

1. **Be precise** - Define terms clearly
2. **Be complete** - Cover all cases and edge conditions
3. **Be consistent** - Use terminology from [Glossary](docs/GLOSSARY.md)
4. **Add examples** - Show concrete use cases
5. **Cross-reference** - Link to related sections

### Changelog

For user-facing changes, update `CHANGELOG.md`:

```markdown
## [Unreleased]

### Added
- New `pivot_refresh` API endpoint for forward secrecy rotation

### Changed
- Improved RLWE NTT performance by 2x using AVX2 intrinsics

### Fixed
- Fixed witness validation for empty Merkle trees (#123)

### Security
- Addressed timing side-channel in polynomial multiplication (GHSA-xxxx)
```

---

## Security Considerations

City-G is cryptographic software. Security is paramount.

### Security-Critical Code

Extra care is required when modifying:

- `crates/msphf-core` - Cryptographic primitives
- `crates/msphf-orchestrator/src/accept` - Server validation
- `crates/capss` - CAPSS Smallwood proofs
- `crates/msphf-lb-vrf` - VRF implementation

### Server-Blindness Verification

The `verify_no_secrets.sh` script ensures server code cannot decrypt:

```bash
./scripts/verify_no_secrets.sh

# Must pass with:
# ✓ No MlKemSecretKey in AcceptanceContext
# ✓ No ml_kem_decapsulate() in accept path
# ✓ All 10 checks passed
```

**If this fails after your changes, you've likely broken server-blindness!**

### Side-Channel Resistance

For constant-time requirements:

1. Use `subtle` crate for timing-sensitive comparisons
2. Avoid conditional branches on secrets
3. Test with dudect/ctgrind:
   ```bash
   # See docs/timing-verification.md
   cargo build --release
   # Run dudect tests
   ```

### Reporting Security Issues

**Do not report security vulnerabilities publicly!**

See [SECURITY.md](SECURITY.md) for our coordinated disclosure process.

---

## Research Contributions

We especially welcome research contributions in:

### Formal Verification
- Coq/Lean proofs of protocol properties
- Verification of cryptographic soundness
- Model checking for concurrency bugs

### Cryptographic Analysis
- RLWE-HPS security analysis
- Post-quantum security evaluation
- Alternative SPHF instantiations
- Zero-knowledge proof optimizations

### Performance Optimization
- SIMD optimizations (AVX2/NEON)
- Constant-time implementations
- Memory efficiency improvements
- Parallelization strategies

### Side-Channel Analysis
- Timing attack analysis (dudect/ctgrind)
- Cache attack resistance
- Power analysis (if hardware testing available)

### Scalability Research
- Multi-million member simulations
- Network latency analysis
- Distributed deployment patterns

---

## Review Process

### What to Expect

1. **Automated Checks** (CI)
   - Formatting (`cargo fmt`)
   - Linting (`cargo clippy`)
   - Tests (`cargo test --all`)
   - Server-blindness verification
   - Documentation builds

2. **Maintainer Review**
   - Code quality and style
   - Test coverage
   - Documentation completeness
   - Security implications
   - Spec alignment

3. **Discussion**
   - May request changes or clarifications
   - Feedback is meant to improve quality
   - Be patient and responsive

### Timelines

- **Initial review**: Within 1 week
- **Follow-up reviews**: 2-3 days
- **Merge**: When all checks pass and reviewers approve

### Large Changes

For substantial changes:

1. **Open an issue first** to discuss approach
2. **Share design doc** for architectural changes
3. **Prototype** to validate feasibility
4. **Incremental PRs** if possible (easier to review)

---

## Getting Help

### Resources

- **[Documentation](docs/README.md)** - Start here
- **[FAQ](docs/protocol/17-faq.md)** - Common questions
- **[Glossary](docs/GLOSSARY.md)** - Terminology reference
- **[GitHub Issues](https://github.com/pwnsdx/cityg/issues)** - Bug reports and feature requests

### Communication

- **GitHub Issues** - Bug reports, feature requests
- **GitHub Discussions** - General questions, ideas
- **Email** - Security issues only (see SECURITY.md)

### Asking Questions

When asking questions:

1. **Search first** - Check docs, issues, and discussions
2. **Be specific** - Include error messages, code snippets, logs
3. **Show effort** - Explain what you've tried
4. **Minimal example** - Reduce to simplest reproduction

---

## Thank You!

Your contributions help make City-G better for everyone. Whether you're:

- Fixing a typo in documentation
- Reporting a bug you found
- Implementing a new feature
- Conducting security research

...every contribution is valuable. Thank you for being part of the City-G community!

---

**See also:**
- [Main README](README.md) - Project overview
- [Security Policy](SECURITY.md) - Vulnerability reporting
- [License](LICENSE) - MIT License

**Last Updated**: 2025-11-12
