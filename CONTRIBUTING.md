# Contributing to City-G

City-G is a research protocol for end-to-end encrypted groups of millions
of members with post-quantum primitives. Its profile is `city-g/v0.4`,
specified in [`docs/specs.md`](docs/specs.md); the
[design note](docs/design.md) explains its choices and the
[glossary](docs/GLOSSARY.md) defines its terms.

## Code of conduct

Be respectful and constructive, focus on technical merit and correctness,
help newcomers, and report concerning behavior to the maintainers.

## Getting started

Prerequisites: a recent stable Rust toolchain (the workspace uses edition
2024) and Git. ProVerif 2.05 runs the symbolic model; CryptoVerif 2.13
runs the computational research model; Python 3 runs the cost models;
emp-toolkit and CMake build the research prover of wrap disputes.

```bash
git clone https://github.com/pwnsdx/cityg.git
cd cityg
cargo test --workspace                     # unit and scenario tests
./scripts/verify_no_secrets.sh             # delivery-service guardrail
docs/formal/run.sh /path/to/proverif       # symbolic model
```

### Where things are

| Path | Content |
| --- | --- |
| `docs/specs.md` | Specification. |
| `docs/design.md` | Design decisions E-1 to E-14. |
| `crates/cityg-pqc` | ML-DSA-65 (FIPS 204) with per-usage contexts. |
| `crates/cityg-core` | Protocol core without I/O and an in-memory delivery service. Its module documentation lists the layers, from deterministic CBOR up to members and the delivery service. |
| `crates/cityg-core/tests/scenarios.rs` | Whole groups on the in-memory delivery service. |
| `crates/cityg-core/tests/scale.rs` | A large window on a full group, against the cost model (release, `--ignored`). |
| `docs/formal/` | Symbolic model of the security choices. |
| `docs/research/` | Research notes (in French), cost models, benchmarks, a zero-knowledge prover, and symbolic and computational models of the proposals. |

## Workflow

1. Branch from `main` (`feature/...`, `fix/...`).
2. Make the change with its tests.
3. Run the local CI, which mirrors the GitHub workflow:

   ```bash
   ./scripts/setup-git-hooks.sh          # once: blocks pushes that fail the checks
   ./scripts/ci/local-ci.sh              # fmt, strict clippy, tests, guardrail, scale test, model
   CITYG_FAST=1 ./scripts/ci/local-ci.sh # fmt, clippy and tests only
   ```

4. Write commit messages that say what changed and why; for protocol
   changes, cite the sections of the specification.
5. Open a pull request with the template's checklist.

## Rules for changes

### Everything

- `cargo fmt --all` and the strict clippy set of the CI (no `unwrap`,
  `expect`, `panic!`, `todo!` or `unimplemented!` outside tests).
- Tests with the change.
- No `unsafe`.
- Update the documentation the change affects and `CHANGELOG.md`.

### Protocol changes

The specification comes first; the code implements it.

- Any change to an encoding, a label, a signature context, an algorithm or
  a parameter is a **new profile version**.
- Register new labels and contexts (specs.md, section 17); the context of a
  signed array is its label.
- Record a design decision in `docs/design.md` when the change makes one.
- Update the symbolic model in `docs/formal/` if the change touches the key
  schedule, taints, removals, joins and welcomes, entrants or open groups.
- Run the scale test if the change touches the tree, the re-key or the
  delivery service.

### Security-critical code

- The public modules of `cityg-core` that the delivery service and auditors
  run (`ds`, `window`, `audit`, `packet`, `registry`, `smm`, `tree`) never
  name a secret-holding type; `scripts/verify_no_secrets.sh` checks it
  syntactically.
- Secrets are zeroized on drop, never logged, and compared in constant time.
- Every decoded object is re-encoded and compared byte for byte; relayed
  objects are never re-encoded.
- Randomness comes from a caller-provided CSPRNG (seeded in tests).
- See [`docs/security-review-checklist.md`](docs/security-review-checklist.md).

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Research contributions

We are especially interested in:

- a model of the whole specification and computational proofs of the taint
  rule, the init chain and anchored joins;
- a message plane and the guarantees of MLS for millions of members: the
  proposals of
  [`docs/research/plan-de-messages-2026-09-26.md`](docs/research/plan-de-messages-2026-09-26.md)
  and [`docs/research/parite-mls-2026-09-26.md`](docs/research/parite-mls-2026-09-26.md)
  need a specification, computational proofs and an implementation;
- cryptanalysis of the construction and of its parameter choices;
- side-channel analysis of the ML-KEM and ML-DSA backends;
- reducing what members download and what committers send;
- a specification and an implementation of the îlots of
  [`docs/research/ilots-2026-09-26.md`](docs/research/ilots-2026-09-26.md),
  and an analysis of a multi-recipient KEM for their top;
- a computational proof of the whole tree under adaptive corruptions,
  with random oracles, following the plan of
  [`docs/research/preuves-et-mesures-2026-09-26.md`](docs/research/preuves-et-mesures-2026-09-26.md)
  (section 4), whose lemmas are the fixed configurations of
  [`docs/research/formal-computational/`](docs/research/formal-computational/README.md);
  and an analysis of BLAKE3's keyed mode as a dual PRF;
- the X25519 half of the zero-knowledge proof that an X-Wing wrap does not
  open in its context, for the disputes proposed in
  [`docs/research/rekey-serveur-2026-09-26.md`](docs/research/rekey-serveur-2026-09-26.md):
  the rest is measured by
  [`docs/research/dispute-zk/`](docs/research/dispute-zk/README.md) (under
  a second and 2 MB); X25519 needs a proof over its own field, then a
  measurement on a phone.

## Review

Maintainers review for correctness, security, tests and documentation, and
may ask for changes. Protocol changes need a specification update reviewed
before the code. Large changes are best discussed in an issue first.

## Getting help

- Questions and ideas: GitHub Discussions.
- Bugs: GitHub Issues (not for vulnerabilities).
- Documentation: [`docs/README.md`](docs/README.md).

Thank you for contributing.
