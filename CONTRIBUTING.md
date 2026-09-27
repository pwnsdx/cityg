# Contributing to City-G

City-G is a research protocol for end-to-end encrypted groups of millions
of members with post-quantum primitives. Its profile is `city-g/v0.4`,
specified in [`docs/specs.md`](docs/specs.md). The draft of the next
profile, `city-g/v0.5-draft`, is a delta on it in
[`docs/specs-v0.5-draft.md`](docs/specs-v0.5-draft.md), whose first stage
`cityg-core` implements. The [design note](docs/design.md) explains their
choices and the [glossary](docs/GLOSSARY.md) defines their terms.

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
| `docs/specs.md` | Specification of `city-g/v0.4`. |
| `docs/specs-v0.5-draft.md` | Draft of `city-g/v0.5-draft`, a delta on v0.4 in three stages; stage 1 and the tasks of stage 2 are implemented. |
| `docs/design.md` | Design decisions E-1 to E-17. |
| `crates/cityg-pqc` | ML-DSA-65 (FIPS 204) with per-usage contexts. |
| `crates/cityg-core` | Protocol core without I/O and an in-memory delivery service. Its module documentation lists the layers, from deterministic CBOR up to members and the delivery service. |
| `crates/cityg-core/tests/scenarios.rs` | Whole groups on the in-memory delivery service. |
| `crates/cityg-core/tests/islands.rs` | Island followers, relays, flat elements and refreshes, and urgent and ordinary removals (stage 1 of the v0.5 draft). |
| `crates/cityg-core/tests/tasks.rs` | Tasks: sub-cities and the top re-keyed by their performers, joiners performing the tasks of the window they enter, order, failover, taints and welcomes, and a sealer that draws nothing (stage 2 of the v0.5 draft). |
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
- Register new labels and contexts (specs.md, section 17, and section 5 of
  the v0.5 draft); the context of a signed array is its label.
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
- the adaptive argument of the proof of the whole tree, with random
  oracles: the game, the safety predicate and the steps, each with its
  mechanized lemma, are in
  [`docs/research/preuve-arbre-2026-09-26.md`](docs/research/preuve-arbre-2026-09-26.md);
  and an analysis of BLAKE3's keyed mode as a dual PRF;
- a zero-knowledge proof without setup that an X-Wing wrap does not open
  in its context, for the disputes proposed in
  [`docs/research/rekey-serveur-2026-09-26.md`](docs/research/rekey-serveur-2026-09-26.md):
  [`docs/research/dispute-zk/`](docs/research/dispute-zk/README.md)
  measures the whole statement with VOLE-based proofs (2 MB without the
  X25519 half, 23 MB with it, most of it the setup of the field of X25519,
  see
  [`docs/research/litige-x25519-2026-09-26.md`](docs/research/litige-x25519-2026-09-26.md)),
  and, without setup, the X25519 half and the hashing with Longfellow (158
  and 552 KB, see
  [`docs/research/litige-sans-mise-en-place-2026-09-26.md`](docs/research/litige-sans-mise-en-place-2026-09-26.md)),
  then the whole first branch in one field (573 KB, 1.49 s to prove, see
  [`docs/research/litige-entier-2026-09-26.md`](docs/research/litige-entier-2026-09-26.md)),
  and the second branch (787 KB, 3.72 s to prove, see
  [`docs/research/litige-deux-branches-2026-09-27.md`](docs/research/litige-deux-branches-2026-09-27.md));
  what remains is a measurement on a phone.

## Review

Maintainers review for correctness, security, tests and documentation, and
may ask for changes. Protocol changes need a specification update reviewed
before the code. Large changes are best discussed in an issue first.

## Getting help

- Questions and ideas: GitHub Discussions.
- Bugs: GitHub Issues (not for vulnerabilities).
- Documentation: [`docs/README.md`](docs/README.md).

Thank you for contributing.
