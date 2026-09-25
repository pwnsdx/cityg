# Contributing to City-G

City-G is a research protocol for end-to-end encrypted groups with
post-quantum primitives. Its current profile is `city-g/v0.3`, specified in
[`docs/specs.md`](docs/specs.md); the [design note](docs/design-v0.3.md)
explains its choices and the [glossary](docs/GLOSSARY.md) defines its
terms.

## Code of conduct

Be respectful and constructive, focus on technical merit and correctness,
help newcomers, and report concerning behavior to the maintainers.

## Getting started

Prerequisites: a recent stable Rust toolchain (the workspace uses edition
2024), Git, and for the GUI on Linux the packages `pkg-config libxcb1-dev
libxkbcommon-dev libxkbcommon-x11-dev`. Python 3 with the `blake3`,
`kyber-py` and `dilithium-py` packages runs the independent vector check.

```bash
git clone https://github.com/pwnsdx/cityg.git
cd cityg
cargo test --workspace                                  # every crate
cargo test -p cityg-gui --features native-app           # the GUI
./scripts/verify_no_secrets.sh --no-build               # server-blindness guardrail
python3 -m pip install blake3 kyber-py dilithium-py && python3 kat/v0.3/verify_vectors.py
```

### Where things are

| Path | Content |
| --- | --- |
| `docs/specs.md` | Normative specification. |
| `crates/cityg-pqc` | ML-DSA-65 (FIPS 204) with per-usage contexts. |
| `crates/cityg-core` | Protocol core without I/O: encodings, KDF, X-Wing, tree and leaf proofs, key schedule, commits, admission, joins and welcomes, messages, full and light member sessions, delivery-service ledger. |
| `crates/cityg-proto` | Protobuf schema and routes of the `/v3` API. |
| `crates/cityg-server` | Rooms of the delivery service: log, journal, stores. |
| `crates/cityg-runtime` | Request handlers and sessions, shared by the two transports. |
| `crates/cityg-api` | Native HTTP server. |
| `crates/cityg-worker` | Cloudflare Worker (one Durable Object per room). |
| `crates/cityg-api-client` | HTTP client and member drivers (full and light). |
| `crates/cityg-gui` | Desktop client and the `join_leave` CLI. |
| `crates/cityg-stress` | Load and chaos tool. |
| `crates/cityg-config` | Configuration. |
| `kat/` | Conformance vectors, independent verifier, requirement map. |
| `docs/formal/` | Symbolic model of the protocol. |

## Workflow

1. Branch from `main` (`feature/...`, `fix/...`).
2. Make the change with its tests.
3. Run the local CI, which mirrors the GitHub workflow:

   ```bash
   ./scripts/setup-git-hooks.sh          # once: blocks pushes that fail the checks
   ./scripts/ci/local-ci.sh              # fmt, strict clippy, tests, guardrail, wasm, GUI, builds
   CITYG_FAST=1 ./scripts/ci/local-ci.sh # fmt, clippy and tests only
   ```

4. Write commit messages that say what changed and why; for protocol
   changes, cite the sections of the specification.
5. Open a pull request with the template's checklist.

## Rules for changes

### Everything

- `cargo fmt --all` and the strict clippy set of the CI (no `unwrap`,
  `expect`, `panic!`, `todo!` or `unimplemented!` outside tests).
- Tests with the change; coverage must not drop.
- No `unsafe` in protocol crates.
- Update the documentation the change affects and `CHANGELOG.md`.

### Protocol changes

The specification comes first; the code implements it.

- Any change to an encoding, a label, a signature context, an algorithm or
  a parameter is a **new profile version**: it changes `city-g/v0.3` and
  every vector.
- Register new labels and contexts (specs.md, section 17).
- Regenerate the vectors, review the diff, and keep the independent verifier
  in step:

  ```bash
  CITYG_WRITE_VECTORS=1 cargo test -p cityg-core --test vectors
  python3 kat/v0.3/verify_vectors.py
  ```

- Map each new requirement in `kat/kat-v0.3-conformance-manifest.json` to
  its section, its vectors, its tests and its origin. `cargo test -p cityg-core --test
  conformance_manifest` fails if a section, a vector section or a test of
  `cityg-core` is left out.
- Update the formal model in `docs/formal/` if the change touches the key
  schedule, joins and welcomes, the tree, removal, admission or key
  rotation.

### Security-critical code

- The server-side crates (`cityg-server`, `cityg-runtime`, `cityg-api`,
  `cityg-worker`) must never use member-side, secret-holding types;
  `scripts/verify_no_secrets.sh` checks it syntactically.
- Secrets are zeroized on drop, never logged, and compared in constant time.
- Every decoded object is re-encoded and compared byte for byte; relayed
  objects are never re-encoded.
- Randomness comes from a caller-provided CSPRNG (seeded in tests).
- See [`docs/security-review-checklist.md`](docs/security-review-checklist.md).

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## Research contributions

We are especially interested in:

- extending the symbolic model (`docs/formal/`) and computational proofs of
  the key schedule and the tree;
- cryptanalysis of the construction and of its parameter choices;
- side-channel analysis of the ML-KEM and ML-DSA backends and of the
  constant-time comparisons;
- scaling beyond `MAX_N_MAX` (sub-groups, federation) and reducing commit
  sizes.

## Review

Maintainers review for correctness, security, tests and documentation, and
may ask for changes. Protocol changes need a specification update reviewed
before the code. Large changes are best discussed in an issue first.

## Getting help

- Questions and ideas: GitHub Discussions.
- Bugs: GitHub Issues (not for vulnerabilities).
- Documentation: [`docs/README.md`](docs/README.md).

Thank you for contributing.
