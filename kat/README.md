# Known-answer tests and conformance map

This directory holds the conformance material of profile `city-g/v0.2`,
specified in [`docs/specs.md`](../docs/specs.md).

| File | Content |
| --- | --- |
| [`v0.2/vectors.json`](v0.2/vectors.json) | Known-answer vectors: deterministic CBOR, `H_L`, the KDF functions, the identifiers, the key schedule and external init, the roster hash, a path-secret wrap, a complete genesis commit with its GroupInfo and two messages, and every signed-array layout. |
| [`v0.2/verify_vectors.py`](v0.2/verify_vectors.py) | Independent verifier: recomputes the vectors from the specification without sharing code with the Rust implementation. |
| [`kat-v0.2-conformance-manifest.json`](kat-v0.2-conformance-manifest.json) | Requirement map: each requirement of the specification, with its section, the vectors and the tests that exercise it, and the audit items it closes. |
| [`legacy/v0.1.4/`](legacy/v0.1.4/) | Archived files of profile v0.1.4, which nothing reads any more. |

## Vectors

The reference implementation computes every vector from fixed inputs and
seeded randomness (`crates/cityg-core/tests/vectors.rs`) and compares the
result with the published file:

```bash
cargo test -p cityg-core --test vectors
```

After an intended change of the profile, regenerate the file and review the
diff:

```bash
CITYG_WRITE_VECTORS=1 cargo test -p cityg-core --test vectors
```

The independent verifier re-implements deterministic CBOR, the BLAKE3
derivations, ChaCha20-Poly1305 and the hashes of the tree, roster and
transcripts. It checks every value, decrypts the two messages of the genesis
epoch and checks that non-deterministic CBOR encodings are rejected. ML-KEM
and ML-DSA outputs appear as data (keys, ciphertexts, shared secrets,
signatures): their correctness is the subject of the FIPS 203 and FIPS 204
test vectors of the underlying libraries.

```bash
python3 -m pip install blake3
python3 kat/v0.2/verify_vectors.py
```

CI runs both.

## Conformance manifest

Each entry of `kat-v0.2-conformance-manifest.json` has:

* `id` and `title`: the requirement;
* `spec`: anchors of the sections of `docs/specs.md` that state it;
* `vectors`: JSON pointers into `v0.2/vectors.json` (`#id` selects the
  element of an array with that `id`);
* `tests`: tests of the reference implementation, by nextest binary id
  (`crate`, `crate::integration_test` or `crate::bin/name`) and test path;
* `checks`: scripts that check it (optional);
* `audit`: findings and proposals of
  [the 2026-09-25 audit](../docs/audits/audit-crypto-conformite-2026-09-25.md)
  that it closes.

`crates/cityg-core/tests/conformance_manifest.rs` checks that every section,
vector, test, script and audit item named in the manifest exists, that every
normative section and every vector section is cited, and that every test of
`cityg-core` is mapped to a requirement:

```bash
cargo test -p cityg-core --test conformance_manifest
```
