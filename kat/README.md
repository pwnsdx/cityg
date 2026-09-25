# Known-answer tests and conformance map

This directory holds the conformance material of profile `city-g/v0.3`,
specified in [`docs/specs.md`](../docs/specs.md).

| File | Content |
| --- | --- |
| [`v0.3/vectors.json`](v0.3/vectors.json) | Known-answer vectors: deterministic CBOR, `H_L`, the KDF functions, the X-Wing draft vector and ML-DSA-65 signatures, the identifiers, the key schedule (joiner secret, external init, transcript with a key rotation), a sample ratchet tree with its hash, resolutions and leaf proofs, the registry hash (with and without a retired floor), a path-secret wrap, a welcome, a complete genesis commit with its GroupInfo and two messages, every signed-array layout, and a LightCommit and LightJoin. |
| [`v0.3/verify_vectors.py`](v0.3/verify_vectors.py) | Independent verifier: recomputes the vectors from the specification without sharing code with the Rust implementation. |
| [`kat-v0.3-conformance-manifest.json`](kat-v0.3-conformance-manifest.json) | Requirement map: each requirement of the specification, with its sections, the vectors and the tests that exercise it, and the audit items or design decisions it comes from. |
| [`legacy/v0.2/`](legacy/v0.2/) | Vectors, verifier and manifest of profile v0.2, which nothing reads any more. |
| [`legacy/v0.1.4/`](legacy/v0.1.4/) | Archived files of profile v0.1.4. |

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
derivations, ChaCha20-Poly1305 and X25519 (checked against the examples of
RFC 8439 and RFC 7748 before use), and the hashes of the tree, leaf proofs,
registry and transcripts. It takes ML-KEM-768 and ML-DSA-65 from
libraries that share no code with the Rust implementation (`kyber-py` and
`dilithium-py`), builds X-Wing from them and checks the X-Wing draft
vector. It then checks every value: it derives the path-wrap and welcome
keys, decapsulates and opens both, verifies every signature under its
context, recomputes the genesis tree hash, registry hash, transcript hashes
and confirmation tag, verifies the leaf proofs (and that tampered ones
fail), decrypts the two messages of the genesis epoch, and checks that
non-deterministic CBOR encodings are rejected.

```bash
python3 -m pip install blake3 kyber-py dilithium-py
python3 kat/v0.3/verify_vectors.py
```

CI runs both.

## Conformance manifest

Each entry of `kat-v0.3-conformance-manifest.json` has:

* `id` and `title`: the requirement;
* `spec`: anchors of the sections of `docs/specs.md` that state it;
* `vectors`: JSON pointers into `v0.3/vectors.json` (`#id` selects the
  element of an array with that `id`);
* `tests`: tests of the reference implementation, by nextest binary id
  (`crate`, `crate::integration_test` or `crate::bin/name`) and test path;
* `checks`: scripts that check it (optional);
* `formal`: scenarios of the symbolic model in [`docs/formal/`](../docs/formal/)
  that state it (optional);
* `origin`: the findings and proposals of
  [the 2026-09-25 audit](../docs/audits/audit-crypto-conformite-2026-09-25.md)
  (`C-`, `H-`, `M-`, `L-`, `P-`) or the decisions of the
  [v0.3 design note](../docs/design-v0.3.md) (`D-`) it comes from.

`crates/cityg-core/tests/conformance_manifest.rs` checks that every section,
vector, test, script, model scenario and origin named in the manifest
exists, that every normative section and every vector section is cited, and
that every test of `cityg-core` is mapped to a requirement:

```bash
cargo test -p cityg-core --test conformance_manifest
```
