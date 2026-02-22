# RLWE Annex-K Vectors

These files are produced with the `cityg-hps-kat` utility in `msphf-orchestrator` and
capture the RLWE/HPS scenarios mandated by the Annex K RLWE profile:

- `A-eqroot`
- `A-rootflip`
- `maskflip`
- `seed-det`
- `pack-sha`
- `hp_commit_mismatch`
- `scenario-mhw-clock`
- `scenario-rho-replay`
- `scenario-accept-ts-locality`
- `scenario-path-oversize`
- `scenario-nonmem-empty`
- `scenario-nonmem-boundary-left`
- `scenario-nonmem-boundary-right`
- `scenario-merge-dedupe`
- `scenario-headmeta-mismatch`
- `scenario-aead-aad-tamper`
- `scenario-srx-valid`
- `scenario-srx-conflict-parent`
- `scenario-srx-conflict-revoke`
- `scenario-srx-conflict-subset`
- `scenario-srx-noncanonical`
- `scenario-srx-noncanonical-right-eq`
- `scenario-srx-noncanonical-interval-order`
- `scenario-srx-commit-mismatch`
- `scenario-missing-revoked-root`
- `scenario-merge-join-keys`

# City-G S14 Conformance Manifest

`kat-s14-conformance-manifest-v0.1.2.json` maps each normative S14 requirement to
deterministic implementation tests covering the same acceptance/rejection behavior.
This manifest is used as an auditable bridge between spec requirements and the
current Rust conformance suite.

## Plan → vectors workflow

1. Edit `plan-rlwe-annex-k.json` if new scenarios are required. The schema matches the
   `KatPlan` structure inside `msphf-orchestrator::kat` (anchor fields are hex strings).
2. Regenerate the outputs:

   ```bash
   cargo run -p msphf-orchestrator --bin cityg-hps-kat \
     -- --plan kat/plan-rlwe-annex-k.json --out kat/kat-rlwe-annex-k.json
   ```

3. The output JSON contains, per case, the anchor header values (including the new
   keys 99/100), hp_k/plaintext/ciphertext, commit/proof, `y_full`, `y_proj`, masks,
   epoch key, and eid. For `hp_commit_mismatch` both the valid and tampered ciphertext
   are emitted alongside the expected client error.

All hex strings are lowercase and unprefixed. Headers 104/105 must be populated with
the KBROAD suite (`ml-kem-768`) and the public key expected by the acceptance path.
