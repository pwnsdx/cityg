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

# City-G Freeze-Blockers Errata Manifest

`kat-freeze-blockers-manifest-v0.1.2-errata.json` tracks post-freeze `v0.1.2`
errata that closed spec blockers without changing the advertised wire/API profile
version. It maps each errata item to deterministic implementation tests so the
repository can audit those fixes independently of the original S14 set.

# City-G Client-State Manifest

`kat-client-state-manifest-v0.1.4.json` maps crash/restart, `pending join_finalize`,
and persisted client-state invariants to deterministic tests and property tests.
It is validated by `client_state_manifest_is_well_formed_and_complete` and is the
release-facing audit bridge for client recovery hardening.

# City-G Slot-Lease Conformance Manifest

`kat-slot-lease-conformance-v0.2.json` maps the reusable-slot invariants to the
current deterministic server/client/public-wire tests. It is validated by
`slot_lease_manifest_is_well_formed_and_complete`; the named runner is further
checked by `slot_lease_conformance_runner_covers_manifest_tests`, and
`scripts/run_slot_lease_conformance.sh` is the named runner for the current
slot-lease suite.

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
