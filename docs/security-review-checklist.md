# Security review checklist

For a release candidate or a change that touches the protocol, the delivery
service or client state. Each item names the check that backs it.

## Automated

- [ ] `./scripts/security_review.sh` passes: protocol core, delivery service,
      client driver and GUI tests, then the server-blindness guardrail.
- [ ] `./scripts/run_protocol_mutation_suite.sh` passes: tampered commits,
      update paths, signatures and encodings, forged senders, forks, joins
      without authority, genesis rules.
- [ ] `./scripts/verify_client_state_hardening.sh` passes: encrypted state,
      refusal of damaged state, durable spent generations, resyncs.
- [ ] `cargo test -p cityg-core --test vectors --test conformance_manifest`
      and `python3 kat/v0.3/verify_vectors.py` pass: the implementation
      matches the published vectors, an independent implementation agrees,
      and every requirement maps to existing tests.
- [ ] `docs/formal/run.sh` (ProVerif 2.05) reports every scenario with its
      expected verdicts: the security properties are proved and the sanity
      scenarios still find their attacks.
- [ ] `cargo audit` reports no unhandled advisory.

## Protocol changes

- [ ] The change is specified in [`specs.md`](specs.md) first. A change to an
      encoding, a label, a signature context, an algorithm or a parameter is
      a new profile version.
- [ ] New labels and contexts are registered (specs.md, section 17) and
      distinct from existing ones.
- [ ] The vectors are regenerated (`CITYG_WRITE_VECTORS=1 cargo test -p
      cityg-core --test vectors`), the diff is reviewed, and
      `verify_vectors.py` is updated so that it still recomputes them.
- [ ] The conformance manifest maps the new requirement to its section,
      vectors and tests, and to the audit item or design decision it comes
      from.
- [ ] The formal model in [`formal/`](formal/) still states the security
      goals of the changed part, or is updated.

## Invariants to re-check by reading the diff

- [ ] Server blindness: the server-side crates use no secret-holding type
      (`scripts/verify_no_secrets.sh` is a grep, not a proof).
- [ ] A member never authors the commit that removes it.
- [ ] Every entry into the tree carries an admission authorized against the
      admins at that point, not retired and above the retired floor.
- [ ] A light member refuses a commit whose authorization needs a member
      record it has no proof of; the only things it takes on trust are the
      new tree hash and the uniqueness of device keys (specs.md, section
      14.6).
- [ ] Every signature uses the context of its usage, and every signed object
      is verified before use.
- [ ] Every decoded object is re-encoded and compared byte for byte
      (deterministic CBOR), and relayed objects are never re-encoded.
- [ ] No secret of epoch `n` is used before the confirmation tag of its
      commit verified; secrets and message keys are erased as specified.
- [ ] A client persists its state after encrypting a message and before
      sending it.
- [ ] Secret material is zeroized on drop and never logged; comparisons of
      tags and secrets are constant time.

## Claims

- [ ] README, SECURITY.md and user-facing text claim no property beyond the
      table of specs.md, section 2.2, for the stated adversary.
- [ ] Known limits (metadata, availability, self-asserted aliases, bearer
      invite links, insider access to group content) are stated.
