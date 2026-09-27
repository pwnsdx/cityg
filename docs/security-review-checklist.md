# Security review checklist

For a release candidate or a change that touches the protocol. Each item
names the check that backs it.

## Automated

- [ ] `./scripts/security_review.sh` passes: the protocol core and the
      signature crate, the delivery-service guardrail, and the symbolic
      model when ProVerif is installed.
- [ ] `cargo test -p cityg-core --release --test scale -- --ignored` passes:
      a window of thousands of changes on a full group matches the cost
      model's count of wraps and keys.
- [ ] `docs/formal/run.sh` (ProVerif 2.05) reports every scenario with its
      expected verdicts: the security properties are proved and the sanity
      scenarios still find their attacks.
- [ ] `cargo audit` reports no unhandled advisory.

## Protocol changes

- [ ] The change is specified in [`specs.md`](specs.md) first, and a design
      decision is recorded in [`design.md`](design.md) if it makes one. A
      change to an encoding, a label, a signature context, an algorithm or
      a parameter is a new profile version.
- [ ] New labels and contexts are registered (specs.md, section 17) and
      distinct from existing ones; the context of a signed array is its
      label.
- [ ] The formal model in [`formal/`](formal/) still states the security
      goals of the changed part, or is updated.

## Invariants to re-check by reading the diff

- [ ] The delivery service holds no group secret: the public modules of
      `cityg-core` (`ds`, `window`, `audit`, `packet`, `registry`, `smm`,
      `tree`) name no secret-holding type (`scripts/verify_no_secrets.sh` is
      a grep, not a proof).
- [ ] A committer or sealer is never a member its window removes, evicts,
      updates or re-enters; an entrant commits every district of its
      window.
- [ ] Every node a window re-keys is tainted by the signer of the commit that
      re-keyed it, and removing or updating a member re-keys every node it
      taints.
- [ ] A parent node is blank exactly when its subtree holds no member.
- [ ] In a closed group, every join carries an admission signed by an admin
      of the previous epoch, directly or through an invite, and every
      admission admits once; a closed group opens only by an admin's policy,
      which members check themselves.
- [ ] Members check the entrant's evidence and signature for every window
      sealed by an entrant: the confirmation tag alone proves nothing then.
- [ ] Joiners and returning members check the chain of seals from their
      anchor, and every recovered path secret against the key of its node.
- [ ] A role checks the public state it is shown against its trusted header
      or anchor before wrapping anything.
- [ ] Every signature uses the context of its usage, and every signed object
      is verified before use.
- [ ] Every decoded object is re-encoded and compared byte for byte
      (deterministic CBOR), and relayed objects are never re-encoded.
- [ ] No secret of epoch `n` is used before the confirmation tag of its seal
      verified; committers erase the secrets they drew once their commit is
      sent.
- [ ] Secret material is zeroized on drop and never logged; comparisons of
      MAC tags and secrets are constant time.
- [ ] Every AEAD key and nonce derived from a secret and a context, not
      from a fresh encapsulation, seals one plaintext, across the branches
      of a fork too: the context binds the transcript, not only the epoch.
      The relay elements of the v0.5 draft bind the interim transcript hash
      (research note `extensions-gsd-2026-09-27.md`, section 5.5).
- [ ] Every value drawn for a window is hedged with the device's leaf
      seed: fresh secrets and the coins of every encapsulation (wraps,
      flat elements, welcomes, external inits). No encapsulation takes its
      coins from the generator alone (v0.5 draft, section 3.3; models
      `task_hedge*.pv`).
- [ ] A sealer checks the secrets of its path against the published keys
      before it seals (v0.5 draft, section 3.5).
- [ ] The delivery service accepts a welcome only from the welcomer the
      window assigned.
- [ ] Every object a device takes from the delivery service by reference
      hashes to that reference: `Requests` files a request under its own
      reference only, catch-ups are checked against theirs, and nothing
      reads a request or an init key from a map keyed by the caller
      unchecked (specs.md, section 10.1; models `welcome_*.pv`).
- [ ] Every key a device encapsulates to for someone else (a flat element,
      a repair, a welcome's leaf key) comes from a state it checked against
      its header, never from the delivery service (models `flat_unchecked.pv`,
      `repair*.pv`).
- [ ] A repair request is checked (signature, seal hash, a node the latest
      window re-keyed on the member's path) and counts once per member
      against a performer; exclusion only withholds roles, and no rule a
      member checks depends on it (v0.5 draft, sections 3.7 and 3.8).

## Claims

- [ ] README, SECURITY.md and user-facing text claim no property beyond the
      table of specs.md, section 2.2, for the stated adversary.
- [ ] Known limits are stated: metadata, availability, insider access to
      the epoch secrets, no confidentiality of an open group against whoever
      joins it, removals enforced by the delivery service until the next
      window, and the items of specs.md, section 19.
