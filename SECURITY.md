# Security Policy

City-G is a research prototype. Profile `city-g/v0.3` has not had an
independent human cryptographic review; do not rely on it to protect
people. Prefer MLS (RFC 9420) implementations for production.

## Reporting a vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Report them privately:

- **Email:** pwnsdx@protonmail.ch (PGP available with ProtonMail)
- **Subject:** `[SECURITY] City-G Vulnerability Report`
- **Response time:** we aim to respond within 48 hours

Please include a description, steps to reproduce, the impact you expect, and
optionally a fix. We follow coordinated disclosure (90 days) and credit
reporters in advisories.

## What City-G claims

The security properties of profile v0.3, per adversary, are stated in
[`docs/specs.md`](docs/specs.md), section 2.2. In short, against the
delivery service (passive or active) and against removed members:

- confidentiality of message content, sender authentication, membership
  agreement, admission control (no member added without an admin's
  signature), post-removal secrecy, and join secrecy (a joiner learns
  nothing of the epochs before its join);
- forward secrecy within `FS_WINDOW` (24 hours) and post-compromise security
  after the next self-update of a device whose state was compromised.

A new member, and a member that resyncs, cannot check the history before the
epoch it enters: a malicious delivery service can make it enter a fabricated
view of the group, containing a member the service controls, where the
service reads its messages. Comparing the security code with a member known
out of band, such as the inviter, detects it (section 2.3).

Light members (section 14) get the same properties, except that against a
delivery service colluding with a member, membership agreement holds for
them only up to the tree hash: they rely on the delivery service for the new
tree hash of each commit and for the uniqueness of device keys.

Device keys (ML-DSA-65) are long-term credentials: an adversary that steals
one can act as that device, and as an admin if the device is one, until the
device is removed and replaced by a new device. A device can rotate its key,
but an adversary holding the key can rotate it first; rotation does not undo
a compromise.

A deployment must not advertise any other property. The following are
**not** provided:

- metadata privacy: the server sees the members, who sends when, message
  sizes and aliases;
- availability: the server can drop or delay traffic and deny service;
- protection of content from a member of the same epoch;
- authenticated identities: aliases are self-asserted; compare security codes
  and device keys out of band ([`docs/fingerprints.md`](docs/fingerprints.md));
- confidentiality of invite links: an invite link is a bearer secret until
  its invite expires, is revoked or has admitted its number of devices.

## Out of scope

- Metadata leakage and traffic analysis (use Tor or a VPN at the network
  layer).
- Denial of service by the delivery service or by members (a member can
  author a commit that others cannot process; it is detected, reported and
  recovered from, not prevented).
- Compromise of an endpoint while it is compromised.

## Verification

```bash
./scripts/security_review.sh             # tests and the server-blindness guardrail
./scripts/run_protocol_mutation_suite.sh # hostile inputs
./scripts/verify_client_state_hardening.sh
python3 kat/v0.3/verify_vectors.py       # independent conformance check (pip install blake3 kyber-py dilithium-py)
```

The guardrail `scripts/verify_no_secrets.sh` is a syntactic check that the
server-side crates use no secret-holding type; it is not a proof. The
protocol argument is in the specification and in the symbolic model under
[`docs/formal/`](docs/formal/). See also
[`docs/security-review-checklist.md`](docs/security-review-checklist.md).

## Audits

- **2026-09-25:** cryptographic and conformance audit of profile v0.1.4
  ([report, in French](docs/audits/audit-crypto-conformite-2026-09-25.md)).
  It found critical flaws in v0.1.4 (C-01 to C-03) and proposed the v0.2
  redesign; its section 6 records how each finding was addressed. Profile
  v0.3 keeps those fixes and changes the design for large groups
  ([design note](docs/design-v0.3.md)).
- **2026-03:** text reviews of the v0.1.4 specification
  ([`docs/audits/`](docs/audits/README.md)).
