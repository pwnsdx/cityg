# Security Policy

City-G is research. Profile `city-g/v0.4` has no test vectors and no
independent human cryptographic review; do not rely on it to protect
people. Prefer MLS (RFC 9420) implementations for production.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.4.x (profile `city-g/v0.4`) | yes |

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

The security properties, per adversary, are stated in
[`docs/specs.md`](docs/specs.md), section 2.2, for members that follow the
group and for joiners and returning members from the epoch they enter. In
short, against the delivery service (passive or active) and against removed
members:

- confidentiality of the epoch secrets in a closed group, membership
  agreement, authenticity of requests, commits and seals, post-removal
  secrecy from the window that applies a removal, forward secrecy through
  the init chain, post-compromise security after a device's next update,
  join secrecy, and visibility of every join;
- admission control in a closed group: no device joins without an admission
  signed by an admin or an invite. An entry that a malicious committer
  places without one is caught by sampled audits with probability about
  `1 - e^-20`, which leave a transferable fraud proof.

A deployment must not advertise any other property. The following are
**not** provided:

- confidentiality in an open group against whoever joins it, the delivery
  service included (joins stay visible, and nobody can speak as a member);
- metadata privacy: the delivery service sees the members, the requests and
  the timing of windows;
- availability: the delivery service can drop or delay anything and deny
  service;
- protection of the epoch secrets from a member of the same epoch;
- cryptographic enforcement of a removal before the window that applies it:
  until then the delivery service enforces it;
- detection of forks by members that follow the group: comparing the
  interim transcript hash out of band detects one;
- a message plane: it is not specified yet (specification, section 19).

## Out of scope

- Metadata leakage and traffic analysis (use Tor or a VPN at the network
  layer).
- Denial of service by the delivery service or by members (a committer can
  wrap a secret that some members cannot open; they reject the window).
- Compromise of an endpoint while it is compromised.

## Verification

```bash
./scripts/security_review.sh     # core tests, delivery-service guardrail, symbolic model
docs/formal/run.sh               # ProVerif 2.05
```

The guardrail `scripts/verify_no_secrets.sh` is a syntactic check that the
modules the delivery service runs name no secret-holding type; it is not a
proof. The protocol argument is in the specification and in the symbolic
model under [`docs/formal/`](docs/formal/). See also
[`docs/security-review-checklist.md`](docs/security-review-checklist.md).
