# Security Policy

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in City-G, please report it privately:

- **Email:** pwnsdx@protonmail.ch (PGP available with ProtonMail)
- **Subject:** `[SECURITY] City-G Vulnerability Report`
- **Response Time:** We aim to respond within 48 hours

### What to Include

1. Description of the vulnerability
2. Steps to reproduce (if applicable)
3. Potential impact assessment
4. Suggested remediation (optional)

### Disclosure Policy

- We follow **coordinated disclosure** (90-day timeline)
- We will acknowledge your contribution in security advisories
- We may offer recognition for significant findings

---

## Security Documentation

For security properties, guarantees, and verification methods, see:

- **Security Model:** [`docs/protocol/10-security-model.md`](docs/protocol/10-security-model.md)
- **Server Acceptance:** [`docs/protocol/07-server-acceptance.md`](docs/protocol/07-server-acceptance.md) (§3 - Publisher Blindness)
- **Testing Guide:** [`docs/protocol/13-testing-guide.md`](docs/protocol/13-testing-guide.md)
- **Security Review Checklist:** [`docs/security-review-checklist.md`](docs/security-review-checklist.md)

---

## Verification

To verify security properties of the implementation:

```bash
# Run automated security checks
./scripts/verify_no_secrets.sh

# Run release-grade security review baseline
./scripts/security_review.sh

# Run full test suite
cargo test --all

# Verify type safety
cargo check --all-features
```

---

## Security Audits

- **October 2024:** Timing side-channel analysis (see [`docs/timing-verification.md`](docs/timing-verification.md))

---

## Out of Scope

The following are not considered security vulnerabilities:

- Metadata leakage (group membership, join times, message counts)
- Denial of service from malicious publishers (by design)
- Traffic analysis attacks (use Tor/VPN at network layer)
- Endpoint compromise revealing current epoch keys

See [`docs/protocol/10-security-model.md`](docs/protocol/10-security-model.md) for complete threat model.
