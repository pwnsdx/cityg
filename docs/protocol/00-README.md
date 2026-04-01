# City-G Protocol Documentation

> [!IMPORTANT]
> This directory is companion and historical material. For the current
> `tswe/msphf-we/fs-hybrid + prs-barrier` profile, the normative source is
> [`../specs.md`](../specs.md).
> If a chapter here conflicts with the unified spec or implementation
> behavior/tests, follow the unified spec and the live code/tests.
>
> Several companion chapters still preserve earlier "Alpha (0.1.0)" labels or
> historical framing in explanatory text. Treat those as citations only.

## Current Role of This Directory

This directory is no longer the normative protocol source. Its job is to make
the current repo easier to navigate by providing:

- explanatory chapterization around the unified spec;
- implementation-oriented walkthroughs;
- error/testing/deployment companion material;
- historical context where useful.

---

## 📚 Documentation Structure

This directory contains companion material that complements the unified
specification and reference implementation.

### Core Protocol Documents

1. **[01-overview.md](01-overview.md)** - High-level protocol architecture and motivation
2. **[02-cryptographic-primitives.md](02-cryptographic-primitives.md)** - All crypto building blocks and domain separation
3. **[03-data-structures.md](03-data-structures.md)** - CBOR encodings, header fields, and wire formats
4. **[04-witness-validation.md](04-witness-validation.md)** - Canonical Merkle witnesses and SRX modes
5. **[05-sphf-meor.md](05-sphf-meor.md)** - Smooth Projective Hash Functions and ME-OR construction
6. **[06-proof-systems.md](06-proof-systems.md)** - CAPSS Smallwood and ZK-VRF proofs
7. **[07-server-acceptance.md](07-server-acceptance.md)** - Complete server-side acceptance pipeline
8. **[08-client-operations.md](08-client-operations.md)** - Client-side key derivation and envelope handling
9. **[09-multi-head-window.md](09-multi-head-window.md)** - Concurrency control and anti-grind mechanisms
10. **[10-security-model.md](10-security-model.md)** - Threat model, assumptions, and security properties

### Implementation Guides

11. **[11-implementation-guide.md](11-implementation-guide.md)** - Code walkthrough with file-by-file references
12. **[12-error-reference.md](12-error-reference.md)** - Complete freeze/reject error catalog
13. **[13-testing-guide.md](13-testing-guide.md)** - Test coverage and known-answer tests (KATs)
14. **[14-deployment-guide.md](14-deployment-guide.md)** - Deployment considerations for experimental/research use
15. **[20-protocol-checklist.md](20-protocol-checklist.md)** - Protocol guarantee checklist and E2E coverage map

### Reference Materials

16. **[15-label-registry.md](15-label-registry.md)** - All domain-separation labels and constants
17. **[16-comparison-mls.md](16-comparison-mls.md)** - How City-G differs from MLS
18. **[17-faq.md](17-faq.md)** - Frequently asked questions

---

## 🎯 Recommended Entry Points

### If you need the protocol rules
- Start with [`../specs.md`](../specs.md).
- Use this directory only for explanation, walkthroughs, and cross-references.

### If you need the current implementation map
- Start with [11-implementation-guide.md](11-implementation-guide.md).
- Then use [13-testing-guide.md](13-testing-guide.md) and
  [20-protocol-checklist.md](20-protocol-checklist.md).

### If you need protocol guarantees and runtime proof coverage
- Start with [20-protocol-checklist.md](20-protocol-checklist.md).
- Then review [`../preproduction-validation.md`](../preproduction-validation.md)
  and [`../evidence/e2e-local-validation-2026-03-27.md`](../evidence/e2e-local-validation-2026-03-27.md).

### If you need security/audit review support
- Start with [10-security-model.md](10-security-model.md),
  [12-error-reference.md](12-error-reference.md),
  [13-testing-guide.md](13-testing-guide.md), and
  [20-protocol-checklist.md](20-protocol-checklist.md).
- Then cross-check the canonical audit state in
  [`../audits/final-verification-report-2026-03-26.md`](../audits/final-verification-report-2026-03-26.md).

---

## 🔗 Cross-References

### Specification Sections → Documentation Mapping

| Specification Section | Documentation |
|-------------------|---------------|
| §1-3 (Motivation, Capabilities, Threat Model) | [01-overview.md](01-overview.md), [10-security-model.md](10-security-model.md) |
| §4 (Public Instance & NP Language) | [05-sphf-meor.md](05-sphf-meor.md) |
| §5 (Canonical Witnesses) | [04-witness-validation.md](04-witness-validation.md) |
| §6 (Crypto, Domains, Labels) | [02-cryptographic-primitives.md](02-cryptographic-primitives.md) |
| §7 (Primitive API) | [05-sphf-meor.md](05-sphf-meor.md) |
| §8 (ME-OR) | [05-sphf-meor.md](05-sphf-meor.md) |
| §9 (Instantiations) | [02-cryptographic-primitives.md](02-cryptographic-primitives.md) |
| §10 (Seed Binding) | [08-client-operations.md](08-client-operations.md) §2 |
| §11 (ZK-VRF) | [06-proof-systems.md](06-proof-systems.md) §2 |
| §12 (Header Keys, Acceptance) | [03-data-structures.md](03-data-structures.md), [07-server-acceptance.md](07-server-acceptance.md) |
| §13 (MHW) | [09-multi-head-window.md](09-multi-head-window.md) |
| §14 (Security Properties) | [10-security-model.md](10-security-model.md) |
| §15 (Error Semantics) | [12-error-reference.md](12-error-reference.md) |
| §16 (Implementation Guidance) | [11-implementation-guide.md](11-implementation-guide.md) |
| Appendix A (CBOR) | [03-data-structures.md](03-data-structures.md) |
| Appendix B (RPO-256) | [02-cryptographic-primitives.md](02-cryptographic-primitives.md) §4 |
| Appendix C (RLWE-HPS) | [02-cryptographic-primitives.md](02-cryptographic-primitives.md) §5 |
| Appendix D (MSPHF_HP) | [08-client-operations.md](08-client-operations.md) §3 |
| Appendix E (Label Registry) | [15-label-registry.md](15-label-registry.md) |
| Appendix F (SRX Modes) | [04-witness-validation.md](04-witness-validation.md) §3 |
| Appendix L (CAPSS Smallwood) | [06-proof-systems.md](06-proof-systems.md) §1 |
| Appendix V (ZK-VRF) | [06-proof-systems.md](06-proof-systems.md) §2 |
| Annex M (MHW) | [09-multi-head-window.md](09-multi-head-window.md) |
| Annex N (Policy) | [07-server-acceptance.md](07-server-acceptance.md) §2 |
| Annex I (Implementation Binding) | [11-implementation-guide.md](11-implementation-guide.md) |

### Code References → Documentation Mapping

| Crate | Primary Documentation |
|-------|----------------------|
| `msphf-core` | [02-cryptographic-primitives.md](02-cryptographic-primitives.md), [04-witness-validation.md](04-witness-validation.md) |
| `msphf-rlwe` | [02-cryptographic-primitives.md](02-cryptographic-primitives.md) §5 |
| `msphf-orchestrator` | [07-server-acceptance.md](07-server-acceptance.md), [09-multi-head-window.md](09-multi-head-window.md) |
| `cityg-client` | [08-client-operations.md](08-client-operations.md) |
| `cityg-server` | [07-server-acceptance.md](07-server-acceptance.md) |
| `cityg-api` | [11-implementation-guide.md](11-implementation-guide.md) §6 |

---

## 🛠️ Notation Conventions

Throughout this documentation:

- **Specification References**: `§12.2` refers to section 12.2 of [`specs.md`](../specs.md)
- **Code References**: References to the acceptance pipeline point to `crates/msphf-orchestrator/src/accept/` (module rooted at `mod.rs`); look for the helper or function named in the surrounding text
- **Header Fields**: `#91` or `HDR_SEED_CTX_HASH` refers to CBOR map key 91
- **Domain Labels**: `"msphf/hp/commit"` refers to a BLAKE3 domain-separation label
- **Error Codes**: `REJECT(923)` refers to deterministic protocol outcome code 923
- **Types**: `[u8; 32]` denotes a 32-byte array
- **Functions**: `H_L(label, args)` denotes a domain-separated hash function

### Symbols

- `X_k` - Public epoch context
- `hp` - Hash projection (secret on server, known to devices)
- `Y*` - VRF output (unique epoch digest)
- `E_k` - Epoch key (derived on device)
- `ρ` - Private seed material (rho)
- `WID` - Window identifier (public)

---

## 📝 Contributing to Documentation

When adding or updating documentation:

1. **Maintain Specification Alignment**: Every normative statement should cite the specification section
2. **Include Code References**: Link to specific files and line numbers
3. **Keep It Current**: Update when code changes
4. **Cross-Reference**: Link to related documents
5. **Examples**: Include concrete examples with test references

---

## 🔍 Finding Information

### Use Case → Document

| I want to... | Read... |
|--------------|---------|
| Understand what City-G does | [01-overview.md](01-overview.md) |
| Implement a client | [08-client-operations.md](08-client-operations.md), [11-implementation-guide.md](11-implementation-guide.md) |
| Implement a server | [07-server-acceptance.md](07-server-acceptance.md), [11-implementation-guide.md](11-implementation-guide.md) |
| Understand the cryptography | [02-cryptographic-primitives.md](02-cryptographic-primitives.md), [05-sphf-meor.md](05-sphf-meor.md) |
| Debug a freeze error | [12-error-reference.md](12-error-reference.md) |
| Understand witness validation | [04-witness-validation.md](04-witness-validation.md) |
| Deploy experimentally | [14-deployment-guide.md](14-deployment-guide.md) |
| Compare to MLS | [16-comparison-mls.md](16-comparison-mls.md) |
| Verify security claims | [10-security-model.md](10-security-model.md), [`../../SECURITY.md`](../../SECURITY.md) |

---

## 📄 License

This documentation is part of the City-G `tswe/msphf-we/fs-hybrid` reference implementation. See the top-level LICENSE file for terms.
