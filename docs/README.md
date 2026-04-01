# City-G Documentation

Welcome to the City-G documentation! This index helps you find the right documentation for your needs.

> [!IMPORTANT]
> For `tswe/msphf-we/fs-hybrid + prs-barrier`, the authoritative normative spec is [`./specs.md`](./specs.md).
> The `docs/protocol/*` chapters are non-normative companion material. Some chapters are explanatory and some are historical; if there is any conflict, follow the unified spec and implementation behavior/tests.
> The current shipping wire/profile baseline in this repo is `v0.1.4`.

## 📚 Documentation by Audience

### For New Users
Start here if you're new to City-G:

- **[GUI User Guide](./gui-user-guide.md)** - Complete guide to using the desktop application
- **[Workflows](./workflows.md)** - Visual sequence diagrams for common operations
- **[Troubleshooting](./TROUBLESHOOTING.md)** - Solutions to common problems

### For Developers & Integrators
Building applications with City-G:

- **[Repository Cleanup Plan](./repo-cleanup-plan-2026-03-29.md)** - Structured cleanup roadmap for code, spec, docs, CI, and repository weight
- **[Legacy Surface Inventory](./legacy-surface-inventory-2026-03-30.md)** - Classified list of obsolete, historical, test-only, and adaptation surfaces to purge or relabel
- **[GUI Material System Roadmap](./gui-material-system-roadmap.md)** - Accepted UI architecture direction for GPUI materials and cross-platform shell design
- **[API Reference](./api-reference.md)** - REST API and WebSocket documentation
- **[Room-Scoped Administration Redesign](./room-admin-governance-redesign.md)** - Current room governance and admin model
- **[Configuration Guide](./configuration.md)** - Configuration options and environment variables
- **[Observability Guide](./OBSERVABILITY.md)** - Logging, metrics, and monitoring

### For Protocol Implementers
Implementing the City-G protocol:

- **[Unified Specification](./specs.md)** - Authoritative normative source
- **[Protocol Companion Index](./protocol/00-README.md)** - Chapterized companion material mapped back to the spec
- **[Implementation Guide](./protocol/11-implementation-guide.md)** - Current code walkthrough and module map
- **[Testing Guide](./protocol/13-testing-guide.md)** - Tests, manifests, CI expectations, and local validation flows
- **[Protocol Checklist](./protocol/20-protocol-checklist.md)** - Guarantee-to-flow coverage matrix for the current profile

### For Operators
Deploying and managing City-G in production:

- **[Configuration Guide](./configuration.md)** - Server and client configuration
- **[Observability Guide](./OBSERVABILITY.md)** - Monitoring and troubleshooting
- **[Deployment Guide](./protocol/14-deployment-guide.md)** - Deployment considerations
- **[Release QA Checklist](./release-qa-checklist.md)** - End-to-end release gate checks
- **[Security Review Checklist](./security-review-checklist.md)** - Security verification workflow
- **[Timing Verification](./timing-verification.md)** - Side-channel analysis and verification

### For Security Auditors
Reviewing the current protocol/profile claims and their proof anchors:

- **[Final Verification Report](./audits/final-verification-report-2026-03-26.md)** - Canonical audit verdict index for the current repo state
- **[Protocol Checklist](./protocol/20-protocol-checklist.md)** - Guarantee-to-flow runtime coverage matrix
- **[Preproduction Validation](./preproduction-validation.md)** - Operational validation gates and longer campaign runners
- **[Evidence Index](./evidence/README.md)** - Benchmarks, Dudect, proof metrics, and runtime evidence

## 📖 Canonical Reading Paths

### Product and Runtime
- [GUI User Guide](./gui-user-guide.md)
- [Workflows](./workflows.md)
- [Troubleshooting](./TROUBLESHOOTING.md)

### Protocol and Implementation
- [Unified Specification](./specs.md)
- [Protocol Companion Index](./protocol/00-README.md)
- [Implementation Guide](./protocol/11-implementation-guide.md)
- [Protocol Checklist](./protocol/20-protocol-checklist.md)

### Operations and Release
- [Configuration Guide](./configuration.md)
- [Observability](./OBSERVABILITY.md)
- [Preproduction Validation](./preproduction-validation.md)
- [Release QA Checklist](./release-qa-checklist.md)
- [Security Review Checklist](./security-review-checklist.md)

## 🔍 Quick Links

### Common Tasks
- **Join a room**: [GUI Guide - Join Flow](./gui-user-guide.md#join-flow)
- **Send encrypted messages**: [GUI Guide - Messaging](./gui-user-guide.md#messaging)
- **Configure the server**: [Configuration Guide](./configuration.md)
- **Deploy to production**: [Deployment Guide](./protocol/14-deployment-guide.md)
- **Troubleshoot issues**: [Troubleshooting Guide](./TROUBLESHOOTING.md)

### API Documentation
- **REST endpoints**: [API Reference - Endpoints](./api-reference.md#api-endpoints)
- **WebSocket API**: [API Reference - WebSocket](./api-reference.md#websocket-api)
- **Error handling**: [API Reference - Error Handling](./api-reference.md#error-handling)

### Protocol Understanding
- **Normative behavior**: [Unified Specification](./specs.md)
- **How server-blindness works**: [Protocol Overview](./protocol/01-overview.md#31-smooth-projective-hash-functions-sphf) (companion chapter)
- **Join flow details**: [Client Operations](./protocol/08-client-operations.md) (companion chapter)
- **Proof verification**: [Server Acceptance](./protocol/07-server-acceptance.md) (companion chapter)
- **Compare to MLS**: [MLS Comparison](./protocol/16-comparison-mls.md)

## 📦 Component Documentation

Crate-specific documentation:

- **[msphf-lb-vrf](../crates/msphf-lb-vrf/README.md)** - Lattice-based VRF implementation
- **[capss](../crates/capss/README.md)** - CAPSS Smallwood proof system
- **[cityg-config](../crates/cityg-config/README.md)** - Configuration management
- **[pqcrypto-kyber](../crates/pqcrypto-kyber/README.md)** - Local ML-KEM-768 bridge preserving the `pqcrypto_kyber::kyber768` API shape

## 🔬 Research & Evidence

Verification artifacts and benchmarks:

- **[Evidence](./evidence/README.md)** - Benchmarks, timing analysis, and proof metrics
  - [Benchmarks](./evidence/benchmarks/README.md) - Performance measurements
  - [Dudect](./evidence/dudect/README.md) - Constant-time verification
  - [Cachegrind](./evidence/cachegrind/README.md) - Cache analysis
  - [Proof Metrics](./evidence/proof_metrics/README.md) - Proof size analysis

## 📋 Additional Resources

- **[Main README](../README.md)** - Project overview and quick start
- **[Security Policy](../SECURITY.md)** - Vulnerability reporting
- **[Specification](./specs.md)** - Formal protocol specification

## 🛠️ For Contributors

- See the main [README](../README.md#contributing) for contribution guidelines
- [Unified Specification](./specs.md) - Normative rules to implement/test against
- [Testing Guide](./protocol/13-testing-guide.md) - How to run and write tests (companion chapter)
- [Implementation Guide](./protocol/11-implementation-guide.md) - Code walkthrough (companion chapter)

## 🚀 Current Cutover Order

Direct cutover policy for the current base profile (`v0.1.4`):

1. Update server and clients from the same release set.
2. Confirm conformance gates on the release candidate:
   - `cargo test --workspace`
   - `cargo llvm-cov --workspace --summary-only` (>=95% line coverage)
3. Roll out server binary and restart all API instances.
4. Roll out clients (GUI/CLI/integrations) built against the same spec/profile.
5. Verify runtime health:
   - API `/health` and telemetry endpoints
   - barrier endpoints (`resolve_revoked_leaves`, `resolve_joins_since`, `fetch_public_tree`)
   - acceptance logs for barrier/FS freeze codes
6. Freeze deployment if acceptance errors regress beyond baseline.

### Rollback Criteria

Rollback to the previous known-good release if any of the following occur:

- sustained acceptance failures tied to migration invariants (`9472`, `96010`, `96011`, `96012`, `96013`);
- barrier snapshot authentication failures (`960.9`) above baseline;
- client/server version skew detected in production traffic;
- message-path regression that prevents normal send/fetch operations after rollout.

Rollback action: revert server + client binaries together as one unit and replay standard validation gates before re-attempting rollout.

---

**Need help?** Start with the [FAQ](./protocol/17-faq.md), [Glossary](./GLOSSARY.md), or [GUI User Guide](./gui-user-guide.md).
