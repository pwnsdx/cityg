# City-G Documentation

Welcome to the City-G documentation! This index helps you find the right documentation for your needs.

> [!IMPORTANT]
> For `tswe/msphf-we/fs-hybrid + prs-barrier`, the authoritative normative spec is [`./specs.md`](./specs.md).
> The `docs/protocol/*` chapters are legacy companion material; if there is any conflict, follow the unified spec and implementation behavior/tests.

## 📚 Documentation by Audience

### For New Users
Start here if you're new to City-G:

- **[GUI User Guide](./gui-user-guide.md)** - Complete guide to using the desktop application
- **[Workflows](./workflows.md)** - Visual sequence diagrams for common operations
- **[Troubleshooting](./TROUBLESHOOTING.md)** - Solutions to common problems

### For Developers & Integrators
Building applications with City-G:

- **[API Reference](./api-reference.md)** - REST API and WebSocket documentation
- **[Configuration Guide](./configuration.md)** - Configuration options and environment variables
- **[Observability Guide](./OBSERVABILITY.md)** - Logging, metrics, and monitoring

### For Protocol Implementers
Implementing the City-G protocol:

- **[Unified Specification](./specs.md)** - Authoritative normative source
- **[Protocol Companion Docs](./protocol/00-README.md)** - Legacy chapterized companion material
  - [01 - Overview](./protocol/01-overview.md) - Protocol architecture and design
  - [02 - Cryptographic Primitives](./protocol/02-cryptographic-primitives.md)
  - [03 - Data Structures](./protocol/03-data-structures.md)
  - [04 - Witness Validation](./protocol/04-witness-validation.md)
  - [05 - SPHF & ME-OR](./protocol/05-sphf-meor.md)
  - [06 - Proof Systems](./protocol/06-proof-systems.md)
  - [07 - Server Acceptance](./protocol/07-server-acceptance.md)
  - [08 - Client Operations](./protocol/08-client-operations.md)
  - [09 - Multi-Head Window](./protocol/09-multi-head-window.md)
  - [10 - Security Model](./protocol/10-security-model.md)
  - [11 - Implementation Guide](./protocol/11-implementation-guide.md)
  - [12 - Error Reference](./protocol/12-error-reference.md)
  - [13 - Testing Guide](./protocol/13-testing-guide.md)
  - [14 - Deployment Guide](./protocol/14-deployment-guide.md)
  - [15 - Label Registry](./protocol/15-label-registry.md)
  - [16 - Comparison with MLS](./protocol/16-comparison-mls.md)
  - [17 - FAQ](./protocol/17-faq.md)

### For Operators
Deploying and managing City-G in production:

- **[Configuration Guide](./configuration.md)** - Server and client configuration
- **[Observability Guide](./OBSERVABILITY.md)** - Monitoring and troubleshooting
- **[Deployment Guide](./protocol/14-deployment-guide.md)** - Deployment considerations
- **[Release QA Checklist](./release-qa-checklist.md)** - End-to-end release gate checks
- **[Security Review Checklist](./security-review-checklist.md)** - Security verification workflow
- **[Timing Verification](./timing-verification.md)** - Side-channel analysis and verification

## 📖 Documentation by Topic

### Getting Started
- [GUI User Guide](./gui-user-guide.md) - Desktop application walkthrough
- [API Reference](./api-reference.md) - REST API quick start
- [Workflows](./workflows.md) - Common operation flows

### Core Concepts
- [Unified Specification](./specs.md) - Normative protocol behavior
- [Protocol Overview](./protocol/01-overview.md) - High-level architecture (legacy companion)
- [Security Model](./protocol/10-security-model.md) - Threat model and guarantees (legacy companion)
- [FAQ](./protocol/17-faq.md) - Frequently asked questions

### Configuration & Deployment
- [Configuration Guide](./configuration.md) - All configuration options
- [Examples Directory](./examples/) - Docker, Kubernetes, production configs
- [Deployment Guide](./protocol/14-deployment-guide.md) - Production deployment
- [Release QA Checklist](./release-qa-checklist.md) - Release validation gates
- [Security Review Checklist](./security-review-checklist.md) - Security validation gates
- [Observability](./OBSERVABILITY.md) - Monitoring and debugging

### Protocol Details
- [Unified Specification](./specs.md) - Full normative protocol definition
- [Cryptographic Primitives](./protocol/02-cryptographic-primitives.md) - Crypto building blocks (legacy companion)
- [SPHF & ME-OR](./protocol/05-sphf-meor.md) - Smooth projective hash functions (legacy companion)
- [Proof Systems](./protocol/06-proof-systems.md) - Zero-knowledge proofs (legacy companion)
- [Multi-Head Window](./protocol/09-multi-head-window.md) - Concurrency control (legacy companion)

### Reference
- [Glossary](./GLOSSARY.md) - Complete terminology reference (A-Z)
- [Data Structures](./protocol/03-data-structures.md) - CBOR encodings and wire formats (legacy companion)
- [Label Registry](./protocol/15-label-registry.md) - Domain separation labels (legacy companion)
- [Error Reference](./protocol/12-error-reference.md) - All error codes explained (legacy companion)
- [Constraints & Requirements](./constraints.md) - Canonical security/functional targets

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
- **How server-blindness works**: [Protocol Overview](./protocol/01-overview.md#31-smooth-projective-hash-functions-sphf) (legacy companion)
- **Join flow details**: [Client Operations](./protocol/08-client-operations.md) (legacy companion)
- **Proof verification**: [Server Acceptance](./protocol/07-server-acceptance.md) (legacy companion)
- **Compare to MLS**: [MLS Comparison](./protocol/16-comparison-mls.md)

## 📦 Component Documentation

Crate-specific documentation:

- **[msphf-lb-vrf](../crates/msphf-lb-vrf/README.md)** - Lattice-based VRF implementation
- **[capss](../crates/capss/README.md)** - CAPSS Smallwood proof system
- **[cityg-config](../crates/cityg-config/README.md)** - Configuration management

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
- [Testing Guide](./protocol/13-testing-guide.md) - How to run and write tests (legacy companion)
- [Implementation Guide](./protocol/11-implementation-guide.md) - Code walkthrough (legacy companion)

## 🚀 0.1.2 Cutover Order

Direct cutover policy for `v0.1.2` (no legacy interop/A-B path):

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

**Last Updated**: 2026-02-25
