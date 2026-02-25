# Changelog

All notable changes to the City-G project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Optional `unsafe-ntt` feature flag in `msphf-core` to re-enable unchecked NTT indexing when benchmarking or running production builds that demand maximum speed.
- Index-schedule unit tests in `msphf-core::rlwe::ntt` to assert the forward and inverse transforms never walk past buffer bounds.

### Changed
- Normalized the multi-head window TTL default to **120 seconds** across orchestrator code, configuration defaults, shipped TOML examples, and protocol docs, including guidance on how the knob impacts DoS posture vs. client jitter tolerance.

### Documentation
- Added comprehensive documentation index (`docs/README.md`) for improved navigation
- Added A-Z glossary (`docs/GLOSSARY.md`) with 50+ cryptographic and protocol terms
- Added troubleshooting guide (`docs/TROUBLESHOOTING.md`) covering common issues
- Added contributing guide (`CONTRIBUTING.md`) with development workflow and standards
- Added crate READMEs for `cityg-server` and `cityg-client` with usage examples
- Fixed broken screenshot reference in GUI user guide
- Documented the `unsafe-ntt` verification path in `docs/timing-verification.md` and added operational notes about the 120s TTL baseline in the configuration and MHW specs.

## [0.1.2] - 2026-02-11

### Added

#### PRS Barrier (Post-Revocation Secrecy)
- KEM-tree cover subsystem (`K_barrier` + `barrier_version`) for post-revocation secrecy (spec S11)
- Barrier error codes: 960.1–960.13, 945.0, 947.0/2/4/5/6, 948.0, 944.6
- Proactive PCS refresh gating with time-blind rate limiting (spec S10.4B)
- Updater local state management with crash-safe persist-before-publish (spec S11.14)
- Client barrier recovery via unique-match and FULL chain-check modes (spec S11.13)
- Join provisioning extended with barrier-required fields (spec S12.2)

#### Payload Key Schedule
- `K_msg_epoch` derivation bound to `K_barrier` and `barrier_version` (spec S8.3)
- PayloadEnvelope wire format `"fs-hybrid-msg-v2"` (spec S8.1)
- No-fallback rule: receivers MUST NOT try alternate `K_barrier` values (spec S8.5)

#### Device-Chain Binding
- `fs_dev_commit` v2 binds `barrier_version` and `barrier_update_digest` (spec S7.4)
- PCS reseed of FS chain on accepted PCS-refresh barrier updates (spec S6.6)

#### Acceptance
- Barrier version gating, revocation-change gating, PCS refresh gating (spec S10.4–S10.4B)
- Forward-Leap Guard with configuration invariant check (spec S10.3)
- Server-side barrier_update validation pipeline (spec S11.12)

### Changed
- Profile ID updated to `tswe/msphf-we/fs-hybrid + prs-barrier`
- Unified spec consolidated into `docs/specs.md` (v0.1.2 final)

### Documentation
- Updated all documentation to reference `docs/specs.md` (removed stale `specs-unified-fs.md` links)
- Added PRS barrier terms to GLOSSARY (K_barrier, BarrierUpdate, barrier_version, etc.)
- Updated README security model with post-revocation secrecy
- Added Post-Revocation Secrecy to constraints
- Added v0.1.2 error codes reference to error reference doc

## [0.1.0] - 2025-11-12

Initial alpha release of City-G `tswe/msphf-we/fs-hybrid` protocol.

### Added

#### Core Protocol
- Server-blind epoch validation using CAPSS Smallwood + ZK-VRF proofs
- Multi-head window (MHW) for parallel join operations (up to 16 concurrent heads)
- Minutes-grade forward secrecy with time-blind enforcement
- Offline join capability (no online handshake required)
- Merkle tree-based membership tracking with O(log N) witness sizes
- KBROAD envelope for group key broadcasting with ML-KEM-768 encryption
- Structured Relational Witness (SRX) system for canonical membership proofs

#### Cryptographic Primitives
- ML-KEM-768 (NIST FIPS 203) for key encapsulation
- ML-DSA-65 (NIST FIPS 204) for digital signatures
- RLWE-HPS instantiation of Smooth Projective Hash Functions
- LB-VRF (Lattice-Based Verifiable Random Function) with deterministic seeding
- CAPSS Smallwood proof system (~12KB typical, ≤16KB maximum)
- RPO-256 (BLAKE3-based) hash function for domain separation

#### Crates
- `msphf-core`: Core cryptographic primitives and Merkle tree operations
- `msphf-rlwe`: RLWE polynomial arithmetic and NTT operations
- `msphf-lb-vrf`: Lattice-based VRF implementation with output-hiding
- `msphf-orchestrator`: High-level protocol orchestration and proof generation
- `capss`: CAPSS Smallwood proof system with Sage reference compatibility
- `cityg-config`: Centralized configuration management (TOML/JSON + env vars)
- `cityg-client`: Client-side epoch generation and witness creation
- `cityg-server`: Server-side validation with crash recovery journaling
- `cityg-api`: HTTP REST API server with WebSocket support
- `cityg-api-client`: Rust HTTP/WebSocket client library
- `cityg-gui`: Desktop GUI application (GPUI-based)

#### API Endpoints
- `POST /v1/accept_epoch` - Submit epoch bundle for validation
- `POST /v1/rooms/bootstrap` - Initialize new room with KBROAD key
- `POST /v1/rooms/join_ticket` - Request join ticket with witness data
- `POST /v1/rooms/merge_ticket` - Request merge ticket for existing member
- `POST /v1/send_message` - Send encrypted message to epoch
- `POST /v1/messages` - Fetch messages for epoch
- `POST /v1/members` - Query group membership roster
- `GET /v1/ws` - WebSocket connection for real-time notifications
- `GET /health` - Health check endpoint (legacy protobuf)
- `GET /health/live` - Liveness probe (JSON)
- `GET /health/ready` - Readiness probe with circuit breaker status (JSON)
- `GET /health/detailed` - Detailed health status (JSON)
- `GET /metrics` - Prometheus-compatible metrics

#### Configuration
- TOML and JSON configuration file support
- Environment variable overrides (`CITYG_*` prefix)
- Per-component configuration (server, client, protocol, GUI)
- Forward secrecy policy configuration (Annex H/J parameters)
- Validation on startup with descriptive error messages

#### Observability
- Structured logging (JSON and human-readable formats)
- Request tracing with correlation IDs (UUID v4)
- Prometheus-compatible metrics (`/metrics` endpoint)
- Multiple health check endpoints for Kubernetes
- Circuit breaker with configurable thresholds
- Retry logic with exponential backoff
- Offline message queue (10,000 message capacity)

#### GUI Features
- Join flow with room ID generation
- Real-time message display with WebSocket notifications
- Member roster with pagination (200 members per page, configurable)
- Automatic epoch rotation (default: 1 hour interval)
- Trust-on-first-use (TOFU) identity binding with alerts
- Session persistence (`~/.config/cityg-gui/config.json`)
- Ciphertext debug view for troubleshooting
- Keyboard shortcuts for common operations

#### Testing & Verification
- 416 passing tests across all crates
- Known-Answer Tests (KATs) for cryptographic primitives
- Side-channel analysis with dudect/cachegrind
- Server-blindness verification script (`./scripts/verify_no_secrets.sh`)
- Property-based tests for Merkle operations
- Integration tests for full join/merge flows
- Fixture-based regression testing for CAPSS

#### Documentation
- Complete protocol specification (`docs/specs.md`)
- 18 protocol documentation files in `docs/protocol/`
- GUI user guide with tutorials and troubleshooting
- API reference with curl and Rust examples
- Configuration guide with Docker/Kubernetes examples
- Observability guide for production monitoring
- Workflows with Mermaid sequence diagrams
- Evidence directory with benchmarks and timing analysis

### Security
- Cryptographically enforced server-blindness (ML-KEM-768 IND-CCA2)
- Zero-knowledge proofs for VRF output hiding
- Constant-time verification for proof acceptance
- Deterministic proof generation to prevent grinding attacks
- Memory zeroization for sensitive cryptographic material
- Timing side-channel analysis (dudect) with mitigation
- Post-quantum security (~96-bit quantum, ~128-bit classical)

### Performance
- Epoch generation: ~90ms typical (Apple M1)
- CAPSS Smallwood proof: ~50ms
- ZK-VRF proof: ~30ms
- Merkle witness: ~1ms for O(log N) size
- Join latency: <100ms server-side validation
- Proof sizes: ~22KB total (CAPSS + VRF + witnesses)
- Supports millions of members (O(log N) scaling)

### Known Limitations
- **Alpha software**: Not production-ready without security audit
- **Metadata exposure**: Server sees join times, message counts, leaf IDs
- **Forward secrecy granularity**: Minutes-grade (not per-message)
- **Novel cryptography**: RLWE-HPS less battle-tested than MLS
- **Rust-only**: No FFI bindings for other languages yet
- **Real deployments**: Tested to ~10,000 members; >100k is research territory

### Breaking Changes
N/A - Initial release

## Version History

- **0.1.0** (2025-11-12) - Initial alpha release

---

## Release Notes Format

Each release includes:

### Added
New features and capabilities

### Changed
Changes to existing functionality

### Deprecated
Features marked for removal in future versions

### Removed
Features removed in this release

### Fixed
Bug fixes

### Security
Security-related changes and advisories

---

## Upgrade Guide

See [UPGRADING.md](UPGRADING.md) for version-specific upgrade instructions (when available).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose changes to this project.

---

**Note**: All cryptographic implementations in this project are research-grade. Independent security audit recommended before production use.
