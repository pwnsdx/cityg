## City‑G: Post-Quantum, Server-Blind E2EE for Large-Scale Groups

[![Status](https://img.shields.io/badge/status-research%20prototype-orange)]()
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**City‑G** is a research‑grade protocol for end‑to‑end encrypted groups designed for very large audiences (architecturally O(log N), targeting millions of members; tested to N_max=2048, large-scale benchmarks pending). The server validates activity cryptographically without ever learning message keys. New members can post and send messages even when everyone else is offline. The shipping profile is `tswe/msphf-we/fs-hybrid + prs-barrier`, integrating server blindness, multi-head windows, minutes-grade forward secrecy, and post-revocation secrecy by default.

---

## Who this is for

* **Large-scale communities**: City/municipality groups, Discord/Telegram-style communities, public event coordination (conferences, open-source projects), large enterprise messaging.
* **Broadcast channels**: Newsletter distribution, activist networks, emergency alert systems with cryptographic server-blindness guarantees.
* **High-concurrency scenarios**: Applications with frequent joins/leaves and many offline participants.
* Teams that want **post‑quantum** building blocks now, not later.

---

## What makes City‑G different

* **Server‑blind by construction.** Acceptance is "publisher‑blind": the service validates structure, policy, and zero‑knowledge proofs but **cannot** decrypt the protected header; decryption happens only on devices.
* **Offline admission.** New devices and existing devices independently derive the same next‑epoch key; no handshake is required to start sending.
* **Minutes‑grade, time‑blind FS.** Forward secrecy rotates on a short cadence and is enforced **without** trusting server clocks (clients police their own schedule).
* **Built for scale.** Membership proofs are canonical and grow **O(log N)**; periodic **checkpoints/rollups** keep sync costs reasonable as groups grow.
* **Post‑quantum by default.** The spec standardizes ML‑KEM/ML‑DSA with modern hashing and AEAD for simple interoperability.

> **Not a metadata‑hiding system.** The server still sees public structure (that "an update happened") but not your message keys or plaintext.

---

## How it works (high-level)

### The Core Idea

City-G splits responsibilities between **trusted clients** and an **untrusted server** using zero-knowledge proofs:

**Join flow** (Bob joins a 7000-person group):
1. **Bob fetches** group state: parent_root, frontier (~13 hashes for 7000 members), kbroad_pub
2. **Bob creates** anchor locally: adds his leaf_id, generates proofs (CAPSS Smallwood ≤16KB, ZK-VRF ≤8KB), encrypts hp
3. **Bob submits** anchor to server
4. **Server validates** cryptographically: PoP signature, proofs, SRX witnesses, Merkle consistency (never decrypts KBROAD)
5. **Server applies** policy: checks rate limits, blocklists (your application code)
6. **Bob sends** messages encrypted with epoch key E_k

**Result**: Bob knows hp, Y*, E_k. Server knows only Merkle roots, Bob's leaf_id (hash), and timing metadata—never the secrets or message content.

For detailed diagrams, see [workflows.md](docs/workflows.md#join-flow) (sequence diagrams + visual guides) and [protocol/01-overview.md](docs/protocol/01-overview.md) (technical specifications).

### Two Proof Systems

City-G uses two complementary zero-knowledge proofs:

- **CAPSS Smallwood** (~12KB): Proves seed→hp derivation was deterministic and binds forward-secrecy context. Prevents grinding attacks and epoch tampering.
- **ZK-VRF** (≤8KB): Proves Y* correctness without revealing it (output-hiding). Prevents forgery.

Both verify correctness without revealing secrets. See [workflows.md#two-proof-systems](docs/workflows.md#two-proof-systems) for visual diagram, or [crates/capss/README.md](crates/capss/README.md) and [crates/msphf-lb-vrf/README.md](crates/msphf-lb-vrf/README.md) for implementation details.

### What the Server Sees (and Doesn't)

**Server sees**: Merkle root transitions, leaf IDs (hashes), timing metadata, proof structures
**Server validates**: Cryptography (proofs, signatures, witnesses) via `accept_anchor`
**Your app enforces**: Policy (rate limits, blocklists) by examining validated anchor fields

**Server never sees**: hp, Y*, E_k (cryptographically hidden), device secret keys (only public keys), message content

See [workflows.md#what-the-server-sees-and-doesnt](docs/workflows.md#what-the-server-sees-and-doesnt) for a detailed diagram.

### Architecture: Where Code Runs

```
┌─────────────────────────────────────────────────────────────────┐
│ msphf-orchestrator (Shared Cryptographic Library)               │
│                                                                 │
│  ┌───────────────────────────┐     ┌─────────────────────────┐  │
│  │ joiner_kgen_or()          │     │ accept_anchor()         │  │
│  │ (Creates anchors)         │     │ (Validates anchors)     │  │
│  │                           │     │                         │  │
│  │ ✓ Knows: hp, Y*, E_k      │     │ ✗ No secrets            │  │
│  │ ✓ Generates proofs        │     │ ✓ Verifies proofs       │  │
│  │ ✓ Encrypts KBROAD         │     │ ✗ No decryption         │  │
│  │                           │     │                         │  │
│  │ RUNS: Client-side         │     │ RUNS: Server-side       │  │
│  │ (Trusted device)          │     │ (Untrusted infra)       │  │
│  └───────────────────────────┘     └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
              ▲                                 ▲
              │                                 │
    ┌─────────┴────────┐              ┌─────────┴────────┐
    │ cityg-client     │              │ cityg-server     │
    │ (Thin wrapper)   │              │ (Thin wrapper)   │
    │ Alice's phone    │              │ AWS/GCP/on-prem  │
    └──────────────────┘              └──────────────────┘

CI enforces separation: ./scripts/verify_no_secrets.sh checks that
accept/ code path has NO access to MlKemSecretKey or decrypt functions
```

### Policy vs Cryptography

City-G separates **cryptographic validation** (protocol-level proofs) from **policy enforcement** (application-level rules):

**Cryptographic layer** (`accept_anchor`):
- Validates proofs (CAPSS Smallwood, ZK-VRF), signatures, SRX witnesses, Merkle consistency
- Never learns hp, Y*, E_k (even if server compromised)
- Returns: Accept | Freeze(error_code)

**Policy layer** (your application):
- Examines validated anchor fields (join_leaf_ids, PoP signer, etc.)
- Enforces group-specific rules: open_join vs admin_only, rate limits, blocklists
- Decides: persist or reject

**Examples**:
- **Open groups**: Bob self-joins → server validates proofs → your app checks rate limits → persist if allowed
- **Controlled groups**: Admin creates anchor for Bob → server validates proofs → your app checks admin authorization → persist if allowed

See [workflows.md#policy-vs-cryptography](docs/workflows.md#policy-vs-cryptography) for a detailed diagram.

---

## At‑a‑glance comparison

| Property | **City‑G** | **MLS (IETF RFC 9420)** | **Signal** | **Matrix (Olm/Megolm)** |
|----------|-----------|-------------------------|------------|-------------------------|
| **Confidentiality & server blindness** | Server validates CAPSS Smallwood + ZK-VRF; epoch keys never reach the server. Metadata (who joined/when) remains visible. | Content keys stay client-side, but "server-blind acceptance" is not part of the protocol; operators must ship the audited binaries. | Content keys remain on devices; trust rests on Signal’s infrastructure choices. | Servers store ciphertext; clients share session keys out-of-band. No cryptographic proof that the homeserver stays blind beyond enforcing transport encryption. |
| **Authentication & membership integrity** | ML-DSA PoP + SRX proofs + CAPSS Smallwood binding freeze anchors if roots or membership drift. | TreeKEM commits authenticate the tree but require an online committer. | Membership is service-controlled; no cryptographic completeness proof. | Membership events are server-signed; authenticity depends on the homeserver you trust. |
| **Forward secrecy granularity** | Minutes-grade per epoch (`H`, default 5 min) with time-blind enforcement. Payload keys require both E_k (ME-OR, independent) and K_barrier (PRS, independent) — K_fs compromise alone cannot decrypt messages. | Per commit (interactive). | Per message (Double Ratchet + Sender Keys). | Megolm ratchets forward per message, but compromise leaks future traffic until the sender rotates the session. |
| **Post-compromise recovery** | Publish a new anchor (FS purge) to rotate `K_fs` (PCS); K_barrier rotation via KEM-tree cover revokes access for compromised members (PRS). | Honest member must commit an update replacing the compromised leaf. | One new ratchet step (send/receive) restores PCS. | Requires establishing a new Megolm session; existing session remains compromised. |
| **Asynchronous join?** | ✅ Yes — joiner fetches anchor + witness; server validates alone. | ⚠️ Needs a live committer. Batching is optional but adds latency while the batch finalises. | ❌ Requires admin/service interaction; no offline admission. | ⚠️ Homeserver accepts the join, but a member must be online to share session keys/history. |
| **Scalability & concurrency** | Multi-Head Windows (default 16 parallel) + deterministic simulations to ~10⁶ members; real deployments >100k are still research pilots. | Sequential commits; batching reduces round-trips but increases wait time. OpenMLS reports strain beyond ≈1–2 k participants.[1] | Service limit 1 000 members per group.[2] | Large rooms are routine, but key-share fan-out grows with membership and stresses clients at very high scale. |
| **Deniability** | Anchors use ML-DSA (non-deniable); application messages share epoch keys, yielding symmetric-key deniability similar to other shared-key groups. | Commit messages are signed (non-deniable). | Double Ratchet provides strong deniability. | Device identity keys are long-lived; deniability is limited. |
| **Server-blindness verifiability** | `cargo test --all` + `./scripts/verify_no_secrets.sh` ensure no decryption helpers ship. | Depends on operator attestations/transparency logs; no built-in guard. | Relies on Signal Foundation operating the published stack. | Depends on homeserver operator policy; no automatic blindness proof. |
| **Deployment maturity** | Research-grade prototype for the current `v0.1.4` base profile. | IETF standard with multiple implementations. | Global production deployment. | Production federated ecosystem. |

**Notes & sources.**
- City‑G's “millions” figure refers to deterministic simulations and architectural limits documented in `docs/protocol/01-overview.md`; real-world deployments beyond ≈100 k members remain research pilots.
- MLS scale observations reference OpenMLS' public benchmarks and documentation.[1]
- Signal’s group size limit is published in the official help center.[2]
- Matrix behaviour depends on homeserver policies; large deployments exist, but recovery from compromise requires session resets.
- For rough codebase scale: City‑G 59,876 LOC total (46,675 LOC core protocol + 13,201 LOC GUI), OpenMLS 76,912 LOC, libsignal 133,424 LOC. Measured using tokei on Rust workspaces. See [docs/evidence/README.md](docs/evidence/README.md) for methodology.

---

## What you get in this repository

* **Profile**: `tswe/msphf-we/fs-hybrid + prs-barrier` — server-blind admission, merge/rollup, mandatory minutes-grade forward secrecy, and post-revocation secrecy via KEM-tree barrier.
* **Server‑blindness guardrails**: automated checks in this repo fail CI if server code ever attempts to handle epoch secrets. It's evidence you can re‑run.
* **Docs you can trace**: every public claim here maps to the final specs bundled in the repo.

---

## Security model in one slide

* **End‑to‑end confidentiality**: only devices hold decryption ability; the server validates proofs but cannot decrypt the protected header.
* **Consistency**: receivers can verify who was added/removed as they adopt new epochs; **checkpoints/rollups** keep that view compact without granting anyone new decryption rights for the past.
* **Forward secrecy**: keys evolve on a short schedule your devices enforce locally; the server cannot secretly widen that window because acceptance is **time‑blind**.
* **Post‑revocation secrecy**: the PRS barrier (`K_barrier` + KEM-tree cover) ensures that revoked members lose access to future message keys, even if they cached prior group state.

---

## Current limits & honest trade‑offs

* **Metadata exposure**: City‑G does not hide metadata (e.g., that an update happened).
* **FS granularity**: minutes‑grade epoch rotation for the FS chain; payload keys additionally depend on E_k (ME-OR, independent of K_fs) and K_barrier (PRS), so K_fs compromise alone does not yield payload decryption. Within an epoch, all messages share K_msg_epoch. If you need per‑message FS, that's a different trade‑off space.
* **Scale in practice**: the architecture and simulations support millions; **real‑world** rollouts above **~100k** are still research pilots at this time.

---

## Client integration

**How clients create anchors**: Fetch group state from server (roots + O(log N) frontier), compute new state with cryptographic proofs locally, submit to server for blind validation. The Merkle frontier scales logarithmically: 1,000 members = ~10 hashes, 1M members = ~20 hashes.

**Implementation guides**:
- **Quick start**: [cityg-client crate](crates/cityg-client/README.md)
- **Protocol details**: [protocol/08-client-operations.md](docs/protocol/08-client-operations.md)
- **API integration**: [api-reference.md](docs/api-reference.md)

---

## Read next

* **Unified spec (v0.1.4):** publisher‑blind acceptance, offline admission, joins that self-finalize without another client online, merges/rollups, FS-hybrid, and PRS barrier — [`docs/specs.md`](docs/specs.md).
* **Protocol companion docs:** chapterized companion and historical material — [`docs/protocol/`](docs/protocol/00-README.md).
* **Workflows & diagrams:** visual sequence diagrams for common operations — [`docs/workflows.md`](docs/workflows.md).

---

## Short glossary

* **Anchor** — a signed, server‑blind update (e.g., "X joined"). The server can validate it but cannot decrypt the header that protects the next keys. Devices derive and use those keys privately.
* **Checkpoint / Rollup** — a compact summary that replaces many anchors so newcomers sync quickly **without** gaining any extra ability to decrypt past content.
* **Minutes‑grade FS (time‑blind)** — your devices rotate secrets on a short timer and enforce adoption locally; the server never consults clocks to admit updates.
* **CAPSS Smallwood** — Fiat-Shamir Linear Integrity proof (ROM soundness, ~12KB typical) that proves seed→hp derivation was deterministic and binds forward-secrecy metadata (fs_epoch_commit, device chain).
* **ZK-VRF** — Zero-Knowledge Verifiable Random Function proof (≤8KB) that proves Y* correctness without revealing it (output-hiding).
* **KBROAD** — Group key broadcasting envelope (ML-KEM-768 + ChaCha20-Poly1305) that encrypts hp; server validates structure without decryption.
* **hp** — Hash projection key (RLWE parameters) used to compute Y* via smooth projective hash functions.
* **Y\*** — VRF output computed via ME-OR (Masked-Equality OR), used to derive epoch key E_k.
* **E_k** — Epoch key derived from SPHF output; in v0.1.4, message keys are further bound to `K_barrier` via HKDF-BLAKE3 (spec S8.3). E_k is independent of K_fs; payload confidentiality requires both E_k and K_barrier.

---

## Local GUI Quick Start

For a clean local manual test with two GUI instances:

**Terminal 1: API**
```bash
cd /Users/admin/Desktop/Repositories/cityg
export CITYG_SERVER_ADDRESS=127.0.0.1:8080
export CITYG_SERVER_ROOMS_ADMIN_TOKEN=dev-admin-token
export CITYG_SERVER_MESSAGE_AUTH_TOKEN=dev-message-token
cargo run -p cityg-api
```

**Terminal 2: first GUI**
```bash
cd /Users/admin/Desktop/Repositories/cityg
export CITYG_CLIENT_ADMIN_TOKEN=dev-admin-token
export CITYG_CLIENT_MESSAGE_AUTH_TOKEN=dev-message-token
export CITYG_GUI_CONFIG_DIR=/tmp/cityg-gui-1
cargo run -p cityg-gui --features native-app
```

**Terminal 3: second GUI**
```bash
cd /Users/admin/Desktop/Repositories/cityg
export CITYG_CLIENT_ADMIN_TOKEN=dev-admin-token
export CITYG_CLIENT_MESSAGE_AUTH_TOKEN=dev-message-token
export CITYG_GUI_CONFIG_DIR=/tmp/cityg-gui-2
cargo run -p cityg-gui --features native-app
```

Notes:

* `CITYG_GUI_CONFIG_DIR` keeps the two GUI instances isolated so they do not share session files.
* The GUI now defaults to the `cityg-gui` binary, so `cargo run -p cityg-gui --features native-app` is sufficient.
* `CITYG_SERVER_ALLOW_INSECURE_ADMIN=1` no longer opens admin endpoints without a token. Even for local testing, set an explicit `CITYG_SERVER_ROOMS_ADMIN_TOKEN` and the matching `CITYG_CLIENT_ADMIN_TOKEN`.

---

## Contributing

We welcome contributions from researchers and engineers! Before submitting:

### **1. Understand the Fundamentals**
- Read [docs/protocol/01-overview.md](docs/protocol/01-overview.md)
- Study [docs/specs.md](docs/specs.md) (normative specification)
- Review [docs/protocol/10-security-model.md](docs/protocol/10-security-model.md)

### **2. Development Workflow**
```bash
# Create feature branch
git checkout -b feature/improve-sphf

# Make changes with tests
vim crates/msphf-core/src/rlwe/mod.rs
vim crates/msphf-core/tests/rlwe_kat.rs

# Verify compliance
./scripts/setup-git-hooks.sh
./scripts/ci/local-ci.sh
CITYG_FAST=1 ./scripts/ci/local-ci.sh

# Commit with spec references
git commit -m "Optimize RLWE NTT (§9, Annex C)"
```

### **3. Contribution Guidelines**
- **Preserve security guarantees** (no secrets in `AcceptanceContext`)
- **Add KATs** (Known-Answer Tests for crypto changes)
- **Reference spec sections** (§12.2, Annex L, etc.)
- **Maintain determinism** (CBOR canonical encoding)
- **Update docs** (protocol docs + CHANGELOG)

### **4. Research Contributions**
We're especially interested in:
- Formal verification (Coq/Lean proofs)
- RLWE-HPS security analysis
- Side-channel analysis (timing, cache)
- SIMD optimizations (AVX2/NEON)
- Alternative SPHF instantiations

---

## Citation

If you use City-G in academic research, please cite:

```bibtex
@misc{cityg2025,
  title={City-G: Research-Grade Post-Quantum E2EE for Massive-Scale Groups},
  author={Sabri Haddouche},
  year={2025},
  howpublished={\url{https://github.com/pwnsdx/cityg}},
  note={Protocol Specification: tswe/msphf-we/fs-hybrid + prs-barrier}
}
```

---

## Frequently Asked Questions

### **Q: Is this production-ready?**
**A:** It's a **research-grade prototype** and not production-ready:
- Security audit complete (timing side-channels fixed)
- `cargo test --all` targets currently pass (200+ core tests; protobuf compiler is automatically vendored)
- CI-enforced server blindness checks (verify_no_secrets.sh)
- Novel cryptography (less battle-tested than MLS)
- Limited ecosystem (Rust only, no FFI yet)
- RLWE-HPS A1 (Module-LWE with n=256, k=3, q=3329, η=2) maps to an LWE instance whose best-known classical attack costs about 2^99 operations and whose best-known quantum attack costs about 2^95 operations (per Albrecht's lattice-estimator); we therefore conservatively quote ≈96-bit quantum security.

**Recommendation:** Suitable for **research deployments** and **experimental pilots** only. Not recommended for production use or consumer apps where MLS suffices.

### **Q: How does server-blindness actually work?**
**A:** Four layers:
1. **Source discipline:** No `MlKemSecretKey` in `AcceptanceContext` (CI guard fails if added)
2. **Functional:** No `ml_kem_decapsulate()` in server code (code review)
3. **Cryptographic:** ML-KEM-768 IND-CCA2 + ZK-VRF output-hiding (FIPS 203)
4. **Automated:** `./scripts/verify_no_secrets.sh` (10 checks, runs in CI)

### **Q: What's the security assumption?**
**A:** Hardness of **Module-LWE** (NIST ML-KEM-768 foundation). If quantum computers break lattices, City-G breaks, but so does all post-quantum crypto.

### **Q: Who creates anchors? Can Bob self-join or does he need admin approval?**
**A:** It depends on group policy. The protocol supports both:

- **Open groups (self-join)**: Bob creates his own anchor. Server validates cryptographically, then applies policy rules (rate limits, blocklists).
- **Controlled groups (admin-only)**: Admin creates anchor for Bob. Server validates cryptographically, then enforces admin-only policy.

The server validates all anchors cryptographically (proofs, signatures, witnesses) but never creates them. Policy determines who can create anchors for each group type.

See [workflows.md#policy-vs-cryptography](docs/workflows.md#policy-vs-cryptography) for detailed examples and patterns.

### **Q: Can I integrate this with my app?**
**A:** Yes! See:
- [docs/protocol/08-client-operations.md](docs/protocol/08-client-operations.md) (API guide)
- [docs/protocol/14-deployment-guide.md](docs/protocol/14-deployment-guide.md) (architecture)
- `crates/cityg-client/` (SDK reference)
- `crates/cityg-gui/` (desktop messaging client)

### **Q: How do I ban or reinstate a member?**
**A:** The **publisher** (orchestrator) generates a merge anchor via `joiner_kgen_merge_or`, adjusting `join_delta_root` and the `revoked_*` roots. The server validates it blindly. See the `ban_and_reinstate_member_flow` test ([crates/msphf-orchestrator/tests/end_to_end.rs](crates/msphf-orchestrator/tests/end_to_end.rs)) for a full example.

### **Q: What metadata does the server see?**
**A:** The server sees:
- **Merkle root transitions** (membership changed, e.g., 7000→7001)
- **Leaf IDs**: 32-byte hashes like `H(device_public_key)`
- **Number of members added/removed** (`join_leaf_ids.len()` from SRX)
- **PoP signer**: which device created the anchor (via PoP public key hash)
- **Timing**: when anchors occur
- **xk_hash**: commitment to anchor context (group+roots), NOT device identity

The server **validates** (`accept_anchor`):
- ✓ Cryptography: CAPSS Smallwood/ZK-VRF proofs, PoP signatures, SRX witnesses, Merkle consistency
- ✓ Coarse policy (AcceptanceOptions): allowed SRX modes, params IDs, bootstrap policy

**Your application** then **enforces fine-grained policy** (before persisting):
- Check `join_leaf_ids.len() == 1` (only one member added)
- Check PoP signer against admin allow-list for this group
- Check rate limits, blocklists
- Decide: open_join vs admin_only (group-specific)

The server does **NOT** see:
- **Device secret keys** (only public keys transmitted)
- **Human identities** (Alice, Bob, etc.) — application-level mapping
- **hp, Y*, E_k** (cryptographically hidden via KBROAD + ZK-VRF)
- **Message content** (encrypted with E_k)

**Key distinction**: `accept_anchor` is policy-agnostic (validates crypto only). You enforce policy by examining validated anchor fields before persisting. Identity linking (leaf_hash → user) is also application-level.

**Clarification on "Publisher-Blind"**: City-G is **cryptographically blind** to encryption keys (hp, Y*, E_k) and message content, but the server **CAN identify devices** via public keys transmitted in field #108 during join/merge. "Publisher-blind" means the server cannot decrypt messages or derive encryption keys, NOT sender anonymity. See [Security Model](docs/protocol/10-security-model.md) for details.

**More Questions?** See [docs/protocol/17-faq.md](docs/protocol/17-faq.md)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Sabri Haddouche

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Contact & Support

- 📧 **Security Issues:** Email pwnsdx@protonmail.ch (PGP available with ProtonMail)
- 🐛 **Bug Reports:** GitHub Issues
- 💬 **Discussions:** GitHub Discussions
- 📚 **Documentation:** [docs/protocol/](docs/protocol/)

---

## Acknowledgments

City-G builds on research in:
- **Smooth Projective Hash Functions** (Cramer & Shoup, 2002)
- **RLWE-Based SPHF** (Benhamouda et al., 2013)
- **NIST Post-Quantum Standards** (ML-KEM, ML-DSA)
- **BLAKE3** cryptographic hash function
- **Smallwood/DECS** proof system for linear integrity
- **ZK-VRF** (Zero-Knowledge Verifiable Random Functions)

Special thanks to the cryptography research community for foundational work on lattice-based cryptography and zero-knowledge proofs.

**Built with ❤️ for a post-quantum future**

[1]: https://github.com/openmls/openmls
[2]: https://support.signal.org/hc/en-us/articles/360007319331-Group-chats
