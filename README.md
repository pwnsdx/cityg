## City‑G: Post-Quantum E2EE for Large Groups (research prototype)

[![Status](https://img.shields.io/badge/status-research%20prototype-orange)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**City‑G** is a research protocol for end‑to‑end encrypted groups aimed at large audiences (O(log N) membership witnesses; tested to N_max=2048, larger benchmarks pending). Message payloads are encrypted under keys derived from `K_barrier`, a group key distributed to members through a post‑quantum KEM tree that the server never receives. New members self‑finalize their join without another member online. The current profile is `v0.1.4` (`tswe/msphf-we/fs-hybrid + prs-barrier`); a `v0.2` profile is in progress.

> **Security status.** The [2026-09-25 audit](docs/audits/audit-crypto-conformite-2026-09-25.md) (in French) found that several headline claims of `v0.1.4` do not hold. In particular the server can recompute `E_k` for JOIN anchors (C-01), the SPHF/CAPSS/ZK-VRF transcripts prove nothing (C-02), and there is no minutes-grade forward secrecy (H-02). What holds is summarized in [Security claims status](#security-claims-status). This branch fixes the P0 findings (C-03, H-09, H-10 receipt checks, M-06, the `capss_witness` leak of C-01) and adopts FIPS 204 ML-DSA-87 (H-05).

---

## Who this is for

* **Large-scale communities**: City/municipality groups, Discord/Telegram-style communities, public event coordination (conferences, open-source projects), large enterprise messaging.
* **Broadcast channels**: Newsletter distribution, community announcements, emergency alert systems.
* **High-concurrency scenarios**: Applications with frequent joins/leaves and many offline participants.
* Teams that want **post‑quantum** building blocks now, not later.

---

## What makes City‑G different

* **The server never holds message keys.** Payload keys derive from `K_barrier`, which travels only inside the ML‑KEM‑768 barrier tree; the server stores ciphertext and validates structure. It is *not* blind to epoch material in `v0.1.4`: `E_k` is computable from public data for JOIN anchors (C-01), so confidentiality rests on `K_barrier` alone.
* **Offline admission.** A joiner self-finalizes (`join_finalize`) without another member online.
* **Post-revocation secrecy on removal.** A member leaves by signing a removal proposal that a remaining member commits; the leaver never chooses the next `K_barrier` (audit C-03). Room admins expel members the same way.
* **Built for scale.** Membership witnesses grow **O(log N)**; periodic **checkpoints/rollups** keep sync costs bounded.
* **Post‑quantum primitives.** ML‑KEM‑768 (FIPS 203), ML‑DSA‑87 (FIPS 204) with a distinct context string per signature usage, BLAKE3, ChaCha20‑Poly1305.

> **Not a metadata‑hiding system.** The server sees public structure (who joined or left, when, and which device authored an update).

---

## How it works (high-level)

### The Core Idea

City-G splits responsibilities between **trusted clients** and an **untrusted server** using zero-knowledge proofs:

**Join flow** (Bob joins a 7000-person group):
1. **Bob fetches** group state: parent_root, frontier (~13 hashes for 7000 members), kbroad_pub
2. **Bob creates** anchor locally: adds his leaf_id, attaches the `v0.1.4` proof transcripts (CAPSS, ZK-VRF; see below), seals hp
3. **Bob submits** anchor to server
4. **Server validates**: PoP signature, transcript structure, SRX witnesses, Merkle consistency (never decrypts KBROAD)
5. **Server applies** policy: checks rate limits, blocklists (your application code)
6. **Bob sends** messages encrypted under a key derived from `K_barrier` and the epoch material

**Result**: Bob and the other members hold `K_barrier`; the server never receives it, nor message plaintext. In `v0.1.4` the server can however recompute `E_k` for JOIN anchors from public data (audit C-01).

For detailed diagrams, see [workflows.md](docs/workflows.md#join-flow) (sequence diagrams + visual guides) and [protocol/01-overview.md](docs/protocol/01-overview.md) (technical specifications).

### Proof transcripts (v0.1.4)

Anchors carry two transcripts, **CAPSS Smallwood** (~12KB) and **ZK-VRF** (≤8KB). The audit (C-02) found that neither proves the relation it was meant to: CAPSS proves a toy relation derived from public data and its verifier does not evaluate constraints, and the VRF key is not bound to the device identity nor its output used. They are structural checks only and are scheduled for removal in `v0.2`. See [crates/capss/README.md](crates/capss/README.md) and [crates/msphf-lb-vrf/README.md](crates/msphf-lb-vrf/README.md).

### What the Server Sees (and Doesn't)

**Server sees**: Merkle root transitions, leaf IDs (hashes), device public keys, timing metadata, sealed envelopes, transcript structures
**Server validates**: signatures, witnesses and structure via `accept_anchor`, and barrier-update authorization (updater = author's own slot; every revocation backed by a signed removal proposal or a room admin)
**Your app enforces**: Policy (rate limits, blocklists) by examining validated anchor fields

**Server never receives**: `K_barrier`, message keys, device secret keys, message content, the CAPSS witness. **Not hidden in `v0.1.4`**: `E_k` of JOIN anchors (C-01).

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

CI runs ./scripts/verify_no_secrets.sh, a syntactic (grep) check that
the accept/ code path does not import MlKemSecretKey or decrypt helpers.
It is a guardrail, not a proof of server blindness.
```

### Policy vs Cryptography

City-G separates **cryptographic validation** (protocol-level proofs) from **policy enforcement** (application-level rules):

**Cryptographic layer** (`accept_anchor`):
- Validates signatures, SRX witnesses, Merkle consistency and transcript structure
- Never receives `K_barrier` or message keys (`E_k` of JOIN anchors is not secret in `v0.1.4`, C-01)
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

## Security claims status

| Property | Status on this branch | Audit |
| --- | --- | --- |
| Payload confidentiality against the server | Holds while `K_barrier` stays secret; `E_k` is not secret from the server | C-01 |
| Post-revocation secrecy on leave/expel | Holds: the leaver never authors its own revocation; removals are signed proposals committed by another member | C-03 (fixed) |
| Sender authentication | ML-DSA-87 signature under the `city-g/msg/v2` context; receivers drop senders outside the current roster and show the signed timestamp | H-05, H-10 (receipt checks fixed; context binding in `v0.2`) |
| Forward secrecy | Granularity is one barrier version, no time bound; `K_fs` does not protect payloads | H-02 (`v0.2`) |
| Post-compromise security | Manual PCS refresh; the barrier leaf key is not rotated | H-03 (`v0.2`) |
| SPHF / CAPSS / ZK-VRF proofs | Structural checks only; parameters are labelled `rlwe-params/mock` | C-02 (removal in `v0.2`) |
| Default server configuration | Fails closed: the global history authority is enabled by default | M-06 (fixed) |

**Scale.** The O(log N) architecture has been simulated deterministically well beyond the tested `N_max=2048`; real deployments above ≈100k members have not been run. For rough codebase scale, see [docs/evidence/README.md](docs/evidence/README.md).

---

## What you get in this repository

* **Profile**: `tswe/msphf-we/fs-hybrid + prs-barrier` (`v0.1.4`) with the audit's P0 fixes; `v0.2` work in progress.
* **Guardrails**: `scripts/verify_no_secrets.sh` (syntactic checks that server code does not import decryption helpers), requirement manifests under [`kat/`](kat/) linking spec requirements to tests.
* **Docs you can trace**: the normative spec [`docs/specs.md`](docs/specs.md) and the [audit report](docs/audits/audit-crypto-conformite-2026-09-25.md).

---

## Security model in one slide

* **Confidentiality**: only members hold `K_barrier`, from which payload keys derive; the server stores ciphertext. Epoch material other than `K_barrier` is not secret from the server in `v0.1.4`.
* **Consistency**: receivers verify roster roots as they adopt new epochs; **checkpoints/rollups** keep that view compact without granting new decryption rights for the past.
* **Forward secrecy**: coarse, one barrier version at a time; a compromise of `K_barrier` exposes the current version since it started (H-02).
* **Post‑revocation secrecy**: a removal is committed by a remaining member, who re-keys its own barrier path and blanks the removed leaf, so the removed member does not learn later barrier keys.

---

## Current limits & honest trade‑offs

* **Metadata exposure**: City‑G does not hide metadata (who changed membership, when, from which device).
* **FS granularity**: no minutes-grade forward secrecy; all messages of one barrier version share its key material.
* **Proof layer**: the SPHF/CAPSS/ZK-VRF transcripts add no security (C-02).
* **Scale in practice**: real‑world rollouts above **~100k** members have not been run.

---

## Client integration

**How clients create anchors**: Fetch group state from server (roots + O(log N) frontier), compute new state with cryptographic proofs locally, submit to server for blind validation. The Merkle frontier scales logarithmically: 1,000 members = ~10 hashes, 1M members = ~20 hashes.

**Implementation guides**:
- **Quick start**: [cityg-client crate](crates/cityg-client/README.md)
- **Protocol details**: [protocol/08-client-operations.md](docs/protocol/08-client-operations.md)
- **API integration**: [api-reference.md](docs/api-reference.md)

---

## Read next

* **Unified spec (v0.1.4):** anchor acceptance, offline admission, joins that self-finalize without another client online, merges/rollups, FS-hybrid, PRS barrier, and removal proposals — [`docs/specs.md`](docs/specs.md).
* **Audit (2026-09-25, French):** findings and the `v0.2` proposals — [`docs/audits/audit-crypto-conformite-2026-09-25.md`](docs/audits/audit-crypto-conformite-2026-09-25.md).
* **Protocol companion index:** explanatory and historical material — [`docs/protocol/`](docs/protocol/00-README.md).
* **Workflows & diagrams:** visual sequence diagrams for common operations — [`docs/workflows.md`](docs/workflows.md).

---

## Short glossary

* **Anchor** — a signed group update (e.g., "X joined"). The server validates its structure and signatures.
* **Removal proposal** — a signed request (`city-g/remove/v1`) to remove a member, signed by that member (leave) or a room admin; another member commits it.
* **Checkpoint / Rollup** — a compact summary that replaces many anchors so newcomers sync quickly **without** gaining any extra ability to decrypt past content.
* **CAPSS Smallwood / ZK-VRF** — proof transcripts carried by `v0.1.4` anchors; structural only (audit C-02), removed in `v0.2`.
* **KBROAD** — ML-KEM-768 + ChaCha20-Poly1305 envelope that seals `hp`.
* **hp, Y\*** — `v0.1.4` projection-key material and ME-OR output from which `E_k` derives.
* **E_k** — epoch key; not secret from the server for JOIN anchors in `v0.1.4` (C-01). Message keys further bind `K_barrier` via HKDF-BLAKE3 (spec S8.3), which carries the confidentiality.
* **K_barrier** — group key distributed through the ML-KEM-768 barrier tree; rotated on every barrier update.

---

## Local GUI Quick Start

For a clean local manual test with two GUI instances:

**Terminal 1: API**
```bash
cd cityg  # repository root
export CITYG_SERVER_ADDRESS=127.0.0.1:8080
export CITYG_SERVER_ROOMS_ADMIN_TOKEN=dev-admin-token
export CITYG_SERVER_MESSAGE_AUTH_TOKEN=dev-message-token
cargo run -p cityg-api
```

**Terminal 2: first GUI**
```bash
cd cityg  # repository root
export CITYG_CLIENT_ADMIN_TOKEN=dev-admin-token
export CITYG_CLIENT_MESSAGE_AUTH_TOKEN=dev-message-token
export CITYG_GUI_CONFIG_DIR=/tmp/cityg-gui-1
cargo run -p cityg-gui --features native-app
```

**Terminal 3: second GUI**
```bash
cd cityg  # repository root
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
**A:** No. It is a **research prototype**:
- The [2026-09-25 audit](docs/audits/audit-crypto-conformite-2026-09-25.md) reports critical findings (C-01, C-02) that only the `v0.2` redesign resolves; this branch fixes the P0 items.
- The RLWE-HPS/SPHF parameters are labelled `rlwe-params/mock` and provide no security level (C-02); no quantum security estimate applies to them.
- Novel, unproven construction; Rust only, no FFI yet.

**Recommendation:** research deployments and experiments only. Prefer MLS for production.

### **Q: What does the server learn, and what keeps it out?**
**A:** The server never receives `K_barrier`, message keys or device secret keys, and the CAPSS witness no longer leaves the device (audit C-01). It can, however, recompute `E_k` for JOIN anchors from public data (C-01), so message confidentiality rests on `K_barrier` and on the ML-KEM-768 barrier tree. `scripts/verify_no_secrets.sh` is a syntactic guardrail (grep), not a proof.

### **Q: What's the security assumption?**
**A:** ML-KEM-768 (FIPS 203) for the barrier tree and KBROAD, ML-DSA-87 (FIPS 204) for signatures, and BLAKE3 / ChaCha20-Poly1305. The SPHF/ME-OR layer contributes no security (C-02).

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

### **Q: How does a member leave, or get removed?**
**A:** Leaving signs a removal proposal (`POST /v1/rooms/remove_proposal`); a remaining member commits it with a LEAVE merge ticket, re-keying its own barrier path and blanking the leaver's leaf. The last member of a room commits its own removal. A room admin expels a member through `expel_member_ticket`, authoring the revocation from its own slot. See `crates/cityg-server/src/tests/removal_proposals.rs` and the GUI tests in `crates/cityg-gui/src/native/tests/`.

### **Q: What metadata does the server see?**
**A:** The server sees:
- **Merkle root transitions** (membership changed, e.g., 7000→7001)
- **Leaf IDs**: 32-byte hashes like `H(device_public_key)`
- **Number of members added/removed** (`join_leaf_ids.len()` from SRX)
- **PoP signer**: which device created the anchor (via PoP public key hash)
- **Timing**: when anchors occur
- **xk_hash**: commitment to anchor context (group+roots), NOT device identity

The server **validates** (`accept_anchor`):
- ✓ Signatures, SRX witnesses, Merkle consistency, barrier-update authorization, transcript structure
- ✓ Coarse policy (AcceptanceOptions): allowed SRX modes, params IDs, bootstrap policy

**Your application** then **enforces fine-grained policy** (before persisting):
- Check `join_leaf_ids.len() == 1` (only one member added)
- Check PoP signer against admin allow-list for this group
- Check rate limits, blocklists
- Decide: open_join vs admin_only (group-specific)

The server does **NOT** see:
- **Device secret keys** (only public keys transmitted)
- **Human identities** (Alice, Bob, etc.) — application-level mapping
- **`K_barrier` and message keys** (members only)
- **Message content** (encrypted under keys derived from `K_barrier`)

It can recompute `E_k` of JOIN anchors in `v0.1.4` (C-01).

**Key distinction**: `accept_anchor` is policy-agnostic (validates crypto only). You enforce policy by examining validated anchor fields before persisting. Identity linking (leaf_hash → user) is also application-level.

**On "publisher-blind"**: the server cannot decrypt messages without `K_barrier`, but it is not blind to all epoch material (C-01), and it **can identify devices** via the public keys in field #108. See [Security Model](docs/protocol/10-security-model.md).

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
