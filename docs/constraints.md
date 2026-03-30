# City-G Constraints & Requirements

Core security, functional, and performance requirements for the City-G protocol. See [`specs.md`](specs.md) for normative definitions.

---

## 1. Security Requirements

1. **Confidentiality** — The validation server must never gain access to hash projections (`hp`), VRF outputs (`Y*`), epoch keys (`E_k`), or message plaintext.
2. **Authentication** — Proof-of-possession signatures bind devices to their operations; bogus joiners must be frozen deterministically.
3. **Integrity** — Canonical Merkle witnesses, SRX payloads, and commitments ensure tamper detection.
4. **Forward Secrecy** — Epoch rotation guarantees that a compromised epoch key does not reveal future epochs.
5. **Post-Compromise Security** — Fresh epochs are independent of previously compromised material; rejoining re-randomizes contributions.
6. **Membership Consistency** — Every device derives the same membership root for a given epoch window; no forked rosters.
7. **Deniability** — AEAD and KBROAD envelopes deliberately avoid non-repudiation; ciphertexts alone are not signatures.
8. **Post-Revocation Secrecy** — Revoked members lose access to future message keys via PRS barrier (`K_barrier` + KEM-tree cover); key rotation is enforced on revocation-change (spec S11).

## 2. Functional Requirements

1. **Instant Join** — A newcomer can post immediately after generating a valid anchor; no coordinator handshakes.
2. **Offline Retrieval** — Devices may fetch anchors/messages on their own schedule; no push channel required.
3. **Concurrent Operations** — The multi-head window must sustain at least 16 concurrent joins per parent root (default `h_max = 16`).
4. **Event Tracking** — Servers record join/revoke activity for auditability without learning shared secrets.
5. **Canonical Member List** — Merkle roots/witnesses give every client the same roster snapshot.
6. **Battery-Friendly** — Proof verification on mobile stays under ~20 ms per join in practice.
7. **Massive Scale** — Witness sizes remain O(log N), targeting ~2 KB at one million members.
8. **Asynchronous Coordination** — All operations route through the server; devices never have to contact each other directly.
9. **Simple Client Footprint** — No MLS-style KeyPackages or per-peer sessions; state machines stay bounded.

## 3. Performance Targets (Reference Measurements)

| Operation             | Target                | Historical baseline |
|-----------------------|-----------------------|-------------------|
| ZK-VRF verification   | ≤ 2 ms server / ≤ 6 ms mobile | ✅ Met |
| CAPSS Smallwood verify| ≤ 12 ms mobile        | ✅ Met |
| SRX verify            | ≤ 60 ms @ 20 K members| ✅ Met |
| Proof size            | < 30 KB               | ~25 KB |
| Witness size          | O(log N)              | ~2 KB at 1 M |
| Working set           | ≤ 48 MB               | ✅ Met |

> These figures are historical reference measurements from the early profile bring-up and profiling runs. The current normative profile is defined in [`specs.md`](specs.md); use `docs/evidence/` and current validation runners for fresh empirical results.
