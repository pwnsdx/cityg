## City‑G: post-quantum end-to-end encrypted groups (research prototype)

[![Status](https://img.shields.io/badge/status-research%20prototype-orange)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**City‑G** is a research protocol and implementation for end-to-end
encrypted group messaging with post-quantum primitives. Its current profile,
**`city-g/v0.3`**, follows MLS (RFC 9420): an epoch-chained key schedule, a
ratchet tree in the RFC 9420 array layout over X-Wing (ML-KEM-768 with
X25519), commits signed with ML-DSA-65, welcomes for members added by
someone else's commit, and a per-sender message ratchet. It is built for
groups of thousands of members where people join and leave all the time:
joins wait in the delivery service and enter together with the next commit,
the tree grows and shrinks with the group, members may follow the group as
*light members* without holding the tree, and a device can rotate its
signature key without leaving. A delivery service orders commits and relays
ciphertexts without holding any group secret.

> **Status.** Research prototype. Profile v0.3 replaces profile v0.2
> ([why](docs/design-v0.3.md)), which replaced profile v0.1.4 after the
> [2026-09-25 audit](docs/audits/audit-crypto-conformite-2026-09-25.md)
> (in French). v0.3 has conformance vectors checked by an independent
> implementation and a symbolic model, but no independent human
> cryptographic review yet. Prefer MLS implementations for production.

---

## Security properties

From the [specification](docs/specs.md), section 2.2, for full members.
"Server" is the delivery service, passive or active.

| Property | Against the server | Against a removed member | Device state compromised | Device key stolen |
| --- | --- | --- | --- | --- |
| Confidentiality of messages | yes | yes, for epochs after its removal | outside the FS and PCS windows | no, until the device is removed |
| Sender authentication | yes | yes | yes | yes, for the other members |
| Membership agreement | yes | yes | yes | yes |
| Admission control (no member without an admin's signature) | yes | yes | yes | yes, unless the device is an admin |
| Post-removal secrecy | yes | yes, even if it authored a commit before | n/a | once the device, and any device it admitted, is removed |
| Forward secrecy | yes | n/a | keys older than `FS_WINDOW` (24 h) | yes |
| Post-compromise security | n/a | n/a | after the device's next self-update | no, until the device is removed |
| Join secrecy (nothing of the epochs before a join) | yes | n/a | yes | yes |

Device keys (ML-DSA-65) are long-term credentials: whoever steals one can
act as that device until it is removed and replaced. A device can rotate
its key, but that does not undo a compromise already used. Light members
get the same properties except membership agreement, which holds for them
only up to the tree hash against a server colluding with a member
([section 14.6](docs/specs.md#14-6-trust)). Not provided at all: metadata
privacy (the server sees the members, who sends when, message sizes and
aliases), availability (the server can deny service), secrecy from members
of the same epoch, and authenticated identities (aliases are self-asserted:
compare [security codes](docs/fingerprints.md)).

## How it works

* **Groups and epochs.** A group (`gid`, bound to its creator's key) moves
  from epoch to epoch through commits. Every secret of epoch `n` derives
  from the previous epoch's `init_secret` and from a fresh path secret of the
  commit's author, bound to a `GroupContext` that commits to the tree, the
  registry (capacity, admins, retired admissions) and the whole transcript:
  members with different views derive different keys and reject the commit.
* **Ratchet tree.** The members live in the leaves of a tree of X-Wing keys
  (RFC 9420 layout) that doubles when it is full, up to the capacity chosen
  at genesis (at most 8192), and halves when its right half empties. Each
  commit renews its author's leaf and direct path and encrypts the new path
  secrets to the rest of the tree; removed members' leaves and paths are
  blanked first, so they learn nothing of later epochs. A member is named by
  its occupancy `[leaf, since]`.
* **Joining.** An admin shares an invite link (server URL, group, invite
  seed); invites expire, count their uses and can be revoked. The joiner
  signs its own admission with the invite key and records a join request.
  The next commit, by any member, places every waiting request at once, and
  each joiner opens a *welcome* holding the new epoch's joiner secret. If
  nobody commits within a second or two, the joiner commits its own entry
  (an external commit) and brings the other waiting joiners along. Every
  member checks that each admission chains to a current admin.
* **Leaving and removal.** A member never commits its own removal: it signs
  a removal proposal, and another member (or an admin directly) commits it.
  Recorded proposals cannot be skipped: every commit includes the oldest
  overdue ones.
* **Messages.** Each member sends on its own chain of keys derived from the
  epoch; messages are signed, bound to their epoch and sender occupancy, and
  accepted only from current members. Late messages of the four previous
  epochs stay readable for 10 minutes.
* **Light members.** A member may keep only the occupancies, the registry,
  its own path and the keys of the senders it met, and check each commit with
  Merkle proofs that the delivery service computes. It becomes full for the
  commits it authors.
* **Key rotation.** A member replaces its signature key with a commit signed
  by the old key and the new one; its occupancy, admission and admin rights
  stay.
* **Delivery service.** It verifies every commit against public state,
  accepts the first valid commit of each epoch, keeps the join requests,
  welcomes and light-member proofs, relays envelopes, and journals
  everything. Members authenticate to it with signed session requests; there
  is no operator token.

Sequence diagrams: [docs/workflows.md](docs/workflows.md).

## Repository

| Crate | Role |
| --- | --- |
| [`cityg-core`](crates/cityg-core) | Protocol core without I/O: encodings, KDF, X-Wing, tree and leaf proofs, key schedule, commits, admission, joins and welcomes, messages, full and light member sessions, delivery-service ledger. |
| [`cityg-pqc`](crates/cityg-pqc) | FIPS 204 ML-DSA-65 with per-usage contexts. |
| [`cityg-cite`](crates/cityg-cite) | Prototype of the draft profile v0.4 for groups of millions of members: districts, windows, taints, a group with no member online, and an in-memory delivery service. No I/O; not wired to the `/v3` stack. |
| [`cityg-proto`](crates/cityg-proto) | Protobuf schema and routes of the `/v3` API. |
| [`cityg-server`](crates/cityg-server), [`cityg-runtime`](crates/cityg-runtime) | Delivery-service rooms, journals and request handlers. |
| [`cityg-api`](crates/cityg-api) | Native delivery service (HTTP, WebSocket, metrics). |
| [`cityg-worker`](crates/cityg-worker) | Cloudflare Worker delivery service, one Durable Object per room. |
| [`cityg-api-client`](crates/cityg-api-client) | HTTP client and member drivers, full and light. |
| [`cityg-gui`](crates/cityg-gui) | Desktop client (GPUI) and the `join_leave` CLI. |
| [`cityg-stress`](crates/cityg-stress) | Load and chaos testing. |
| [`cityg-config`](crates/cityg-config) | Configuration. |

Documentation index: [docs/README.md](docs/README.md). Conformance:
[kat/](kat/README.md). Earlier profiles are archived:
[v0.2](docs/legacy/v0.2/specs.md) and [v0.1.4](docs/legacy/v0.1.4/README.md).

## Quick start

A delivery service and two desktop clients on one machine:

```bash
# Terminal 1: the delivery service (rooms in memory; set
# CITYG_SERVER_STATE_PATH to keep them across restarts)
cargo run -p cityg-api

# Terminals 2 and 3: two clients with separate state
CITYG_GUI_CONFIG_DIR=/tmp/cityg-alice cargo run -p cityg-gui --features native-app
CITYG_GUI_CONFIG_DIR=/tmp/cityg-bob   cargo run -p cityg-gui --features native-app
```

In the first client, enter `http://127.0.0.1:8080`, choose **New room** and
**Create room**, then **Copy Invite**. In the second, paste the link and
**Join room**. See the [GUI guide](docs/gui-user-guide.md).

Simulated members from the command line:

```bash
cargo run -p cityg-gui --bin join_leave -- http://127.0.0.1:8080 --count=3 --batch --message-burst-count=2
```

Rust integration goes through the member driver of `cityg-api-client`
([API reference](docs/api-reference.md)); deployment options are in
[docs/deployment.md](docs/deployment.md).

## Verification

```bash
cargo test --workspace && cargo test -p cityg-gui --features native-app
./scripts/ci/local-ci.sh                     # everything the CI runs
./scripts/security_review.sh                 # tests and the server-blindness guardrail
python3 kat/v0.3/verify_vectors.py           # independent check (pip install blake3 kyber-py dilithium-py)
```

* **Conformance vectors** ([`kat/v0.3/vectors.json`](kat/v0.3/vectors.json))
  are computed by the implementation and recomputed from the specification
  by an independent Python verifier.
* **A requirement map** ([`kat/kat-v0.3-conformance-manifest.json`](kat/kat-v0.3-conformance-manifest.json))
  links every requirement of the specification to its vectors and tests; a
  test checks that nothing is left out.
* **A symbolic model** ([`docs/formal/`](docs/formal/)) states the security
  goals for the key schedule, joins and welcomes, removal, admission, key
  rotation and messages.
* **`scripts/verify_no_secrets.sh`** checks, syntactically, that the
  server-side code uses no secret-holding type. It is a guardrail, not a
  proof.

## Limits

* Metadata is visible to the delivery service.
* Groups have at most 8192 members (the reference delivery service accepts
  up to 1024 by default). The largest commit of an 8192-member group is
  under 10 MB and its tree about 35 MB, which is why such groups need light
  members. A [research note](docs/research/grands-groupes-2026-09-25.md)
  (in French) studies how to reach groups of millions of members. A draft
  profile v0.4 ([design note](docs/design-v0.4.md),
  [draft specification](docs/specs-v0.4-draft.md)) and its prototype crate
  `cityg-cite` follow it; they are not normative and not deployed.
* A joiner cannot check the history before the epoch it enters: a malicious
  delivery service can show it a fabricated view of the group until it
  compares its security code with a member it knows.
* Light members rely on the delivery service for the new tree hash of each
  commit and for the uniqueness of device keys.
* Invite links are bearer secrets until their invite expires, is revoked or
  has admitted its number of devices.
* A malicious member can author a commit that others cannot process: it is
  detected, attributed and recovered from (resync), not prevented.
* Research code: side channels of the dependencies and of the GUI's local
  storage have not been assessed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Protocol changes start with the
specification and come with regenerated vectors and an updated requirement
map. Report vulnerabilities privately ([SECURITY.md](SECURITY.md)).

## Citation

```bibtex
@misc{cityg2026,
  title={City-G: Post-Quantum End-to-End Encrypted Groups},
  author={Sabri Haddouche},
  year={2026},
  howpublished={\url{https://github.com/pwnsdx/cityg}},
  note={Protocol specification: profile city-g/v0.3}
}
```

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2025 Sabri Haddouche.

## Contact

- **Security issues:** pwnsdx@protonmail.ch (PGP available with ProtonMail)
- **Bugs:** GitHub Issues
- **Discussions:** GitHub Discussions

## Acknowledgments

City-G builds on MLS (RFC 9420) and the TreeKEM line of work, on the NIST
post-quantum standards FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), and on
BLAKE3 and ChaCha20-Poly1305.
