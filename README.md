## City‑G: post-quantum end-to-end encrypted groups (research prototype)

[![Status](https://img.shields.io/badge/status-research%20prototype-orange)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**City‑G** is a research protocol and implementation for end-to-end
encrypted group messaging with post-quantum primitives. Its current profile,
**`city-g/v0.2`**, follows the structure of MLS (RFC 9420): an epoch-chained
key schedule, a TreeKEM-style ratchet tree over ML-KEM-768, commits signed
with ML-DSA-87, joins by external commit with admin-signed admissions, and a
per-sender message ratchet. A delivery service orders commits and relays
ciphertexts without holding any group secret.

> **Status.** Research prototype. Profile v0.2 replaces profile v0.1.4,
> whose headline claims did not hold according to the
> [2026-09-25 audit](docs/audits/audit-crypto-conformite-2026-09-25.md)
> (in French; its section 6 maps each finding to its fix). v0.2 has
> conformance vectors checked by an independent implementation and a
> symbolic model, but no independent human cryptographic review yet.
> Prefer MLS implementations for production.

---

## Security properties

From the [specification](docs/specs.md), section 2.2. "Server" is the
delivery service, passive or active.

| Property | Against the server | Against a removed member | Device state compromised | Device key stolen |
| --- | --- | --- | --- | --- |
| Confidentiality of messages | yes | yes, for epochs after its removal | outside the FS and PCS windows | no, until the device is removed |
| Sender authentication | yes | yes | yes | yes, for the other members |
| Membership agreement | yes | yes | yes | yes |
| Admission control (no member without an admin's signature) | yes | yes | yes | yes, unless the device is an admin |
| Post-removal secrecy | yes | yes, even if it authored a commit before | n/a | once the device, and any device it admitted, is removed |
| Forward secrecy | yes | n/a | keys older than `FS_WINDOW` (24 h) | yes |
| Post-compromise security | n/a | n/a | after the device's next self-update | no, until the device is removed |

Device keys (ML-DSA-87) are long-term credentials: whoever steals one can
act as that device until it is removed and replaced. Not provided at all:
metadata privacy (the server sees the roster, who sends when, message sizes
and aliases), availability (the server can deny service), secrecy from
members of the same epoch, and authenticated identities (aliases are
self-asserted: compare [security codes](docs/fingerprints.md)).

## How it works

* **Groups and epochs.** A group (`gid`, bound to its creator's key) moves
  from epoch to epoch through commits. Every secret of epoch `n` derives
  from the previous epoch's `init_secret` and from a fresh path secret of the
  commit's author, bound to a `GroupContext` that commits to the tree, the
  roster and the whole transcript: members with different views derive
  different keys and reject the commit.
* **Barrier tree.** A binary tree of ML-KEM-768 keys over `n_max` slots
  (at most 1024). Each commit renews its author's leaf and direct path and
  encrypts the new path secrets to the rest of the tree; removed members'
  leaves and paths are blanked first, so they learn nothing of later epochs.
* **Joining.** An admin shares an invite link (server URL, group, invite
  seed). The joiner signs its own admission with the invite key and joins
  with an external commit: no member needs to be online, and every member
  checks that the admission chains to a current admin.
* **Leaving and removal.** A member never commits its own removal: it signs
  a removal proposal, and another member (or an admin directly) commits it.
* **Messages.** Each member sends on its own chain of keys derived from the
  epoch; messages are signed, bound to their epoch and sender, and accepted
  only from current members. Late messages of the previous epoch stay
  readable for 10 minutes.
* **Delivery service.** It verifies every commit against public state,
  accepts the first valid commit of each epoch, relays envelopes, and
  journals everything. Members authenticate to it with signed session
  requests; there is no operator token.

Sequence diagrams: [docs/workflows.md](docs/workflows.md).

## Repository

| Crate | Role |
| --- | --- |
| [`cityg-core`](crates/cityg-core) | Protocol core without I/O: encodings, KDF, tree, key schedule, commits, admission, messages, member session, delivery-service ledger. |
| [`cityg-pqc`](crates/cityg-pqc) | FIPS 204 ML-DSA-87 with per-usage contexts. |
| [`cityg-proto`](crates/cityg-proto) | Protobuf schema and routes of the `/v2` API. |
| [`cityg-server`](crates/cityg-server), [`cityg-runtime`](crates/cityg-runtime) | Delivery-service rooms, journals and request handlers. |
| [`cityg-api`](crates/cityg-api) | Native delivery service (HTTP, WebSocket, metrics). |
| [`cityg-worker`](crates/cityg-worker) | Cloudflare Worker delivery service, one Durable Object per room. |
| [`cityg-api-client`](crates/cityg-api-client) | HTTP client and member driver. |
| [`cityg-gui`](crates/cityg-gui) | Desktop client (GPUI) and the `join_leave` CLI. |
| [`cityg-stress`](crates/cityg-stress) | Load and chaos testing. |
| [`cityg-config`](crates/cityg-config) | Configuration. |

Documentation index: [docs/README.md](docs/README.md). Conformance:
[kat/](kat/README.md). Profile v0.1.4 is archived in
[docs/legacy/v0.1.4/](docs/legacy/v0.1.4/README.md).

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
python3 kat/v0.2/verify_vectors.py           # independent check of the vectors (pip install blake3)
```

* **Conformance vectors** ([`kat/v0.2/vectors.json`](kat/v0.2/vectors.json))
  are computed by the implementation and recomputed from the specification
  by an independent Python verifier.
* **A requirement map** ([`kat/kat-v0.2-conformance-manifest.json`](kat/kat-v0.2-conformance-manifest.json))
  links every requirement of the specification to its vectors and tests; a
  test checks that nothing is left out.
* **A symbolic model** ([`docs/formal/`](docs/formal/)) states the security
  goals for the key schedule, the tree, removal and admission.
* **`scripts/verify_no_secrets.sh`** checks, syntactically, that the
  server-side code uses no secret-holding type. It is a guardrail, not a
  proof.

## Limits

* Metadata is visible to the delivery service.
* Groups have at most 1024 members; a commit of a full group is about 1.2 MB.
  Larger groups need sub-groups or federation.
* Invite links are bearer secrets until their invite expires.
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
  note={Protocol specification: profile city-g/v0.2}
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
