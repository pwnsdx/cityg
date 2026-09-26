## City‑G: post-quantum end-to-end encrypted groups of millions of members

[![Status](https://img.shields.io/badge/status-research-orange)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**City‑G** is a research protocol for end-to-end encrypted groups with
post-quantum primitives, built for groups of millions of members, bursts of
hundreds of thousands of joins and departures, and groups where no member
may be online for long periods. Its profile, **`city-g/v0.4`**, keeps the
structure of MLS (RFC 9420) — a ratchet tree whose root secret feeds an
epoch-chained key schedule, confirmation tags, welcomes and an external
init — over X-Wing (ML-KEM-768 with X25519) and ML-DSA-65, and changes how
the group is re-keyed: the tree is split into *districts* under a *city*,
every *window* of requests becomes one epoch, districts are re-keyed in
parallel by different members, and a delivery service orders and checks
everything without holding any group secret.

> **Status.** Initial version, research. This repository holds the
> [specification](docs/specs.md), the [design note](docs/design.md), a
> [symbolic model](docs/formal/) and the protocol core
> [`cityg-core`](crates/cityg-core) with an in-memory delivery service. The
> message plane, the networked delivery service and the clients are not
> there yet ([specification, section 19](docs/specs.md#19-open-items)).
> There are no test vectors and no independent human cryptographic review:
> prefer MLS implementations for production.

---

## Security properties

From the [specification](docs/specs.md), section 2.2, for members that
follow the group. "Epoch secrets" are what the message plane will encrypt
under. The delivery service is passive or active.

| Property | Against the delivery service | Against a removed member | Device state compromised | Device key stolen |
| --- | --- | --- | --- | --- |
| Confidentiality of epoch secrets | yes in a closed group; none in an open group, which anyone can join | yes, from the window that applies its removal | outside the forward-secrecy and post-compromise windows | no, until the device is removed |
| Membership agreement | yes | yes | yes | yes |
| Admission control in a closed group (no member without an admin's admission) | yes | yes | yes | yes, unless the device is an admin |
| Post-removal secrecy | n/a | yes, including for the nodes it drew as a committer | n/a | once the device is removed |
| Forward secrecy | yes | n/a | for the epochs the device erased | yes |
| Post-compromise security | n/a | n/a | after the device's next update | no, until the device is removed |
| Join secrecy | yes | n/a | yes | yes |

A malicious member that commits a district can place an entry without a
valid admission; sampled audits catch it with probability about
`1 - e^-20` and leave a transferable fraud proof. Not provided: metadata
privacy, availability (the delivery service can deny service), secrecy from
members of the same epoch, and, in an open group, secrecy from whoever joins
it. Every join stays visible, and nobody can speak as another member.

## How it works

* **Windows.** The delivery service collects requests (joins, removals,
  evictions, key updates, re-entries, catch-ups) for up to `WINDOW_MAX`
  (60 s), or `WINDOW_REMOVAL` (5 s) when a removal waits. One epoch seals
  the whole window, with no cap on its size.
* **Districts and a city.** The tree has up to `2^24` leaves, split into
  districts of `2^L` leaves (`L = 12` by default). Each district a window
  changes gets a *district commit* from its own committer, in parallel; a
  *sealer* re-keys the city above them and signs the *seal* that creates the
  epoch. Secrets chain up each changed path, so the cost stays within a
  small factor of the `D·ln(N/D)` lower bound for `D` changes among `N`
  members.
* **Taints.** Committers re-key nodes of other members, so every node
  records who drew its secret. Removing or updating a member re-keys every
  node it drew: a removed committer keeps nothing.
* **Anyone can commit.** Any member of the epoch can commit any district or
  seal a window from the public state, once it has checked that state
  against its own header.
* **Nobody online.** A joiner or a returning member seals the window itself
  with an external init, and members check its admission and signature
  later. With no participant at all, recorded removals are enforced by the
  delivery service at delivery until someone comes.
* **Members.** A member keeps its path, its epoch's secrets and header —
  O(log N) — and downloads one packet per window, checked by the
  confirmation tag: about 12 KB for a window of 200,000 changes among a
  million members, in the cost model.
* **Joining.** A joiner anchors on an admin checkpoint and checks the chain
  of seals up to the epoch it enters; a welcome gives it the joiner secret.
  A member coming back replays, jumps to the present with a welcome, or
  re-enters its leaf.
* **Open groups.** An admin-signed policy can open a group: any device joins
  with its own signed request, and every join is visible to the members.
* **Audits.** The delivery service checks every request, committers the
  entries of their districts, the sealer the structure of every commit, and
  members audit random entries.

Sequence diagrams: [docs/workflows.md](docs/workflows.md). Measured costs,
from the scale test (one core, release build): a window of 1,000 removals
and 1,000 joins among 16,384 members in 16 districts takes 5,333 wraps, the
count of the cost model; district commits of 852 KB at most, a 51 KB seal,
packets of 7.7 KB on average and seal links of 9 KB.

## Repository

| Path | Content |
| --- | --- |
| [`crates/cityg-core`](crates/cityg-core) | Protocol core without I/O: deterministic CBOR, X-Wing, device identities, hashing and wraps, the tree, re-key plans, the registry, the key schedule, signed requests, district commits and seals, welcomes, members, joiners and returning members, an in-memory delivery service, audits and fraud proofs. |
| [`crates/cityg-pqc`](crates/cityg-pqc) | FIPS 204 ML-DSA-65 with per-usage contexts. |
| [`docs/`](docs/README.md) | Specification, design note, glossary, workflows, symbolic model, research. |
| [`scripts/`](scripts/) | Local CI, security review, delivery-service guardrail. |

## Quick start

```bash
cargo test --workspace                                            # unit and scenario tests
cargo test -p cityg-core --release --test scale -- --ignored --nocapture   # a large window
./scripts/ci/local-ci.sh                                          # everything the CI runs
docs/formal/run.sh /path/to/proverif                              # symbolic model (ProVerif 2.05)
cargo run --release --manifest-path docs/research/bench/Cargo.toml   # primitive costs
python3 docs/research/rekey_sim.py                                # cost model
```

The scenario tests of `crates/cityg-core/tests/scenarios.rs` run whole
groups on the in-memory delivery service: growth over several districts,
windows sealed by an entrant with nobody online, recorded removals, removal
of a committer that kept its secrets, forged epochs, jumps and re-entries,
failed committers, eviction, audits and fraud proofs, invites, anchored
joins, and open groups.

## Limits

* The delivery service sees the members, the requests and the timing of
  windows.
* Removals take effect when their window is sealed; until then the delivery
  service enforces them, which is not cryptographic.
* Committers learn the secrets they draw until they erase them; taints make
  a removed committer's knowledge useless, at the cost of re-keying what it
  drew.
* Admission control in a closed group rests, for entries a malicious
  committer places, on sampled audits.
* A committer can wrap a secret that some members cannot open: they reject
  the window and must re-enter. Reports that expose such a committer are an
  open item.
* Members that follow the group check tags, not the history: comparing the
  interim transcript hash out of band detects a fork.
* Research code: side channels of the dependencies have not been assessed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Protocol changes start with the
specification. Report vulnerabilities privately ([SECURITY.md](SECURITY.md)).

## Citation

```bibtex
@misc{cityg2026,
  title={City-G: Post-Quantum End-to-End Encrypted Groups of Millions of Members},
  author={Sabri Haddouche},
  year={2026},
  howpublished={\url{https://github.com/pwnsdx/cityg}},
  note={Protocol specification: profile city-g/v0.4}
}
```

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2025 Sabri Haddouche.

## Contact

- **Security issues:** pwnsdx@protonmail.ch (PGP available with ProtonMail)
- **Bugs:** GitHub Issues
- **Discussions:** GitHub Discussions

## Acknowledgments

City-G builds on MLS (RFC 9420) and the TreeKEM line of work, on batch
re-keying of multicast key trees and Tainted TreeKEM, on the NIST
post-quantum standards FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), and on
BLAKE3 and ChaCha20-Poly1305.
