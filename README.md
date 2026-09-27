# City‑G

**Post-quantum end-to-end encrypted groups of millions of members.**

[![Status](https://img.shields.io/badge/status-research-orange)]()
[![Profile](https://img.shields.io/badge/profile-city--g%2Fv0.4-blue)](docs/specs.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

City‑G is a research protocol for end-to-end encrypted groups that are too
large, too busy or too often offline for a standard group protocol: up to
`2^24` members, bursts of hundreds of thousands of joins and departures in
one epoch, and groups in which nobody may be online. Its profile,
**`city-g/v0.4`**, keeps the key schedule of MLS (RFC 9420) and changes how
the group is re-keyed. It is post-quantum by default: X-Wing (ML-KEM-768
with X25519) and ML-DSA-65.

> **Status: research.** This repository holds the
> [specification](docs/specs.md), the [design note](docs/design.md), a
> [symbolic model](docs/formal/) and the protocol core
> [`cityg-core`](crates/cityg-core) with an in-memory delivery service. The
> core implements stage 1 of the [v0.5 draft](docs/specs-v0.5-draft.md), a
> delta on v0.4: members may read the tree by island through relays, and
> removals are urgent or ordinary. It also implements stage 2: the city is
> re-keyed by sub-city, the window's joiners perform tasks first, the
> sealer draws nothing, entrants enter by island, and a member that a
> faulty task cut off asks for a repair, which counts against the
> performer to blame, and disputes the faulty wrap; the delivery service
> judges disputes with a proof system it is given, which the core does not
> include. Of stage 3, it implements cards in leaves, unique keys and the
> message plane: messages whose sender the delivery service does not see,
> signed once per burst by the sender's card, and logged in the next seal.
> The authorized mode, the networked
> delivery service and the clients do not exist yet
> ([specification, section 19](docs/specs.md#19-open-items)). There are no
> test vectors and no independent human cryptographic review: **for
> production, use MLS.**

---

## Why

MLS is the IETF standard for end-to-end encrypted groups. It provides
key establishment "for groups in size ranging from two to thousands"
([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)), and messaging
systems that use it "aim to scale to groups with tens of thousands of
members" ([RFC 9750, §6](https://www.rfc-editor.org/rfc/rfc9750.html#section-6)).
At a million members, four of its choices get in the way:

1. **One committer per epoch.** Every epoch comes from one commit by one
   member, and concurrent commits conflict. A burst of 100,000 joins is one
   commit built by one device, or 100,000 epochs in a row.
2. **Everyone processes everything.** Every member downloads every commit
   and keeps the whole public tree, which grows with the group.
3. **Someone must be online.** A joiner can add itself with an external
   commit, but it cannot apply the removal of another member, and a member
   cannot leave on its own: "they must be removed by a remaining member"
   ([RFC 9750, §6.1](https://www.rfc-editor.org/rfc/rfc9750.html#section-6.1)).
4. **Classical cryptography.** The cipher suites of RFC 9420 are classical;
   post-quantum suites are an
   [Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/).

## Key ideas

| Idea | What it does |
| --- | --- |
| **Windows** | The delivery service (DS) collects requests for up to 60 s, or 5 s when a removal waits. One epoch seals the whole window, whatever its size. |
| **Districts and a city** | The tree is split into districts of 4,096 leaves under a binary city. Each district a window changes is re-keyed by its own committer, in parallel; a sealer re-keys the city and creates the epoch. The total cost stays within ×1.1 to ×1.3 of the lower bound `D·ln(N/D)` for `D` changes among `N` members. |
| **Taints** | A committer draws secrets for other members' nodes. Every node records who drew it, and removing or updating a member re-keys every node it drew: a removed committer keeps nothing useful. |
| **Anyone can commit** | A committer needs no state of its own: any member of the epoch can commit any district, or seal, from the public state. |
| **Init chain** | As in MLS, each epoch depends on the previous one: the DS alone cannot fabricate an epoch, and a member checks the confirmation tag instead of signatures. |
| **Nobody online** | A joiner or a returning member seals the window itself with an external init, pending removals included; members check its admission and signature when they come back. |
| **Light members** | A member keeps its path and the secrets of its epoch, O(log N), and downloads one packet per window with the steps of its own path. |
| **Checks by sampling** | The DS checks every request, committers the entries of their district, the sealer the structure of every commit, and members audit random entries. |
| **Open groups** | An admin-signed policy can open a group to any device; every join stays visible. |
| **Relays** (v0.5 draft) | A member may read the tree by island of 256 leaves: a member of its island seals each window's root secret for it in 52 bytes, checked by the tag. Urgent removals keep their 5-second windows; departures wait for the next scheduled window. |
| **Messages** (v0.5 draft) | A secret tree gives each member a chain per epoch, as in MLS. The DS sees neither the sender nor the content; the sender's card, the key in its leaf, signs once per burst, and the next seal logs the epoch's messages, so that members agree on them. |

## City‑G 0.4 and MLS

City‑G keeps the structure of MLS where it can: the init secret chain, the
joiner secret, confirmation tags over the transcript, welcomes and the
external init. It departs from it where a group of millions needs something
else ([specification, section 20](docs/specs.md#20-mls)).

### Design

| | MLS (RFC 9420) | City‑G 0.4 |
| --- | --- | --- |
| Maturity | IETF standard (2023), independent implementations, years of analysis | Research profile, one implementation (this repository), symbolic model and first computational proofs of its key schedule, no independent review |
| Target size | "Two to thousands" (RFC 9420); tens of thousands (RFC 9750) | Up to `2^24` leaves; modelled for `2^20` |
| Cryptography | Classical cipher suites; post-quantum suites in draft, whose hybrid KEM is X-Wing's | X-Wing (ML-KEM-768 with X25519), ML-DSA-65, BLAKE3, ChaCha20-Poly1305 |
| An epoch | One commit by one member | One window of requests, of any size |
| Concurrent changes | Concurrent commits conflict; one is kept | Districts committed in parallel by different members, then one seal |
| Re-key | The committer's own path, encrypted to the resolution of its copath | Every changed path of the window, chained where possible |
| Who knows a node's secret | The members below it; a committer re-keys only its own path | Also the committer that drew it, recorded as its taint |
| What a member stores | The whole public tree | Its path and its epoch's secrets, O(log N) |
| What a member downloads per epoch | The whole commit | One packet with the steps of its own path |
| Leaving | Removed by another member | Its own signed request |
| Nobody online | A joiner adds itself by external commit; removals wait for a member | A joiner or a returning member seals the window, removals included |
| Who validates changes | Every member, every proposal | The DS, the committers and the sealer; members audit samples |
| What a joiner checks | The group information signed by a member | The chain of seals from an admin checkpoint |
| Message plane | Secret tree, encrypted sender data, signed messages | Not specified yet |

### Guarantees

| Property | MLS | City‑G 0.4 |
| --- | --- | --- |
| Group secrets hidden from the DS | Yes | Yes in closed groups. In an open group, anyone can join and read, the DS included, and every join is visible. |
| Secrecy after a removal | From the commit that removes the member | From the window that applies it, which closes at most 5 s after the removal is recorded; until then the DS withholds deliveries, which is not cryptographic |
| Forward secrecy and post-compromise security | Yes | Yes: the init chain, and healing at the device's next update |
| Joiners do not read the past | Yes | Yes |
| Agreement on the membership | Every member holds the tree | Every seal commits to the tree and the registry; the list is read on demand |
| Admission control | Every member validates every addition | In a closed group, the DS cannot add a member. A malicious committer can place an invalid entry: sampled audits catch it with probability about `1 - e^-20`, with a transferable fraud proof |
| Unique keys in the tree | Required ([RFC 9420, §7.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-7.3)) | Unique devices; unique leaf keys not required |
| Forks by the DS | Possible; detected by comparing the epoch authenticator out of band | Possible; detected by comparing the transcript hash out of band. The DS alone cannot fabricate an epoch |
| A malicious committer cuts members off | Possible ([RFC 9420, §16.12](https://www.rfc-editor.org/rfc/rfc9420.html#section-16.12)) | Possible: a committer its district, the sealer the group. They reject the window and re-enter; reports are an open item |
| Messages: sender authenticated, sender hidden from the DS | Yes | Not yet: no message plane |

**In short:** City‑G 0.4 reaches sizes and bursts that MLS was not designed
for, is post-quantum, lets a member leave on its own and lets a group move
on with nobody online. It pays for this with admission checks by sampling,
committers that learn other members' secrets (bounded by taints), and a
message plane that does not exist yet. The research notes below look for a
profile with every guarantee of MLS at this scale.

## How a window works

```mermaid
sequenceDiagram
    participant R as Requesters
    participant DS as Delivery service
    participant C as District committers
    participant S as Sealer
    participant M as Members
    R->>DS: signed requests: joins, removals, updates
    DS->>DS: check them, close the window (60 s at most, 5 s if a removal waits)
    DS->>C: one district each, in parallel
    C->>DS: district commits: the changed paths re-keyed
    DS->>S: the commits
    S->>DS: seal: the city re-keyed, the epoch created, its confirmation tag
    DS->>M: one packet per member, with the steps of its path
    M->>M: derive the epoch, check the tag
    C->>DS: welcomes of the window's joiners
```

More diagrams — creating a group, joining, nobody online, coming back — in
[docs/workflows.md](docs/workflows.md).

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

Not provided: metadata privacy, availability (the delivery service can deny
service), secrecy from members of the same epoch, and, in an open group,
secrecy from whoever joins it. Every join stays visible, and nobody can
speak as another member. The [symbolic model](docs/formal/README.md) checks
the choices these properties rest on in 18 ProVerif scenarios, those of
stage 1 of the v0.5 draft in five more, and those of stage 2 in ten more.

## Numbers

**Measured.** The scale test (`crates/cityg-core/tests/scale.rs`, one core,
release build) builds a full group and runs one window of half removals
and half joins:

| | 16,384 members, 2,000 changes | 65,536 members, 4,000 changes |
| --- | --- | --- |
| Wraps (against the bound `D·ln(N/D)`) | 5,261 (×1.25) | 12,394 (×1.11) |
| District commits | 16, busiest 846 KB | 16, busiest 1.9 MB |
| Seal, which re-keys the city (v0.4) | 51 KB | 51 KB |
| Seal and city task (v0.5 draft, stage 2) | 5.4 KB and 48.9 KB | 5.4 KB and 48.9 KB |
| Packet per member | mean 7.7 KB | mean 8.2 KB |
| Packet per member by island of 256 leaves, with a relay element (v0.5 draft) | mean 3.5 KB | mean 2.9 KB |
| DS check of the whole window | 0.8 s | 1.6 s |

**Modelled**, for a group of `2^20` members
([`rekey_sim.py`](docs/research/rekey_sim.py),
[`parity_sim.py`](docs/research/parity_sim.py)):

* **A burst of 100,000 joins and 100,000 departures** in one window: 648,420
  wraps across 256 districts, the busiest commit 6.0 MB; each member
  downloads 11.9 KB.
* **Following the group**, per member and per day, with 60-second windows:
  3.2 MB at 0.1 change per second, 7.4 MB at 1.7 and 10.3 MB at 12.
* **The weak point.** At a million members, departures come every second or
  so, and under the rule that a removal closes its window within 5 s,
  windows last 5 s: following the group then costs about 44 MB a day at
  1.7 changes per second. The research notes bring this down (below), and
  stage 1 of the [v0.5 draft](docs/specs-v0.5-draft.md) implements the
  first step: with ordinary removals, 5-minute windows and relays, about
  94 KB a day ([`ilots_sim.py`](docs/research/ilots_sim.py)).

## Limits

* The delivery service sees the members, the requests and the timing of
  windows.
* Removals take effect when their window is sealed; until then, the delivery
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
* A stolen device key lets the thief take the member's place by an update
  or a re-entry until the device is removed; the member can then no longer
  follow, and notices. A catch-up gives the thief nothing: its welcome is
  sealed to the member's leaf key too.
* Research code: side channels of the dependencies have not been assessed.

## Research beyond 0.4

The architecture of 0.4 comes from a first research note,
[Groupes de millions de membres](docs/research/grands-groupes-2026-09-25.md).
Fourteen more, in French, look at what comes next; the fifth gathers them
into a candidate profile for the next version, in three stages, and the
following ones work on its open problems. None of them is part of profile
v0.4; the [v0.5 draft](docs/specs-v0.5-draft.md) specifies the three
stages, and `cityg-core` implements the first two and the first two
parts of the third.

| Note | Question | What it finds |
| --- | --- | --- |
| [A message plane](docs/research/plan-de-messages-2026-09-26.md) | How do a million members send and read messages? | Sender cards with compact signatures, burst chains, committing messages, a sealed message log. |
| [The guarantees of MLS](docs/research/parite-mls-2026-09-26.md) | What must change for every guarantee of MLS at a million members? | An MLS-style message plane with the sender hidden from the DS, unique keys, a mode where the service authorizes joins, a membership log, urgent and ordinary removals: following costs 2.0 MB a day with 5-minute windows. |
| [Re-keying by the server](docs/research/rekey-serveur-2026-09-26.md) | Could the server re-key the tree, with zero-knowledge proofs? | Not without knowing the keys: one that draws them reads every later epoch with one member it removed. Proposes disputes proved in zero knowledge. |
| [Îlots under a flat top](docs/research/ilots-2026-09-26.md) | What is the best re-key technique at this scale? | Small subtrees, relays and joiners that do the work: following costs 94 KB a day with relays and 415 KB without, instead of 1.8 MB for the profile of the previous note, whatever the group's size. A city maintained above the îlots keeps a window that changes one îlot at 30 KB. |
| [Beyond 0.4](docs/research/au-dela-0.4-2026-09-26.md) | What would the next version be, and what is still open? | The 0.4 tree read through relays and re-keyed by small tasks that joiners take on, with the parity profile's authorized mode and message plane: a member who reads 100 messages a day downloads 213 KB instead of 2.1 MB. It can follow 0.4 in three steps. Open, in order: a computational proof, dispute proofs for X-Wing, forks, standards. |
| [Open problems](docs/research/problemes-ouverts-2026-09-26.md) | Which of those open problems can be solved now? | First computational proofs with CryptoVerif, and an assumption the key schedule needs: `Extract` must be a dual PRF. A wrap dispute is about 1.1 million AND gates, about 0.4 MB to prove to the server. Three witnesses out of four against forks, a cache for sender cards. |
| [Proofs and measurements](docs/research/preuves-et-mesures-2026-09-26.md) | What does a dispute really cost, and what would prove the whole tree? | A wrap dispute measured with emp-zk: under a second and 2 MB without its X25519 half, which needs a proof over its own field. Authentication in the computational model. A weakness of 0.4: a stolen device key read every window through catch-ups, unseen; 0.4 now binds the catch-up's welcome to the member's leaf key. A proof plan for the whole tree, with random oracles, and `Extract` as HKDF for the next profile. |
| [The proof of the tree](docs/research/preuve-arbre-2026-09-26.md) | What must be proved for the whole tree, and what already is? | The security game under adaptive corruptions and its safety predicate, executable and checked against 24 formal models; a proof sketch with random oracles whose every step has a mechanized lemma, the taint rule and post-compromise healing among them. The adaptive argument comes in the next note. |
| [The adaptive argument](docs/research/argument-adaptatif-2026-09-27.md) | How do the lemmas proved window by window add up against adaptive corruptions, and at what loss? | The tree reduces to the generalized selective decryption game that proofs of MLS use (Alwen, Jost and Mularczyk), with two more oracles for external inits, jumps and relays, and a lemma that a safe epoch stays unexposed. Counted in the secrets City-G draws, the loss is `2^67` for a million members over ten years, 125 bits left to ML-KEM-768. The next note writes the extensions and the invariant in full. |
| [The GSD extensions, in full](docs/research/extensions-gsd-2026-09-27.md) | Does the theorem hold with City-G's two extra oracles, and is the reduction's graph the one the proof assumes, for every object a member handles? | Yes, with every encapsulation made a vertex, so that a member that reopens an honest encapsulation in another format stays inside the game; the oracle is observed, never programmed, and the loss is `2^69`, 123 bits left to ML-KEM-768. Writing the invariant object by object found a flaw of stage 1: the relays of two branches of a fork sealed two roots under the same key and nonce, which gave a removed member the epoch that removes it. Relay elements now bind the interim transcript hash. |
| [The X25519 half of a dispute](docs/research/litige-x25519-2026-09-26.md) | What does the X25519 half of a dispute cost in its own field, and can a phone produce it? | Proved with Diet Mac'n'Cheese in the field of X25519: 5,048 multiplications, but 23 MB, most of it the setup of a 255-bit field. Over an emulated 4G link, 1.8 s without the X25519 half and 21.6 s for it; no phone measured. Revealing `ss_X` instead stays rejected. Next: a proof without setup over two fields, as Longfellow's. |
| [A dispute without setup](docs/research/litige-sans-mise-en-place-2026-09-26.md) | What does a dispute cost with a proof that needs no setup, and on a phone? | With Longfellow (sumcheck and Ligero), the X25519 half takes 158 KB and 65 ms, the hashing 552 KB and 0.69 s, in one message anyone can verify; this machine runs Longfellow's ECDSA benchmark in a Pixel 9's time. The lattice part, not yet written, would dominate: its anchor, an ML-DSA-65 verification, takes 3.2 s. |
| [The whole dispute](docs/research/litige-entier-2026-09-26.md) | What does the whole dispute cost without setup, and for which statement? | In the field of X25519 alone, with a revised statement (no seed, no re-encryption check in the usual case, 2 Keccak permutations instead of 26), the whole first branch of a dispute, `ExpandLabel` and ChaCha20 included, takes 573 KB: 1.49 s to prove and 0.97 s to verify, at a Pixel 9's speed. The lattice part, checked at a point drawn after the commitment, takes 109,000 terms. A ciphertext whose re-encryption fails is convicted apart, without saying where it differs. |
| [Both branches of a dispute](docs/research/litige-deux-branches-2026-09-27.md) | What does the second branch cost, and is the norm bound tight enough? | The second branch, a wrap that opens to a secret whose node key is not the published one, takes 787 KB: 3.72 s to prove and 2.26 s to verify, at a Pixel 9's speed, without revealing where the keys differ; in the common case, a short statement takes 635 KB and about half that time. The exact decryption failure rate corrects an estimate: `2^-98.9` for the worst key under the old bound, `2^-121.2` under a bound on each half of the key. Loaded from its serialized form (0.6 to 1.5 MB with zstd), the circuit needs 104 MB for the first branch and 251 MB for the second. |

## Repository

| Path | Content |
| --- | --- |
| [`crates/cityg-core`](crates/cityg-core) | Protocol core without I/O: deterministic CBOR, X-Wing, device identities, hashing and wraps, the tree, re-key plans, the registry, the key schedule, signed requests, district commits and seals, welcomes, members, joiners and returning members, relay and flat elements for island followers, an in-memory delivery service, audits and fraud proofs. |
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
python3 docs/research/msg_sim.py                                  # cost model of the proposed message plane
python3 docs/research/parity_sim.py                               # cost model of the profile at parity with MLS
python3 docs/research/ilots_sim.py                                # cost model of îlots and of the candidate profile
python3 docs/research/open_problems_sim.py                        # cost model of the open problems
python3 docs/research/safety_predicate.py                         # safety predicate of the tree proof
python3 docs/research/dispute-zk/x25519_ir.py check               # the X25519 half of a dispute, checked
python3 docs/research/dispute-zk/x25519_dleq.py                   # the rejected shortcut, priced
python3 docs/research/dispute-zk/decryption_failure.py            # decryption failures under the norm bounds (numpy)
docs/research/formal-computational/run.sh /path/to/cryptoverif   # computational model (CryptoVerif 2.13)
```

The scenario tests of `crates/cityg-core/tests/scenarios.rs` run whole
groups on the in-memory delivery service: growth over several districts,
windows sealed by an entrant with nobody online, recorded removals, removal
of a committer that kept its secrets, forged epochs, jumps and re-entries,
a stolen device key, failed committers, eviction, audits and fraud proofs,
invites, anchored joins, and open groups. Those of
`crates/cityg-core/tests/islands.rs` run island followers: relays, flat
elements, a relay that lies, replays, a sealer that refreshes its path, a
removed member facing its island's top, and urgent and ordinary removals.
Those of `crates/cityg-core/tests/tasks.rs` run the tasks: sub-cities and
a top re-keyed by their own performers, tasks that wait for what they
build on, failed performers replaced, a removed performer's parts re-keyed,
an entrant that performs every task, joiners that perform the tasks of the
window they enter from the state their chain of seals gives, entries by
island, repairs that members ask for, and a performer excluded from roles
once two members blamed it.

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
