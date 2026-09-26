# Changelog

All notable changes to the City-G project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation

- The README presents City-G 0.4: why it exists, its key ideas, a
  comparison with MLS (design and guarantees, from RFC 9420 and RFC 9750),
  how a window works, measured and modelled costs, including the cost of
  following a group of a million members with 5-second windows, its limits,
  and the research notes beyond 0.4.
- The sequence diagrams of [`docs/workflows.md`](docs/workflows.md) no longer
  put semicolons in messages, which Mermaid reads as line breaks.
- The specification (section 3.3) states that the key schedule needs
  `Extract` to be a dual PRF, pseudorandom when keyed by its input keying
  material under a known salt: post-compromise security, external inits and
  the exclusion of a removed member that missed a window rest on it.

### Research

- A message plane for very large groups, proposed in
  [`docs/research/plan-de-messages-2026-09-26.md`](docs/research/plan-de-messages-2026-09-26.md)
  (in French) and not part of profile `city-g/v0.4`:
  - keepers and readers: only keepers stay in the tree; readers get the
    reader secrets of the epochs they missed in key bundles, sealed to a
    one-time key they sign and checked against a chained reader tag in the
    seal. Removing a reader needs no re-key, and a reader recovers from a
    compromise at its next session;
  - sender cards: a compact message key per member (FN-DSA, and the
    round-3 candidates for reference), checked against the roster of the
    message's epoch;
  - burst chains: one signature per burst of messages;
  - committing messages and verifiable reports;
  - a sealed message log in the next seal, for transcript consistency;
  - checkpoints and signed bundles against forks of readers;
  - for public groups, where any member may be hostile or offline: a public
    chain of reader secrets in the seals, broken at bans, so that readers
    need no member online between breaks; bundles served by any member;
    windows sealed by any member, readers included, with an external init;
    keepers admitted by an admin.
- Its cost model, [`docs/research/msg_sim.py`](docs/research/msg_sim.py): for a reader of a group
  of 2^20 members, 6 times fewer bytes per message and 32 times less
  traffic to stay able to read. With 16,384 keepers, a burst of 100,000
  joins and 100,000 departures takes 64 times fewer wraps.
- Its symbolic model, [`docs/research/formal-messages/`](docs/research/formal-messages/README.md):
  17 ProVerif scenarios, which the formal-model CI job and the local CI now
  run.
- The benchmarks measure FN-DSA-512 and FN-DSA-1024, the derivation of a
  sender's chain, and ChaCha20-Poly1305.
- The guarantees of MLS for a million members, in
  [`docs/research/parite-mls-2026-09-26.md`](docs/research/parite-mls-2026-09-26.md)
  (in French), not part of the profile:
  - City-G compared with RFC 9420 and RFC 9750, guarantee by guarantee;
  - an argument that members outside the tree cannot have them, which
    takes the readers of the message-plane note out of the target profile;
  - the proposed profile: every member in the tree; a mode where the
    service authorizes joins, with batched authorizations and a checkpoint
    per window that joiners anchor on and members may check; an MLS-style
    message plane with encrypted sender data; unique leaf keys and cards; a
    membership log; urgent and ordinary removals; exporter and epoch
    authenticator;
  - history links, studied and rejected: a removed member that joins again
    would read the epochs it was out of.
- Its cost model, [`docs/research/parity_sim.py`](docs/research/parity_sim.py), and its symbolic model,
  [`docs/research/formal-parity/`](docs/research/formal-parity/README.md): 10 ProVerif scenarios, run by
  the formal-model CI job and the local CI.
- Whether the server could re-key the tree instead of members, in
  [`docs/research/rekey-serveur-2026-09-26.md`](docs/research/rekey-serveur-2026-09-26.md)
  (in French), not part of the profile:
  - a server cannot draw the tree's secrets without knowing them, and no
    zero-knowledge proof changes that; one that draws them reads, with a
    single member it removed, every later epoch;
  - the options compared with MLS: one server, k servers that each draw a
    share of every node, an enclave, and members that draw while the server
    manages the rest;
  - the recommendation: members' work as background tasks the server hands
    out, disputes of wraps proved in zero knowledge, which reveal no key and
    no past secret, and repairs; a cheaper dispute, which reveals the
    encapsulation's shared secret, is rejected (replay).
- The parity cost model prints what members download and servers compute
  when one or k servers re-key the tree, and the size of the members'
  tasks; the parity symbolic model gains 9 scenarios (19 in all).
- Îlots under a flat top, in
  [`docs/research/ilots-2026-09-26.md`](docs/research/ilots-2026-09-26.md)
  (in French), not part of the profile:
  - with continuous churn at a million members, every subtree above about
    2^14 leaves changes in almost every window, and the binary city makes
    85 to 95 % of what a member downloads;
  - the tree is cut into îlots of 2^8 leaves with no tree above them; every
    window sends a fresh secret to every îlot root, with X-Wing or a
    multi-recipient KEM; a member of an îlot may relay it to the others in
    52 bytes, checked against the tag; joiners take the leaves removals
    free and re-key their own paths, and share the top; a cut îlot is
    repaired through its members' leaves;
  - following a group of 2^20 members costs 94 KB a day with relays and
    415 KB without, instead of 1.8 MB, and no longer grows with the group;
  - a cheaper welcome, the init secret sealed to the îlots of joiners, is
    rejected: it would open past epochs to a later compromise;
  - with nobody online, a joiner seals the window alone with an external
    init, as in v0.4: with no removal waiting, the top is not renewed and
    the joiner sends 24 KB; with a removal waiting, it renews the top, which
    costs 4.8 MB at a million members (the price of a flat top in a sparse
    window, which the îlot size trades against following).
- Its cost model, [`docs/research/ilots_sim.py`](docs/research/ilots_sim.py); the parity symbolic model
  gains 10 scenarios (29 in all).
- A synthesis beyond v0.4, in
  [`docs/research/au-dela-0.4-2026-09-26.md`](docs/research/au-dela-0.4-2026-09-26.md)
  (in French), not part of the profile:
  - a candidate profile for the next version: the v0.4 tree read through
    relays at îlots of 2^8 and re-keyed by small tasks given first to
    joiners, with the authorized mode and the MLS-style message plane of
    the parity note; it can follow v0.4 in three steps, relays first;
  - what each research note kept and rejected, the guarantees of MLS with
    the scenarios behind each, costs, and the open problems ranked: a
    computational proof, dispute proofs for X-Wing, forks, standards,
    sender cards, metadata;
  - a leaf hash that keeps the leaf key apart, so that readers fetch only
    the card part of a sender's leaf (39 % less for senders), and the
    authorizer's checkpoints checked by their signature alone: 192 KB a day
    with FN-DSA-512 instead of 278 KB, or 28 KB with a UOV key kept for
    following.
- The îlots note gains a city maintained above the îlots: every window
  re-keys it along the paths of the îlots it changes, relays read it, and
  the flat top becomes a fallback. A window that changes one îlot costs
  30 KB instead of 4.8 MB, and a joiner alone that applies a removal 95 KB
  instead of 4.8 MB. A city that a window does not re-key lets two removed
  members read the epoch, while one alone stays out through the init
  chain.
- The îlots cost model gains reports 9 (the maintained city) and 10 (a
  member's day at the candidate profile); the parity symbolic model gains
  3 scenarios (32 in all).
- The open problems of that note, in
  [`docs/research/problemes-ouverts-2026-09-26.md`](docs/research/problemes-ouverts-2026-09-26.md)
  (in French), not part of the profile:
  - a computational model,
    [`docs/research/formal-computational/`](docs/research/formal-computational/README.md):
    14 CryptoVerif models, 7 properties proved (forward secrecy with stable
    tree keys, a removed member that stays out once it missed a window, a
    window sealed by an entrant, relays and flat items, the maintained
    city, fresh secrets hedged against a weak generator) and 7 controls;
    the formal-model CI job now builds CryptoVerif 2.13 and runs them, and
    the local CI runs them when CryptoVerif is installed;
  - the assumption those proofs need and the specification did not state:
    `Extract` as a dual PRF;
  - the statement of a wrap dispute and its size, about 1.1 million AND
    gates and 6,140 multiplications in the field of X25519 (the matrix of
    ML-KEM is public and its arithmetic linear); about 0.4 MB to prove to
    the server as designated verifier, 1.5 to 2.2 MB for the boolean part
    of a public post-quantum proof;
  - witnesses against forks, three signatures out of four per window,
    which tolerate one absent and one dishonest witness, falling back to
    MLS when the quorum does not answer; sender cards kept in a cache;
    what tasks and relays reveal to the server.
- Its cost model, [`docs/research/open_problems_sim.py`](docs/research/open_problems_sim.py).

## [0.4.0] — initial version

Profile `city-g/v0.4`, for end-to-end encrypted groups of millions of
members.

### Protocol

- Specification ([`docs/specs.md`](docs/specs.md)) and design note
  ([`docs/design.md`](docs/design.md), decisions E-1 to E-14).
- One epoch per window of requests: district commits built in parallel,
  then a seal that re-keys the city and creates the epoch, then welcomes.
- A sparse tree of up to `2^24` leaves split into districts under a city;
  a parent node is blank exactly when its subtree is empty; taints record
  who drew each node's secret, and removing or updating a member re-keys
  every node it drew.
- Multi-path re-key plans that anyone can recompute from public data.
- The key schedule of MLS with the window's root secret: init chain,
  joiner secret, confirmation tag, transcript hashes, external init.
- Registry of admins and two sparse Merkle maps (devices, used admissions);
  an admission admits once.
- Admissions by admins or invites, anchored joins on admin checkpoints,
  replay, jump and re-entry for returning members.
- A group with no member online: an entrant seals the window with an
  external init; recorded removals are enforced at delivery until the first
  participant applies them; eviction only under an admin-signed policy.
- Open groups: an admin-signed policy lets any device join with its own
  signed request; every join stays visible.
- Sampled audits of the entries of a window, with transferable fraud
  proofs.
- One packet per member and window; seal links and entries for joiners and
  returning members.

### Implementation

- `cityg-core`: the protocol core without I/O and an in-memory delivery
  service; 22 scenario tests on whole groups and a scale test that matches
  the cost model's count of wraps and keys.
- `cityg-pqc`: ML-DSA-65 (FIPS 204) with one context per signed object.
- Symbolic model ([`docs/formal/`](docs/formal/)): 16 ProVerif scenarios.
- Research note, cost model and primitive benchmarks
  ([`docs/research/`](docs/research/)).

### Not yet

The message plane, the networked delivery service and the clients, test
vectors, and the other open items of the specification (section 19).
