# Changelog

All notable changes to the City-G project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Protocol: the v0.5 draft, stage 1

- A draft of the next profile, `city-g/v0.5-draft`, in
  [`docs/specs-v0.5-draft.md`](docs/specs-v0.5-draft.md): a delta on v0.4
  in three stages, from the research synthesis beyond 0.4. Stage 1 is
  specified and implemented in `cityg-core`; stages 2 (island tasks,
  disputes, repairs) and 3 (parity with MLS) are outlined, with their
  labels reserved. Design decisions E-15 and E-16.
- **Islands read through relays.** The tree is read in islands of `2^c`
  leaves (`island_bits`, 8 by default, at most `L`, fixed at genesis and
  bound in the seal header, the group context and checkpoints). An island
  follower takes the steps of its path up to its island root, and the
  window's root secret from a relay element that a member of its island
  seals under the island root's secret (52 bytes), a flat element that
  wraps it to the island root for an island without a relay, or a refresh
  from the latest re-key of each node above its island. It checks the tag
  as before; a relay can only delay it. The delivery service names a relay
  per island among its online members, spreads the flat elements over the
  relays, and serves whole or island packets. A sealer without a city
  refreshes its path first. In the scale test, an island packet with a
  relay element weighs 3.6 KB against 7.7 KB for the whole path (16,384
  members, 2,000 changes), and 3.0 KB against 8.3 KB (65,536 members,
  4,000 changes).
- **Urgent and ordinary removals.** A removal proposal carries a signed
  urgency. Urgent removals (an admin's, or a reported compromise) keep the
  windows within `WINDOW_URGENT` (5 s) and the rule that members do not
  send while one waits; ordinary ones (departures, evictions) wait for the
  window their age closes, at most `WINDOW_ORDINARY`. `DsConfig` fields are
  renamed `window_ordinary_ms` and `window_urgent_ms`.
- Breaking: every label ends in `/v5` and the framing tags are
  `city-g/v0.5-draft`, so nothing of v0.4 decodes. `Member::create` takes
  `island_bits`; `Member::remove_proposal` and `RemoveProposal::sign` take
  an `Urgency`; `Packet` gains `top`; `MemberPath` returns `PathSecrets`,
  with the epoch of each secret. The ML-DSA known-answer test keeps its
  original context string.
- Symbolic model of stage 1 ([`docs/formal/`](docs/formal/README.md)):
  five ProVerif scenarios, run by `run.sh` and the formal-model CI job. The
  window that removes a member leaves it no top to open, while a relay
  that seals under its island root's former secret, or a flat maker that
  takes the island key from the delivery service, gives the removed member
  the epoch; a refresh on its own leads only to the real path when checked
  against the root secret, and to secrets the service chose otherwise. The
  safety predicate mirrors the three removal scenarios (31 traces).
- Scenario tests in `crates/cityg-core/tests/islands.rs`: relays, a flat
  element for an island with nobody online, a relay that sends garbage,
  replays through relays, flat elements and refreshes, a sealer that
  refreshes its path, urgent and ordinary removals, a removed member facing
  its island's top, an entrant window followed by refresh, and a window
  that re-keys nothing.

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

### Security

- A relay element of the v0.5 draft binds the interim transcript hash of
  its epoch, which covers the window's seal and confirmation tag, in its
  context (`RelayContext`). The branches of a fork share the epoch and the
  islands that no branch re-keys: two sealers can seal two windows, and an
  insider that knows the previous init secret can lead a member into a
  root of its choice under the real seal. Bound to the epoch alone, two
  honest relays of such an island sealed two branches' root secrets under
  the same ChaCha20-Poly1305 key and nonce. Their XOR is the XOR of the
  roots, so a member that one branch removes, and that knows another
  branch's root, could read the root of the branch that removes it, then
  its epoch with the init secret it held. Binding the seal alone does not
  separate the insider's branch. Found while writing the proof that each
  relay key seals one plaintext (research note on the GSD extensions).
  `RelayElement::seal` and `open` now take a `RelayContext`.
- A catch-up's welcome is sealed to the member's leaf key as well as to the
  request's one-time init key (specification, section 11). A catch-up is
  signed with the device key alone and changes nothing in the tree:
  welcomed to the init key alone, a device key stolen without the member's
  state obtained the epoch of every window it asked for, and nobody could
  see it. The member keeps its leaf key through a jump, or opens the welcome
  with its pending leaf key if a window it missed applied its update.
  Breaking: the welcome gains a field, `leaf_ciphertext` (`null` for joins
  and re-entries), and its context the hash of the leaf key, so welcomes of
  0.4.0 do not decode. A jump's welcome grows by 1,120 bytes.
- A member whose packet names a leaf key it neither holds nor requested
  gets `LEAF_TAKEN`: an update or a re-entry was signed with its device key
  without it, and it treats the key as stolen (specification, section
  12.2).
- The symbolic model gains the stolen-key catch-up and the rule it replaces
  (18 scenarios), and the scenario tests a thief that asks for a jump or
  changes a member's leaf.

### Research

- The adaptive argument of the proof of the tree, in
  [`docs/research/argument-adaptatif-2026-09-27.md`](docs/research/argument-adaptatif-2026-09-27.md)
  (in French): the game reduced to the modified generalized selective
  decryption game of Alwen, Jost and Mularczyk (Crypto 2022), whose theorem
  carries the order of replacements and the guessing; two more oracles for
  external inits, jumps and relays; a simulation lemma and a combinatorial
  lemma resting on an invariant of coherence. The loss, counted in secrets
  drawn rather than as `(Qn)²`: `2^67` for a million members over ten
  years, 125 bits left to ML-KEM-768 instead of 92. The safety predicate
  gains three traces of stage 1 and checks that every trace is an acyclic
  GSD hypergraph whose challenge is a sink; the cost model of the open
  problems counts the secrets.

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
- Proofs and measurements, in
  [`docs/research/preuves-et-mesures-2026-09-26.md`](docs/research/preuves-et-mesures-2026-09-26.md)
  (in French), not part of the profile:
  - the zero-knowledge proof of a wrap dispute, measured with emp-zk
    (QuickSilver) by [`docs/research/dispute-zk/`](docs/research/dispute-zk/README.md):
    the hashing and the arithmetic of ML-KEM-768 take 9.7 million AND
    gates, 2 MB (0.65 MB of setup) and under a second between a prover and
    the server; the X25519 half would take 150 MB over bits and needs a
    proof over its own field;
  - authentication in the computational model: a lying relay is caught by
    the tag under collision resistance, and three witnesses out of four
    stop a fork with one of them dishonest;
  - a weakness of profile `city-g/v0.4`: whoever holds a member's device
    key, not its state, has catch-ups welcomed with init keys of its own
    and reads every window, unseen, like the external operations of MLS
    that ETK (Eurocrypt 2026) analyses; the fix, applied since (see
    Security), also encapsulates a catch-up's welcome to the member's leaf
    key;
  - the plan of a proof of the whole tree under adaptive corruptions, with
    random oracles, since the standard-model loss is beyond any security
    level at a million members; the recommendation to make `Extract`
    HKDF-Extract with SHA-384 in the next profile.
- The computational model gains 7 models (21 in all), the parity symbolic
  model 2 scenarios (34 in all), and the cost model a report on the loss
  of adaptive proofs.
- The proof of the whole tree, in
  [`docs/research/preuve-arbre-2026-09-26.md`](docs/research/preuve-arbre-2026-09-26.md)
  (in French): the security game of City-G under adaptive corruptions, a
  CGKA by windows; its safety predicate over the graph of secrets, made
  executable in
  [`docs/research/safety_predicate.py`](docs/research/safety_predicate.py)
  and checked against the verdicts of 24 formal models; the target theorem
  with random oracles; and a sketch of the proof whose every step has a
  mechanized lemma. The adaptive argument itself remains to be written.
- The computational model gains the taint rule and the healing of a
  leaked member by its update, with their controls (25 models in all).
- The X25519 half of the wrap dispute, in
  [`docs/research/litige-x25519-2026-09-26.md`](docs/research/litige-x25519-2026-09-26.md)
  (in French):
  - proved in the field of X25519 with Diet Mac'n'Cheese, from a SIEVE IR
    relation that
    [`docs/research/dispute-zk/x25519_ir.py`](docs/research/dispute-zk/x25519_ir.py)
    generates and checks against RFC 7748: 5,048 multiplications and 1,024
    bit conversions, 18.5 MB and 4.6 MB in under 3 s, of which 20.6 MB
    before the first gate, for the setup of a 255-bit field; two patches
    add that field to swanky;
  - the dispute over emulated mobile links, with
    [`docs/research/dispute-zk/link.py`](docs/research/dispute-zk/link.py):
    1.8 s without the X25519 half and 21.6 s for it on a 4G-like link; no
    phone was measured;
  - revealing `ss_X` with a Chaum-Pedersen proof, priced at 97 bytes by
    [`docs/research/dispute-zk/x25519_dleq.py`](docs/research/dispute-zk/x25519_dleq.py),
    stays rejected: a server allied with a copier delivers the copied
    `ct_X` before the honest wrap; a `ct_X` outside the prime-order
    subgroup convicts the committer without any proof;
  - the next step: a proof without setup over two fields, with sumcheck
    and Ligero, as Longfellow's.
- A wrap dispute without setup, in
  [`docs/research/litige-sans-mise-en-place-2026-09-26.md`](docs/research/litige-sans-mise-en-place-2026-09-26.md)
  (in French), with Longfellow (sumcheck and Ligero), whose proofs are
  single messages anyone can verify:
  - the X25519 half as a Longfellow circuit over the field of X25519, in
    [`docs/research/dispute-zk/longfellow/`](docs/research/dispute-zk/longfellow/),
    checked against OpenSSL and RFC 7748: 158 KB, proved in 65 ms and
    verified in 48 ms, instead of 23 MB and 178 flights with Diet
    Mac'n'Cheese;
  - the 26 Keccak-f permutations of the dispute over GF(2^128): 552 KB,
    0.69 s;
  - this machine runs Longfellow's ECDSA benchmark in the time the paper
    measured on a Pixel 9, so these times are close to a Pixel 9's;
  - the lattice part of ML-KEM is not written; its anchor, an ML-DSA-65
    verification, takes 3.2 s and 790 KB, so it would dominate.
- The whole wrap dispute without setup, in
  [`docs/research/litige-entier-2026-09-26.md`](docs/research/litige-entier-2026-09-26.md)
  (in French), with Longfellow over the field of X25519 alone:
  - ML-KEM-768's lattice part as polynomial identities checked at a point
    drawn after the commitment: 109,000 to 184,000 terms instead of
    1.57 million for dense products; a witness forged for a known point
    fails elsewhere;
  - a revised statement: the member's seed stays out (a norm bound keeps
    the key close to honest ones), and so does the re-encryption check in
    the usual case, 2 Keccak permutations instead of 26; a second
    statement convicts a ciphertext whose re-encryption fails without
    revealing which coefficient differs;
  - the whole first branch, `ExpandLabel` (BLAKE3) and ChaCha20 included,
    reveals only the wrap's Poly1305 key: 573 KB, 1.49 s to prove and
    0.97 s to verify, at a Pixel 9's speed; the second statement takes
    615 KB and 2.56 s;
  - a C++ reference of ML-KEM-768 and X-Wing, checked against the X-Wing
    draft's vectors, and a wrap made by `cityg-core`
    ([`docs/research/bench/src/bin/wrap_vector.rs`](docs/research/bench/src/bin/wrap_vector.rs)),
    whose altered version the proof convicts, in
    [`docs/research/dispute-zk/longfellow/`](docs/research/dispute-zk/longfellow/).
- Both branches of a wrap dispute, in
  [`docs/research/litige-deux-branches-2026-09-27.md`](docs/research/litige-deux-branches-2026-09-27.md)
  (in French):
  - the second branch, a wrap that opens to a secret whose node key is
    not the published `pk_v`: ChaCha20's second block opens the secret,
    X-Wing's key generation derives its node key with the public matrix of
    `pk_v`, and a hidden place shows where the keys differ; 787 KB, 3.72 s
    to prove and 2.26 s to verify, at a Pixel 9's speed; it checks no tag
    and reveals no Poly1305 key, since a wrong tag convicts as well;
  - a short statement of the second branch for the common case, where the
    committer sealed another secret: the node key's matrix seed or X25519
    key differs from `pk_v`'s, so it stops before the six PRF calls and
    `t'`: half the terms, 635 KB and 54% of the full statement's proving
    time; the full one remains for a `pk_v` wrong in `t` alone;
  - the decryption failure rate of ML-KEM-768 for the worst key of bounded
    norm, computed exactly by
    [`docs/research/dispute-zk/decryption_failure.py`](docs/research/dispute-zk/decryption_failure.py):
    `2^-98.9` under the earlier joint bound, not the estimated `2^-129`;
    the lattice part now bounds each half of the key, for `2^-121.2`;
  - the verifier's public checks of `ct_X` (prime-order subgroup) and of
    `pk_v` (canonical encoding), coded and tested;
  - the circuits serialized and compressed with zstd (0.6 to 1.5 MB) and
    loaded by a fresh process: the prover needs 104 MB for the first
    branch and 251 MB for the second, not the 315 to 740 MB measured with
    the compiler's heap;
  - [`docs/research/bench/src/bin/wrap_vector.rs`](docs/research/bench/src/bin/wrap_vector.rs)
    also prints slices of the node key that the wrap's secret gives.

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
