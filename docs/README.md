# City-G documentation

City-G's protocol is profile **`city-g/v0.4`**, its initial version. The
reference is the [specification](specs.md); everything else here explains
or checks it.

## Protocol

| Document | Content |
| --- | --- |
| [specs.md](specs.md) | Specification: threat model and security properties, cryptographic suite and encodings, tree, signed requests, re-key, registry, key schedule, district commits and seals, welcomes, members, packets, delivery service, audits, parameters, label registry, security considerations, open items, relation to MLS. |
| [design.md](design.md) | Why the protocol is built as it is (decisions E-1 to E-14), what each decision costs, and what was left out. |
| [workflows.md](workflows.md) | Sequence diagrams: creating a group, joining, a window of changes, nobody online, coming back, seeing who joined an open group. |
| [GLOSSARY.md](GLOSSARY.md) | Terms of the specification. |
| [formal/](formal/README.md) | ProVerif model of the security choices: taint rule, init chain, signed confirmation tag, district welcomes, anchored joins, windows sealed by an entrant, open groups. |
| [security-review-checklist.md](security-review-checklist.md) | Security review of a change or a release. |

## Research

| Document | Content |
| --- | --- |
| [research/grands-groupes-2026-09-25.md](research/grands-groupes-2026-09-25.md) | Groups of millions of members (in French): the limits of a classic TreeKEM group, lower bounds and related work, the architecture of City-G (districts re-keyed in parallel by committers that hold no state of their own, per-district queues, taints, district welcomes, anchored joins, sampling audits), its costs, guarantees, risks and roadmap. |
| [research/rekey_sim.py](research/rekey_sim.py) | Cost model behind the note's figures: windows, placement of joins, district size, CPU, steady-state traffic, audits. |
| [research/plan-de-messages-2026-09-26.md](research/plan-de-messages-2026-09-26.md) | A message plane for very large groups (in French), not part of the profile: keepers and readers (readers leave the tree and get the reader secrets of the epochs they missed in key bundles checked against chained tags, so removing a reader needs no re-key), sender cards with compact signatures (FN-DSA, round-3 candidates), burst chains, committing messages and reports, a sealed message log for transcript consistency, checkpoints against forks, and, for public groups with hostile or offline members, a public chain of reader secrets broken at bans, bundles served and windows sealed by any member, keepers admitted by an admin; costs, guarantees, risks and roadmap. |
| [research/msg_sim.py](research/msg_sim.py) | Cost model of the message-plane note: bytes per message by signature scheme, sender keys, following versus key bundles or the public chain, a reader's day, bursts with keepers only, the load of the members that serve bundles, history. |
| [research/formal-messages/](research/formal-messages/README.md) | ProVerif model of the mechanisms of the message-plane note: key bundles, removal of a reader without re-key, forks, the public chain and its breaks, windows sealed by a reader, burst chains, sender cards. |
| [research/bench/](research/bench/src/main.rs) | Micro-benchmarks of the primitives (X-Wing, ML-DSA-65, FN-DSA, BLAKE3, ChaCha20-Poly1305) through `cityg-core`, the source of the CPU figures of both notes. |
