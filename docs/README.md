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
| [research/bench/](research/bench/src/main.rs) | Micro-benchmarks of the primitives (X-Wing, ML-DSA-65, BLAKE3) through `cityg-core`, the source of the CPU figures. |
