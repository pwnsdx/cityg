# Symbolic model of City-G v0.3

A [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) model of the
key schedule, the ratchet tree, external and batched joins with welcomes,
admission, removal, device-key rotation and the message plane of profile
`city-g/v0.3` ([specification](../specs.md)), against the adversaries of
section 2.1. It answers proposal P-8 of the
[2026-09-25 audit](../audits/audit-crypto-conformite-2026-09-25.md), for the
profile of the [v0.3 design note](../design-v0.3.md). The model of profile
v0.2 is archived in [`../legacy/v0.2/formal/`](../legacy/v0.2/formal/README.md).

## Running it

ProVerif 2.05 (OCaml 4.03 or later; `opam install proverif`, or build the
[source release](https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz)
with `./build`), then:

```bash
docs/formal/run.sh                 # ProVerif in PATH
docs/formal/run.sh /path/to/proverif
```

`run.sh` runs every scenario and compares each verdict with the expected
one. A single scenario runs with `proverif -lib cityg.pvl <scenario>.pv`
from this directory. The whole set takes about eight minutes.

## Files

| File | Content |
| --- | --- |
| [`cityg.pvl`](cityg.pvl) | Primitives, protocol functions, events and the processes of every scenario. |
| [`key_schedule.pv`](key_schedule.pv) | Scenario KS, no compromise: secrecy, agreement, admission. |
| [`forward_secrecy.pv`](forward_secrecy.pv) | Scenario KS; A's state leaks after the last epoch. |
| [`post_compromise.pv`](post_compromise.pv) | Scenario KS; B's state leaks, then B re-keys. |
| [`joins.pv`](joins.pv) | Scenario JN: two devices enter with one commit and their welcomes. |
| [`join_secrecy.pv`](join_secrecy.pv) | Scenario JN; a joiner's state leaks once it entered. |
| [`joins_from_any_signer.pv`](joins_from_any_signer.pv) | JN with a joiner that accepts any GroupInfo signer: must find an attack. |
| [`removal.pv`](removal.pv) | Scenario RM: an admin removes a malicious member. |
| [`removal_without_author_rule.pv`](removal_without_author_rule.pv) | RM without the rule that a removal never targets the commit's author: must find an attack. |
| [`removal_without_retired_rule.pv`](removal_without_retired_rule.pv) | RM without retired admissions: must find an attack. |
| [`rotation.pv`](rotation.pv) | Scenario RT: a member rotates its device key, then the old key leaks. |
| [`messages.pv`](messages.pv) | Scenario MS: sender authentication and confidentiality of messages. |
| [`run.sh`](run.sh) | Runs all of them and checks the verdicts. |

## Scenarios

In every scenario the network, hence the delivery service, is the
adversary: it may drop, replay, reorder or forge any message. Each member
is a chain of processes, one per epoch, handing its state over on private
channels.

**KS, a group grows.** Epoch 0: A creates the group (genesis, one leaf).
Epoch 1: B enters with an ExternalJoin commit: it verifies A's GroupInfo,
encapsulates to the external key of epoch 0 and presents an admission A
signed; the tree doubles to two leaves. Epoch 2: B re-keys from a fresh
leaf secret.

**JN, batched joins.** The group is at epoch 1 with A (admin) and B. Two
devices, J1 and J2, record join requests carrying admissions A signed, their
leaf keys and one-time init keys. Epoch 2: A's Member commit places both
requests: the tree doubles to four leaves, the joiners enter leaves 2 and 3
under a blank node, and A's update path re-keys the old root (wrapped to B)
and the new root (wrapped to both joiners' leaf keys, the resolution of the
blank node). A seals a welcome with the joiner secret for each request. B
checks the requests and processes the commit; each joiner checks that the
commit includes its request, opens its welcome, checks the confirmation tag
and the GroupInfo, and decrypts the new root secret.

**RM, removal of a malicious member.** The group is at epoch 2 with A
(admin), B and C, a malicious member: the adversary holds C's device key,
all the secrets C holds (its leaf key, the keys of its direct path, the
epoch secret) and the admission A once signed for it. Epoch 3: A removes C:
the commit blanks C's leaf and path, retires C's admission and halves the
tree; B processes it. Epoch 4: A processes an ExternalJoin, by D, an honest
device it admitted, or by the adversary trying to bring C back; the tree
doubles again.

**RT, rotation of a device key.** The group is at epoch 1 with A and B.
Epoch 2: B's Member commit replaces its device key, signed by the old key
and by the new one, and B sends a message signed with the new key. Once A
accepted the rotation, the old key leaks. Epoch 3: A processes the next
commit of B's leaf and the message.

**MS, messages.** A sends messages in two groups: one with a malicious
member that knows the epoch secret, one without. A also signs, under the
commit context, anything the adversary asks.

## Results

"Proved" means ProVerif proves the property for an unbounded adversary in
the scenario; "attack" means ProVerif finds a trace, as expected for sanity
checks and reachability queries; "not provable" means it finds the
derivation of the attack but cannot rebuild the trace through the private
channels that carry the members' state.

| Property (specs.md section 2.2) | Scenario, query | Result | Requirements |
| --- | --- | --- | --- |
| Confidentiality of every accepted epoch secret against the delivery service | KS, JN | proved | KS.2, SEC.1 |
| Membership agreement: every accepted epoch context was committed by an honest member | KS, JN | proved | KS.1, KS.3, COM.6 |
| Membership agreement: two members accepting an epoch agree on its context and secret | KS | proved | KS.1, KS.3 |
| Membership agreement for joiners: a member, joiners included, that accepts the committer's context derives the committer's epoch secret | JN | proved | JOIN.2, JOIN.3 |
| Admission control: an entry is accepted only with an admin's admission | KS, JN, RM | proved | ADM.2, ADM.3 |
| Confidentiality of the welcomes and of the epoch before the joins | JN | proved | JOIN.2 |
| Reachability: both joiners enter with one commit | JN | attack (reached) | |
| Join secrecy: the epoch before a join stays secret when the joiner's whole state leaks | JS | proved | JOIN.3, SEC.1 |
| Sanity: the leaked joiner exposes the epoch it entered | JS | attack | |
| Sanity: a joiner that accepts any GroupInfo signer enters an epoch the adversary fabricated (section 2.3) | JN | attack | JOIN.3 |
| Forward secrecy: epochs 0 to 2 stay secret when A's retained state leaks after epoch 2 | FS | proved | KS.4, SEC.1 |
| Sanity: the secrets A keeps for the next epoch do leak | FS | not provable (derivation found, trace not rebuilt) | |
| Post-compromise security: after B's state leaks, B's self-update makes the next epoch secret | PCS | proved | TREE.5, SEC.1 |
| Sanity: the epoch before the self-update is exposed | PCS | attack | |
| Post-removal secrecy: the epoch created by C's removal is secret | RM | proved | REM.3, COM.4 |
| The removed member does not come back with its admission, and the next epoch is secret | RM | proved | REG.3 |
| Reachability: the removal and D's join happen | RM | attack (reached) | |
| Without "a removal never targets the commit's author", C authors a Resync that includes its own removal, re-enters its leaf and learns the next epoch (audit C-03) | RM | attack | REM.2 |
| Without retired admissions, C joins again with its old admission | RM | attack | REG.3 |
| After a rotation, the old key, leaked, can author neither a commit nor a message of the member's occupancy | RT | proved | ROT.1, COM.2 |
| The leak of the rotated key exposes no epoch secret | RT | proved | ROT.1 |
| Reachability: A accepts the member's next commit and its message | RT | attack (reached) | |
| Sender authentication, against a member that knows the epoch secret and with signatures of the sender under another context | MS | proved | MSG.1, MSG.3, SUITE.2 |
| Confidentiality of messages against non-members | MS | proved | MSG.1 |
| Sanity: a member reads its group's messages | MS | attack | |

JS is `join_secrecy.pv`, FS `forward_secrecy.pv`, PCS `post_compromise.pv`.

## What the model shows about joiners

A joiner, and a member that resyncs, checks the epoch it enters (the
commit, the GroupInfo, the tree and the registry against each other) but
cannot check the history before it. The scenarios where a joiner is proved
safe (KS for an external join, JN for a welcome) let it check the GroupInfo
under the key of A, the admin that admitted it and that authored the
commit. `joins_from_any_signer.pv` shows what happens without that
knowledge: the adversary fabricates an epoch whose committer and signer is a
key it holds, puts the joiner's own request and a welcome in it, and the
joiner enters an epoch the adversary knows. The implementation, like the
specification (section 2.3), takes the signer from the tree it received:
this is the forked view that comparing security codes detects (see
[fingerprints.md](../fingerprints.md)).

## Abstractions and limits

* **Symbolic model.** Primitives are ideal: X-Wing is an IND-CCA2 KEM,
  ChaCha20-Poly1305 an ideal AEAD, ML-DSA-65 an unforgeable signature bound
  to its context, BLAKE3 and its keyed modes one-way functions. The model
  says nothing about the computational security of the primitives or of the
  construction (in particular of the X-Wing combiner), nor about side
  channels.
* **Bounded scenarios.** Each scenario is one run with a fixed number of
  members and epochs, trees of one to four leaves, and a fixed order of
  commits; ProVerif covers every adversary behaviour within that run, not
  arbitrary group histories or sizes. The JN, RM and RT scenarios start from
  an arbitrary state rather than from genesis.
* **Trees and hashes.** A tree is hashed as one tuple of its leaf and parent
  nodes, which binds the same values as the Merkle hash of section 6.3; leaf
  proofs are not modelled. Resolutions, unmerged leaves, the doubling and
  halving of the tree and the blanking of a removed member's path are
  written out for each scenario rather than computed.
* **Transcript.** The confirmed transcript hash is modelled as the hash of
  the commit's signatures. A symbolic signature contains the signed content,
  and the content contains the previous interim hash, so this binds the same
  values as the specification with smaller terms.
* **Not modelled.** Light members (section 14; their trust assumption is
  stated in section 14.6); invite-based admissions (kind 1), invite expiry,
  use counts and revocation; admission validity windows and the retired
  floor (the scenarios retire at most one admission); cover-failure reports;
  concurrent commits and the delivery service's ordering and overdue rule;
  admin changes and the promotion rule; the message ratchet beyond the
  first generation of each chain, the replay window and the grace window;
  the deployment binding (aliases, sessions). These are covered by the tests
  mapped in the [conformance manifest](../../kat/kat-v0.3-conformance-manifest.json).
