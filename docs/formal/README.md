# Symbolic model of City-G v0.2

A [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) model of the
key schedule, the barrier tree, external joins, admission, removal and the
message plane of profile `city-g/v0.2` ([specification](../specs.md)),
against the adversaries of section 2.1. It answers proposal P-8 of the
[2026-09-25 audit](../audits/audit-crypto-conformite-2026-09-25.md).

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
from this directory. The whole set takes a few minutes.

## Files

| File | Content |
| --- | --- |
| [`cityg.pvl`](cityg.pvl) | Primitives, protocol functions, events and the processes of every scenario. |
| [`key_schedule.pv`](key_schedule.pv) | Scenario KS, no compromise: secrecy, agreement, admission. |
| [`forward_secrecy.pv`](forward_secrecy.pv) | Scenario KS; A's state leaks after the last epoch. |
| [`post_compromise.pv`](post_compromise.pv) | Scenario KS; B's state leaks, then B re-keys. |
| [`removal.pv`](removal.pv) | Scenario RM: an admin removes a malicious member. |
| [`removal_without_author_rule.pv`](removal_without_author_rule.pv) | RM without the rule that a commit cannot remove its author: must find an attack. |
| [`removal_without_retired_rule.pv`](removal_without_retired_rule.pv) | RM without retired devices: must find an attack. |
| [`messages.pv`](messages.pv) | Scenario MS: sender authentication and confidentiality of messages. |
| [`run.sh`](run.sh) | Runs all of them and checks the verdicts. |

## Scenarios

**KS, a group grows.** Epoch 0: A creates the group (genesis). Epoch 1: B
joins with an ExternalJoin commit: it verifies A's GroupInfo, encapsulates to
the external key of epoch 0 and presents an admission A signed. Epoch 2: B
re-keys from a fresh leaf secret. Tree of 2 slots. Each member is a chain of
processes, one per epoch, handing its state over on private channels; the
network, hence the delivery service, is the adversary.

**RM, removal of a malicious member.** The group is at epoch 2 with A
(admin), B and C, a malicious member: the adversary holds C's device key,
all the secrets C holds (its leaf key, the keys of its direct path, the
epoch secret) and the admission A once signed for it. Epoch 3: A removes C
and B processes the commit. Epoch 4: A processes an ExternalJoin, by D, an
honest device it admitted, or by the adversary trying to bring C back. Tree
of 4 slots, with the blanking of C's leaf and direct path.

**MS, messages.** A sends messages in two groups: one with a malicious
member that knows the epoch secret, one without. A also signs, under the
commit context, anything the adversary asks.

## Results

"Proved" means ProVerif proves the property for an unbounded adversary in
the scenario; "attack" means ProVerif finds a trace, as expected for sanity
checks; "not provable" means it finds the derivation of the attack but
cannot rebuild the trace through the private channels that carry the
members' state.

| Property (specs.md section 2.2) | Scenario, query | Result | Requirements |
| --- | --- | --- | --- |
| Confidentiality of every accepted epoch secret against the delivery service | KS | proved | KS.2, SEC.1 |
| Membership agreement: every accepted epoch context was committed by an honest member | KS | proved | KS.1, KS.3, COM.6 |
| Membership agreement: two members accepting an epoch agree on its context and secret | KS | proved | KS.1, KS.3 |
| Admission control: a join is accepted only with an admin's admission | KS, RM | proved | ADM.2, ADM.3 |
| Forward secrecy: epochs 0 to 2 stay secret when A's retained state leaks after epoch 2 | FS | proved | KS.4, SEC.1 |
| Sanity: the secrets A keeps for the next epoch do leak | FS | not provable (derivation found, trace not rebuilt) | |
| Post-compromise security: after B's state leaks, B's self-update makes the next epoch secret | PCS | proved | TREE.3, SEC.1 |
| Sanity: the epoch before the self-update is exposed | PCS | attack | |
| Post-removal secrecy: the epoch created by C's removal is secret | RM | proved | REM.3, COM.4 |
| The removed member does not join again, and the next epoch is secret | RM | proved | ROS.4 |
| Reachability: the removal and D's join happen | RM | attack (reached) | |
| Without "a commit cannot remove its author", C authors its own removal and learns the next epoch (audit C-03) | RM | attack | REM.2 |
| Without retired devices, C joins again with its old admission | RM | attack | ROS.4 |
| Sender authentication, against a member that knows the epoch secret and with signatures of the sender under another context | MS | proved | MSG.1, MSG.3, SUITE.2 |
| Confidentiality of messages against non-members | MS | proved | MSG.1 |
| Sanity: a member reads its group's messages | MS | attack | |

## What the model changed

Writing the scenarios led to two corrections of the specification and the
code:

* **Retired devices.** An admin admission names a device, not an occupancy,
  and did not expire: a removed member kept it and could join again alone.
  The roster now retires the leaf id of every ended occupancy (section 7);
  `removal_without_retired_rule.pv` shows the attack without the rule.
* **Device-key compromise.** Section 2 claimed post-compromise security
  against an adversary that learns a device's full state. With the device
  key, that adversary can sign a Resync commit that re-enters the device's
  slot at any time, so the claim does not hold. The threat model now
  separates the compromise of the device state (A5, healed by the next
  self-update, as `post_compromise.pv` shows) from the theft of the device
  key (A6, repaired only by removing the device).

## Abstractions and limits

* **Symbolic model.** Primitives are ideal: ML-KEM-768 is an IND-CCA2 KEM,
  ChaCha20-Poly1305 an ideal AEAD, ML-DSA-87 an unforgeable signature bound
  to its context, BLAKE3 and its keyed modes one-way functions. The model
  says nothing about the computational security of the primitives or of the
  construction, nor about side channels.
* **Bounded scenarios.** Each scenario is one run with a fixed number of
  members and epochs, trees of 2 and 4 slots, and a fixed order of commits;
  ProVerif covers every adversary behaviour within that run (the delivery
  service may drop, replay, reorder or forge any message), not arbitrary
  group histories or sizes. The removal scenario starts from an arbitrary
  epoch-2 state rather than from genesis.
* **Transcript.** The confirmed transcript hash is modelled as the hash of
  the commit signature. A symbolic signature contains the signed content,
  and the content contains the previous interim hash, so this binds the same
  values as the specification with smaller terms.
* **Not modelled.** Invite-based admissions (kind 1) and invite expiry;
  Resync commits and cover-failure reports; concurrent commits and the
  delivery service's ordering; admin changes and the promotion rule; the
  message ratchet beyond the first generation of each chain, the replay
  window and the grace window; the deployment binding (aliases, sessions).
  These are covered by the tests mapped in the
  [conformance manifest](../../kat/kat-v0.2-conformance-manifest.json).
