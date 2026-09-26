# Symbolic model of City-G

A [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) model of the
design choices of City-G, recorded in the [design note](../design.md) and
studied in the research note
[`grands-groupes-2026-09-25.md`](../research/grands-groupes-2026-09-25.md)
(in French). It checks the choices the [specification](../specs.md) relies
on, against the adversaries of its section 2.1. It is not a model of the
whole specification (section 19 of the specification).

## Running it

ProVerif 2.05, then:

```bash
docs/formal/run.sh                 # ProVerif in PATH
docs/formal/run.sh /path/to/proverif
```

`run.sh` runs every scenario and compares each verdict with the expected
one. The whole set takes a few seconds. A single scenario runs with
`proverif -lib cityg.pvl <scenario>.pv` from this directory. CI runs the
set on schedule.

## Scenarios

In every scenario, the network, and hence the delivery service, is the
adversary. "Proved" means ProVerif proves the property for an unbounded
adversary in the scenario. "Attack" means ProVerif finds a trace, as
expected for the sanity checks. The *sealer* re-keys the city and seals the
window; the scenarios call its seal the city commit.

| Scenario | What it checks | Expected result |
| --- | --- | --- |
| [`taint.pv`](taint.pv) | Removal of a malicious committer, M. In window 1, M re-keyed district 1, which it does not belong to, and kept the secret it drew. In window 2, M is removed: its district is re-keyed and, because its node is tainted by M, so is district 1. | Proved: the removed M does not read epoch 2. |
| [`taint_without_rule.pv`](taint_without_rule.pv) | The same removal re-keying only M's path, as plain TreeKEM would. | Attack: the new root is wrapped to a key M drew. |
| [`post_compromise.pv`](post_compromise.pv) | M is honest, but its device leaked while it committed district 1. M updates in window 2, which re-keys its path and its taints. | Proved: epoch 2 is secret, and M reads it. |
| [`forward_secrecy.pv`](forward_secrecy.pv) | Two windows, then A's device leaks. The leak includes the leaf key A has not updated since, which opens A's wraps of both windows. The epoch secret goes through the init chain. | Proved: epoch 1 stays secret. |
| [`forward_secrecy_without_init.pv`](forward_secrecy_without_init.pv) | The same leak with an epoch secret derived from the root alone. | Attack: the leaf key gives epoch 1. |
| [`fabrication.pv`](fabrication.pv) | The delivery service forges the next epoch for A, who checks only the confirmation tag, with the init chain. | Proved: A accepts no epoch the attacker knows. |
| [`fabrication_without_init.pv`](fabrication_without_init.pv) | The same check without the init chain. | Attack: A enters an epoch the attacker made. |
| [`fabrication_without_init_signed.pv`](fabrication_without_init_signed.pv) | No init chain, but A also verifies the committer's signature. | Proved. |
| [`join.pv`](join.pv) | J enters with a district welcome: the joiner secret is sealed to its one-time init key once the root is known. Then J's whole state leaks. | Proved: the epoch before J's entry stays secret. Attack (sanity): the epoch J entered is exposed. |
| [`anchored_join.pv`](anchored_join.pv) | J's invite carries a checkpoint signed by an admin. J accepts only a commit signed by a member behind that checkpoint. The delivery service controls a device that is not a member. | Proved. |
| [`anchored_join_unsigned_tag.pv`](anchored_join_unsigned_tag.pv) | The same join, with a confirmation tag the committer does not sign. | Attack: the service replaces both the welcome and the tag. |
| [`join_without_anchor.pv`](join_without_anchor.pv) | J accepts a commit signed by any key it is shown, as a joiner that checks only the epoch it enters. | Attack. |
| [`entrant_removal.pv`](entrant_removal.pv) | No member is online. M's removal is recorded; M had committed district 1 and knows everything of epoch 1, the external key included. J, admitted by an admin, seals window 2 as an entrant: it takes M's leaf, re-keys M's taints and seals with an external init that M can open. A checks J's admission and signature. | Proved: the removed M does not read epoch 2. |
| [`external_tag_only.pv`](external_tag_only.pv) | The delivery service forges a window "sealed by an entrant" for A, who checks only the confirmation tag. | Attack: the external key is public, so the service computes the tag. |
| [`external_checked.pv`](external_checked.pv) | The same forgery, with a device the service controls, for a member that also checks the entrant's admission and its signature of the seal. | Proved. |
| [`open_group.pv`](open_group.pv) | An open group: a join needs no admission. A accepts a window sealed by any new device that signed it, whose key the new epoch binds for every member to see. B sends signed messages. | Attack, as expected: the delivery service joins a device of its own and reads what A sends (an open group gives no confidentiality against whoever joins it). Proved: it cannot make A accept a message as B's. |
| [`catch_up_stolen_key.pv`](catch_up_stolen_key.pv) | The attacker holds M's device key, not M's state. A welcomes any catch-up of M signed with that key for the epoch; the welcome is sealed to the request's init key and to M's leaf key, which A takes from the tree. The attacker records a catch-up with an init key of its own. M jumps too. | Proved: the message A sends in epoch 2 stays secret. Reachable, as intended: M's own jump. |
| [`catch_up_init_only.pv`](catch_up_init_only.pv) | The same catch-ups, welcomed to the request's init key alone. | Attack: the attacker reads epoch 2, and could in every window, without changing the tree. Reachable: M's own jump. |

The results bear on seven decisions of the design note:

* **Taint rule (E-4).** Removing a member re-keys the nodes it tainted.
  Updating re-keys them too.
* **Init chain (E-5).** Keeping it gives forward secrecy of past epochs even
  when a leaf key is kept for a long time. It also lets members check the
  confirmation tag instead of a signature in every window.
* **Signed tag (E-5).** The seal's signature covers the confirmation tag,
  because a welcome is not signed.
* **Anchoring (E-10).** Anchoring joins on an admin checkpoint keeps the
  delivery service from leading a joiner into an epoch it fabricated.
* **Zero online (E-7).** An entrant can seal a window, removals included,
  when no member is online. Members then check the entrant's admission and
  signature: for such a window, the confirmation tag alone proves nothing
  against the delivery service.
* **Open groups (E-14).** Without admissions, anyone can join, the delivery
  service included; what it cannot do is speak as a member.
* **Jumps (E-8).** A catch-up is signed with the device key alone and
  changes nothing in the tree, so its welcome is sealed to the member's
  leaf key too: a device key stolen without the member's state does not
  jump.

## Abstractions and limits

* **Symbolic.** Primitives are ideal. In particular, the wrap is one ideal
  public-key encryption. This hides the attacks by malicious public keys on
  multi-recipient lattice KEMs that the research note discusses: such
  attacks are outside this model.
* **Small trees.** Each scenario uses two windows and trees of two to four
  leaves, written out with districts of two leaves. Chains of secrets inside
  a larger district, the plans of section 7.3 of the specification and the
  recovery of a path from its last steps are not modelled.
* **Committer assignment.** It is given: a member accepts a district commit
  only from the committer the window assigned. The delivery service's
  queues, windows, placement, the enforcement of recorded removals at
  delivery and the sampling audits are not modelled.
* **Other districts.** Checking the entries of other districts, the sparse
  Merkle maps and the transcript chain behind a checkpoint are abstracted:
  a checkpoint binds its members' keys directly.
