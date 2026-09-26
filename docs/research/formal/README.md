# Symbolic model of the "Cité" design

A [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) model of the
design choices of the research note
[`grands-groupes-2026-09-25.md`](../grands-groupes-2026-09-25.md) (in
French), which studies groups of millions of members. The draft profile
v0.4 follows that design: see the [design note](../../design-v0.4.md), the
[draft specification](../../specs-v0.4-draft.md) and the prototype
[`crates/cityg-cite`](../../../crates/cityg-cite). The model checks the
choices the design relies on, against the adversaries of
[specs.md](../../specs.md) section 2.1. It is not a model of the draft
specification itself. The model of the current profile, v0.3, is in
[`../../formal/`](../../formal/README.md).

## Running it

ProVerif 2.05, then:

```bash
docs/research/formal/run.sh                 # ProVerif in PATH
docs/research/formal/run.sh /path/to/proverif
```

`run.sh` runs every scenario and compares each verdict with the expected
one. The whole set takes a few seconds. A single scenario runs with
`proverif -lib cite.pvl <scenario>.pv` from this directory.

## Scenarios

In every scenario, the network, and hence the delivery service, is the
adversary. "Proved" means ProVerif proves the property for an unbounded
adversary in the scenario. "Attack" means ProVerif finds a trace, as
expected for the sanity checks.

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
| [`join_without_anchor.pv`](join_without_anchor.pv) | J accepts a commit signed by any key it is shown, as a v0.3 joiner does (specification, section 2.3). | Attack. |
| [`entrant_removal.pv`](entrant_removal.pv) | No member is online. M's removal is recorded; M had committed district 1 and knows everything of epoch 1, the external key included. J, admitted by an admin, seals window 2 as an entrant: it takes M's leaf, re-keys M's taints and seals with an external init that M can open. A checks J's admission and signature. | Proved: the removed M does not read epoch 2. |
| [`external_tag_only.pv`](external_tag_only.pv) | The delivery service forges a window "sealed by an entrant" for A, who checks only the confirmation tag. | Attack: the external key is public, so the service computes the tag. |
| [`external_checked.pv`](external_checked.pv) | The same forgery, with a device the service controls, for a member that also checks the entrant's admission and its signature of the seal. | Proved. |
| [`open_group.pv`](open_group.pv) | An open group: a join needs no admission. A accepts a window sealed by any new device that signed it, whose key the new epoch binds for every member to see. B sends signed messages. | Attack, as expected: the delivery service joins a device of its own and reads what A sends (an open group gives no confidentiality against whoever joins it). Proved: it cannot make A accept a message as B's. |

The results bear on six decisions:

* **Taint rule.** Removing a member re-keys the nodes it tainted. Updating re-keys them too.
* **Init chain.** Keeping it gives forward secrecy of past epochs even when a
  leaf key is kept for a long time. It also lets members check the
  confirmation tag instead of a signature in every window.
* **Signed tag.** The signed header of a commit carries the confirmation tag,
  because a welcome is not signed.
* **Anchoring.** Anchoring joins on an admin checkpoint closes the forked
  entry of section 2.3.
* **Zero online (E-7 of the design note).** An entrant can seal a window,
  removals included, when no member is online. Members then check the
  entrant's admission and signature: for such a window, the confirmation
  tag alone proves nothing against the delivery service.
* **Open groups (E-14).** Without admissions, anyone can join, the
  delivery service included; what it cannot do is speak as a member.

## Abstractions and limits

* **Symbolic.** Primitives are ideal. In particular, the wrap is one ideal
  public-key encryption. This hides the attacks by malicious public keys on
  multi-recipient lattice KEMs that the note discusses: such attacks are
  outside this model.
* **Small trees.** Each scenario uses two windows and trees of two to four
  leaves, written out with districts of two leaves. Chains of path secrets
  inside a district are those of TreeKEM, modelled for profile v0.3 in
  [`../../formal/`](../../formal/README.md).
* **Committer assignment.** It is given: a member accepts a district commit
  only from the committer the window assigned. The delivery service's
  queues, windows, placement, the enforcement of recorded removals at
  delivery and the sampling audits are not modelled.
* **Other districts.** Checking the entries of other districts, the sparse
  Merkle maps and the transcript chain behind a checkpoint are abstracted:
  a checkpoint binds its members' keys directly.
