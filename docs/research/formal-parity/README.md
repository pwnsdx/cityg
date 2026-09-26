# Symbolic model of City-G at parity with MLS (research)

A [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) model of the
mechanisms that the research note
[`parite-mls-2026-09-26.md`](../parite-mls-2026-09-26.md) (in French) adds
to City-G so that it keeps the guarantees of MLS (RFC 9420) for groups of a
million members, bursts of joins and departures, and a membership that the
service authorizes. None of them is part of profile `city-g/v0.4`. The model
of the protocol itself is in [`docs/formal/`](../../formal/README.md); that
of the message-plane note in [`../formal-messages/`](../formal-messages/README.md).

## Running it

ProVerif 2.05, then:

```bash
docs/research/formal-parity/run.sh                 # ProVerif in PATH
docs/research/formal-parity/run.sh /path/to/proverif
```

`run.sh` runs every scenario and compares each verdict with the expected
one, in about a second. A single scenario runs with
`proverif -lib parity.pvl <scenario>.pv` from this directory.

## Scenarios

The network, and hence the delivery service, is the adversary in every
scenario. "Proved" means ProVerif proves the property for an unbounded
adversary in the scenario; "attack" means it finds a trace; "not proved"
means it cannot prove an equivalence. The *authorizer* is the service that
decides who may join; it signs, for every window, one Merkle root over the
join requests it authorizes and a checkpoint of the epoch the window
creates.

| Scenario | What it checks | Expected result |
| --- | --- | --- |
| [`batch_authorization.pv`](batch_authorization.pv) | A checker (the delivery service, a committer, an auditor) accepts a join only with its inclusion proof in a root the authorizer signed for the window. The delivery service has device keys of its own, not the authorizer's key. | Proved: only authorized devices are accepted. |
| [`batch_authorization_unsigned.pv`](batch_authorization_unsigned.pv) | The checker does not check the authorizer's signature of the root. | Attack. |
| [`authorizer_anchor.pv`](authorizer_anchor.pv) | Joiner J trusts the authorizer's key and accepts the epoch it enters only if the authorizer's checkpoint of that epoch is signed and the joiner secret of its welcome reproduces the checkpoint's confirmation tag. It checks no chain of seals. | Proved: what J sends stays secret, and J enters only the real epoch. |
| [`authorizer_anchor_unsigned.pv`](authorizer_anchor_unsigned.pv) | J accepts a checkpoint nobody signed. | Attack: the delivery service seals a joiner secret of its own to J's init key and computes the tag. |
| [`authorizer_follow.pv`](authorizer_follow.pv) | Member A follows the group and also checks the authorizer's checkpoint of every window. A hostile member of epoch 1, which knows its init secret, and the delivery service make up a window 2 for A. | Proved: A accepts only the epoch the authorizer signed, and what A sends stays secret. |
| [`authorizer_follow_unchecked.pv`](authorizer_follow_unchecked.pv) | A checks the tag only, as in v0.4. | Attack: the fork that the specification states (section 2.3). |
| [`history_link.pv`](history_link.pv) | R, a member offline in epoch 2, comes back in epoch 3 and reads epoch 2 through a history link: the commit secret of epoch 2 under a key derived from that of epoch 3. M, removed by window 2, attacks with the delivery service. | Proved: M does not read the real epoch 2. Attack, as expected: M knows the init secret of epoch 1 and makes up an epoch 2 for R, the fork of the specification (section 2.3). |
| [`history_link_rejoin.pv`](history_link_rejoin.pv) | M, removed by window 2, joins again in window 3. | Attack: with its old init secret and the link, M reads epoch 2, where it was not a member. History links are rejected. |
| [`sender_hidden.pv`](sender_hidden.pv) | A or B sends a message framed as an MLS PrivateMessage: sender data encrypted under the epoch's sender-data key with a fresh nonce, content and card signature under the sender's key. | Proved: the delivery service cannot tell who sent it (observational equivalence). |
| [`sender_visible.pv`](sender_visible.pv) | The same message with the sender's leaf in clear. | Not proved, as expected. |

## Abstractions and limits

* **Symbolic.** Primitives are ideal. Equivalence is diff-equivalence of one
  message; unlinkability across many messages is not modelled.
* **Small.** Two batch entries, two or three epochs, one leaf per member;
  Merkle proofs of depth one.
* **Trust.** The authorizer is honest in these scenarios: an authorizer
  that signs for the adversary admits it, as a compromised MLS
  authentication service would.
* **No computational proof.**
