# Symbolic model of City-G at parity with MLS (research)

A [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) model of the
mechanisms that the research note
[`parite-mls-2026-09-26.md`](../parite-mls-2026-09-26.md) (in French) adds
to City-G so that it keeps the guarantees of MLS (RFC 9420) for groups of a
million members, bursts of joins and departures, and a membership that the
service authorizes. It also models the options of the note
[`rekey-serveur-2026-09-26.md`](../rekey-serveur-2026-09-26.md) (in French),
which asks whether the server could re-key the tree instead of members, and
the disputes it proposes against a committer that sends bad wraps; and the
îlots of [`ilots-2026-09-26.md`](../ilots-2026-09-26.md) (in French): small
subtrees with no tree above them, whose roots receive the epoch secret of
every window, and relays that pass it on inside an îlot. None of them is
part of profile `city-g/v0.4`. The model of the protocol itself is
in [`docs/formal/`](../../formal/README.md); that of the message-plane note
in [`../formal-messages/`](../formal-messages/README.md).

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
| [`server_rekey.pv`](server_rekey.pv) | The server draws the root of window 2 and wraps it to every leaf; entrant J joins with a signed external init. Nobody who knows a secret of epoch 1 helps the server. | Proved: what member A and entrant J send in epoch 2 stays secret. The init secret and the external init keep the epoch from the server alone. |
| [`server_rekey_removed.pv`](server_rekey_removed.pv) | The same server draws the roots of windows 2 and 3; M, a member of epoch 1 that window 2 removes, gives it the secrets of epoch 1. | Attack on both epochs: M opens J's external init, and the server, which draws every root, derives epoch 2 and every later epoch. |
| [`member_rekey_removed.pv`](member_rekey_removed.pv) | The same removal when committers, members of the group, draw the roots, as in v0.4. | Proved: neither M nor the server reads the real epochs 2 and 3. |
| [`split_rekey.pv`](split_rekey.pv) | Two servers each keep a tree of shares and re-key it; the root secret combines both roots. Server S1 and the removed M help the attacker; S2 signs its shares. | Proved: what A sends stays secret. |
| [`split_rekey_unsigned.pv`](split_rekey_unsigned.pv) | A does not check S2's signature. | Attack: the attacker wraps a share of its own to A's leaf. |
| [`split_rekey_collude.pv`](split_rekey_collude.pv) | Both servers and M help the attacker. | Attack. |
| [`wrap_dispute.pv`](wrap_dispute.pv) | An honest committer wraps a node's secret to child u; a hostile member under u, which holds u's key, files disputes: a wrap from a signed commit and a proof of decryption in the wrap's context. The judge convicts if the wrap is not well formed or opens to a secret whose public key is not the node's. | Proved: the honest committer is never convicted. |
| [`wrap_dispute_report.pv`](wrap_dispute_report.pv) | Member B, which holds u's key, files a dispute against a hostile committer, which may replay a wrap of epoch 1. | Proved: u's key and the secret wrapped to u in epoch 1 stay secret. Reachable, as intended: the hostile committer is convicted (third query false). |
| [`wrap_dispute_replay.pv`](wrap_dispute_replay.pv) | A cheaper dispute reveals the shared secret of the wrap's encapsulation, which does not depend on the wrap's context; the hostile committer replays the encapsulation of a wrap of epoch 1. | Attack: the attacker reads the secret of epoch 1. A dispute proves the verdict in the wrap's context and never reveals the encapsulation's secret. |
| [`ilot_removal.pv`](ilot_removal.pv) | Îlot j holds A and M, îlot i holds B; window 2 removes M. The îlot task re-keys j; the top seals the epoch secret to the new root of j and the unchanged root of i, with no tree above the îlots. M gives the server the secrets of epoch 1 and the old root of j. | Proved: the real epoch 2 stays secret. |
| [`ilot_removal_unrekeyed.pv`](ilot_removal_unrekeyed.pv) | The window does not re-key îlot j. | Attack: the top seals the epoch secret to a root M knows. |
| [`ilot_relay.pv`](ilot_relay.pv) | Member B takes the epoch secret from relay C, a hostile member of its îlot working with the server, in a blob under the îlot's relay key, and checks it against the tag the sealer signed. | Proved: B accepts only the real epoch. |
| [`ilot_relay_unchecked.pv`](ilot_relay_unchecked.pv) | B does not check the tag. | Attack: the relay leads B into an epoch nobody sealed. |
| [`ilot_forward_secrecy.pv`](ilot_forward_secrecy.pv) | Îlot j keeps its root through windows 1 to 3, whose epoch secrets the top seals to it; member A is compromised in epoch 3 and had erased the secrets of epochs 1 and 2. | Proved: the attacker opens the epoch secrets of the three windows, but the init chain keeps epoch 2 from it. |
| [`ilot_forward_secrecy_without_init.pv`](ilot_forward_secrecy_without_init.pv) | The same compromise with a key schedule that does not chain the init secret. | Attack: stable îlot keys need the init chain. |
| [`ilot_init_by_ilot.pv`](ilot_init_by_ilot.pv) | A cheaper welcome: the init secret of epoch 1 is sealed to the root of the îlot that receives a joiner, instead of a welcome to each joiner's one-time init key; a member of that îlot is compromised in epoch 3. | Attack: the îlot's root opens the init secret and the epoch secret of window 2, hence epoch 2. Welcomes stay sealed to one-time init keys. |

## Abstractions and limits

* **Symbolic.** Primitives are ideal. Equivalence is diff-equivalence of one
  message; unlinkability across many messages is not modelled.
* **Small.** Two batch entries, two or three epochs, one leaf per member;
  Merkle proofs of depth one.
* **Trust.** The authorizer is honest in these scenarios: an authorizer
  that signs for the adversary admits it, as a compromised MLS
  authentication service would. A server that re-keys the tree is the
  network, hence the adversary, in the `server_rekey` scenarios; a second
  server is honest in `split_rekey.pv`.
* **Ideal proofs of decryption.** The proof of a dispute is a constructor
  with one destructor that returns the plaintext of the wrap in its
  context, or a verdict that the wrap is not well formed. It stands for a
  zero-knowledge proof over the decapsulation, the derivation of the AEAD
  key and the AEAD; its cost and its soundness are not modelled.
* **No computational proof.**
