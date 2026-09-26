# Symbolic model of the message plane (research)

A [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) model of the
mechanisms that the research note
[`plan-de-messages-2026-09-26.md`](../plan-de-messages-2026-09-26.md)
(in French) proposes for the message plane of very large groups. None of
them is part of profile `city-g/v0.4`: the specification does not define a
message plane yet (section 19). The model of the protocol itself is in
[`docs/formal/`](../../formal/README.md).

## Running it

ProVerif 2.05, then:

```bash
docs/research/formal-messages/run.sh                 # ProVerif in PATH
docs/research/formal-messages/run.sh /path/to/proverif
```

`run.sh` runs every scenario and compares each verdict with the expected
one, in about a second. A single scenario runs with
`proverif -lib msg.pvl <scenario>.pv` from this directory.

## Scenarios

The network, and hence the delivery service, is the adversary in every
scenario. "Proved" means ProVerif proves the property for an unbounded
adversary in the scenario. "Attack" means ProVerif finds a trace, as
expected for the sanity checks. A *reader* is a member outside the
keepers' tree: it holds reader secrets, which it gets in *key bundles*
from *keepers*, and never an epoch secret.

| Scenario | What it checks | Expected result |
| --- | --- | --- |
| [`reader_bundle.pv`](reader_bundle.pv) | Reader R holds the reader secret of epoch 1. It signs a request with a one-time key; keeper K seals the reader secret of epoch 2 to that key. R accepts it only if the chained reader tag of epoch 2, keyed by the reader secret of epoch 1, checks. | Proved: what R sends in epoch 2 stays secret, and R accepts only the real secret. |
| [`reader_bundle_no_tag.pv`](reader_bundle_no_tag.pv) | The same bundle, but R does not check the tag. | Attack: anyone can seal a secret to the one-time key, and R encrypts under it. |
| [`reader_bundle_unsigned_request.pv`](reader_bundle_unsigned_request.pv) | K does not check that R's device key signed the request. | Attack on secrecy: the delivery service asks for a bundle with its own one-time key. Proved: R still accepts only the real secret. |
| [`reader_removed.pv`](reader_removed.pv) | Readers R and Q hold the reader secret of epoch 1. Window 2 removes R and re-keys nothing: the keepers' tree keeps its root, and epoch 2 is fresh through the init chain only. R and the delivery service attack. | Proved: R does not read the real epoch 2. Attack, as expected: with the delivery service, R makes Q accept an epoch of its own, since Q checks only a tag keyed by a secret R held (the fork of the specification, section 2.3). |
| [`reader_removed_signed_bundle.pv`](reader_removed_signed_bundle.pv) | The same removal; Q also requires the bundle to be signed by a keeper it knows from its anchor. | Proved, both properties: the fork needs a keeper. |
| [`reader_removed_with_root.pv`](reader_removed_with_root.pv) | The same removal in a design where readers hold the root of the keepers' tree and the epoch secret. | Attack: the removed reader derives epoch 2. |
| [`reader_removed_ratchet.pv`](reader_removed_ratchet.pv) | The same removal in a design where reader secrets are ratcheted from one epoch to the next, as a Megolm session. | Attack. |
| [`burst_chain.pv`](burst_chain.pv) | Sender S signs one burst of two envelopes with its sender card, over the chain of both. The attacker is a member of the epoch. | Proved: a reader accepts as S's only what S sent. |
| [`burst_chain_mac_only.pv`](burst_chain_mac_only.pv) | The chain is authenticated with a MAC under a key of the epoch instead of S's card. | Attack: any member speaks as S. |
| [`card_revalidated.pv`](card_revalidated.pv) | Window 2 removes S, which keeps its card key and colludes with a member of epoch 2. The reader checks a card against the roster of the message's epoch. | Proved: it accepts a card only for epochs where its member was in the roster. |
| [`card_cached.pv`](card_cached.pv) | The same, with a reader that keeps accepting the cards it checked in epoch 1. | Attack: S still speaks after its removal. |

The results bear on the rules of the note:

* **Readers never hold chain secrets.** A removal of a reader then needs no
  re-key (`reader_removed`); a design that gives readers the tree's root
  (`reader_removed_with_root`) or a ratchet of reader secrets
  (`reader_removed_ratchet`) needs one.
* **Bundles are checked, requests are signed.** A reader checks every
  secret against a chained tag (`reader_bundle_no_tag`: the key-request
  attacks on Matrix), and a keeper serves only a request signed by a reader
  in the roster (`reader_bundle_unsigned_request`).
* **Forks.** A tag keyed by the previous reader secret lets any member of
  the previous epoch, with the delivery service, fork a reader, as any
  member can fork a member that checks only tags. A bundle signed by a
  keeper restricts the fork to keepers (`reader_removed_signed_bundle`);
  admin checkpoints bound its length.
* **Burst chains** need the sender's signature over the chain
  (`burst_chain_mac_only`).
* **Sender cards** are checked against the roster of the message's epoch
  (`card_cached`).

## Abstractions and limits

* **Symbolic.** Primitives are ideal: the X-Wing encapsulation and the
  AEAD of a bundle are one public-key encryption with associated data;
  signatures are unforgeable, whatever the scheme of the card.
* **Two epochs.** The chain of tags over many epochs, the transcript
  hashes, the sealed message log and the checkpoints are not modelled; the
  roster is a hash of its cards.
* **Given roles.** The keeper that serves a bundle, the roster and its
  roots are given; how the keepers' tree produces the epoch secret is the
  key schedule of `docs/formal/cityg.pvl`, not re-proved here.
* **No computational proof.**
