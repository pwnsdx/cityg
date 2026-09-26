# Computational model of the key schedule and the îlots (research)

A [CryptoVerif](https://bblanche.gitlabpages.inria.fr/CryptoVerif/) model
of the properties that the research notes
[`ilots-2026-09-26.md`](../ilots-2026-09-26.md) and
[`au-dela-0.4-2026-09-26.md`](../au-dela-0.4-2026-09-26.md) (in French) rest
on, in the computational model: the key schedule of a window with tree keys
that stay the same across windows, the removed member that stays out once
it has missed one window, the window an entrant seals alone, the relays
inside an îlot, the city maintained above the îlots, and the hedge of fresh
node secrets. Two authentication properties follow: a relay cannot make a
member accept another window secret than the sealed one, and witnesses that
countersign checkpoints stop a fork while one of them lies. A last pair
bears on profile `city-g/v0.4` itself: a catch-up signed with a stolen
device key, and the fix, which the profile now has. The set is the first step of the first open problem
of the note [`problemes-ouverts-2026-09-26.md`](../problemes-ouverts-2026-09-26.md),
continued in [`preuves-et-mesures-2026-09-26.md`](../preuves-et-mesures-2026-09-26.md),
which proposes that fix. The profile's own model, symbolic, is in
[`docs/formal/`](../../formal/README.md); the symbolic counterparts of these
models are in [`../formal-parity/`](../formal-parity/README.md).

## Running it

CryptoVerif 2.13, built from its sources (`./build`, OCaml 4.08 or later),
then:

```bash
docs/research/formal-computational/run.sh                        # cryptoverif in PATH
docs/research/formal-computational/run.sh /path/to/cryptoverif
```

`run.sh` runs every model and compares each verdict with the expected one,
in about 20 seconds. CryptoVerif's library `default.ocvl` must sit next to
its executable, as it does after `./build`. A single model runs with
`cryptoverif -lib /path/to/default -lib dualprf <model>.ocv` from this
directory.

## Assumptions

| Primitive | Assumption | In the models |
| --- | --- | --- |
| `Extract(salt, ikm)`, BLAKE3 keyed by the salt | a **dual PRF**: a PRF keyed by its salt, and a PRF keyed by its input keying material when the salt is known ([`dualprf.ocvl`](dualprf.ocvl)) | `Psalt`, `Pikm` |
| `ExpandLabel`, `DeriveSecret`, `MAC`: BLAKE3 keyed mode and its XOF | a PRF keyed by the secret | `Pexpand`, `Pmac` |
| X-Wing | IND-CCA2, with key pairs derived from a seed ([Barbosa et al., 2024](https://eprint.iacr.org/2024/039)) | `Pcca` |
| ChaCha20-Poly1305 | IND-CPA and INT-CTXT, nonces not repeated under a key | `Penc`, `Pencctxt` |
| The chain from window secret to confirmation tag (BLAKE3) | collision resistance of each step, with keys the adversary knows | `Pcr` |
| ML-DSA-65, the witnesses' signatures | EUF-CMA | `Psign` |

The specification (section 3.3) states that BLAKE3's keyed mode is a PRF
and that `Extract` must be a dual PRF. The PRF keyed by the salt suffices
for forward secrecy with stable keys and for the hedge against a weak
generator. Everything in which a fresh secret heals a known init secret
needs the other half: the sticky removal, the maintained city, the
external init (whose salt is `ZERO32`) and, in general, post-compromise
security. So does the catch-up bound to the leaf key, whose salt, the
shared secret of the init key, the adversary knows. HKDF analyses make the
same assumption of HMAC; [Backendal et al. (Crypto 2023)](https://eprint.iacr.org/2023/861)
characterise when it holds. No such analysis exists for BLAKE3's keyed
mode. `sticky_removal_single_prf.ocv` shows that CryptoVerif proves nothing
without it.

## Models

| Model | What it checks | Expected |
| --- | --- | --- |
| [`fs_stable_keys.ocv`](fs_stable_keys.ocv) | Member A erases epoch 1 when epoch 2 is active. The adversary knows every commit secret, as when tree keys that stay the same across windows leak, and A's whole state in epoch 3. | Proved: the message secret of epoch 2 stays secret. |
| [`fs_stable_keys_without_init.ocv`](fs_stable_keys_without_init.ocv) | The same, with an epoch derived from the commit secret alone. | Not proved. |
| [`sticky_removal.ocv`](sticky_removal.ocv) | M, removed by window 2, knows epoch 1 but not the window secret of window 2; the window secret of window 3 reaches it through a node it still knows. | Proved: epoch 3 stays secret. |
| [`sticky_removal_single_prf.ocv`](sticky_removal_single_prf.ocv) | The same, with `Extract` only a PRF keyed by its salt. | Not proved: the step of window 2 needs the dual PRF. |
| [`sticky_removal_collude.ocv`](sticky_removal_collude.ocv) | A second removed member, a member of epoch 2, gives the init secret of epoch 2. | Not proved. |
| [`entrant_window.ocv`](entrant_window.ocv) | An entrant seals window 2 alone: an external init encapsulated to the external key of epoch 1, and a commit secret that is a public constant. The adversary, who does not know epoch 1, has members decapsulate its own encapsulations. | Proved: epoch 2 stays secret. |
| [`entrant_window_removal_waiting.ocv`](entrant_window_removal_waiting.ocv) | A removal waits: the adversary knows epoch 1, hence the external key. | Not proved. |
| [`relay.ocv`](relay.ocv) | A relay item and a flat item carry the same window secret, under keys derived from the secret of the îlot's root with distinct labels: the relay's AEAD key and nonce, and the X-Wing key pair of the root. The adversary sees both, window after window, and the root's public key. | Proved: the window secret stays secret. |
| [`relay_known_root.ocv`](relay_known_root.ocv) | The adversary knows the root's secret. | Not proved. |
| [`city_maintained.ocv`](city_maintained.ocv) | The maintained city with wraps (X-Wing and ChaCha20-Poly1305) and keys derived from node secrets: window 2 removes M1 and re-keys node P along its îlot's path; window 3 removes M2 and wraps its window secret to P and Q. M1 and M2 work with the server. | Proved: epoch 3 stays secret. |
| [`city_stale.ocv`](city_stale.ocv) | Window 2 does not re-key P. | Not proved: M1 opens the window secret of window 3, and M2 knows the init secret of epoch 2. |
| [`city_sticky.ocv`](city_sticky.ocv) | The same stale city, with M1 alone. | Proved, through the init chain. |
| [`weak_rng.ocv`](weak_rng.ocv) | The committer's generator is broken; its fresh node secrets are hedged with its init secret (specification, section 7.1). | Proved: they stay secret from an outsider. |
| [`weak_rng_unhedged.ocv`](weak_rng_unhedged.ocv) | The same generator, without the hedge. | Not proved. |
| [`relay_tag.ocv`](relay_tag.ocv) | A relay knows the init secret of the previous epoch and the true window secret, and gives member B a secret of its choice. B derives the epoch from it and accepts it only if the confirmation tag matches the sealed one. | Proved: B accepts only the true window secret. |
| [`relay_tag_unbound.ocv`](relay_tag_unbound.ocv) | A tag computed without the window secret. | Not proved. |
| [`witness_quorum.ocv`](witness_quorum.ocv) | Checkpoints countersigned by 3 witnesses out of 4. The server chooses what each honest witness signs, once per epoch; witness 4 gives it its signing key. | Proved: two members that accept a checkpoint of the epoch accept the same one. |
| [`witness_quorum_two_dishonest.ocv`](witness_quorum_two_dishonest.ocv) | Witnesses 3 and 4 both give their keys. | Not proved; the fork exists: two checkpoints, each signed by one honest witness and the two dishonest ones. |
| [`witness_quorum_two_of_four.ocv`](witness_quorum_two_of_four.ocv) | A quorum of 2 out of 4, with one dishonest witness. | Not proved; the fork exists: two checkpoints, each signed by one honest witness and the dishonest one. |
| [`catch_up_leaf_bound.ocv`](catch_up_leaf_bound.ocv) | The adversary holds M's device key, not its state, and has catch-ups of M welcomed with init keys of its own. The welcome key is `Extract(ss_init, ss_leaf)`: the welcomer also encapsulates to M's current leaf key, with which M decapsulates the adversary's encapsulations. | Proved: the joiner secret of epoch 2 stays secret, through the half of the dual PRF keyed by `ss_leaf`. |
| [`catch_up_init_only.ocv`](catch_up_init_only.ocv) | The former rule of v0.4: a welcome key from the init key's shared secret alone. | Not proved; the attack exists (`formal-parity/catch_up_device_key.pv`). |

The three city models are the computational counterparts of
`ilot_city_maintained.pv`, `ilot_city_stale.pv` and `ilot_city_sticky.pv`,
and reach the same verdicts; `relay_tag.ocv` is that of the tag check of
`ilot_relay.pv`, and the two catch-up models those of
`catch_up_leaf_bound.pv` and `catch_up_device_key.pv`. The quorum of the
witness models is the one of the note on open problems: with `n = 3f + 1`
witnesses and `k = 2f + 1` signatures, `f` dishonest witnesses cannot fork
the group, and `f + 1` can.

## Abstractions and limits

* **Small configurations.** Each model fixes the number of windows, nodes
  and members. The tree of a real group, with adaptive corruptions, needs
  a hybrid argument over the whole tree, with random oracles at a million
  members; these models are its lemmas (plan in
  [`preuves-et-mesures-2026-09-26.md`](../preuves-et-mesures-2026-09-26.md),
  section 4).
* **Authentication in part.** Two properties are authentication ones:
  the relay's tag, which rests on collision resistance since the relay
  knows every key of the chain, and the witnesses' quorum. The signatures
  of seals, admissions and requests are left to the symbolic models; the
  relay model receives the sealed tag authentically, and the witness
  models do not model what the checkpoint says, only that two members
  accept the same one.
* **Controls.** "Not proved" means that CryptoVerif finds no proof, not
  that it finds an attack; each control removes the mechanism or the
  assumption a property rests on, and the symbolic model shows the attack
  where there is one.
* **Assumptions as stated.** The probabilities are symbolic; no concrete
  bound for BLAKE3's keyed mode as a dual PRF is known.
