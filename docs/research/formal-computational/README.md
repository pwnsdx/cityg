# Computational model of the key schedule and the îlots (research)

A [CryptoVerif](https://bblanche.gitlabpages.inria.fr/CryptoVerif/) model
of the properties that the research notes
[`ilots-2026-09-26.md`](../ilots-2026-09-26.md) and
[`au-dela-0.4-2026-09-26.md`](../au-dela-0.4-2026-09-26.md) (in French) rest
on, in the computational model: the key schedule of a window with tree keys
that stay the same across windows, the removed member that stays out once
it has missed one window, the window an entrant seals alone, the relays
inside an îlot, the city maintained above the îlots, and the hedge of fresh
node secrets. It is the first step of the first open problem of the note
[`problemes-ouverts-2026-09-26.md`](../problemes-ouverts-2026-09-26.md).
None of it is part of profile `city-g/v0.4`, whose own symbolic model is in
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

The specification (section 3.3) states only that BLAKE3's keyed mode is a
PRF. The PRF keyed by the salt suffices for forward secrecy with stable
keys and for the hedge against a weak generator. Everything in which a
fresh secret heals a known init secret needs the other half: the sticky
removal, the maintained city, the external init (whose salt is `ZERO32`)
and, in general, post-compromise security. HKDF analyses make the same
assumption of HMAC; [Backendal et al. (Crypto 2023)](https://eprint.iacr.org/2023/861)
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

The three city models are the computational counterparts of
`ilot_city_maintained.pv`, `ilot_city_stale.pv` and `ilot_city_sticky.pv`,
and reach the same verdicts.

## Abstractions and limits

* **Small configurations.** Each model fixes the number of windows, nodes
  and members; the tree of a real group, with adaptive corruptions, needs a
  generalized selective decryption argument (see the research note).
* **Secrecy only.** The models prove that secrets stay secret; the
  authentication of seals, admissions and checkpoints is left to the
  symbolic models. A relay that lies is caught by the tag it cannot match:
  the computational version of that argument, in which the relay knows the
  keys, needs the chain from window secret to tag to resist second
  preimages, and is not modelled.
* **Controls.** "Not proved" means that CryptoVerif finds no proof, not
  that it finds an attack; each control removes the mechanism or the
  assumption a property rests on, and the symbolic model shows the attack
  where there is one.
* **Assumptions as stated.** The probabilities are symbolic; no concrete
  bound for BLAKE3's keyed mode as a dual PRF is known.
