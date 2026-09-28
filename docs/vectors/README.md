# Test vectors of `city-g/v0.5-draft`

These files record what the implementation computes for the hash and
derivation functions, the key schedule, the message plane, the Merkle
structures, the tree, the registry and one instance of each encoded object
of the profile, from inputs they list in full. Another implementation
reproduces every output byte for byte from them; this one regenerates them
and checks them at every test run.

```bash
cargo test -p cityg-core --test vectors                          # regenerate in memory, compare with the files, check them
cargo test -p cityg-core --test vectors write_vectors -- --ignored   # rewrite the files after an intended change
```

The generator is [`crates/cityg-core/tests/vectors/`](../../crates/cityg-core/tests/vectors/main.rs):
one module per file, each with a `generate` that samples the inputs and
computes the outputs, both by the implementation and by the definitions of
the specification written out again, and a `check` that reads the file as
a verifier would, from its inputs alone. A change to an encoding or a
derivation fails the test until the files are rewritten; the failure names
the first field that differs.

**What they are not.** They come from this implementation, and no second
implementation has checked them: they show what this one does, they do not
settle what the profile means where the specification and the code differ.
They cover derivations and encodings, not a window that applies: the
district commit and the city tasks are signed over synthetic nodes, and
entries, packets, seal links, audit records, island packets and the
authorizer's checkpoints, which need a followed window, are not covered.

## Conventions

* Every file is a JSON object naming its `profile`. Byte strings are
  lowercase hex; integers are JSON numbers; an absent optional field is
  `null`. Occupancies are `[leaf, since]` and node addresses
  `[level, index]`, as in the specification.
* Every input is listed, secrets included: seeds, node secrets, the
  randomness each operation draws. An operation run on the randomness a
  vector lists draws exactly it, in order, and nothing else: `rnd` is the
  32-byte hedge of an ML-DSA-65 signature (FIPS 204), `random` the 32
  bytes behind the coins of a hedged encapsulation
  ([draft, section 3.3](../specs-v0.5-draft.md#33-performers)),
  `reuse_guard` the 4 bytes of a message's nonce guard.
* ML-DSA-65 key pairs derive from a 32-byte `seed` (`ML-DSA.KeyGen_internal`),
  cards from a `card_seed` the same way; X-Wing keys from a 32-byte `seed`,
  their decapsulation key. Public keys are listed beside the seeds.
* An `encoded` field is the exact `CBOR_det` of the object, the bytes a
  party hashes, signs and relays; `preimage` fields give the bytes a hash
  is taken over.
* A *wrap record* (in `crypto-basics.json`, and for flat elements, repairs
  and the wraps of tasks in `objects.json`) lists `epoch`, `node`,
  `target`, `target_pk` (and `target_seed` when the target holds a leaf
  key), `secret`, `hedge`, `context` (v0.4 §7.2), `random`, `prk`
  (`Extract(hedge, random)`), `info` (`CBOR_det([context,
  kem_pk_hash(target_pk)])`), `coins`, `kem_ciphertext`, `shared_secret`,
  `key`, `nonce`, `sealed` and `encoded`
  (`[level, index, target_level, target_index, kem_ciphertext, sealed]`).
  A *hedged encapsulation* record is the same from `random` to
  `shared_secret`.

## Files

| File | Covers | Sections |
| --- | --- | --- |
| [`crypto-basics.json`](crypto-basics.json) | `H`, `H_L` with its preimage, `Extract`, `ExpandLabel` with its `info`, `DeriveSecret`, `MAC` with its framing; the identifiers (`gid`, `device_id`, `kem_pk_hash`, the leaf key hash, the card hash, the authorizer's key hash); ML-DSA-65 keys from a seed and signatures with a given `rnd`; X-Wing keys from a seed and derandomized encapsulation; hedged coins; a wrap; the task hedge, a fresh secret, a node key, a chain step, a commit secret. | v0.4 §3, §4, §7; draft §3.3, §4.1, §4.2, §5 |
| [`key-schedule.json`](key-schedule.json) | Three epochs: the group context, its encoding and hash; from the root secret to the joiner, epoch, init, message, confirmation and external secrets; the external key; the confirmed and interim transcript hashes and the confirmation tag; the third epoch sealed by an entrant, whose external init replaces the init chain; the secrets of the message plane and two exports. | v0.4 §9; draft §2.1, §3.1, §4.3 |
| [`secret-tree.json`](secret-tree.json) | The secret tree from the encryption secret down to three leaves, their first ratchet, and the key, nonce and next secret of three generations. | draft §4.4 |
| [`message-protection.json`](message-protection.json) | Three messages of one sender: one signed at once, one unsigned, one that signs the burst of both; for each, the chain, the signed burst and its signature, the content and its padding, the key, nonce and reuse guard, the ciphertext and its commitment, the sender data and its encryption, the message and its hash; the log of the three. | draft §4.5 to §4.8 |
| [`merkle.json`](merkle.json) | `MTH` roots and inclusion proofs under the three labels, for zero to eight leaves; four membership records, their encodings, hashes and proofs, and their log. | draft §4.8 to §4.10 |
| [`tree.json`](tree.json) | A tree of four leaves, two occupied: leaf nodes with their value, summary and hash, keyed parents and their content digests, the hashes of empty subtrees, every node hash, the tree hash and a proof of each leaf. | v0.4 §5; draft §4.1 |
| [`registry.json`](registry.json) | Sparse Merkle maps of zero, one and four entries, their roots and proofs of presence and of absence; two registry headers with the preimage and the value of `registry_hash`. | v0.4 §8; draft §4.2, §4.9 |
| [`objects.json`](objects.json) | One of each encoded object, with its signer's seed and `rnd`: an invite, an admission by an admin and one by an invite, join requests admitted, invited and open, three removal proposals, an eviction, three policies, an update, a catch-up, a re-entry, a repair request, a checkpoint, an authorization batch and its proofs, a joiner's welcome and a catch-up's, a relay element, a flat element, a repair, a district commit, two city tasks, a dispute and its statement; and two genesis seals, of a closed and an open group, with the secrets of epoch 0. | v0.4 §6, §10, §11; draft §2.3, §3.2, §3.7, §3.8, §4.9 |

### `crypto-basics.json`

`hash[]` (`input`, `output`); `labelled_hash[]` (`label`, `args`, the
`CBOR_det` of the argument array, `preimage`, `output`); `extract[]`
(`salt`, `ikm`, `output`); `expand_label[]` (`secret`, `label`, `context`,
`length`, `info`, `output`); `derive_secret[]` (`secret`, `label`,
`output`); `mac[]` (`key`, `data`, `framed`, `output`); `identifiers`
(seeds, keys and hashes, by name); `ml_dsa_65[]` (`seed`, `public_key`,
`context`, the FIPS 204 context string, `message`, `rnd`, `signature`);
`x_wing[]` (`seed`, `public_key`, `coins`, `ciphertext`, `shared_secret`);
`hedged_encapsulation[]` (`seed`, `public_key`, `context`, `hedge` and a
hedged encapsulation record); `wrap[]` (`gid` and a wrap record);
`task_hedge[]` (`leaf_seed`, `gid`, `epoch`, `context`, `output`);
`fresh_secret[]` (`hedge`, `random`, `prk`, `output`); `node_key[]`
(`secret`, `seed`, `public_key`); `chain[]` (`child_secret`, `output`);
`commit_secret[]` (`root_secret`, `output`).

### `key-schedule.json`

`gid`, then `epochs[]`, each with `epoch`, `sealed_by` (`member` or
`entrant`), `prev_init` and `prev_interim` (`ZERO32` at epoch 0),
`root_secret`, `commit_secret`, `seal_hash` (an input: the hash of the
seal header), `confirmed_transcript_hash`, `group_context` (its fields,
`encoded` and `hash`), `joiner_secret`, `epoch_secret`, `init_secret`,
`msg_secret`, `confirm_key`, `external_secret`, `external_kem_seed`,
`external_pk`, `confirmation_tag`, `interim_transcript_hash`, and
`message_plane` (`sender_data_secret`, `encryption_secret`,
`exporter_secret`, `epoch_authenticator`, `exports[]` with `label`,
`context`, `length`, `output`). The entrant's epoch adds `external_init`:
`external_pk` (the previous epoch's), `context` (`CBOR_det([gid, epoch])`),
`hedge`, a hedged encapsulation record whose ciphertext is `kem_output`,
and `external_init_secret`, which is that epoch's `prev_init`.

### `secret-tree.json`

`height`, `encryption_secret`, then `leaves[]`, each with `leaf`, `path[]`
(`level`, `index`, `secret`, from the root down), `ratchet_0` and
`generations[]` (`generation`, `context`, the `CBOR_det` of the generation,
`key`, `nonce`, `next_secret`).

### `message-protection.json`

`gid`, `epoch`, `height`, `leaf` (the sender's), `msg_secret`,
`sender_data_secret`, `encryption_secret`, `ratchet_0`, `card_seed`,
`card`, `aad`, then `messages[]`, each with `application_data`, `time_ms`,
`generation`, `first_generation`, `chain`, `signed_burst`, `rnd` and
`signature` (signed messages; `signature` is `null` otherwise), `padding`,
`content`, `key`, `nonce`, `reuse_guard`, `guarded_nonce`, `ciphertext`,
`commitment`, `sender_data`, `sender_data_key`, `sender_data_nonce`,
`encrypted_sender_data`, `message` and `hash`; and `message_log` (`count`,
`root`, `encoded`). A reader at another leaf opens the three and delivers
them after each signature.

### `merkle.json`

`trees[]`, each with `label` and `cases[]` (`count`, `leaves`, `root`,
`proofs`, one per leaf); `membership_log` with `records[]` (`kind`, `leaf`,
`device_id`, `card_seed`, `card`, `card_prefix`, `encoded`, `hash`,
`proof`), `count`, `root` and `encoded`.

### `tree.json`

`gid`, `divisions`, `height`, `empty_hashes` (by level), `leaves[]`
(`index`, the device's seed, key and id, `since`, the leaf key's seed and
value, the card's seed and value, `admission_hash`, `updated`, `value`,
`summary`, `hash`), `parents[]` (`node`, `secret`, `encryption_key`,
`taint`, `content_digest`), `node_hashes[]` (`node`, `hash`), `tree_hash`,
`district_hashes[]` and `leaf_proofs[]` (`index`, `leaf`, `steps[]` with
`content` and `sibling_hash`).

### `registry.json`

`sparse_merkle_maps[]`, each with `entries[]` (`key`, `value`), `root` and
`proofs[]` (`key`, `siblings`, `terminal`, the entry where the key's branch
ends or `null`, and `value`, the key's value or `null` when absent);
`registry_headers[]` (`admins[]` with `occupancy` and `public_key`,
`devices_root`, `admissions_root`, `keys_root`, `policy`,
`admission_mode`, `authorizer`, `preimage`, `hash`).

### `objects.json`

`gid`, `group_nonce` and `devices` (`creator`, `member`, `joiner_1` to
`joiner_3`, `authorizer`, each with `seed`, `public_key`, `device_id`);
`member` sits at `[2, 1]`, the creator at `[0, 0]`. Every signed object
names its `signer` (a device, or `invite` for the admission the invite key
signs) and lists `rnd` and `encoded`, with its fields:

* `invite`: `invite_seed`, `invite_pk`, `expires_at_ms`, `max_uses`,
  `inviter`, `id`;
* `admission_by_admin`, `admission_with_invite`: `device`, `device_id`,
  `not_after_epoch`, `admin` (the first), `hash`;
* `join_requests`: `admitted`, `invited` and `open[]` (three, for the
  batch), each with `leaf_seed`, `encryption_key`, `card_seed`, `card`,
  `init_seed`, `init_key`, `not_after_epoch`, `admission` (encoded, or
  `null`), `reference`, `token`;
* `remove_proposal_self`, `remove_proposal_admin`,
  `remove_proposal_authorizer`: `target`, `proposer` (`null` for the
  authorizer's), `urgency`;
* `group_policy_closed`, `group_policy_open`, `group_policy_authorized`:
  `admission_mode`, `max_idle_epochs`, `authorizer_pk`, `admin`, `hash`;
  `eviction`: `target`, `policy_hash` (the closed policy's), `encoded`;
* `update_request`: `member`, `current_key_seed`, `current_key`,
  `replaces`, the new leaf key and card; `catch_up_request`: `member`,
  `prev_interim`, `init_seed`, `init_key`, `reference`;
  `re_entry_request`: `member`, `current_key`, `replaces`, the new leaf
  key and card, `init_seed`, `init_key`, `reference`; `repair_request`:
  `epoch`, `seal_hash`, `member`, `level`;
* `checkpoint`: the fields of its content and `admin`;
* `authorization_batch`: `epoch`, `requests` (the hashes of the open
  joins, in order), `root`, `count`, `authorizations[]` (`index`, `path`);
* `welcome` (a joiner's, to its init key) and `welcome_catch_up` (to the
  member's leaf key too): `epoch`, `request`, `init_seed`, `init_key`,
  `leaf_seed`, `leaf_key`, `joiner_secret`, `hedge`, `context`,
  `init_encapsulation` and `leaf_encapsulation` (hedged encapsulation
  records; `random` is drawn for the init key first), `welcome_secret`,
  `key`, `nonce`, `sealed`, `encoded`;
* `relay_element`: `epoch`, `island_bits`, `island`, `interim`, `context`,
  `island_secret`, `root_secret`, `key`, `nonce`, `sealed`, `encoded`;
  `flat_element`: a wrap record with `height`, `divisions`, `island` and
  `island_secret`, whose key the target holds; `repair`: a wrap record with
  `height`, `divisions`, `leaf` and `repair`, the encoded object;
* `district_commit`: `epoch`, `district`, `height`, `prev_district_hash`,
  `committer`, `changes[]` (`kind`, `leaf`, `request`), `node_secrets` (of
  the keyed nodes, in order), `nodes[]` (`node`, `public_key`), `wraps[]`
  (wrap records), `district_hash`, `hash`; `city_tasks[]`: the same with
  `part` (a sub-city, or `null` for the top), `performer` and `part_hash`;
* `dispute`: `epoch`, `seal_hash`, `member`, `task` (the district commit's
  hash), `wrap_index`, `kind`, `proof`, `node_key` (the published key the
  statement names), `statement` (the encoded public inputs);
* `genesis_closed`, `genesis_open`: `open`, `group_nonce`, `gid`,
  `divisions`, `time_ms`, the randomness the creation draws in order
  (`policy_rnd` for an open group, `leaf_seed`, `card_seed`,
  `root_random`, `seal_rnd`), `policy`, `encryption_key`, `card`, `hedge`,
  `root_secret`, `root_pk`, `seal`, `seal_proof`, `seal_hash`,
  `body_hash`, `tree_hash`, `registry_header`, `membership_log`,
  `message_log`, `group_context`, and the secrets of epoch 0 from
  `confirmed_transcript_hash` and `commit_secret` to
  `interim_transcript_hash` and `epoch_authenticator`.
