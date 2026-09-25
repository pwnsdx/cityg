# City-G protocol specification — profile v0.2

| | |
| --- | --- |
| Profile | `city-g/v0.2` |
| Status | Archived: replaced by profile v0.3 ([specification](../../specs.md), [design note](../../design-v0.3.md)). It superseded profile v0.1.4 ([archived](../v0.1.4/specs.md)); the profiles do not interoperate. Its vectors, verifier and manifest are in [`kat/legacy/v0.2/`](../../../kat/legacy/v0.2/kat-v0.2-conformance-manifest.json), its symbolic model in [`formal/`](formal/). |
| Reference implementation | [`crates/cityg-core`](../../../crates/cityg-core) (protocol core, no I/O), [`crates/cityg-server`](../../../crates/cityg-server) and [`crates/cityg-runtime`](../../../crates/cityg-runtime) (delivery service), [`crates/cityg-api-client`](../../../crates/cityg-api-client) (member driver) |
| Conformance | [`kat/v0.2/vectors.json`](../../../kat/legacy/v0.2/vectors.json), checked by the reference implementation and by the independent verifier [`kat/v0.2/verify_vectors.py`](../../../kat/legacy/v0.2/verify_vectors.py); requirement map [`kat/kat-v0.2-conformance-manifest.json`](../../../kat/legacy/v0.2/kat-v0.2-conformance-manifest.json) |
| Formal model | [`docs/formal/`](formal/) |
| Origin | Audit [`audits/audit-crypto-conformite-2026-09-25.md`](../../audits/audit-crypto-conformite-2026-09-25.md), proposals P-1 to P-8 |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be
interpreted as in RFC 2119 and RFC 8174 when they appear in capitals.

City-G is an end-to-end encrypted group messaging protocol with
post-quantum primitives. Its group key agreement follows the structure of
MLS (RFC 9420): an epoch-chained key schedule, a TreeKEM-style ratchet tree
(the *barrier tree*), commits that move a group from one epoch to the next,
external commits for joins, and a per-sender message ratchet. A delivery
service orders commits and relays encrypted messages without holding any
group secret.

## Contents

1. [Architecture](#1-architecture)
2. [Security goals and threat model](#2-security-goals)
3. [Cryptographic suite](#3-cryptographic-suite)
4. [Encodings and derivation functions](#4-encodings)
5. [Identifiers](#5-identifiers)
6. [Barrier tree](#6-barrier-tree)
7. [Roster](#7-roster)
8. [Key schedule](#8-key-schedule)
9. [Commits](#9-commits)
10. [Removal proposals, admission, GroupInfo, cover-failure reports](#10-signed-objects)
11. [Message plane v3](#11-message-plane)
12. [Delivery service](#12-delivery-service)
13. [Member behavior](#13-member-behavior)
14. [Deployment binding and HTTP API](#14-deployment-binding)
15. [Parameters](#15-parameters)
16. [Label registry](#16-label-registry)
17. [Conformance](#17-conformance)
18. [Changes from profile v0.1.4](#18-changes)

<a id="1-architecture"></a>
## 1. Architecture

* **Device.** Each member device holds an ML-DSA-87 signing key pair (its
  *device key*) per group membership. A device is a member of a group in
  one *slot* of the barrier tree.
* **Group.** A group is identified by `gid` (section 5). Its state at epoch
  `n` consists of a public part (barrier tree, roster, transcript hashes)
  that every member and the delivery service share, and a secret part
  (private tree keys, epoch secrets, message ratchets) that only members
  hold.
* **Commit.** A commit moves a group from epoch `n - 1` to epoch `n`. It is
  authored by a single device, signed by it, re-keys the author's leaf and
  direct path, and may remove members, change the admin set, add a joiner
  (external join) or renew the author's own slot (resync).
* **Delivery service (DS).** The DS stores, for each group, an ordered log
  of commits, message envelopes and removal proposals. It runs the public
  part of every commit transition, so it relays only commits that members
  accept, and it enforces the rules that need a global order or a clock
  (section 12). It never holds a group secret.
* **Deployment binding.** Display names (aliases) and the authentication of
  requests to the DS are signed objects outside the group protocol
  (section 14). They change no group state and no key.

The protocol core is specified without I/O: every random input comes from a
caller-provided cryptographically secure generator, which makes runs and
test vectors reproducible.

<a id="2-security-goals"></a>
## 2. Security goals and threat model

### 2.1 Adversaries

| ID | Adversary | Capabilities |
| --- | --- | --- |
| A1 | Passive DS | Reads everything the DS stores and relays. |
| A2 | Active DS | A1, and drops, delays, reorders or replays traffic, answers requests arbitrarily, and creates its own device keys. |
| A3 | Malicious member | Holds the secrets of its own membership; deviates arbitrarily from the protocol. |
| A4 | Removed or departed member | A3 for the epochs it belonged to; after its removal it has no further secret. |
| A5 | Temporarily compromised device state | Learns the group state of one device (tree private keys, epoch secrets, message chains) at one point in time, then loses access. The device key stays secret, for instance in a hardware keystore. |
| A6 | Compromised device key | Learns the ML-DSA-87 device key of one member device. |

The network is controlled by A2. Admins are trusted to admit members: an
admin that admits the adversary gives it membership.

### 2.2 Properties

"Guaranteed" means: under the assumptions of section 2.3, the property holds
against that adversary. A deployment MUST NOT advertise a property that this
table does not list as guaranteed for the stated adversary.

| Property | A1 | A2 | A3 | A4 | A5 | A6 |
| --- | --- | --- | --- | --- | --- | --- |
| Confidentiality of message content | guaranteed | guaranteed | no (insider) | guaranteed for epochs after its removal | guaranteed outside the FS and PCS windows | no, until the device is removed |
| Sender authentication | guaranteed | guaranteed | guaranteed (cannot impersonate another member) | guaranteed | guaranteed | guaranteed for the other members |
| Membership agreement | guaranteed | guaranteed | guaranteed | guaranteed | guaranteed | guaranteed |
| Admission control (no member added without an admin's signature) | guaranteed | guaranteed | n/a | guaranteed | guaranteed | guaranteed unless the device is an admin |
| Post-removal secrecy (PRS) | guaranteed | guaranteed | n/a | guaranteed, including when it authored a commit before its removal | n/a | guaranteed once the device, and any device it admitted, is removed |
| Forward secrecy (FS) | guaranteed | guaranteed | n/a | n/a | window `FS_WINDOW` | guaranteed |
| Post-compromise security (PCS) | n/a | n/a | n/a | n/a | after the next self-update of the compromised device | no, until the device is removed |
| Liveness, availability | no | no | no | no | no | no |
| Metadata privacy (who talks when, group size, roster) | no | no | no | no | no | no |

Definitions (normative):

* **Membership agreement.** Two members that accept the commit of epoch `n`
  agree on the tree, the roster (members, admins, slot generations) and the
  transcript of epochs `0..n`: these are bound into `GroupContext_n`
  (section 8), from which every secret of the epoch derives, and verified by
  the confirmation tag.
* **PRS.** A member whose occupancy is ended by the commit of epoch `n` MUST
  NOT be able to derive any secret of an epoch `>= n`, unless an admin admits
  it again as a new device. A member never authors the commit that removes it
  (section 9.4), the removed leaf and its direct path are blanked in the tree
  the removing commit starts from, and the removed device is retired: no
  admission it held can bring it back (section 7).
* **FS.** Compromise of a device at time `T` MUST NOT reveal message content
  of epochs whose keys the device erased before `T`. Members erase epoch
  secrets when the next epoch becomes active, erase each message key once
  used, keep previous-epoch message keys for at most `GRACE_WINDOW_MS`, and
  re-key their own leaf at least every `FS_WINDOW` (section 13.4), so the
  content of epochs older than `FS_WINDOW` stays confidential.
* **PCS.** After a device whose state was compromised completes a
  self-update (a commit re-keying its leaf from a fresh leaf secret), the
  attacker MUST NOT derive secrets of later epochs, unless it compromises a
  member again.
* **Device keys.** A device key is a long-term credential that the profile
  never rotates. Whoever holds it can sign as the device: commits (including
  a Resync that re-enters the device's slot with keys of its choice, from
  which it derives the next epoch's secrets), messages, proposals, and
  admissions if the device is an admin, which lets the adversary admit
  devices of its own. The only repair is to remove the device, which retires
  its key (section 7), together with any device it admitted, and to admit a
  new one. The
  device itself notices a commit authored in its name that it did not
  produce: it cannot process it and resyncs.

### 2.3 Assumptions and limits

* ML-KEM-768 is IND-CCA2, ML-DSA-87 is EUF-CMA (and strongly unforgeable),
  BLAKE3 in keyed mode is a PRF, ChaCha20-Poly1305 is an AEAD. Random
  numbers come from a CSPRNG.
* The DS can always deny service: drop commits, messages or whole groups,
  and refuse joins. Members detect some of it (gaps in the log, a commit
  they cannot process, section 10.4) but cannot prevent it.
* The DS sees the roster (device keys, slots, admins), who sends when, the
  size of messages and the aliases members publish. Aliases are
  self-asserted (section 14.1).
* A member can send a message that other members cannot decrypt (a forged
  ciphertext on its own chain) and can author a commit whose path secret some
  members cannot decrypt; the latter is detected and reported (section 10.4)
  and the affected members resync.
* `signed_timestamp_ms` of a message is the sender's clock, authenticated by
  its signature, not a trusted time.
* Profile v0.2 does not protect message content against a member of the same
  epoch: group encryption is not end-to-end between subsets of a group.

<a id="3-cryptographic-suite"></a>
## 3. Cryptographic suite

| Function | Primitive | Use |
| --- | --- | --- |
| KEM | ML-KEM-768 (FIPS 203) | tree node keys, external init |
| Signature | ML-DSA-87 (FIPS 204), hedged, with context strings | commits and every signed object |
| Hash `H` | BLAKE3, 256-bit output | labelled hashes, digests |
| PRF / KDF | BLAKE3 keyed mode and its XOF | Extract, ExpandLabel, MAC |
| AEAD | ChaCha20-Poly1305 (RFC 8439) | path secret wrapping, messages |

* **ML-KEM-768.** A private key is held as its 64-byte FIPS 203 seed
  `(d, z)`; the decapsulation key is `ML-KEM.KeyGen_internal(d, z)`.
  Encapsulation draws its 32-byte message `m` from the caller's generator
  (`ML-KEM.Encaps_internal`). Encapsulation keys are 1184 bytes, ciphertexts
  1088 bytes, shared secrets 32 bytes. An encapsulation key MUST pass the
  FIPS 203 input check (modulus check) before use.
* **ML-DSA-87.** Key pairs derive from a 32-byte seed `xi`
  (`ML-DSA.KeyGen_internal`). Signing is hedged: the 32-byte `rnd` input is
  drawn from the caller's generator. Public keys are 2592 bytes, secret keys
  4896 bytes, signatures 4627 bytes. Every signature uses a FIPS 204 context
  string (`ctx`) naming its usage (section 16.3); a signature produced under
  one context MUST NOT verify under another.
* **Randomness.** Every random value of the protocol (seeds, nonces, leaf
  secrets, KEM messages, signing randomness, invite seeds) MUST come from a
  CSPRNG.

<a id="4-encodings"></a>
## 4. Encodings and derivation functions

### 4.1 Deterministic CBOR

`CBOR_det(x)` is the core deterministic encoding of RFC 8949, section 4.2.1:

* integers and lengths use the shortest head;
* only definite lengths;
* map keys are sorted by the bytewise lexicographic order of their
  encodings, and no key appears twice;
* no floating-point values and no tags; the simple values `false`, `true`,
  `null` are allowed.

A decoder MUST re-encode every decoded object and reject it unless the
result is byte-identical to its input. Every object of this profile is
exchanged as the exact bytes of its deterministic encoding; an
implementation MUST NOT re-encode an object it relays or hashes.

`h''` denotes the empty byte string. Integers are unsigned unless stated.

<a id="4-2-labelled-hash"></a>
### 4.2 Labelled hash

```text
H(x)           := BLAKE3-256(x)
H_L(label, args) := H(CBOR_det(["city-g/v0.2", label, args]))
```

`label` is a text string, `args` a CBOR array. Every labelled hash of the
profile uses this array encoding; a map MUST NOT appear as the argument
list. The labels are listed in section 16.1.

<a id="4-3-kdf"></a>
### 4.3 Key derivation

```text
Extract(salt, ikm)               := BLAKE3-keyed(key = salt, ikm)          (32 bytes)
ExpandLabel(secret, label, ctx, L) := BLAKE3-keyed-XOF(key = secret,
                                        CBOR_det(["city-g/v0.2 expand", label, ctx, L]))[0..L]
DeriveSecret(secret, label)      := ExpandLabel(secret, label, h'', 32)
MAC(key, data)                   := BLAKE3-keyed(key = key, CBOR_det(["city-g/v0.2 mac", data]))
```

`salt`, `secret` and `key` are 32 bytes; `ctx` is a byte string; `L` is an
unsigned integer. Extract and ExpandLabel follow the HKDF structure with
keyed BLAKE3 in place of HMAC. MAC tags are compared in constant time.

<a id="4-4-signed-arrays"></a>
### 4.4 Signed arrays

Every signed object except the commit (section 9) is a signed array:

```text
TBS    := CBOR_det([field_1, ..., field_k])
Signed := CBOR_det([field_1, ..., field_k, signature])
signature := ML-DSA-87.Sign(sk, TBS, ctx)
```

`field_1` is the text label naming the object and its version (section
16.2). A verifier checks the label and the number of fields before
verifying the signature over `TBS`, which it rebuilds from the received
fields.

<a id="5-identifiers"></a>
## 5. Identifiers

```text
gid        := H_L("group-id", [creator_device_pk, group_nonce])     group_nonce: 32 random bytes
leaf_id    := H_L("leaf-id",  [gid, device_pk])
invite_id  := H_L("invite-id", [invite_pk])
epoch_ref  := H_L("msg/epoch-ref", [gid, epoch])
H_pk(pk)   := H_L("kem-pk", [pk])                                   pk: ML-KEM-768 encapsulation key
```

Binding the creator's device key into `gid` makes the creator the verifiable
first admin of the group: the genesis commit is valid only if its author key
and nonce hash to the group identifier.

<a id="6-barrier-tree"></a>
## 6. Barrier tree

### 6.1 Shape

The tree has `n_max` leaf slots, a power of two with `2 <= n_max <=
MAX_N_MAX` (1024), stored in heap order: node 0 is the root, node `i` has
children `2i + 1` and `2i + 2`, and slot `s` is leaf node `n_max - 1 + s`.
`n_max` is fixed at genesis.

* A leaf is empty or holds `[leaf_id, generation, public_key]`, where
  `public_key` is the member's ML-KEM-768 *leaf key*.
* A parent node is blank or holds an ML-KEM-768 public key.
* The *direct path* of a slot is the list of parent nodes from the parent of
  its leaf up to the root; its *copath* is, for each node of the direct
  path, the child that is not on the path.
* The *resolution* of a node is the smallest set of non-blank nodes covering
  the leaves below it: the node itself if it is not blank, else the union of
  the resolutions of its children (none for an empty leaf). Resolutions are
  listed in increasing node order.

<a id="6-2-tree-hash"></a>
### 6.2 Tree hash

```text
leaf_hash(slot)   := H_L("tree/leaf",   [n_max, slot, occupant])
    occupant := [leaf_id, generation, public_key] for an occupied slot, [] for an empty one
parent_hash(node) := H_L("tree/parent", [node, public_key or h'', hash(2 node + 1), hash(2 node + 2)])
tree_hash         := hash(0)
```

<a id="6-3-update-path"></a>
### 6.3 Update path

A commit re-keys its author's leaf and direct path:

```text
leaf_secret            : 32 fresh random bytes
leaf key               := ML-KEM.KeyGen_internal(ExpandLabel(leaf_secret, "tree leaf key", h'', 64))
path_secret[0]         := DeriveSecret(leaf_secret, "tree path")
path_secret[i + 1]     := DeriveSecret(path_secret[i], "tree path")
node key of path[i]    := ML-KEM.KeyGen_internal(ExpandLabel(path_secret[i], "tree node key", h'', 64))
root path secret       := path_secret[d - 1]                  d = log2(n_max)
```

For each node `path[i]` of the direct path, the author encrypts
`path_secret[i]` to every node of the resolution of `copath[i]`, in the tree
the commit starts from (after the removals and the join of that commit,
section 9.4):

```text
(kem_ciphertext, shared) := ML-KEM.Encaps(pk_target)
wrap_context := CBOR_det([gid, epoch, author_slot, node, target, H_pk(pk_target)])
wrap_key     := ExpandLabel(shared, "tree path wrap key",   wrap_context, 32)
wrap_nonce   := ExpandLabel(shared, "tree path wrap nonce", wrap_context, 12)
wrapped_secret := ChaCha20-Poly1305(wrap_key, wrap_nonce, aad = wrap_context, pt = path_secret[i])
```

`epoch` is the epoch the commit creates. The update path is encoded as

```text
UpdatePath := [leaf_public_key, [PathNode, ...]]
PathNode   := [node, public_key, [[target, kem_ciphertext, wrapped_secret], ...]]
```

with one `PathNode` per direct-path node in order, and one target per
resolution node in increasing node order. `wrapped_secret` is 48 bytes.

**Validation** (needs no secret; run by the DS and by every member): the
author slot is occupied in the starting tree; every public key is a valid
ML-KEM-768 key; the path has one entry per direct-path node with the right
node index; the targets of entry `i` are exactly the resolution of
`copath[i]`, in order; ciphertexts are 1088 bytes and wrapped secrets 48
bytes.

**Decryption** by a member in slot `s != author_slot`: find the lowest level
`i` whose copath node is an ancestor of (or equal to) the member's leaf;
decapsulate the target the member holds a private key for; open the wrapped
secret; derive the path secrets above; and check that every derived node
public key equals the published one. Any failure is a cover failure
(section 10.4).

**Application.** The new tree is the starting tree with the author's leaf
key replaced by `leaf_public_key` and each direct-path node set to its new
public key. Members keep the private keys of the nodes they learnt and drop
keys of nodes that become blank.

<a id="6-4-update-bound"></a>
### 6.4 Bound on update size

```text
max_update_path_bytes(n) := 64 + (1184 + 8)(d + 1) + 16 d + (1088 + 48 + 16)(n - 1),   d = log2(n)
```

Every copath resolution holds at most `n - 1` targets in total, so an
update of a 1024-slot tree stays near 1.2 MB. Groups larger than `MAX_N_MAX`
need sub-groups or federation, outside this profile.

<a id="7-roster"></a>
## 7. Roster

```text
MemberRecord := [leaf_id, device_pk, slot, generation, admission_hash]
roster_hash  := H_L("roster", [[MemberRecord, ... sorted by slot],
                               [admin device_pk, ... sorted bytewise],
                               [[slot, last_generation], ... sorted by slot],
                               [retired leaf_id, ... oldest first]])
```

* `generation` counts the occupancies of a slot: the next occupant of slot
  `s` carries `last_generation[s] + 1`. A slot keeps its counter after its
  occupant leaves, so an `(slot, generation)` pair names one occupancy.
* `admission_hash := H(SignedAdmission)` for a joiner, `ZERO32` for the
  creator (section 10.2).
* The genesis roster holds the creator in slot 0 with generation 1, as sole
  admin.
* At most `MAX_ADMINS` (64) admins. The last admin cannot be revoked. A
  removed member loses its admin rights. If members remain but no admin
  does, the member in the lowest occupied slot becomes admin.
* **Retired devices.** When an occupancy ends by a removal (a leave or an
  admin's removal), its `leaf_id` is appended to `retired`, which keeps the
  last `MAX_RETIRED` (4096) entries, dropping the oldest first. A device
  whose `leaf_id` is retired MUST NOT join again. A device key thus names one
  membership, and an admission, which names a device, is good for one
  occupancy: a removed member cannot come back with an admission it kept.
  Clients use a fresh device key for every join.

<a id="8-key-schedule"></a>
## 8. Key schedule

```text
GroupContext_n := CBOR_det(["city-g/group-context/v2", gid, n, tree_hash_n,
                            roster_hash_n, "city-g/v0.2", confirmed_transcript_hash_n])

commit_secret_n := DeriveSecret(root path secret of commit n, "commit")
epoch_secret_n  := ExpandLabel(Extract(init_secret_{n-1}, commit_secret_n),
                               "epoch", H(GroupContext_n), 32)
init_secret_n     := DeriveSecret(epoch_secret_n, "init")
msg_secret_n      := DeriveSecret(epoch_secret_n, "msg")
confirm_key_n     := DeriveSecret(epoch_secret_n, "confirm")
external_secret_n := DeriveSecret(epoch_secret_n, "external")

confirmed_transcript_hash_n := H_L("confirmed-transcript",
                                   [interim_transcript_hash_{n-1}, anchor_tbs_n, signature_n])
confirmation_tag_n          := MAC(confirm_key_n, confirmed_transcript_hash_n)
interim_transcript_hash_n   := H_L("interim-transcript",
                                   [confirmed_transcript_hash_n, confirmation_tag_n])
```

* `init_secret_{-1}` and `interim_transcript_hash_{-1}` are `ZERO32`.
* The GroupContext binds the tree, the roster and the whole transcript into
  every epoch secret: members with diverging views derive different keys and
  fail the confirmation tag.
* **Erasure.** When epoch `n` becomes active, a member erases
  `epoch_secret_{n-1}`, `init_secret_{n-1}`, `external_secret_{n-1}`,
  `epoch_secret_n`, `confirm_key_n` and `msg_secret_n` (after deriving the
  message chains, section 11.2). It keeps `init_secret_n` and
  `external_secret_n` until epoch `n + 1` becomes active.

<a id="8-1-external-init"></a>
### 8.1 External init

From `external_secret_n` every member of epoch `n` derives the ML-KEM-768
*external key pair* of the epoch:

```text
external_n := ML-KEM.KeyGen_internal(ExpandLabel(external_secret_n, "external kem", h'', 64))
```

Its public key is published in the signed GroupInfo of epoch `n` (section
10.3). The author of an external commit (join or resync) encapsulates to it
and uses the *external init secret* in place of `init_secret_n` for epoch
`n + 1`:

```text
(kem_output, shared) := ML-KEM.Encaps(external_pk_n)
external_init_secret := ExpandLabel(Extract(ZERO32, shared), "external init", H(kem_output), 32)
```

Members recover `shared` by decapsulation. No member needs to be online for
a join.

<a id="9-commits"></a>
## 9. Commits

<a id="9-1-registry"></a>
### 9.1 Registry

A commit is a CBOR map with a closed key registry. An unknown key, a key
absent where it is required or present where it is forbidden makes the
commit malformed.

| Key | Name | Type | Genesis | Member | ExternalJoin | Resync |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | profile | tstr `"city-g/v0.2"` | R | R | R | R |
| 2 | gid | bstr .size 32 | R | R | R | R |
| 3 | epoch | uint (the epoch `n` it creates) | R (0) | R | R | R |
| 4 | kind | uint: 0 Genesis, 1 Member, 2 ExternalJoin, 3 Resync | R | R | R | R |
| 5 | prev_interim_transcript_hash | bstr .size 32 | R (ZERO32) | R | R | R |
| 6 | author_leaf_id | bstr .size 32 | R | R | R | R |
| 7 | roster_hash (epoch `n`) | bstr .size 32 | R | R | R | R |
| 8 | tree_hash (epoch `n`) | bstr .size 32 | R | R | R | R |
| 9 | update_path | UpdatePath (section 6.3) | R | R | R | R |
| 10 | removals | array of bstr (SignedRemoveProposal), by increasing target slot | - | R | R | R |
| 11 | admin_changes | array of `[op, device_pk]`, op 0 grant, 1 revoke | - | R | - | - |
| 12 | join | `[slot, generation, SignedAdmission bstr or null]` | - | - | R (admission) | R (null) |
| 13 | external_init | bstr (ML-KEM-768 ciphertext) | - | - | R | R |
| 14 | group_nonce | bstr .size 32 | R | - | - | - |
| 15 | n_max | uint | R | - | - | - |
| 108 | author_device_pk | bstr (ML-DSA-87 public key) | R | R | R | R |
| 109 | signature | bstr | R | R | R | R |
| 110 | confirmation_tag | bstr .size 32 | R | R | R | R |

`admin_changes` holds at most `MAX_ADMINS` entries with distinct device
keys. The encoded commit is at most `max_commit_bytes(n_max) :=
max_update_path_bytes(n_max) + 12 KiB n_max + 64 KiB`.

<a id="9-2-signature"></a>
### 9.2 Signature and confirmation tag

```text
anchor_tbs := CBOR_det(commit map without keys 109 and 110)
signature  := ML-DSA-87.Sign(author_sk, anchor_tbs, ctx = "city-g/anchor/v2")
confirmation_tag := MAC(confirm_key_n, confirmed_transcript_hash_n)
```

Every commit carries exactly one signature, by its author. The confirmation
tag cannot be signed: it authenticates the confirmed transcript hash, which
covers the signature. `author_leaf_id` MUST equal `H_L("leaf-id", [gid,
author_device_pk])`.

<a id="9-3-kinds"></a>
### 9.3 Kinds

* **Genesis** (epoch 0): the first commit of a group, by its creator. It
  carries `group_nonce` and `n_max`; `gid` MUST equal `H_L("group-id",
  [author_device_pk, group_nonce])`. The starting tree holds the creator's
  leaf in slot 0 (generation 1, key `leaf_public_key`); the key schedule
  starts from `init_secret_{-1} = ZERO32`.
* **Member**: by a current member. May remove members and change admins.
* **ExternalJoin**: by a joiner holding a valid admission (section 10.2). It
  uses the external init of the previous epoch.
* **Resync**: by a current member that lost its state or could not process
  a commit. It re-enters its own slot under the next generation, keeping its
  identity, admission and admin rights, and uses the external init.

<a id="9-4-transition"></a>
### 9.4 Transition rules

A commit for epoch `n` applies to the public state of epoch `n - 1` in this
order:

1. **Removals.** Each removal proposal is authorized against roster
   `n - 1` (section 10.1). A removal MUST NOT target the author. Each removal
   ends its target's occupancy and blanks its leaf; every parent node whose
   subtree contained it is blanked as well (the removed leaf's direct path).
2. **Admin changes** (Member commits only): the author MUST be an admin of
   roster `n - 1`; grants and revokes apply in order.
3. **Entry.** ExternalJoin: the joiner enters the *lowest free slot* after
   step 1, with generation `last_generation + 1`; its admission MUST be
   authorized by the admins remaining after step 1, and its `leaf_id` MUST
   NOT be retired (including by the removals of step 1). Resync: the
   author's own slot gets the next generation and the new leaf key.
4. **Promotion.** If members remain but no admin does, the lowest-slot
   member becomes admin.
5. **Update path.** The author's update path is validated against the tree
   of steps 1 to 3, then applied.

The resulting tree hash and roster hash MUST equal keys 8 and 7. The author
of a Member or Resync commit MUST be a member of roster `n - 1` whose record
matches `author_device_pk`; the author of an ExternalJoin MUST NOT be a
member.

<a id="9-5-verification"></a>
### 9.5 Verification

A verifier (the DS or a member) checks, for a commit on state `n - 1`:
its encoding and registry (section 9.1), the signature (section 9.2), `gid`,
`epoch = n`, `prev_interim_transcript_hash = interim_transcript_hash_{n-1}`,
the author leaf id, and the transition (section 9.4). A member then runs the
secret part: it decrypts the path (section 6.3; for its own commit it uses
the path secrets it generated), derives the epoch secrets (section 8,
from `init_secret_{n-1}` or the external init secret), and checks the
confirmation tag in constant time. A member MUST NOT use any secret of epoch
`n` before the confirmation tag verified.

<a id="10-signed-objects"></a>
## 10. Removal proposals, admission, GroupInfo, cover-failure reports

<a id="10-1-removal"></a>
### 10.1 Removal proposals

```text
RemoveProposal := ["city-g/remove/v2", gid, target_leaf_id, target_slot,
                   target_generation, proposer_device_pk]
signed with ctx "city-g/remove/v1" by proposer_device_pk
```

A proposal is authorized against a roster when the target occupancy
`(target_slot, target_generation, target_leaf_id)` is in the roster and the
proposer is the target itself (a voluntary leave) or an admin. A member
never commits its own removal: removals are committed by another member, or
by the next joiner once every member has a recorded removal. A proposal is
single-use: once the occupancy ends it no longer matches the roster.

<a id="10-2-admission"></a>
### 10.2 Invites and admissions

```text
Invite    := ["city-g/invite/v1", gid, invite_pk, expires_at_ms, inviter_device_pk]
             signed with ctx "city-g/invite/v1" by inviter_device_pk (an admin)
Admission := ["city-g/admission/v1", gid, joiner_leaf_id, authorizer_kind,
              authorizer_pk, invite]
             signed with ctx "city-g/admission/v1" by authorizer_pk
    authorizer_kind 0: authorizer_pk is an admin device key, invite = null
    authorizer_kind 1: authorizer_pk = invite_pk of the embedded SignedInvite (bstr)
admission_hash := H(SignedAdmission)
```

An admin either signs an admission for a known joiner device, or signs an
invite whose key pair derives from a 32-byte *invite seed* shared out of
band (`invite key := ML-DSA.KeyGen_internal(invite_seed)`); the joiner then
signs its own admission with the invite key. An admission is authorized
against a roster when its `gid` and `joiner_leaf_id` match the join, the
admission signature verifies, and the signer is an admin of that roster
(kind 0) or the embedded invite verifies and its inviter is an admin of that
roster (kind 1). The roster commits to each member's `admission_hash`, so a
DS cannot add a member on its own. Invite expiry needs a clock and is
enforced by the DS (section 12).

<a id="10-3-group-info"></a>
### 10.3 GroupInfo

```text
GroupInfo := ["city-g/group-info/v2", GroupContext_n (bstr), confirmation_tag_n,
              external_pk_n, signer_leaf_id]
             signed with ctx "city-g/group-info/v2" by the device key of signer_leaf_id
```

The author of epoch `n` signs the GroupInfo of that epoch and publishes it
with its commit. A joiner or resyncing member verifies it against the tree
and roster the DS provides: their hashes MUST match those in
`GroupContext_n`, the signer MUST be a member of that roster, and the
interim transcript hash it derives (`H_L("interim-transcript",
[confirmed_transcript_hash_n, confirmation_tag_n])`) becomes the
`prev_interim_transcript_hash` of its external commit.

<a id="10-4-cover-failure"></a>
### 10.4 Cover-failure reports

```text
CoverFailureReport := ["city-g/cover-failure/v1", gid, epoch, reporter_leaf_id, reason]
                      signed with ctx "city-g/cover-failure/v1" by the reporter
reason: 1 not covered, 2 path key mismatch, 3 confirmation tag mismatch, 4 state lost
```

A member that cannot process the commit of epoch `epoch` signs a report
naming it; the DS records reports of current members next to the commit, so
the failure and the author of the faulty commit are visible to every member.
The reporter then re-enters the group with a Resync commit: with a chained
key schedule, a member that missed an epoch can only come back through the
external init.

<a id="11-message-plane"></a>
## 11. Message plane v3

<a id="11-1-framing"></a>
### 11.1 Framing and envelope

```text
FramedContent  := ["city-g/msg/v3", gid, epoch, sender_leaf_id, generation, content_type,
                   authenticated_data, signed_timestamp_ms, plaintext]
signature      := ML-DSA-87.Sign(sender_sk, CBOR_det(FramedContent), ctx = "city-g/msg/v3")
EnvelopeHeader := ["city-g-msg-v3", epoch_ref, sender_leaf_id, generation, key_commitment]
Envelope       := [EnvelopeHeader fields..., ciphertext]
ciphertext     := ChaCha20-Poly1305(key_g, nonce_g, aad = CBOR_det(EnvelopeHeader),
                                    pt = CBOR_det([CBOR_det(FramedContent), signature]))
```

`content_type` 1 is UTF-8 text. Plaintexts are at most 256 KiB and
authenticated data at most 4 KiB.

<a id="11-2-ratchet"></a>
### 11.2 Per-sender ratchet

When an epoch becomes active, every member derives one chain per roster
member and erases `msg_secret_n`:

```text
sender_secret_0     := ExpandLabel(msg_secret_n, "msg sender", sender_leaf_id, 32)
sender_secret_{g+1} := DeriveSecret(sender_secret_g, "msg next")
key_g               := ExpandLabel(sender_secret_g, "msg key", h'', 32)
nonce_g             := ExpandLabel(sender_secret_g, "msg nonce", h'', 12)
key_commitment_g    := H_L("msg/key-commitment", [key_g, nonce_g])
```

A device sends only on its own chain, with a strictly increasing
`generation`, so no two messages share a key and nonce. A secret is erased
as soon as its chain moves past it.

<a id="11-3-receiving"></a>
### 11.3 Receiving

A receiver:

1. selects the epoch by `epoch_ref`: the current epoch, or the previous one
   while its keys are kept (at most `GRACE_WINDOW_MS` after the current
   epoch became active);
2. requires `sender_leaf_id` to be a member of that epoch's roster **and of
   the current roster** (a member removed by the last commit cannot keep
   sending during the grace window);
3. derives `key_g` and `nonce_g`: at most `MAX_FORWARD_GENERATIONS` (1024)
   ahead of the chain; keys of skipped generations are kept, at most
   `MAX_SKIPPED_KEYS` (256) per sender; a key is deleted once used, so a
   replayed or too-old generation has no key and is rejected;
4. checks the key commitment, opens the ciphertext, decodes the framed
   content and checks that its `gid`, `epoch`, `sender_leaf_id` and
   `generation` match the envelope;
5. verifies the signature under the sender's device key from the roster;
6. only then releases the plaintext. Applications display
   `signed_timestamp_ms` and the sender identity from the roster.

<a id="12-delivery-service"></a>
## 12. Delivery service

The DS keeps, per group, a *ledger* (the public state, the current and
previous epoch's replay state, recorded proposals, invites and cover-failure
reports) and an ordered *log*.

<a id="12-1-ledger"></a>
### 12.1 Ledger rules

* **Genesis.** A group is created by a valid genesis commit (section 9) with
  its GroupInfo; `gid` MUST NOT exist.
* **Ordering.** The first valid commit for epoch `n + 1` wins. A later commit
  for the same epoch is rejected with an epoch mismatch; its author syncs and
  rebuilds on the new epoch.
* **Recorded removals.** A commit MUST include every recorded removal
  proposal (by increasing target slot). A removal proposal is recorded only
  if it is authorized against the current roster; recording the same
  proposal twice is idempotent. The group is *vacant* when every member has a
  recorded removal; the next joiner then commits them.
* **GroupInfo.** The GroupInfo published with a commit MUST be signed by the
  commit's author and describe exactly the epoch the ledger computed
  (GroupContext and confirmation tag). The DS never signs one itself.
* **Invites.** Admin-signed invites are stored by `invite_id` (at most
  `MAX_INVITES` = 256 per group); an expired invite (by the DS clock) is
  refused, and a join whose admission embeds an expired invite is rejected.
* **Messages.** An envelope is accepted for the current epoch, or for the
  previous one during `GRACE_WINDOW_MS` after the current epoch started,
  only from a sender that is a member of the current roster and of the
  envelope's epoch, without a recorded removal, and at most once per
  `(epoch, sender, generation)` (a 64-generation sliding window per sender).
  The DS cannot check the ciphertext.
* **Cover failures.** Reports of current members naming the current epoch
  are recorded (at most `MAX_COVER_FAILURES` = 256 per group).

<a id="12-2-log"></a>
### 12.2 Log

Every accepted commit (with its GroupInfo), envelope and recorded removal
proposal is appended to the group log with a sequence number `seq` (starting
at 1 with the genesis commit), its epoch and the DS acceptance time. Members
read the log in order, in pages that also give `first_seq`, the oldest
retained entry. Messages expire after a retention period, commits after a
longer one, and the log keeps at most a bounded number of entries: when it
is full, the oldest message or proposal goes first, then the oldest commit;
neither the entry being appended nor the latest commit is ever dropped.
Messages that expired
before a member read them are lost to it; a member that meets a commit of a
later epoch than the next one it needs has lost a commit and resyncs
(section 13.2).

<a id="12-3-journal"></a>
### 12.3 Persistence

A DS journals a record of every state change before answering the request
that caused it, and restores a group by replaying its records on its latest
snapshot; replay is deterministic. A request whose record could not be
written fails, and the in-memory group is reloaded from storage.

<a id="13-member-behavior"></a>
## 13. Member behavior

<a id="13-1-create-join"></a>
### 13.1 Creating and joining

* **Create.** Draw `group_nonce`, build the genesis commit and GroupInfo,
  publish them.
* **Join with an invite link.** The link carries the DS URL, `gid` and the
  invite seed (section 14.3). The joiner derives the invite key, fetches the
  invite by `invite_id`, signs its own admission with the invite key, fetches
  the GroupInfo, tree, roster and recorded removals, verifies the GroupInfo
  (section 10.3), and publishes an ExternalJoin commit that includes every
  recorded removal. On an epoch mismatch it retries on the new epoch.

<a id="13-2-sync"></a>
### 13.2 Following the log

A member processes log entries in order: commits (section 9.5), recorded
proposals, and envelopes (section 11.3). If it cannot process a commit, it
signs a cover-failure report and resyncs with a Resync commit; it also
resyncs when a commit it needs is no longer in the log. If the commit
removes it, it deletes the group state. A commit of its own that it did not
see accepted (a lost reply) is recognised when it appears in the log.

<a id="13-3-persistence"></a>
### 13.3 Persistence order

A member persists its state:

* after encrypting a message and **before** sending it, so that a restarted
  device never reuses a generation (and hence a key and nonce);
* after every commit it applies or has accepted;
* after following the log.

The persisted state includes secrets and MUST be protected at rest.

<a id="13-4-maintenance"></a>
### 13.4 Maintenance

* A member commits the recorded removal proposals of *other* members;
  committers SHOULD wait a random delay to limit concurrent commits.
* A member MUST re-key its own leaf (a Member commit with no other change)
  at least every `FS_WINDOW` (default 24 hours).
* A member erases the previous epoch's message keys `GRACE_WINDOW_MS` after
  the current epoch became active.
* A member whose own removal is recorded stops committing and sending.

<a id="14-deployment-binding"></a>
## 14. Deployment binding and HTTP API

This section is outside the group protocol: its objects change no group
state and no key.

<a id="14-1-binding-objects"></a>
### 14.1 Binding objects

```text
AliasBinding := ["city-g/alias/v1", gid, device_pk, alias]
                signed with ctx "city-g/identity-binding/v1" by device_pk
SessionAuth  := ["city-g/session-auth/v1", gid, device_pk, issued_at_ms]
                signed with ctx "city-g/session-auth/v1" by device_pk
```

* An alias is a display name a member claims for itself: 1 to 64 bytes of
  UTF-8, no control characters, no leading or trailing whitespace. It is
  self-asserted; clients SHOULD pin the device key first seen for an alias
  and warn when it changes (trust on first use).
* A SessionAuth fresh within the DS clock skew (default 5 minutes) and
  signed by a current member's device key is exchanged for a 32-byte bearer
  token (default lifetime 1 hour). A token stops working when the commit
  removing its member is accepted.

<a id="14-2-api"></a>
### 14.2 HTTP API

Every request is an HTTP `POST` of a protobuf message
([`crates/cityg-proto/proto/cityg_v2.proto`](../../../crates/cityg-proto/proto/))
whose field 1 is `gid`; protocol objects travel as their exact
deterministic-CBOR bytes. Bodies are at most 16 MiB. Routes marked *token*
require `Authorization: Bearer <hex token>`.

| Route | Request → response | Token |
| --- | --- | --- |
| `/v2/groups/create` | genesis commit + GroupInfo → epoch, seq | |
| `/v2/groups/info` | → GroupInfo, tree, roster, recorded removals, head seq, vacant | |
| `/v2/groups/commit` | commit + GroupInfo → epoch, seq | |
| `/v2/groups/log` | after_seq, limit (default 256, at most 1024) → entries, head_seq, first_seq | token |
| `/v2/groups/remove_proposal` | SignedRemoveProposal → recorded / already_recorded, vacant | |
| `/v2/groups/invite` | SignedInvite → invite_id | |
| `/v2/groups/invite/get` | invite_id → SignedInvite | |
| `/v2/groups/send` | Envelope → epoch, seq | token |
| `/v2/groups/cover_failure` | CoverFailureReport → count | |
| `/v2/groups/cover_failures` | → reports | token |
| `/v2/groups/session` | SessionAuth → token, expires_at_ms | |
| `/v2/groups/alias` | AliasBinding → count | |
| `/v2/groups/aliases` | → bindings of current members | token |

Errors carry a protobuf `ErrorResponse {code, message}` with these HTTP
statuses: 400 malformed request or non-deterministic encoding, 401 missing
or invalid token, 403 not allowed (not a member, pending removal, not an
admin), 404 unknown group or invite, 409 conflict (stale epoch, recorded
removals not committed, replay, existing group), 410 a route of the removed
v0.1.4 API, 413 over a size or count limit, 422 verification failure, 429
rate limited (the reference DS does not rate-limit; a deployment may, in
front of it), 500 internal error.

**Notifications.** `GET /v2/ws?gid=<hex>&token=<hex>` upgrades to a
WebSocket that sends `{"type":"head","gid":…,"head_seq":N}` when the log
grows, and `{"type":"resync","gid":…}` when notices were dropped; the client
then fetches the log.

<a id="14-3-invite-link"></a>
### 14.3 Invite links

```text
cityg-invite:{"version":4,"server_url":"<DS URL>","room_id":"<gid hex>","invite_seed":"<hex, 32 bytes>"}
```

The invite seed is a bearer secret: anyone holding the link can join until
the invite expires. Links SHOULD be shared over an authenticated channel and
given a short lifetime (default 7 days).

<a id="15-parameters"></a>
## 15. Parameters

| Name | Value |
| --- | --- |
| `MAX_N_MAX` | 1024 slots (`n_max` a power of two, at least 2) |
| `MAX_ADMINS` | 64 |
| `MAX_RETIRED` | 4096 retired leaf ids per roster |
| `FS_WINDOW` | 24 hours (self-update interval) |
| `GRACE_WINDOW_MS` | 600 000 (10 minutes) |
| `MAX_FORWARD_GENERATIONS` | 1024 |
| `MAX_SKIPPED_KEYS` | 256 per sender |
| Replay window of the DS | 64 generations per sender and epoch |
| Plaintext / authenticated data | 256 KiB / 4 KiB per message |
| Envelope | at most 256 KiB + 4 KiB + 16 KiB |
| Signed invite / admission / removal proposal / GroupInfo / cover-failure report / binding | 16 / 32 / 12 / 16 / 8 / 12 KiB |
| Commit | `max_commit_bytes(n_max)` (section 9.1) |
| `MAX_INVITES`, `MAX_COVER_FAILURES` | 256 per group |
| DS defaults | group size 256, message retention 7 days, commit retention 30 days, 50 000 log entries, session tokens 1 hour, SessionAuth skew 5 minutes |

<a id="16-label-registry"></a>
## 16. Label registry

<a id="16-1-labelled-hashes"></a>
### 16.1 Labelled hashes (`H_L`)

| Label | Arguments | Section |
| --- | --- | --- |
| `group-id` | `[creator_device_pk, group_nonce]` | 5 |
| `leaf-id` | `[gid, device_pk]` | 5 |
| `invite-id` | `[invite_pk]` | 5 |
| `kem-pk` | `[pk]` | 5 |
| `msg/epoch-ref` | `[gid, epoch]` | 5 |
| `tree/leaf` | `[n_max, slot, occupant]` | 6.2 |
| `tree/parent` | `[node, public_key or h'', left_hash, right_hash]` | 6.2 |
| `roster` | `[members, admins, last_generations, retired]` | 7 |
| `confirmed-transcript` | `[prev_interim, anchor_tbs, signature]` | 8 |
| `interim-transcript` | `[confirmed, confirmation_tag]` | 8 |
| `msg/key-commitment` | `[key, nonce]` | 11.2 |

<a id="16-2-derivation-labels"></a>
### 16.2 Derivation labels and object labels

| Kind | Labels |
| --- | --- |
| `ExpandLabel` / `DeriveSecret` | `epoch`, `init`, `msg`, `confirm`, `external`, `commit`, `external kem`, `external init`, `tree leaf key`, `tree path`, `tree node key`, `tree path wrap key`, `tree path wrap nonce`, `msg sender`, `msg next`, `msg key`, `msg nonce` |
| Framing tags | `city-g/v0.2` (H_L), `city-g/v0.2 expand`, `city-g/v0.2 mac` |
| Encoded objects | `city-g/group-context/v2`, `city-g/remove/v2`, `city-g/invite/v1`, `city-g/admission/v1`, `city-g/group-info/v2`, `city-g/cover-failure/v1`, `city-g/msg/v3`, `city-g-msg-v3` (envelope header), `city-g/alias/v1`, `city-g/session-auth/v1` |

<a id="16-3-contexts"></a>
### 16.3 Signature contexts (FIPS 204 `ctx`)

| Context | Signed object |
| --- | --- |
| `city-g/anchor/v2` | commit (`anchor_tbs`) |
| `city-g/group-info/v2` | GroupInfo |
| `city-g/admission/v1` | Admission |
| `city-g/invite/v1` | Invite |
| `city-g/remove/v1` | RemoveProposal |
| `city-g/cover-failure/v1` | CoverFailureReport |
| `city-g/msg/v3` | FramedContent |
| `city-g/identity-binding/v1` | AliasBinding |
| `city-g/session-auth/v1` | SessionAuth |
| `city-g/policy/v1` | deployment policy documents (reserved) |

Any change to an encoding, a label or a context is a new profile version.

<a id="17-conformance"></a>
## 17. Conformance

* [`kat/v0.2/vectors.json`](../../../kat/legacy/v0.2/vectors.json) holds vectors for
  `CBOR_det`, `H_L`, the KDF functions, the identifiers, the key schedule and
  external init, the roster hash, the path-secret wrap, a complete genesis
  commit with its GroupInfo and two messages of epoch 0, and every signed
  array layout.
* The reference implementation recomputes them
  (`cargo test -p cityg-core --test vectors`).
* [`kat/v0.2/verify_vectors.py`](../../../kat/legacy/v0.2/verify_vectors.py) recomputes
  them independently from this document (CBOR, BLAKE3 derivations and
  ChaCha20-Poly1305 re-implemented), including the genesis tree hash, roster
  hash, transcript hashes, confirmation tag, and the decryption of the
  messages.
* [`kat/kat-v0.2-conformance-manifest.json`](../../../kat/legacy/v0.2/kat-v0.2-conformance-manifest.json)
  maps each requirement to this document and to the vectors that exercise it.
* The symbolic model in [`docs/formal/`](formal/) (ProVerif) proves, in
  bounded scenarios and with ideal primitives, the confidentiality of epoch
  secrets against the delivery service, membership agreement, admission
  control, forward secrecy, post-compromise security after a self-update,
  post-removal secrecy, and sender authentication; two sanity scenarios show
  the attacks that the author rule (section 9.4) and retired devices
  (section 7) prevent. Its README lists the abstractions.

<a id="18-changes"></a>
## 18. Changes from profile v0.1.4

Profile v0.2 is a new protocol; v0.1.4 groups cannot be upgraded in place.

| v0.1.4 | v0.2 | Audit |
| --- | --- | --- |
| ME-OR / SPHF, `E_k`, `K_fs` | epoch-chained key schedule (section 8) | C-01, C-02, H-02, P-2 |
| CAPSS / SRX SmallWood proofs, `hp_binding`, ZK-VRF checked by the server | removed; the server verifies signatures and the public transition only | C-02, P-5 |
| Leaver authors its own revocation | a member never commits its own removal (sections 9.4, 10.1) | C-03 |
| Server-provisioned joins | admissions signed by admins or invite keys, verified by every member (section 10.2) | H-01, P-4 |
| Leaf keys never renewed | every commit renews its author's leaf; periodic self-update (sections 6.3, 13.4) | H-03, P-3 |
| Several partial signatures per anchor | one ML-DSA-87 signature per commit with a closed registry (section 9) | H-04, P-5 |
| "ML-DSA-65" (pre-standard Dilithium) | FIPS 204 ML-DSA-87 with per-usage contexts (section 3) | H-05 |
| `H_L` over CBOR maps | `H_L` over CBOR arrays, one encoding (section 4.2) | H-06 |
| Unbounded barrier updates | bounded update size, `MAX_N_MAX` (section 6.4) | H-08 |
| Message signatures without context, no membership check | message plane v3 (section 11) | H-10, M-01, M-02, M-03, P-6 |
| Silent exclusion by a faulty updater | cover-failure reports and resync (section 10.4) | M-05 |
| Open server defaults, admin tokens | members authenticate with signed SessionAuth; no operator token | M-06 |
