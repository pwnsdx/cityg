# City-G protocol specification — profile v0.3

| | |
| --- | --- |
| Profile | `city-g/v0.3` |
| Status | Normative. Supersedes profile v0.2 ([archived](legacy/v0.2/specs.md)); the two profiles do not interoperate. |
| Reference implementation | [`crates/cityg-core`](../crates/cityg-core) (protocol core, no I/O), [`crates/cityg-server`](../crates/cityg-server) and [`crates/cityg-runtime`](../crates/cityg-runtime) (delivery service), [`crates/cityg-api-client`](../crates/cityg-api-client) (member drivers, full and light) |
| Conformance | [`kat/v0.3/vectors.json`](../kat/v0.3/vectors.json), checked by the reference implementation and by the independent verifier [`kat/v0.3/verify_vectors.py`](../kat/v0.3/verify_vectors.py); requirement map [`kat/kat-v0.3-conformance-manifest.json`](../kat/kat-v0.3-conformance-manifest.json) |
| Formal model | [`docs/formal/`](formal/) |
| Origin | Design for large groups with concurrent joins and departures: batched joins, a growable tree holding the members, light members, device-key rotation, X-Wing and ML-DSA-65 (section 20); rationale in [design-v0.3.md](design-v0.3.md) |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be
interpreted as in RFC 2119 and RFC 8174 when they appear in capitals.

City-G is an end-to-end encrypted group messaging protocol with
post-quantum primitives. Its group key agreement follows MLS (RFC 9420): an
epoch-chained key schedule, a TreeKEM ratchet tree in the RFC 9420 array
layout, commits that move a group from one epoch to the next, external
commits, welcomes for members added by someone else's commit, and a
per-sender message ratchet. A delivery service orders commits and relays
encrypted messages without holding any group secret.

Profile v0.3 is built for groups of thousands of members where people join
and leave all the time: any number of joins wait in the delivery service and
enter with one commit; the tree grows and shrinks with the group; a member
that does not want to hold the whole tree can follow the group as a *light
member*; and a device can replace its signature key without leaving.

## Contents

1. [Architecture](#1-architecture)
2. [Security goals and threat model](#2-security-goals)
3. [Cryptographic suite](#3-cryptographic-suite)
4. [Encodings and derivation functions](#4-encodings)
5. [Identifiers](#5-identifiers)
6. [Ratchet tree](#6-ratchet-tree)
7. [Registry](#7-registry)
8. [Key schedule](#8-key-schedule)
9. [Commits](#9-commits)
10. [Signed objects](#10-signed-objects)
11. [Message plane v4](#11-message-plane)
12. [Delivery service](#12-delivery-service)
13. [Member behavior](#13-member-behavior)
14. [Light members](#14-light-members)
15. [Deployment binding and HTTP API](#15-deployment-binding)
16. [Parameters](#16-parameters)
17. [Label registry](#17-label-registry)
18. [Conformance](#18-conformance)
19. [Security considerations](#19-security-considerations)
20. [Changes from profile v0.2](#20-changes)

<a id="1-architecture"></a>
## 1. Architecture

* **Device.** A member device holds an ML-DSA-65 signing key pair, its
  *device key*, per group membership. It may replace it by a new one without
  leaving the group (section 9.3).
* **Group.** A group is identified by `gid` (section 5). Its state at epoch
  `n` consists of a public part (the ratchet tree, which also lists the
  members, the registry, and the transcript hashes) that every full member
  and the delivery service share, and a secret part (private tree keys,
  epoch secrets, message ratchets) that only members hold.
* **Occupancy.** A member occupies one leaf of the tree from the epoch it
  entered, `since`. The pair `[leaf, since]`, a *member reference*, names
  the occupancy for good: messages, removal proposals and admin changes name
  members by it. A resync starts a new occupancy of the same leaf; a
  device-key rotation does not.
* **Commit.** A commit moves a group from epoch `n - 1` to epoch `n`. It is
  authored by a single device, signed by it, re-keys the author's leaf and
  direct path, and carries membership changes: removals, joins, admin
  changes, the author's own entry (an external join or a resync) and the
  rotation of the author's device key.
* **Joins.** A joiner records a signed *join request* with the delivery
  service. The next commit, by any member, or by a joiner through an external
  commit, places every waiting request in the tree at once; each joiner then
  receives a *welcome* holding the new epoch's joiner secret.
* **Delivery service (DS).** The DS stores, for each group, an ordered log
  of commits, message envelopes, removal proposals and join requests. It
  runs the public part of every commit transition, so it relays only commits
  full members accept, and it enforces the rules that need a global order, a
  count or a clock (section 12). It never holds a group secret.
* **Light members.** A member MAY keep only a small part of the public state
  and verify commits with Merkle proofs that the DS computes (section 14).
* **Deployment binding.** Display names (aliases) and the authentication of
  requests to the DS are signed objects outside the group protocol
  (section 15). They change no group state and no key.

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
| A5 | Temporarily compromised device state | Learns the group state of one device (tree private keys, epoch secrets, message chains, pending join secrets) at one point in time, then loses access. The device key stays secret, for instance in a hardware keystore. |
| A6 | Compromised device key | Learns the ML-DSA-65 device key of one member device. |

The network is controlled by A2. Admins are trusted to admit members: an
admin that admits the adversary gives it membership.

### 2.2 Properties

"Guaranteed" means: under the assumptions of section 2.3, the property holds
against that adversary, for full members. Section 14.6 states what changes
for light members. A deployment MUST NOT advertise a property that this
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
| Join secrecy (a joiner learns nothing of epochs before its join) | guaranteed | guaranteed | guaranteed | n/a | guaranteed | guaranteed |
| Liveness, availability | no | no | no | no | no | no |
| Metadata privacy (who talks when, group size, members) | no | no | no | no | no | no |

Definitions (normative):

* **Membership agreement.** Two full members that accept the commit of
  epoch `n` agree on the tree (members, their keys and occupancies), the
  registry (capacity, admins, retired admissions) and the transcript of
  epochs `0..n`: these are bound into `GroupContext_n` (section 8), from
  which every secret of the epoch derives, and verified by the confirmation
  tag.
* **PRS.** A member whose occupancy is ended by the commit of epoch `n` MUST
  NOT be able to derive any secret of an epoch `>= n`, unless an admin admits
  it again with a new admission. A member never authors the commit that
  removes it (section 9.4), the removed leaf and its direct path are blanked
  in the tree the removing commit encrypts to, and its admission is retired:
  it cannot come back with it (section 7).
* **FS.** Compromise of a device at time `T` MUST NOT reveal message content
  of epochs whose keys the device erased before `T`. Members erase epoch
  secrets when the next epoch becomes active, erase each message key once
  used, keep previous-epoch message keys for at most `GRACE_WINDOW_MS`, and
  re-key their own leaf at least every `FS_WINDOW` (section 13.4).
* **PCS.** After a device whose state was compromised completes a
  self-update (a commit re-keying its leaf from a fresh leaf secret), the
  attacker MUST NOT derive secrets of later epochs, unless it compromises a
  member again.
* **Join secrecy.** A joiner that enters with a welcome receives only
  `joiner_secret_n` (section 8), from which nothing of epoch `n - 1` or
  before derives. Its `init_key` is used for one welcome and erased.
* **Device keys.** Whoever holds a device key can sign as the device:
  commits (including a Resync that re-enters the device's leaf with keys of
  its choice), messages, proposals, a rotation of the key, and admissions if
  the device is an admin. A device that rotates its key (section 9.3) stops
  signing with the old one; this does not undo a compromise the adversary
  already used, and an adversary holding the key can rotate it first. The
  reliable repair is to remove the device, together with any device it
  admitted, and to admit a new one. The device itself notices a commit
  authored in its name that it did not produce: it cannot process it and
  resyncs, or finds it was removed.

### 2.3 Assumptions and limits

* X-Wing is IND-CCA2 if either ML-KEM-768 or X25519 is; ML-DSA-65 is
  EUF-CMA (and strongly unforgeable); BLAKE3 in keyed mode is a PRF;
  ChaCha20-Poly1305 is an AEAD. Random numbers come from a CSPRNG.
* The DS can always deny service: drop commits, messages, join requests or
  whole groups. Members detect some of it (gaps in the log, a commit they
  cannot process, section 10.5) but cannot prevent it.
* The DS sees the members (device keys, leaves, occupancies, admins), who
  sends when, the size of messages and the aliases members publish. Aliases
  are self-asserted (section 15.1).
* A member can send a message that other members cannot decrypt (a forged
  ciphertext on its own chain) and can author a commit whose path secret some
  members cannot decrypt; the latter is detected and reported (section 10.5)
  and the affected members resync.
* `signed_timestamp_ms` of a message is the sender's clock, authenticated by
  its signature, not a trusted time.
* Group encryption is not end-to-end between subsets of a group: every
  member of an epoch can read every message of that epoch.
* **Forks.** The DS decides which commits each member sees. It can show
  different members different valid histories (a fork) and keep each branch
  going; members on one branch reject the commits of the other. Comparing
  the security code (the interim transcript hash of an epoch, section 8)
  out of band detects a fork.
* **Entering a group.** A joiner, and a member that resyncs, cannot check
  the history before the epoch it enters: it checks the commit, GroupInfo,
  tree and registry of that epoch against each other, but they come from
  the DS. A DS can therefore fabricate an epoch whose committer and
  GroupInfo signer is a device it controls, and make a joiner enter this
  forked view, where the DS reads the joiner's messages. The properties of
  section 2.2 hold for a member from the first epoch it shares with members
  that followed the history; a joiner SHOULD compare its security code out
  of band with a member it knows, such as the one who invited it.

<a id="3-cryptographic-suite"></a>
## 3. Cryptographic suite

| Function | Primitive | Use |
| --- | --- | --- |
| KEM | X-Wing (ML-KEM-768 and X25519), draft-connolly-cfrg-xwing-kem-06 | tree node and leaf keys, welcome init keys, external init |
| Signature | ML-DSA-65 (FIPS 204), hedged, with context strings | commits and every signed object |
| Hash `H` | BLAKE3, 256-bit output | labelled hashes, digests |
| PRF / KDF | BLAKE3 keyed mode and its XOF | Extract, ExpandLabel, MAC |
| AEAD | ChaCha20-Poly1305 (RFC 8439) | path secret and welcome wrapping, messages |

* **X-Wing.** A private key is held as its 32-byte decapsulation key (a seed
  from which X-Wing derives the ML-KEM-768 and X25519 keys). Encapsulation
  draws its 64 random bytes (32 for ML-KEM, 32 for the X25519 ephemeral key)
  from the caller's generator. Encapsulation keys are 1216 bytes (the
  ML-KEM-768 key, then the X25519 key), ciphertexts 1120 bytes, shared
  secrets 32 bytes. An encapsulation key MUST pass the FIPS 203 input check
  of its ML-KEM part before use. The hybrid keeps confidentiality if either
  component holds, against an adversary that records traffic today to
  decrypt it with a quantum computer later.
* **ML-DSA-65.** Key pairs derive from a 32-byte seed `xi`
  (`ML-DSA.KeyGen_internal`). Signing is hedged: the 32-byte `rnd` input is
  drawn from the caller's generator. Public keys are 1952 bytes, secret keys
  4032 bytes, signatures 3309 bytes. Every signature uses a FIPS 204 context
  string (`ctx`) naming its usage (section 17.3); a signature produced under
  one context MUST NOT verify under another.
* **Randomness.** Every random value of the protocol (seeds, nonces, leaf
  secrets, KEM randomness, signing randomness, invite seeds) MUST come from
  a CSPRNG.

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

`h''` denotes the empty byte string and `ZERO32` 32 zero bytes. Integers are
unsigned unless stated.

<a id="4-2-labelled-hash"></a>
### 4.2 Labelled hash

```text
H(x)             := BLAKE3-256(x)
H_L(label, args) := H(CBOR_det(["city-g/v0.3", label, args]))
```

`label` is a text string, `args` a CBOR array. A map MUST NOT appear as the
argument list. The labels are listed in section 17.1.

<a id="4-3-kdf"></a>
### 4.3 Key derivation

```text
Extract(salt, ikm)                 := BLAKE3-keyed(key = salt, ikm)                 (32 bytes)
ExpandLabel(secret, label, ctx, L) := BLAKE3-keyed-XOF(key = secret,
                                        CBOR_det(["city-g/v0.3 expand", label, ctx, L]))[0..L]
DeriveSecret(secret, label)        := ExpandLabel(secret, label, h'', 32)
MAC(key, data)                     := BLAKE3-keyed(key = key, CBOR_det(["city-g/v0.3 mac", data]))
KeyGen(secret, label)              := the X-Wing key whose decapsulation key is
                                      ExpandLabel(secret, label, h'', 32)
```

`salt`, `secret` and `key` are 32 bytes; `ctx` is a byte string; `L` is an
unsigned integer. MAC tags are compared in constant time.

<a id="4-4-signed-arrays"></a>
### 4.4 Signed arrays

Every signed object except the commit (section 9) is a signed array:

```text
TBS       := CBOR_det([field_1, ..., field_k])
Signed    := CBOR_det([field_1, ..., field_k, signature])
signature := ML-DSA-65.Sign(sk, TBS, ctx)
```

`field_1` is the text label naming the object and its version (section
17.2). A verifier checks the label and the number of fields before
verifying the signature over `TBS`, which it rebuilds from the received
fields.

<a id="5-identifiers"></a>
## 5. Identifiers

```text
gid          := H_L("group-id",  [creator_device_pk, group_nonce])     group_nonce: 32 random bytes
device_id    := H_L("device-id", [gid, device_pk])
MemberRef    := [leaf, since]
invite_id    := H_L("invite-id", [invite_pk])
proposal_ref := H_L("proposal-ref", [signed proposal or join request bytes])
epoch_ref    := H_L("msg/epoch-ref", [gid, epoch])
H_pk(pk)     := H_L("kem-pk", [pk])                                    pk: X-Wing encapsulation key
```

* Binding the creator's device key into `gid` makes the creator the
  verifiable first admin of the group.
* `device_id` names a device in an admission, before it has a leaf.
* A member reference `[leaf, since]` names one occupancy: no later occupant
  of the leaf can enter at the same epoch, so the pair is never reused, even
  when the tree shrinks and grows again.

<a id="6-ratchet-tree"></a>
## 6. Ratchet tree

<a id="6-1-layout"></a>
### 6.1 Layout

The tree follows the array layout of RFC 9420: with `width` leaves (a power
of two), leaf `i` is node `2i`, parent nodes have odd indices, the level of
node `x` is the number of trailing one bits of `x`, and the root is node
`width - 1`. Node indices do not depend on the width: when the tree doubles,
the old root becomes the left child of the new root; when it halves, the
right half is dropped.

* `capacity`, a power of two with `2 <= capacity <= MAX_CAPACITY` (8192),
  is fixed at genesis; `width <= capacity`.
* **Canonical width.** `width` is the smallest power of two covering the
  rightmost occupied leaf (1 for a tree whose only member is in leaf 0).
  Every accepted tree is canonical: after its membership changes, a commit
  halves the tree while the right half holds no member.
* **Entry leaf.** A member enters the lowest blank leaf; when every leaf is
  occupied and `width < capacity`, the tree doubles and the member takes
  leaf `width`. A group whose `capacity` leaves are all occupied is full.
* The *direct path* of a leaf lists the parent nodes from its parent up to
  the root; its *copath* lists, for each node of the direct path, the child
  that is not on the path. `ancestor(leaf, l) := ((leaf >> l) << (l + 1)) +
  2^l - 1` is the ancestor of `leaf` at level `l`, and two distinct leaves
  `a` and `b` have their lowest common ancestor at level `bitlen(a XOR b)`.

<a id="6-2-nodes"></a>
### 6.2 Nodes

```text
LeafNode   := [device_pk, since, encryption_key, admission_hash]
ParentNode := [encryption_key, [unmerged leaf, ... increasing]]
```

* A leaf is blank (`null`) or holds a member: its ML-DSA-65 device key, the
  epoch its occupancy began, the X-Wing key of the leaf, and
  `admission_hash := H(SignedAdmission)` of its join (`ZERO32` for the
  creator).
* A parent is blank (`null`) or holds an X-Wing key and its *unmerged
  leaves*: the leaves below it that entered after its key was set and hence
  do not hold its private key.
* **Entering.** A member that enters without re-keying (a join request, or
  the author of an external commit before its own update path is applied)
  is added to the unmerged list of every non-blank node of its direct path.
* **Removing.** A removal blanks the leaf and every node of its direct path.
* Device keys are distinct across the tree; unmerged leaves name occupied
  leaves below their node.
* The tree of a snapshot is encoded as `[capacity, [leaf or null, ...],
  [parent or null, ...]]`, parents indexed by `node / 2`. A decoder MUST
  check the invariants of this section and reject a non-canonical width.

<a id="6-3-tree-hash"></a>
### 6.3 Tree hash

```text
leaf_hash(i)     := H_L("tree/leaf",   [i, LeafNode or null])
node_digest(x)   := H_L("tree/parent-node", [encryption_key, [unmerged leaf, ...]])
parent_hash(x)   := H_L("tree/parent", [node_digest(x) or null, hash(left(x)), hash(right(x))])
tree_hash        := hash(root)
```

A parent's content is hashed first so that a Merkle proof of a leaf carries
32 bytes per level (section 6.7).

<a id="6-4-resolution"></a>
### 6.4 Resolution

The *resolution* of a node is the smallest set of nodes whose private keys
cover every member below it:

* a non-blank parent: the node, then its unmerged leaves;
* a blank parent: the resolution of its left child, then of its right child;
* an occupied leaf: the leaf; a blank leaf: nothing.

Resolutions are listed in increasing node order.

<a id="6-5-update-path"></a>
### 6.5 Update path

A commit re-keys its author's leaf and direct path:

```text
leaf_secret        : 32 fresh random bytes
leaf key           := KeyGen(leaf_secret, "tree leaf key")
path_secret[0]     := DeriveSecret(leaf_secret, "tree path")
path_secret[i + 1] := DeriveSecret(path_secret[i], "tree path")
node key of path[i] := KeyGen(path_secret[i], "tree node key")        0 <= i < d
commit_secret      := path_secret[d]                                  d = |direct path| = log2(width)
```

`commit_secret` is one step past the root, so a tree of one leaf (`d = 0`)
still yields a fresh commit secret. For each node `path[i]`, the author
encrypts `path_secret[i]` to every node of the resolution of `copath[i]` in
the *staged tree*: the tree after every membership change of the commit
(steps 1 to 7 of section 9.4):

```text
(kem_ciphertext, shared) := X-Wing.Encaps(pk_target)
wrap_context   := CBOR_det([gid, epoch, author_leaf, node, target, H_pk(pk_target)])
wrap_key       := ExpandLabel(shared, "tree path wrap key",   wrap_context, 32)
wrap_nonce     := ExpandLabel(shared, "tree path wrap nonce", wrap_context, 12)
wrapped_secret := ChaCha20-Poly1305(wrap_key, wrap_nonce, aad = wrap_context, pt = path_secret[i])
```

`epoch` is the epoch the commit creates and `author_leaf` the author's leaf
in it. Members that entered with the same commit are unmerged leaves of the
copath nodes above them, so they receive the path secrets under their own
leaf keys. The update path is encoded as

```text
UpdatePath := [leaf_public_key, [PathNode, ...]]
PathNode   := [node, public_key, [[target, kem_ciphertext, wrapped_secret], ...]]
```

with one `PathNode` per direct-path node in order, and one target per
resolution node in increasing node order. `wrapped_secret` is 48 bytes.

**Validation** (needs no secret; run by the DS and by every full member,
against the staged tree): the author's leaf is occupied; every public key is
a valid X-Wing key; the path has one entry per direct-path node with the
right node index; the targets of entry `i` are exactly the resolution of
`copath[i]`, in order; ciphertexts are 1120 bytes and wrapped secrets 48
bytes.

**Decryption** by the member in leaf `m != author_leaf`: take the entry of
the lowest common ancestor, index `bitlen(author_leaf XOR m) - 1`; among its
targets, take the node the member holds a private key for (its leaf, or a
node of its direct path of which it is not an unmerged leaf); decapsulate,
open the wrapped secret (with `H_pk` of that node's public key); derive the
path secrets above; and check that every derived node public key equals the
published one. Any failure is a cover failure (section 10.5).

**Application.** The new tree is the staged tree with the author's leaf key
replaced by `leaf_public_key` and each direct-path node set to its new
public key with an empty unmerged list. Members keep the private keys of the
nodes they learnt and drop keys of nodes that are blank or gone.

<a id="6-6-update-bound"></a>
### 6.6 Bound on update size

```text
max_update_path_bytes(c) := 64 + (1216 + 8)(d + 1) + 16 d + (1120 + 48 + 16)(c - 1),   d = log2(c)
```

The copath resolutions cover every other member once (an unmerged leaf is
listed below one node only), so they hold at most `c - 1` targets overall:
an update of an 8192-leaf tree stays under 10 MB.

<a id="6-7-leaf-proof"></a>
### 6.7 Leaf proofs

```text
LeafProof := [leaf, width, LeafNode or null, [[node_digest or null, sibling_hash], ...]]
```

A leaf proof shows that leaf `leaf` of a tree of `width` leaves holds a
member (or is blank). Its steps go from the leaf's parent up to the root:
step `k` gives the `node_digest` of the ancestor at level `k + 1` (`null` if
blank) and the hash of the sibling of the node at level `k`. A verifier
checks that `width` is a power of two at most `MAX_CAPACITY`, `leaf <
width` and there are `log2(width)` steps, recomputes the root hash with
section 6.3 and compares it with the expected tree hash. A proof is at most
8 KiB.

<a id="7-registry"></a>
## 7. Registry

```text
Registry      := [capacity, [admin leaf, ... increasing],
                  [[admission_hash, expires_epoch], ... oldest first], retired_floor]
registry_hash := H_L("registry", Registry)
```

* **Admins** are named by their leaf: admin rights belong to an occupancy,
  end with it (a removal), and survive a resync of the same leaf and a
  rotation of the device key. At most `MAX_ADMINS` (64). If a commit leaves
  no admin, its author becomes one (section 9.4). The genesis registry has
  the creator's leaf 0 as sole admin.
* **Retired admissions.** When an occupancy that began at epoch `since` ends
  by a removal in epoch `n`, its `admission_hash` is appended with
  `expires_epoch := since + MAX_ADMISSION_EPOCHS`, unless it is `ZERO32`
  (the creator), already retired, or `expires_epoch < n`. Entries whose
  `expires_epoch < n` are dropped at the start of every commit for epoch
  `n`, and at most `MAX_RETIRED` (4096) entries are kept, the oldest going
  first. An admission is valid for at most `MAX_ADMISSION_EPOCHS` epochs
  (section 10.2), so a retired admission cannot be used again while it is
  valid: a removed member cannot come back with an admission it kept.
* **Retired floor.** When the list overflows, the entry dropped may not have
  expired yet: `retired_floor := max(retired_floor, its expires_epoch)`, and
  an admission whose `not_after_epoch` is not above `retired_floor` is
  refused (section 10.2). The dropped admission is among them, since its
  `not_after_epoch` is at most its entry's `expires_epoch`. The floor starts
  at 0 and never decreases; clients give their admissions a last epoch above
  it (section 13.1).

<a id="8-key-schedule"></a>
## 8. Key schedule

```text
GroupContext_n := CBOR_det(["city-g/group-context/v3", gid, n, tree_hash_n,
                            registry_hash_n, "city-g/v0.3", confirmed_transcript_hash_n])

joiner_secret_n   := ExpandLabel(Extract(init_secret_{n-1}, commit_secret_n),
                                 "joiner", H(GroupContext_n), 32)
epoch_secret_n    := DeriveSecret(joiner_secret_n, "epoch")
init_secret_n     := DeriveSecret(epoch_secret_n, "init")
msg_secret_n      := DeriveSecret(epoch_secret_n, "msg")
confirm_key_n     := DeriveSecret(epoch_secret_n, "confirm")
external_secret_n := DeriveSecret(epoch_secret_n, "external")

confirmed_transcript_hash_n := H_L("confirmed-transcript",
    [interim_transcript_hash_{n-1}, anchor_tbs_n, signature_n, rotation_signature_n or h''])
confirmation_tag_n          := MAC(confirm_key_n, confirmed_transcript_hash_n)
interim_transcript_hash_n   := H_L("interim-transcript",
                                   [confirmed_transcript_hash_n, confirmation_tag_n])
```

* `init_secret_{-1}` and `interim_transcript_hash_{-1}` are `ZERO32`.
* The GroupContext binds the tree, the registry and the whole transcript
  into every epoch secret: members with diverging views derive different
  keys and fail the confirmation tag.
* **Joiners** receive `joiner_secret_n` in a welcome (section 10.3) and
  derive the rest; they never learn `init_secret_{n-1}`.
* **Erasure.** When epoch `n` becomes active, a member erases
  `init_secret_{n-1}`, `external_secret_{n-1}`, `joiner_secret_n`,
  `epoch_secret_n`, `confirm_key_n` and `msg_secret_n` (after deriving the
  message chains, section 11.2). It keeps `init_secret_n` and
  `external_secret_n` until epoch `n + 1` becomes active.

<a id="8-1-external-init"></a>
### 8.1 External init

From `external_secret_n` every member of epoch `n` derives the X-Wing
*external key pair* of the epoch, `external_n := KeyGen(external_secret_n,
"external kem")`. Its public key is published in the signed GroupInfo of
epoch `n` (section 10.4). The author of an external commit (a join or a
resync) encapsulates to it and uses the *external init secret* in place of
`init_secret_n` for epoch `n + 1`:

```text
(kem_output, shared) := X-Wing.Encaps(external_pk_n)
external_init_secret := ExpandLabel(Extract(ZERO32, shared), "external init", H(kem_output), 32)
```

Members recover `shared` by decapsulation. No member needs to be online for
an external commit.

<a id="9-commits"></a>
## 9. Commits

<a id="9-1-registry"></a>
### 9.1 Key registry

A commit is a CBOR map with a closed key registry. An unknown key, a key
absent where it is required or present where it is forbidden makes the
commit malformed (R required, O optional, - forbidden).

| Key | Name | Type | Genesis | Member | ExternalJoin | Resync |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | profile | tstr `"city-g/v0.3"` | R | R | R | R |
| 2 | gid | bstr .size 32 | R | R | R | R |
| 3 | epoch | uint (the epoch `n` it creates) | R (0) | R | R | R |
| 4 | kind | uint: 0 Genesis, 1 Member, 2 ExternalJoin, 3 Resync | R | R | R | R |
| 5 | prev_interim_transcript_hash | bstr .size 32 | R (`ZERO32`) | R | R | R |
| 6 | author_leaf | uint (the author's leaf in epoch `n`) | R (0) | R | R | R |
| 7 | tree_hash (epoch `n`) | bstr .size 32 | R | R | R | R |
| 8 | registry_hash (epoch `n`) | bstr .size 32 | R | R | R | R |
| 9 | update_path | UpdatePath (section 6.5) | R | R | R | R |
| 10 | removals | array of bstr (SignedRemoveProposal), at most 256 | - | R | R | R |
| 11 | joins | array of bstr (SignedJoinRequest), at most 64 | - | R | R | R |
| 12 | admin_changes | array of `[op, leaf, since]`, op 0 grant, 1 revoke | - | R | - | - |
| 13 | admission | bstr (SignedAdmission of the author) | - | - | R | - |
| 14 | external_init | bstr (X-Wing ciphertext) | - | - | R | R |
| 15 | group_nonce | bstr .size 32 | R | - | - | - |
| 16 | capacity | uint | R | - | - | - |
| 17 | new_device_pk | bstr (ML-DSA-65 public key) | - | O | - | - |
| 108 | author_device_pk | bstr (ML-DSA-65 public key) | R | R | R | R |
| 109 | signature | bstr | R | R | R | R |
| 110 | confirmation_tag | bstr .size 32 | R | R | R | R |
| 111 | rotation_signature | bstr | - | R iff 17 | - | - |

The encoded commit is at most `max_commit_bytes(capacity) :=
max_update_path_bytes(capacity) + 256 × 8 KiB + 64 × 32 KiB + 16 KiB + 64
KiB`.

<a id="9-2-signature"></a>
### 9.2 Signatures and confirmation tag

```text
anchor_tbs         := CBOR_det(commit map without keys 109, 110 and 111)
signature          := ML-DSA-65.Sign(author_sk, anchor_tbs, ctx = "city-g/anchor/v3")
rotation_signature := ML-DSA-65.Sign(new_sk,    anchor_tbs, ctx = "city-g/key-rotation/v1")
confirmation_tag   := MAC(confirm_key_n, confirmed_transcript_hash_n)
```

A commit carries one signature by its author (key 108), and a second one by
the author's new device key when it rotates it: the old key authorizes the
rotation and the new key proves possession. The confirmation tag cannot be
signed: it authenticates the confirmed transcript hash, which covers the
signatures.

<a id="9-3-kinds"></a>
### 9.3 Kinds

* **Genesis** (epoch 0): the first commit of a group, by its creator. It
  carries `group_nonce` and `capacity`; `gid` MUST equal `H_L("group-id",
  [author_device_pk, group_nonce])`. The staged tree holds the creator's
  leaf in leaf 0 (`since` 0, key `leaf_public_key`, admission hash
  `ZERO32`); the registry is the genesis registry; the key schedule starts
  from `init_secret_{-1} = ZERO32`.
* **Member**: by a current member. May remove members, place join requests,
  change admins (if the author is an admin) and rotate the author's device
  key (key 17). A Member commit with no change is a *self-update*.
* **ExternalJoin**: by a joiner holding a valid admission (key 13). It uses
  the external init of the previous epoch and may carry the other waiting
  removals and join requests.
* **Resync**: by a current member that lost its state or could not process a
  commit. It re-enters its own leaf as a new occupancy (`since = n`), keeping
  its device key, admission hash and admin rights, and uses the external
  init.

<a id="9-4-transition"></a>
### 9.4 Transition rules

A commit for epoch `n` applies to the public state of epoch `n - 1` in this
order:

1. **Pruning.** Retired admissions with `expires_epoch < n` are dropped.
2. **Removals.** Each removal proposal is authorized against epoch `n - 1`
   (section 10.1). A removal MUST NOT target the author of a Member or
   Resync commit, and a leaf MUST NOT be removed twice. Each removal ends
   its target's occupancy: the leaf and its direct path are blanked, the
   member loses its admin rights and its admission is retired (section 7).
3. **Admin changes** (Member commits only): the author MUST be an admin of
   epoch `n - 1`; each target `[leaf, since]` MUST be a current occupancy
   after step 2; grants (at most `MAX_ADMINS` admins) and revokes (the
   target MUST be an admin) apply in order.
4. **Entries**, each into the entry leaf (section 6.1) with `since = n`,
   added to the unmerged lists of its non-blank ancestors: first the author
   of an ExternalJoin (the entry leaf MUST equal `author_leaf`; its leaf key
   is the update path's `leaf_public_key`), then each join request in order
   (its leaf key is the request's `encryption_key`). For each entrant, its
   device MUST NOT be a member, and its admission MUST be authorized for
   `device_id := H_L("device-id", [gid, device_pk])` at epoch `n` against
   the admins and retired admissions at that point (section 10.2); its
   `admission_hash` goes into its leaf. The author of a Resync re-enters its
   own leaf instead: `since := n`, leaf key `leaf_public_key`, same device
   key and admission hash, unmerged at its ancestors.
5. **Rotation** (Member commits with key 17): the new device key MUST NOT be
   a member's; it replaces the author's device key.
6. **Promotion.** If no admin remains, the author becomes admin.
7. **Truncation** to the canonical width.
8. **Update path.** The author's update path is validated against the staged
   tree of steps 1 to 7 (section 6.5), then applied.

The resulting tree hash and registry hash MUST equal keys 7 and 8. The author
of a Member or Resync commit MUST be the member of `author_leaf` in epoch
`n - 1`, with device key `author_device_pk`; the author of an ExternalJoin
MUST NOT be a member.

<a id="9-5-verification"></a>
### 9.5 Verification

A verifier (the DS or a full member) checks, for a commit on state `n - 1`:
its encoding and key registry (section 9.1), the signatures (section 9.2),
`gid`, `epoch = n`, `prev_interim_transcript_hash =
interim_transcript_hash_{n-1}`, and the transition (section 9.4). A member
then runs the secret part: it decrypts the path (section 6.5; for its own
commit it uses the path secrets it generated), derives the epoch secrets
(section 8, from `init_secret_{n-1}` or the external init secret), and
checks the confirmation tag in constant time. A member MUST NOT use any
secret of epoch `n` before the confirmation tag verified.

<a id="10-signed-objects"></a>
## 10. Signed objects

<a id="10-1-removal"></a>
### 10.1 Removal proposals

```text
RemoveProposal := ["city-g/remove/v3", gid, target_leaf, target_since, proposer_device_pk]
signed with ctx "city-g/remove/v3" by proposer_device_pk
```

A proposal is authorized against an epoch when the occupancy `[target_leaf,
target_since]` is current and the proposer is the target itself (a
voluntary leave) or an admin. A member never commits its own removal:
removals are committed by another member, or by a joiner. A proposal is
single use: once the occupancy ends it no longer matches.

<a id="10-2-admission"></a>
### 10.2 Invites, admissions and revocations

```text
Invite           := ["city-g/invite/v2", gid, invite_pk, expires_at_ms, max_uses, inviter_device_pk]
                    signed with ctx "city-g/invite/v2" by inviter_device_pk (an admin)
Admission        := ["city-g/admission/v2", gid, device_id, not_after_epoch,
                     authorizer_kind, authorizer_pk, invite]
                    signed with ctx "city-g/admission/v2" by authorizer_pk
    authorizer_kind 0: authorizer_pk is an admin device key, invite = null
    authorizer_kind 1: authorizer_pk = invite_pk of the embedded SignedInvite (bstr)
InviteRevocation := ["city-g/invite-revocation/v1", gid, invite_id, revoker_device_pk]
                    signed with ctx "city-g/invite-revocation/v1" by an admin
admission_hash   := H(SignedAdmission)
```

An admin either signs an admission for a known device, or signs an invite
whose key pair derives from a 32-byte *invite seed* shared out of band
(`invite key := ML-DSA.KeyGen_internal(invite_seed)`); the joiner then signs
its own admission with the invite key. An admission is authorized for a
join of `device_id` entering epoch `n` against a membership when:

* its `gid` and `device_id` match;
* `n <= not_after_epoch <= n + MAX_ADMISSION_EPOCHS`;
* its hash is not retired, and `not_after_epoch > retired_floor` (section 7);
* its signer is the device key of an admin (kind 0), or the embedded invite
  is for `gid`, its signature verifies and its inviter is an admin (kind 1).

The tree records each member's `admission_hash`, so a DS cannot add a
member on its own. Invite expiry (a time), use count (`max_uses`) and
revocation need a clock or a global count and are enforced by the DS
(section 12).

<a id="10-3-join"></a>
### 10.3 Join requests and welcomes

```text
JoinRequest := ["city-g/join-request/v1", gid, device_pk, encryption_key, init_key, SignedAdmission]
               signed with ctx "city-g/join-request/v1" by device_pk
request_ref := H_L("proposal-ref", [SignedJoinRequest])

Welcome := ["city-g/welcome/v1", gid, epoch, request_ref, kem_ciphertext, wrapped]
    (kem_ciphertext, shared) := X-Wing.Encaps(init_key)
    context := CBOR_det([gid, epoch, request_ref, H_pk(init_key)])
    wrapped := ChaCha20-Poly1305(ExpandLabel(shared, "welcome key", context, 32),
                                 ExpandLabel(shared, "welcome nonce", context, 12),
                                 aad = context, pt = joiner_secret_epoch)
```

A joiner publishes a signed request: its device key, the X-Wing key of its
future leaf (`encryption_key`), a one-time X-Wing key for its welcome
(`init_key`) and its admission. A request is authorized for epoch `n` when
the device is not a member and its admission is authorized for epoch `n`.
The author of the commit that includes it seals one welcome per request, in
the order of key 11. A welcome is not signed: the joiner checks the secret
it carries against the confirmation tag of the commit and the GroupInfo its
author signed.

**Entering with a welcome.** The joiner obtains the commit of epoch `n`,
the GroupInfo, tree and registry of epoch `n` (or, as a light member, the
data of section 14.4) and its welcome. It checks that the commit includes
its request unchanged and creates epoch `n`; opens the welcome with
`init_key`; derives the epoch secrets from `joiner_secret_n`; checks the
confirmation tag and the GroupInfo (its external public key MUST derive from
the epoch); finds its leaf (`since = n`, its `encryption_key`); decrypts the
commit's update path with its leaf key (section 6.5); and erases `init_key`.
A welcome is usable only while the joiner can obtain the state of epoch `n`;
afterwards the joiner resyncs (section 13.1). The joiner cannot check the
history before epoch `n` (section 2.3).

<a id="10-4-group-info"></a>
### 10.4 GroupInfo

```text
GroupInfo := ["city-g/group-info/v3", GroupContext_n (bstr), confirmation_tag_n,
              external_pk_n, signer_leaf]
             signed with ctx "city-g/group-info/v3" by the device key of signer_leaf
```

The author of epoch `n` signs the GroupInfo of that epoch (with its new key
after a rotation) and publishes it with its commit; `signer_leaf` is its
leaf. A joiner or resyncing member verifies it against the tree and registry
the DS provides: their hashes MUST match those in `GroupContext_n` and the
signature MUST verify under the device key of `signer_leaf` in that tree.
The interim transcript hash it derives (`H_L("interim-transcript",
[confirmed_transcript_hash_n, confirmation_tag_n])`) becomes the
`prev_interim_transcript_hash` of its external commit.

<a id="10-5-cover-failure"></a>
### 10.5 Cover-failure reports

```text
CoverFailureReport := ["city-g/cover-failure/v2", gid, epoch, reporter_device_pk, reason]
                      signed with ctx "city-g/cover-failure/v2" by the reporter
reason: 1 not covered, 2 path key mismatch, 3 confirmation tag mismatch, 4 state lost
```

A member that cannot process the commit of epoch `epoch` signs a report
naming it; the DS records reports of current members about the current
epoch, so the failure and the author of the faulty commit are visible to
every member. The reporter then re-enters the group with a Resync commit:
with a chained key schedule, a member that missed an epoch can only come
back through the external init.

<a id="11-message-plane"></a>
## 11. Message plane v4

<a id="11-1-framing"></a>
### 11.1 Framing and envelope

```text
FramedContent  := ["city-g/msg/v4", gid, epoch, sender_leaf, sender_since, generation,
                   content_type, authenticated_data, signed_timestamp_ms, plaintext]
signature      := ML-DSA-65.Sign(sender_sk, CBOR_det(FramedContent), ctx = "city-g/msg/v4")
EnvelopeHeader := ["city-g-msg-v4", epoch_ref, sender_leaf, sender_since, generation, key_commitment]
Envelope       := [EnvelopeHeader fields..., ciphertext]
ciphertext     := ChaCha20-Poly1305(key_g, nonce_g, aad = CBOR_det(EnvelopeHeader),
                                    pt = CBOR_det([CBOR_det(FramedContent), signature]))
```

`content_type` 1 is UTF-8 text. Plaintexts are at most 256 KiB and
authenticated data at most 4 KiB.

<a id="11-2-ratchet"></a>
### 11.2 Per-sender ratchet

When an epoch becomes active, every member derives one chain per member of
the epoch and erases `msg_secret_n`:

```text
sender_secret_0     := ExpandLabel(msg_secret_n, "msg sender", CBOR_det([leaf, since]), 32)
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

1. selects the epoch by `epoch_ref`: the current epoch, or one of the
   `MAX_GRACE_EPOCHS` (4) previous ones while their keys are kept (at most
   `GRACE_WINDOW_MS` after the epoch that followed them became active);
2. requires `[sender_leaf, sender_since]` to be a member of that epoch **and
   of the current epoch** (the same occupancy), without a recorded removal:
   a member removed by a later commit cannot keep sending during the grace
   window;
3. derives `key_g` and `nonce_g`: at most `MAX_FORWARD_GENERATIONS` (1024)
   ahead of the chain; keys of skipped generations are kept, at most
   `MAX_SKIPPED_KEYS` (256) per sender; a key is deleted once used, so a
   replayed or too-old generation has no key and is rejected;
4. checks the key commitment, opens the ciphertext, decodes the framed
   content and checks that its `gid`, `epoch`, sender and `generation` match
   the envelope;
5. verifies the signature under the device key the sender held in that
   epoch: its current key, or, if it rotated its key since, the key it held
   then;
6. only then releases the plaintext. Applications display
   `signed_timestamp_ms` and the sender from the tree.

<a id="12-delivery-service"></a>
## 12. Delivery service

The DS keeps, per group, a *ledger* (the public state, the replay state of
the current and recent epochs, recorded proposals and join requests,
invites, welcomes and cover-failure reports) and an ordered *log*.

<a id="12-1-ledger"></a>
### 12.1 Ledger rules

* **Genesis.** A group is created by a valid genesis commit (section 9)
  with its GroupInfo; `gid` MUST NOT exist.
* **Ordering.** The first valid commit for epoch `n + 1` wins. A later
  commit for the same epoch is rejected with an epoch mismatch; its author
  syncs and rebuilds on the new epoch.
* **Recorded proposals.** A removal proposal is recorded only if it is
  authorized against the current epoch, and once per target occupancy. A
  join request is recorded only if it is authorized for the next epoch, its
  device has no other recorded request, the group has room for every member
  and recorded request, and its invite (if any) is valid (below); recording
  the same object twice is idempotent. Each is tagged with the epoch in
  which it was recorded.
* **Overdue proposals.** A proposal recorded before the current epoch
  started is *overdue*. A commit MUST include every overdue removal (the
  oldest `MAX_REMOVALS_PER_COMMIT` when more are waiting) and the oldest
  overdue join requests, up to `MAX_JOINS_PER_COMMIT`. Proposals recorded
  during the current epoch MAY wait for the next commit, so a commit never
  fails because a proposal arrived while it was being built. After each
  commit, the proposals it did not include are authorized again and dropped
  if they no longer apply.
* **GroupInfo and welcomes.** The GroupInfo published with a commit MUST be
  signed by the commit's author for its leaf and describe exactly the epoch
  the ledger computed. The commit comes with one welcome per join request it
  includes, in order, each naming its request and epoch; the DS stores them
  by `request_ref` (at most `MAX_WELCOMES` = 4096 per group, oldest out
  first) and answers a request's status: pending, committed (with its epoch
  and welcome) or unknown. The DS never signs a GroupInfo itself.
* **Invites.** Admin-signed invites are stored by `invite_id` (at most
  `MAX_INVITES` = 256 per group). An expired invite (by the DS clock), a
  revoked one (an admin-signed revocation; at most `MAX_REVOKED_INVITES` =
  1024 remembered) or one that already admitted `max_uses` joins is refused,
  and so is a join whose admission embeds it; revoking an invite drops the
  recorded join requests that rely on it. A use is counted when a join
  request is recorded, or when an external join that was not recorded as a
  request is accepted.
* **Messages.** An envelope is accepted for the current epoch, or for one of
  the `MAX_GRACE_EPOCHS` previous epochs during `GRACE_WINDOW_MS` after that
  epoch ended, only from a sender that is a member of the current epoch (the
  same occupancy) and of the envelope's epoch, without a recorded removal,
  and at most once per `(epoch, sender, generation)` (a 64-generation sliding
  window per sender). The DS cannot check the ciphertext.
* **Cover failures.** Reports of current members naming the current epoch
  are recorded (at most `MAX_COVER_FAILURES` = 256 per group).
* **Light-member data.** For each accepted commit the DS computes its
  LightCommit (section 14.3) from the tree the commit starts from, which only
  it still holds afterwards, and keeps it with the commit in the log. It
  serves leaf proofs against the current tree, and the LightJoin (section
  14.4) of a committed join request while the commit's epoch is the current
  one.

<a id="12-2-log"></a>
### 12.2 Log

Every accepted commit (with its GroupInfo and LightCommit), envelope,
recorded removal proposal and recorded join request is appended to the group
log with a sequence number `seq` (starting at 1 with the genesis commit),
its epoch and the DS acceptance time. Members read the log in order, in
pages that also give `first_seq`, the oldest retained entry. Messages expire
after a retention period, commits after a longer one, and the log keeps at
most a bounded number of entries: when it is full, the oldest message or
proposal goes first, then the oldest commit; neither the entry being
appended nor the latest commit is ever dropped. Messages that expired before
a member read them are lost to it; a member that meets a commit of a later
epoch than the next one it needs has lost a commit and resyncs (section
13.2).

<a id="12-3-journal"></a>
### 12.3 Persistence

A DS journals a record of every state change before answering the request
that caused it, and restores a group by replaying its records on its latest
snapshot; replay is deterministic, derived data such as LightCommits
included. A request whose record could not be written fails, and the
in-memory group is reloaded from storage.

<a id="13-member-behavior"></a>
## 13. Member behavior

<a id="13-1-create-join"></a>
### 13.1 Creating and joining

* **Create.** Draw `group_nonce`, build the genesis commit and GroupInfo,
  publish them.
* **Admission.** With an invite link (section 15.3), the joiner derives the
  invite key, fetches the invite by `invite_id` and signs its own admission
  with the invite key, for `device_id` of its fresh device key; or an admin
  signs its admission directly. Made while epoch `n` is current, an
  admission gets `not_after_epoch := min(max(n + validity, retired_floor +
  1), n + MAX_ADMISSION_EPOCHS)` (the reference clients use a validity of
  1024 epochs).
* **Batched join.** The joiner records a join request and polls its status
  for a short, randomized time (the reference client waits between 1 and 2
  seconds). If a commit included it while its epoch is still the current
  one, the joiner enters with its welcome (section 10.3). If nobody commits
  it in time, the joiner authors an ExternalJoin that includes every
  recorded removal and the other waiting requests (whose authors enter with
  welcomes). If its request was committed but the group moved on before the
  joiner could read that epoch, the joiner resyncs. On an epoch mismatch it
  rebuilds on the new epoch; if its request was committed meanwhile, it
  reads its welcome instead.

<a id="13-2-sync"></a>
### 13.2 Following the log

A member processes log entries in order: commits (section 9.5), recorded
removal proposals (messages from their targets are rejected from then on),
join requests, and envelopes (section 11.3). If it cannot process a commit,
it signs a cover-failure report and resyncs with a Resync commit; it also
resyncs when a commit it needs is no longer in the log. If a commit removes
it, it deletes the group state. A commit of its own that it did not see
accepted (a lost reply) is recognised when it appears in the log.

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

* Online members commit the recorded proposals of *other* members (removals
  and join requests); committers SHOULD wait a random delay to limit
  concurrent commits.
* A member MUST re-key its own leaf (a self-update) at least every
  `FS_WINDOW` (default 24 hours).
* A member erases the keys of a previous epoch `GRACE_WINDOW_MS` after the
  next epoch became active.
* A member whose own removal is recorded stops committing and sending.
* A member MAY rotate its device key with a Member commit (key 17), for
  instance when it suspects its key store; it then signs with the new key
  only.

<a id="14-light-members"></a>
## 14. Light members

<a id="14-1-state"></a>
### 14.1 State

A full member holds the whole public tree: about 4 KB per member (a device
key and a leaf key per leaf, a key per parent node), so tens of megabytes
for the largest groups. A *light member* holds instead:

* `GroupContext_n` and `interim_transcript_hash_n`;
* the registry (small, and checked against `registry_hash` at every commit);
* the occupied leaves with the epoch each occupancy began (a few bytes per
  member): with them it places entering members exactly like the tree does
  (section 6.1) and derives the message chains (section 11.2);
* its own leaf record, its private path keys and the epoch secrets, like a
  full member;
* the device keys of the members it verified (at most `MAX_KNOWN_KEYS` =
  1024), kept current through the commits it processes: a key ends with its
  occupancy, and a rotation replaces it.

A full member becomes light by dropping its tree; a light member becomes
full by fetching the snapshot of its current epoch and checking that it
matches its context, registry, occupancies, own record and private keys.

<a id="14-2-processing"></a>
### 14.2 Processing a commit

A light member processes the commit of epoch `n` with its LightCommit
(section 14.3), in this order:

1. the checks of section 9.5 that need no tree: encoding and key registry,
   signatures, `gid`, `epoch`, `prev_interim_transcript_hash`;
2. each proof of the LightCommit MUST verify against `tree_hash_{n-1}`
   (section 6.7) and show an occupancy the light member knows (its own
   record if it is its leaf);
3. the transition of section 9.4, steps 1 to 7, on its *partial tree*: the
   occupancies, plus the member records proven in step 2 and those the
   commit itself brings (entrants). Authorizations that need a member record
   use only these records, so a missing proof makes the commit fail;
4. the update path's shape: `log2(width_n)` entries on the author's direct
   path, valid keys and ciphertext sizes, where `width_n` is the canonical
   width of the occupancies after step 3;
5. the registry hash of step 3 MUST equal key 8;
6. if the commit removes the light member, it stops here;
7. the path secret: the entry of the lowest common ancestor with the author
   (section 6.5), and in it the target naming a node whose private key the
   light member holds; then the derived public keys MUST match the published
   ones;
8. the epoch secrets, with `tree_hash_n` taken from key 7, and the
   confirmation tag; the GroupInfo, when present, MUST match the epoch and
   verify under the author's key (its new key after a rotation);
9. its private keys: it drops the keys of nodes on the direct path of a
   removed leaf, of nodes above the new root and of the author's path, then
   stores the keys derived in step 7.

<a id="14-3-light-commit"></a>
### 14.3 LightCommit

```text
LightCommit := ["city-g/light-commit/v1", [LeafProof, ... by increasing leaf]]
```

The proofs, against the tree of epoch `n - 1`, of every member record the
commit's authorization refers to: the author of a Member or Resync commit;
the target of each removal and, when it is not the target, the member whose
device key signed it; and the member whose device key authorized each
admission (the admin of a kind-0 admission, the inviter of a kind-1 one).
A LightCommit is at most 8 MiB.

<a id="14-4-light-join"></a>
### 14.4 Light join

```text
LightJoin := ["city-g/light-join/v1", Registry (bstr), [MemberRef, ...], LeafProof]
```

For a committed join request whose epoch `n` is still current, the DS gives
the registry of epoch `n`, its occupancies and the joiner's leaf proof. The
joiner checks its welcome and the confirmation tag as in section 10.3, the
GroupInfo under the author's key, the registry against key 8 of the commit,
its leaf proof against key 7 (the leaf MUST hold its own record, `since =
n`), and that the occupancies include itself, the author and every admin and
fit the capacity; it then decrypts the update path with its leaf key. The
occupancy list is not authenticated: a wrong list makes the joiner's view
diverge, which the next commit it processes detects (a width or entry-leaf
mismatch). A LightJoin is at most 1 MiB.

<a id="14-5-messages"></a>
### 14.5 Messages and commits

* A message from a sender whose key the light member does not know waits
  until the member obtains a leaf proof of the sender against the current
  tree hash; senders of messages received while catching up are proven once
  the member reached the DS's epoch. Keys of previous epochs follow section
  11.3.
* Removal proposals read from the log block their target's messages, as for
  a full member; the light member checks the proposal's signature and
  target, and relies on the DS for the proposer's authorization.
* A light member does not author commits. To commit (a self-update, its
  own maintenance, a rotation), it becomes full with the snapshot of its
  epoch, commits, and becomes light again.

<a id="14-6-trust"></a>
### 14.6 What a light member relies on

A light member verifies every signature, every authorization (removals,
admin changes, admissions, retired admissions), the entry leaves, the
registry, the path secrets and the confirmation tag. It cannot recompute the
new tree hash, nor check that a joining device or a rotated key is not
already used elsewhere in the tree; for these it relies on the DS, which
verifies every commit on the full tree, and on the committer, whose tree
hash the confirmation tag binds. Consequently, against a DS that colludes
with a member, **membership agreement** holds for light members only up to
the tree hash: they can be shown a tree that full members reject. Admission
control, sender authentication and the confidentiality properties of section
2.2 are unchanged: the DS still cannot forge a commit or authorize an
admission.

<a id="15-deployment-binding"></a>
## 15. Deployment binding and HTTP API

This section is outside the group protocol: its objects change no group
state and no key.

<a id="15-1-binding-objects"></a>
### 15.1 Binding objects

```text
AliasBinding := ["city-g/alias/v1", gid, device_pk, alias]
                signed with ctx "city-g/identity-binding/v1" by device_pk
SessionAuth  := ["city-g/session-auth/v1", gid, device_pk, issued_at_ms]
                signed with ctx "city-g/session-auth/v1" by device_pk
```

* An alias is a display name a member claims for itself: 1 to 64 bytes of
  UTF-8, no control characters, no leading or trailing whitespace. It is
  self-asserted; clients SHOULD pin the device key first seen for an alias
  and warn when a different occupancy claims it (trust on first use). A new
  key on the same occupancy is a rotation its old key signed.
* A SessionAuth fresh within the DS clock skew (default 5 minutes) and
  signed by a current member's device key is exchanged for a 32-byte bearer
  token (default lifetime 1 hour). A token stops working when its member's
  occupancy ends or its key is rotated.

<a id="15-2-api"></a>
### 15.2 HTTP API

Every request is an HTTP `POST` of a protobuf message
([`crates/cityg-proto/proto/cityg_v3.proto`](../crates/cityg-proto/proto/cityg_v3.proto))
whose field 1 is `gid`; protocol objects travel as their exact
deterministic-CBOR bytes. Bodies are at most 16 MiB. Routes marked *token*
require `Authorization: Bearer <hex token>`.

| Route | Request → response | Token |
| --- | --- | --- |
| `/v3/groups/create` | genesis commit + GroupInfo → epoch, seq | |
| `/v3/groups/info` | → GroupInfo, tree, registry, recorded removals and join requests, head seq | |
| `/v3/groups/commit` | commit + GroupInfo + welcomes → epoch, seq | |
| `/v3/groups/log` | after_seq, limit (default 256, at most 1024), light → entries (commits with their LightCommit when `light`), head_seq, first_seq | token |
| `/v3/groups/remove_proposal` | SignedRemoveProposal → recorded / already_recorded | |
| `/v3/groups/join_request` | SignedJoinRequest → request_ref, recorded / already_recorded | |
| `/v3/groups/join_status` | request_ref, light → pending / committed (epoch, welcome, commit) / unknown, current epoch, LightJoin when `light` | |
| `/v3/groups/invite` | SignedInvite → invite_id | |
| `/v3/groups/invite/get` | invite_id → SignedInvite | |
| `/v3/groups/invite/revoke` | SignedInviteRevocation → references of the dropped join requests | |
| `/v3/groups/send` | Envelope → epoch, seq | token |
| `/v3/groups/cover_failure` | CoverFailureReport → count | |
| `/v3/groups/cover_failures` | → reports | token |
| `/v3/groups/session` | SessionAuth → token, expires_at_ms | |
| `/v3/groups/alias` | AliasBinding → count | |
| `/v3/groups/aliases` | → bindings of current members | token |
| `/v3/groups/leaf_proofs` | leaves (at most 64) → epoch, one LeafProof per leaf against the current tree | |

Errors carry a protobuf `ErrorResponse {code, message}` with these HTTP
statuses: 400 malformed request or non-deterministic encoding, 401 missing
or invalid token, 403 not allowed (not a member, pending removal, not an
admin, revoked or used-up invite), 404 unknown group or invite, 409 conflict
(stale epoch, overdue proposals not committed, a pending request of the same
device, replay, existing group), 410 a route of a removed API version
(`/v1/` and `/v2/`), 413 over a size or count limit, 422 verification
failure, 429 rate limited (the reference DS does not rate-limit; a
deployment may, in front of it), 500 internal error.

**Notifications.** `GET /v3/ws?gid=<hex>&token=<hex>` upgrades to a
WebSocket that sends `{"type":"head","gid":…,"head_seq":N}` when the log
grows, and `{"type":"resync","gid":…}` when notices were dropped; the client
then fetches the log.

<a id="15-3-invite-link"></a>
### 15.3 Invite links

```text
cityg-invite:{"version":5,"server_url":"<DS URL>","room_id":"<gid hex>","invite_seed":"<hex, 32 bytes>"}
```

The invite seed is a bearer secret: anyone holding the link can join until
the invite expires, is revoked or has admitted `max_uses` devices. Links
SHOULD be shared over an authenticated channel and given a short lifetime
(default 7 days) and a use count matching their audience.

<a id="16-parameters"></a>
## 16. Parameters

| Name | Value |
| --- | --- |
| `MAX_CAPACITY` | 8192 leaves (`capacity` a power of two, at least 2) |
| `MAX_ADMINS` | 64 |
| `MAX_RETIRED` | 4096 retired admissions per registry |
| `MAX_ADMISSION_EPOCHS` | 4096 epochs of validity at most per admission |
| `MAX_REMOVALS_PER_COMMIT`, `MAX_JOINS_PER_COMMIT` | 256, 64 |
| `FS_WINDOW` | 24 hours (self-update interval) |
| `GRACE_WINDOW_MS` | 600 000 (10 minutes) |
| `MAX_GRACE_EPOCHS` | 4 previous epochs |
| `MAX_FORWARD_GENERATIONS` | 1024 |
| `MAX_SKIPPED_KEYS` | 256 per sender |
| Replay window of the DS | 64 generations per sender and epoch |
| Plaintext / authenticated data | 256 KiB / 4 KiB per message |
| Envelope | at most 256 KiB + 4 KiB + 16 KiB |
| Signed invite / admission / removal proposal / join request / welcome / invite revocation / GroupInfo / cover-failure report / binding | 8 / 16 / 8 / 32 / 2 / 8 / 16 / 8 / 12 KiB |
| Commit | `max_commit_bytes(capacity)` (section 9.1) |
| Leaf proof / LightCommit / LightJoin | 8 KiB / 8 MiB / 1 MiB |
| `MAX_INVITES`, `MAX_COVER_FAILURES` | 256 per group |
| `MAX_WELCOMES`, `MAX_REVOKED_INVITES` | 4096, 1024 per group |
| `MAX_KNOWN_KEYS` (light members) | 1024 device keys |
| Leaf proofs per request | 64 |
| DS defaults | largest capacity 1024, message retention 7 days, commit retention 30 days, 50 000 log entries, session tokens 1 hour, SessionAuth skew 5 minutes |
| Client defaults | admissions valid 1024 epochs, join wait 1 to 2 s, invite links 7 days |

<a id="17-label-registry"></a>
## 17. Label registry

<a id="17-1-labelled-hashes"></a>
### 17.1 Labelled hashes (`H_L`)

| Label | Arguments | Section |
| --- | --- | --- |
| `group-id` | `[creator_device_pk, group_nonce]` | 5 |
| `device-id` | `[gid, device_pk]` | 5 |
| `invite-id` | `[invite_pk]` | 5 |
| `proposal-ref` | `[signed proposal or join request]` | 5 |
| `kem-pk` | `[pk]` | 5 |
| `msg/epoch-ref` | `[gid, epoch]` | 5 |
| `tree/leaf` | `[leaf, LeafNode or null]` | 6.3 |
| `tree/parent-node` | `[encryption_key, unmerged]` | 6.3 |
| `tree/parent` | `[node_digest or null, left_hash, right_hash]` | 6.3 |
| `registry` | `[capacity, admins, retired, retired_floor]` | 7 |
| `confirmed-transcript` | `[prev_interim, anchor_tbs, signature, rotation_signature or h'']` | 8 |
| `interim-transcript` | `[confirmed, confirmation_tag]` | 8 |
| `msg/key-commitment` | `[key, nonce]` | 11.2 |

<a id="17-2-derivation-labels"></a>
### 17.2 Derivation labels and object labels

| Kind | Labels |
| --- | --- |
| `ExpandLabel` / `DeriveSecret` / `KeyGen` | `joiner`, `epoch`, `init`, `msg`, `confirm`, `external`, `external kem`, `external init`, `tree leaf key`, `tree path`, `tree node key`, `tree path wrap key`, `tree path wrap nonce`, `welcome key`, `welcome nonce`, `msg sender`, `msg next`, `msg key`, `msg nonce` |
| Framing tags | `city-g/v0.3` (H_L), `city-g/v0.3 expand`, `city-g/v0.3 mac` |
| Encoded objects | `city-g/group-context/v3`, `city-g/remove/v3`, `city-g/invite/v2`, `city-g/admission/v2`, `city-g/invite-revocation/v1`, `city-g/join-request/v1`, `city-g/welcome/v1`, `city-g/group-info/v3`, `city-g/cover-failure/v2`, `city-g/msg/v4`, `city-g-msg-v4` (envelope header), `city-g/light-commit/v1`, `city-g/light-join/v1`, `city-g/alias/v1`, `city-g/session-auth/v1` |

<a id="17-3-contexts"></a>
### 17.3 Signature contexts (FIPS 204 `ctx`)

| Context | Signed object |
| --- | --- |
| `city-g/anchor/v3` | commit (`anchor_tbs`), by the author |
| `city-g/key-rotation/v1` | commit (`anchor_tbs`), by the author's new device key |
| `city-g/group-info/v3` | GroupInfo |
| `city-g/admission/v2` | Admission |
| `city-g/invite/v2` | Invite |
| `city-g/invite-revocation/v1` | InviteRevocation |
| `city-g/join-request/v1` | JoinRequest |
| `city-g/remove/v3` | RemoveProposal |
| `city-g/cover-failure/v2` | CoverFailureReport |
| `city-g/msg/v4` | FramedContent |
| `city-g/identity-binding/v1` | AliasBinding |
| `city-g/session-auth/v1` | SessionAuth |
| `city-g/policy/v1` | deployment policy documents (reserved) |

Any change to an encoding, a label or a context is a new profile version.

<a id="18-conformance"></a>
## 18. Conformance

* [`kat/v0.3/vectors.json`](../kat/v0.3/vectors.json) holds vectors for
  `CBOR_det`, `H_L`, the KDF functions, the identifiers, the X-Wing draft
  vector and the ML-DSA-65 signatures of the suite, the key schedule
  (joiner secret) and external init, the tree hash and a leaf proof, the
  registry hash, the path-secret and welcome wraps, a complete genesis
  commit with its GroupInfo and two messages of epoch 0, and every signed
  array layout.
* The reference implementation recomputes them
  (`cargo test -p cityg-core --test vectors`).
* [`kat/v0.3/verify_vectors.py`](../kat/v0.3/verify_vectors.py) recomputes
  them independently from this document (CBOR, BLAKE3 derivations,
  ChaCha20-Poly1305, X-Wing and ML-DSA-65 re-implemented or taken from
  independent libraries), including the genesis tree hash, registry hash,
  transcript hashes, confirmation tag, the leaf proof and the decryption of
  the messages.
* [`kat/kat-v0.3-conformance-manifest.json`](../kat/kat-v0.3-conformance-manifest.json)
  maps each requirement to this document and to the vectors and tests that
  exercise it.
* The symbolic model in [`docs/formal/`](formal/) (ProVerif) proves, in
  bounded scenarios and with ideal primitives, the confidentiality of epoch
  secrets and welcomes against the delivery service, membership agreement
  (joiners included, when they check the GroupInfo under a key they know),
  admission control, join secrecy, forward secrecy, post-compromise security
  after a self-update, the authentication of a member's commits and
  messages after it rotated its device key even if the old key leaks,
  post-removal secrecy, and sender authentication. Sanity scenarios find the
  attacks that the author rule and retired admissions prevent, and the
  forked view of section 2.3. Its README lists the abstractions.

<a id="19-security-considerations"></a>
## 19. Security considerations

* **Batched joins.** A commit places every waiting join request at once, so
  the cost of a commit grows with the number of joiners but the number of
  epochs does not: a group absorbs a wave of joins in one epoch instead of
  one epoch per joiner, and members re-key once. The overdue rule (section
  12.1) keeps committers from skipping recorded removals and joins: every
  commit includes the oldest overdue ones, up to the caps, so a proposal
  waits for the next commit, plus the commits needed for the backlog ahead
  of it.
* **Unmerged leaves.** A joiner does not know the parent keys above it until
  a commit re-keys them; encryptors add it to the resolution of those nodes.
  The number of ciphertexts of an update grows with the unmerged leaves, and
  shrinks back as members self-update. Removals blank the direct path of the
  removed leaf, which also makes resolutions larger until the next
  self-updates. `FS_WINDOW` bounds both effects.
* **Welcomes.** The welcome's `init_key` is distinct from the leaf key and
  used once: the leaf key of a member may leak later without exposing the
  epoch of its join.
* **Retired admissions.** Admissions carry a validity window
  (`not_after_epoch`), so the registry keeps only the admissions that could
  still be used. Its size is bounded without letting a removed member back:
  under heavy churn (more than `MAX_RETIRED` removals within an admission's
  validity), the retired floor refuses the admissions whose entries were
  dropped, at the price of shortening the window in which new admissions can
  be used.
* **Device-key rotation.** A rotation is authorized by the old key and
  proven by the new one; messages of previous epochs still verify under the
  key held then. A rotation does not change the occupancy, the admission or
  the admin rights.
* **Joiners.** A joiner trusts the DS for the state of the epoch it enters,
  and compares its security code with a member it knows to detect a forked
  view (section 2.3). The admin that admitted it does not need to be online.
* **Light members.** See section 14.6.
* **Large groups.** The largest update of an 8192-leaf tree is under 10 MB
  and a full tree of 8192 members about 35 MB. A light member of such a
  group keeps its occupancies and registry (a few hundred kilobytes), the
  device keys it verified and its message ratchets: a few megabytes at
  most.

<a id="20-changes"></a>
## 20. Changes from profile v0.2

Profile v0.3 is a new protocol; v0.2 groups cannot be upgraded in place.

| v0.2 | v0.3 | Section |
| --- | --- | --- |
| Fixed barrier tree of `n_max` slots in heap order, and a separate roster | Growable ratchet tree in the RFC 9420 array layout holding the members, and a registry for capacity, admins and retired admissions | 6, 7 |
| One join per external commit | Join requests recorded concurrently and placed by any commit, welcomes with the joiner secret, unmerged leaves | 9.4, 10.3, 12.1 |
| `leaf_id` and slot generations | `device_id`, and member references `[leaf, since]` | 5 |
| The last 4096 removed device ids, retired for good | Admissions valid for a bounded number of epochs, retired while valid, and a retired floor when the list overflows | 7, 10.2 |
| Device keys never rotated | Rotation by a Member commit signed by the old and the new key | 9.2, 9.3 |
| ML-KEM-768 | X-Wing (ML-KEM-768 and X25519) | 3 |
| ML-DSA-87 | ML-DSA-65 | 3 |
| `epoch_secret` from the commit secret and init secret | `joiner_secret` step, `commit_secret` one step past the root | 8 |
| Invites expire | Invites also count their uses and can be revoked | 10.2, 12.1 |
| Late messages for one previous epoch | Up to four previous epochs, each for `GRACE_WINDOW_MS` | 11.3, 12.1 |
| Every recorded removal in the next commit | Overdue proposals (recorded before the current epoch) in the next commit, up to the caps | 12.1 |
| Every member holds the whole tree | Light members with Merkle proofs of the records they need | 6.7, 14 |
| `n_max` at most 1024 | Capacity up to 8192 | 6.1 |
