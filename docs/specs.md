# City-G protocol specification

| | |
| --- | --- |
| Profile | `city-g/v0.4` |
| Status | Initial version. The key schedule, the tree, windows, welcomes, joins and the delivery-service rules are specified and implemented; the items of section 19 are not yet. |
| Implementation | [`crates/cityg-core`](../crates/cityg-core): protocol core and an in-memory delivery service, no I/O |
| Design | [design.md](design.md) (decisions E-1 to E-14) |
| Formal model | [`formal/`](formal/README.md) (ProVerif) |
| Research | [`research/grands-groupes-2026-09-25.md`](research/grands-groupes-2026-09-25.md) (in French); cost model [`research/rekey_sim.py`](research/rekey_sim.py); a proposed message plane, [`research/plan-de-messages-2026-09-26.md`](research/plan-de-messages-2026-09-26.md), and the guarantees of MLS at this scale, [`research/parite-mls-2026-09-26.md`](research/parite-mls-2026-09-26.md) (both in French) |
| Conformance | None yet: no test vectors (section 19) |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be
interpreted as in RFC 2119 and RFC 8174 when they appear in capitals.

City-G is an end-to-end encrypted group protocol with post-quantum
primitives, built for groups of millions of members, bursts of hundreds of
thousands of joins and departures, and groups where no member may be online
for long periods. Its group key agreement follows the structure of MLS
(RFC 9420): a ratchet tree whose root secret feeds an epoch-chained key
schedule, transcript hashes and confirmation tags, welcomes for members
added by someone else, and an external init for a device that is not yet a
member (section 20). It changes how the group is re-keyed:

* the group changes by *windows*: the delivery service collects requests
  for up to a minute, and one epoch seals them all;
* the tree is split into *districts* under a *city*; each district that
  changes is re-keyed by its own committer, in parallel, and a *sealer*
  re-keys the city and creates the epoch;
* any member can commit any district or seal a window; when no member is
  online, a joiner or a returning member seals the window itself;
* a group can be *open*: any device joins without an admin's signature, and
  every join stays visible (section 6.1);
* a member downloads one small packet per window and keeps O(log N) state.

A delivery service (DS) orders and checks everything without holding any
group secret.

## Contents

1. [Architecture](#1-architecture)
2. [Security goals and threat model](#2-security)
3. [Cryptographic suite and encodings](#3-suite)
4. [Identifiers](#4-identifiers)
5. [Tree](#5-tree)
6. [Signed requests](#6-requests)
7. [Re-key](#7-rekey)
8. [Registry](#8-registry)
9. [Key schedule](#9-key-schedule)
10. [Windows: district commits and seals](#10-windows)
11. [Welcomes](#11-welcomes)
12. [Members](#12-members)
13. [Packets, seal links and entries](#13-packets)
14. [Delivery service](#14-delivery-service)
15. [Audits and fraud proofs](#15-audits)
16. [Parameters](#16-parameters)
17. [Label registry](#17-labels)
18. [Security considerations](#18-security-considerations)
19. [Open items](#19-open-items)
20. [Relation to MLS](#20-mls)

<a id="1-architecture"></a>
## 1. Architecture

* **Device and occupancy.** A member device holds an ML-DSA-65 device key
  per group, and occupies one leaf from the epoch it entered, `since`. The
  pair `[leaf, since]`, its *occupancy*, names the member for good: it is
  never reused, even when the leaf is.
* **Tree.** A binary tree of `2^height` leaves, split into districts of
  `2^L` leaves (section 5). Members hold X-Wing leaf keys; every non-blank
  parent node holds an X-Wing key and its *taint*, the occupancy of the
  committer that drew its secret.
* **Window.** The delivery service (DS) collects requests: joins, removals,
  evictions, key updates, re-entries and catch-ups (section 6). It closes a
  window after at most `WINDOW_MAX`, or `WINDOW_REMOVAL` when a removal is
  pending (section 14.2). A window is sealed in three phases:
  1. one *district commit* per district the window changes (section 10.3);
  2. one *seal*, which re-keys the city and creates the epoch (section
     10.4);
  3. the *welcomes* of the window's joiners and returning members
     (section 11).
* **Roles.** The DS assigns the committers and the sealer of a window among
  online members. With no member online, the window's *entrant* (a joiner
  or a member re-entering its leaf) takes every role and seals with an
  external init (section 12.7). With no member online and no entrant, the
  window stays open and recorded removals are enforced at delivery
  (section 14.6).
* **Members.** A member keeps its leaf key, the secrets of its path, the
  secrets of its epoch and the epoch's header (section 12.1). It follows the
  group from one *packet* per window (section 13.1).
* **Delivery service.** The DS holds the public state, checks every request
  and every commit, stores the windows, and serves packets, chains of seals
  and entries. It never draws a group secret and never signs a group
  object.

<a id="2-security"></a>
## 2. Security goals and threat model

### 2.1 Adversaries

| ID | Adversary | Capabilities |
| --- | --- | --- |
| A1 | Passive DS | Reads everything the DS stores and relays. |
| A2 | Active DS | A1, and drops, delays, reorders or replays traffic, answers requests arbitrarily, decides which requests enter which window, and creates its own device keys. |
| A3 | Malicious member | Holds the secrets of its own membership; deviates arbitrarily from the protocol, including as a committer, sealer, welcomer or entrant. |
| A4 | Removed member | A3 for the epochs it belonged to, keeping whatever it learned then, including the secrets it drew as a committer. |
| A5 | Temporarily compromised device state | Learns the group state of one device (leaf key, path secrets, epoch secrets, pending keys) at one point in time, then loses access. The device key stays secret, for instance in a hardware keystore. |
| A6 | Compromised device key | Learns the ML-DSA-65 device key of one member device. |

The network is controlled by A2. In a closed group, admins are trusted to
admit members: an admin that admits the adversary gives it membership.
Anyone can join an open group (section 6.1).

### 2.2 Properties

"Guaranteed" means: under the assumptions of section 2.3, the property holds
against that adversary for members that follow the group (section 12.2), and
for joiners and returning members from the epoch they enter (sections 12.9
and 12.10). *Epoch secrets* are the secrets of section 9; the message plane
encrypts under `msg_secret_n` (section 19), so the confidentiality of what it
carries rests on theirs. A deployment MUST NOT advertise a property that
this table does not list as guaranteed for the stated adversary.

| Property | A1 | A2 | A3 | A4 | A5 | A6 |
| --- | --- | --- | --- | --- | --- | --- |
| Confidentiality of epoch secrets | guaranteed | guaranteed in a closed group; none in an open group, which the DS can join | no (insider) | guaranteed from the window that applies its removal | guaranteed outside the FS and PCS windows | no, until the device is removed |
| Membership agreement | guaranteed | guaranteed | guaranteed | guaranteed | guaranteed | guaranteed |
| Authenticity of requests, commits and seals | guaranteed | guaranteed | guaranteed (cannot act as another member) | guaranteed | guaranteed | guaranteed for the other members |
| Admission control, in a closed group | guaranteed | guaranteed | detected: an entry it places without a valid admission is caught by sampled audits and leaves a fraud proof (section 15) | guaranteed | guaranteed | as A3; none if the device is an admin |
| Post-removal secrecy (PRS) | n/a | n/a | n/a | guaranteed from the window that applies the removal, including for the nodes it drew as a committer | n/a | guaranteed once the device is removed |
| Forward secrecy (FS) | guaranteed | guaranteed | n/a | n/a | guaranteed for epochs whose secrets the device erased | guaranteed |
| Post-compromise security (PCS) | n/a | n/a | n/a | n/a | after the device's next update | no, until the device is removed |
| Join secrecy | guaranteed | guaranteed | guaranteed | n/a | guaranteed | guaranteed |
| Visibility of joins | guaranteed | guaranteed (the DS can refuse to show a window's joins, not misrepresent them) | guaranteed | n/a | guaranteed | guaranteed |
| Liveness, availability | no | no | no | no | no | no |
| Metadata privacy (who is a member, who sends when, group size) | no | no | no | no | no | no |

Definitions (normative):

* **Membership agreement.** Two members that accept epoch `n` with the same
  interim transcript hash agree on the tree hash, the registry and the
  transcript of epochs `0..n`: they are bound into `GroupContext_n`, from
  which every secret of the epoch derives, and the confirmation tag proves
  it (section 9). For a window sealed by an entrant the tag alone proves
  nothing against the DS, which knows the external public key; members also
  check the entrant's admission and signature (section 12.2).
* **Admission control.** In a closed group no device becomes a member
  without an admission signed by an admin of the previous epoch, directly
  or through an invite, and an admission admits once. The DS checks every
  request, each committer the entries of its districts, the sealer the
  structure of every district commit, and members audit random entries
  (section 15): an invalid entry placed by a malicious committer escapes
  every auditor with probability about `e^-AUDIT_K`, and a fraud proof then
  names the committer.
* **PRS.** A member whose occupancy a window ends MUST NOT be able to
  derive any secret of an epoch `>= n`, where `n` is the epoch that window
  creates. The window re-keys the member's path and every node it taints,
  so what it drew as a committer is useless to it (section 10.2; model
  `taint.pv`); the external init of a window sealed by an entrant does not
  help it either (model `entrant_removal.pv`). A removal is recorded when
  the DS accepts its proposal and applied by the next window (section
  14.2): until then the DS refuses the removed member's requests and stops
  delivering to it (section 14.6), which is not cryptographic, and members
  do not send while a removal recorded more than `WINDOW_REMOVAL` ago waits
  (section 12.8).
* **FS.** Compromise of a device at time `T` MUST NOT reveal the secrets of
  epochs the device erased before `T`. Members erase the secrets of an epoch
  when the next one is active; the init chain makes a leaked leaf key
  useless for past epochs (model `forward_secrecy.pv`).
* **PCS.** After a device whose state was compromised completes an update
  (section 12.6), which re-keys its path and every node it taints, the
  attacker MUST NOT derive the secrets of later epochs, unless it
  compromises a member again (model `post_compromise.pv`). Members SHOULD
  update at least every `UPDATE_INTERVAL`.
* **Join secrecy.** A joiner that enters with a welcome receives only
  `joiner_secret_n` and the secrets of its path (section 9), from which
  nothing of epoch `n - 1` or before derives. Its init key is used for one
  welcome.
* **Device keys.** Whoever holds a device key can sign as the device:
  requests, including a re-entry that gives the member a leaf key of its
  choice, district commits and seals if it is given the role, and
  admissions if the device is an admin. The repair is to remove the device,
  together with any device it admitted, and to admit a new one.
* **Visibility of joins.** Every join is a change of a district commit that
  the seal lists; a member that holds the seal of an epoch it accepted can
  list the devices that window let in (section 12.11). Nobody can take a
  member's place: a request claiming a member's device key fails its
  signature, and a device already a member cannot join again.

### 2.3 Assumptions and limits

* X-Wing is IND-CCA2 if either ML-KEM-768 or X25519 is; ML-DSA-65 is
  EUF-CMA (and strongly unforgeable); BLAKE3 in keyed mode is a PRF;
  ChaCha20-Poly1305 is an AEAD. Random numbers come from a CSPRNG.
* The DS decides which requests enter which window, can delay any window
  indefinitely, and can deny service. It cannot make a member accept an
  epoch it forged.
* The DS sees the members (device keys, leaves, occupancies, admins), every
  request, the timing and size of windows, and who downloads what.
* A committer learns the secrets of the nodes it re-keys, including off its
  own path. An honest committer erases them once its commit is sent (section
  12.4); taints bound the damage of one that does not.
* An entrant learns every secret of the window it seals. It is a member of
  the new epoch: admitted by an admin, a device of an open group, or already
  a member.
* In a window sealed by an entrant, the external init secret is known to
  every member of the previous epoch, including those the window removes.
  The new epoch's secrecy against them rests on the root secret, which the
  window re-keys away from them.
* A committer can wrap a secret that some members cannot open. They reject
  the window (the confirmation tag does not check) and are cut off until
  they re-enter; reports that would expose such a committer are an open
  item (section 19).
* Group encryption is not end-to-end between subsets of a group: every
  member of an epoch holds its secrets.
* **Forks.** The DS decides what each member sees. It can show different
  members different valid histories (a fork) and keep each branch going;
  members on one branch reject the windows of the other. Members that
  follow the group check tags, not the history, and would not notice a
  fork: comparing the interim transcript hash of an epoch out of band
  detects it. A joiner checks the chain of seals from an admin checkpoint
  (section 12.9), so the DS cannot lead it into an epoch it forged.
* `time_ms` of a seal is the sealer's clock, not a trusted time.

<a id="3-suite"></a>
## 3. Cryptographic suite and encodings

### 3.1 Suite

| Function | Primitive | Use |
| --- | --- | --- |
| KEM | X-Wing (ML-KEM-768 and X25519), draft-connolly-cfrg-xwing-kem-06 | leaf and node keys, the init keys of welcomes, external keys |
| Signature | ML-DSA-65 (FIPS 204), hedged, with context strings | requests, district commits, seals, checkpoints, policies |
| Hash `H` | BLAKE3, 256-bit output | labelled hashes, digests |
| PRF / KDF | BLAKE3 keyed mode and its XOF | Extract, ExpandLabel, MAC |
| AEAD | ChaCha20-Poly1305 (RFC 8439) | wraps and welcomes |

* **X-Wing.** A private key is held as its 32-byte decapsulation key (a
  seed from which X-Wing derives the ML-KEM-768 and X25519 keys).
  Encapsulation draws its 64 random bytes (32 for ML-KEM, 32 for the X25519
  ephemeral key) from the caller's generator. Encapsulation keys are 1216
  bytes (the ML-KEM-768 key, then the X25519 key), ciphertexts 1120 bytes,
  shared secrets 32 bytes. An encapsulation key MUST pass the FIPS 203
  input check of its ML-KEM part before use. The hybrid keeps
  confidentiality if either component holds, against an adversary that
  records traffic today to decrypt it with a quantum computer later.
* **ML-DSA-65.** Key pairs derive from a 32-byte seed `xi`
  (`ML-DSA.KeyGen_internal`). Signing is hedged: the 32-byte `rnd` input is
  drawn from the caller's generator. Public keys are 1952 bytes, secret
  keys 4032 bytes, signatures 3309 bytes. Every signature uses a FIPS 204
  context string (`ctx`) naming its usage (section 17.3); a signature
  produced under one context MUST NOT verify under another.
* **Randomness.** Every random value of the protocol (seeds, nonces, node
  secrets, KEM randomness, signing randomness, invite seeds) MUST come from
  a CSPRNG.

### 3.2 Deterministic CBOR

`CBOR_det(x)` is the core deterministic encoding of RFC 8949, section
4.2.1:

* integers and lengths use the shortest head;
* only definite lengths;
* map keys are sorted by the bytewise lexicographic order of their
  encodings, and no key appears twice;
* no floating-point values and no tags; the simple values `false`, `true`,
  `null` are allowed.

A decoder MUST re-encode every decoded object and reject it unless the
result is byte-identical to its input. Every object is exchanged as the
exact bytes of its deterministic encoding; an implementation MUST NOT
re-encode an object it relays or hashes. `h''` denotes the empty byte
string and `ZERO32` 32 zero bytes. Integers are unsigned.

### 3.3 Hashing and key derivation

```text
H(x)                               := BLAKE3-256(x)
H_L(label, args)                   := H(CBOR_det(["city-g/v0.4", label, args]))
Extract(salt, ikm)                 := BLAKE3-keyed(key = salt, ikm)                (32 bytes)
ExpandLabel(secret, label, ctx, L) := BLAKE3-keyed-XOF(key = secret,
                                        CBOR_det(["city-g/v0.4 expand", label, ctx, L]))[0..L]
DeriveSecret(secret, label)        := ExpandLabel(secret, label, h'', 32)
MAC(key, data)                     := BLAKE3-keyed(key, CBOR_det(["city-g/v0.4 mac", data]))
KemKey(secret, label)              := the X-Wing key whose decapsulation key is
                                      ExpandLabel(secret, label, h'', 32)
kem_pk_hash(pk)                    := H_L("kem-pk", [pk])
```

`label` is a text string and `args` a CBOR array; a map MUST NOT appear as
the argument list (the labels are listed in section 17.1). `salt`, `secret`
and `key` are 32 bytes, `ctx` is a byte string and `L` an unsigned integer.
BLAKE3 in keyed mode is a PRF and its XOF output a PRF output of any length,
so `Extract` and `ExpandLabel` follow the HKDF structure with BLAKE3 in
place of HMAC. MAC tags MUST be compared in constant time.

### 3.4 Signed arrays

Every signed object except the seal is a signed array:

```text
TBS       := CBOR_det([label, field_2, ..., field_k])
Signed    := CBOR_det([label, field_2, ..., field_k, signature])
signature := ML-DSA-65.Sign(sk, TBS, ctx)
```

The label names the object and its version; every label of this profile
ends in `/v4`, and the signature context of each signed array is its label
(section 17). A verifier checks the label and the number of fields before
verifying the signature over `TBS`, which it rebuilds from the received
fields. Seals are signed differently (section 10.4).

**Occupancies and node addresses** are encoded `[leaf, since]` and
`[level, index]`.

<a id="4-identifiers"></a>
## 4. Identifiers

```text
gid       := H_L("group-id",  [creator_device_pk, group_nonce])     group_nonce: 32 random bytes
device_id := H_L("device-id", [gid, device_pk])
invite_id := H_L("invite-id", [invite_pk])
request_ref := H(encoded request)
```

<a id="5-tree"></a>
## 5. Tree

### 5.1 Shape and addresses

A tree has `2^height` leaves, `1 <= height <= MAX_HEIGHT`. Node
`(k, i)` is the ancestor at level `k` of leaves `i·2^k .. (i+1)·2^k`;
leaves are level 0. With `L = district_bits` (fixed at genesis,
`1 <= L <= MAX_HEIGHT`):

* the *district level* is `min(L, height)`;
* if `height > L`, there are `2^(height - L)` districts; district `d` is
  the subtree under node `(L, d)`, and the *city* is the set of levels
  `L + 1 .. height`;
* otherwise there is one district, whose root is the tree's root, and no
  city.

The district of a leaf `i` is `i >> L` when `height > L`, else 0.

### 5.2 Nodes

```text
LeafNode   := [device_pk, since, encryption_key, admission_hash, updated]
ParentNode := [encryption_key, taint]            taint: an occupancy
```

* `encryption_key` of a leaf is chosen by the member; `admission_hash` is
  the hash of the admission it entered with (`ZERO32` for the creator);
  `updated` is the epoch its leaf key last changed.
* A parent node is **blank exactly when its subtree holds no member**.
  Every other parent node holds the key derived from its secret and its
  taint. There are no unmerged leaves.

### 5.3 Hashes

```text
leaf_hash(i)   := H_L("tree/leaf", [LeafNode or null])
content(n)     := H_L("tree/node", [encryption_key, taint])
node_hash(n)   := H_L("tree/parent", [content(n) or null, node_hash(left), node_hash(right)])
tree_hash      := node_hash(root)
district_hash  := node_hash(district root)
```

Positions are not hashed: they follow from the structure. The hash of an
empty subtree at level `k` is fixed, and equals the generic formula.

**Leaf proofs.** A leaf proof of leaf `i` is the leaf (or `null`) and, for
each level `1..height` from the bottom, `content` of the ancestor (or
`null`) and the hash of the sibling subtree. It recomputes `tree_hash`. It
MUST be rejected if `i >= 2^height` for the height it claims. A proof of a
member's path parents checks each against the `content` of its level.

### 5.4 Growth

The tree grows by raising `height`. Addresses are unchanged: the old root
becomes node `(old_height, 0)`. The nodes `(k, 0)` for
`old_height < k <= height` hold the old tree, so a window that grows a
non-empty tree re-keys them (section 10.2). The height of a window is the
smallest height, not below the current one, whose width holds every
changed leaf. This version never shrinks the tree (section 19).

<a id="6-requests"></a>
## 6. Signed requests

Every request is a signed array (section 3.4), except the eviction, which
the DS writes under an admin-signed policy. Members are named by
occupancy. Sizes are bounded by the parameters of section 16.

```text
Invite         := ["city-g/invite/v4", gid, invite_pk, expires_at_ms, max_uses,
                   inviter, inviter_pk, signature]
Admission      := ["city-g/admission/v4", gid, device_id, not_after_epoch, kind,
                   admin or null, authorizer_pk, invite or null, signature]
JoinRequest    := ["city-g/join-request/v4", gid, device_pk, encryption_key,
                   init_key, not_after_epoch, admission or null, signature]
RemoveProposal := ["city-g/remove/v4", gid, target, proposer, signature]
Eviction       := ["city-g/eviction/v4", gid, target, policy_hash]
GroupPolicy    := ["city-g/group-policy/v4", gid, admission_mode,
                   max_idle_epochs or null, admin, signature]   admission_mode: 0 closed, 1 open
UpdateRequest  := ["city-g/update/v4", gid, member, replaces, encryption_key, signature]
CatchUpRequest := ["city-g/catch-up/v4", gid, member, prev_interim, init_key, signature]
ReEntryRequest := ["city-g/re-entry/v4", gid, member, replaces, encryption_key,
                   init_key, signature]
Checkpoint     := ["city-g/checkpoint/v4", gid, epoch, interim, tree_hash,
                   registry_hash, height, district_bits, external_pk_hash,
                   time_ms, admin, signature]
```

* **Invite.** Signed by the inviter, an admin (`inviter` its occupancy,
  `inviter_pk` its device key). The invite key pair derives from a 32-byte
  seed shared out of band, for instance in an invite link. It is valid for a
  window if the
  inviter is an admin of the previous epoch with that key. Expiry and the
  number of uses are enforced by the DS.
* **Admission.** Kind 0: signed by the admin `admin`, whose key is
  `authorizer_pk`, `invite = null`. Kind 1: `admin = null`, signed by the
  invite key `authorizer_pk` of the enclosed invite, which MUST name the
  same group and key. `admission_hash := H(Admission)`. For a join creating
  epoch `n`, an admission is valid if it names the device
  (`device_id`), `n <= not_after_epoch <= n + MAX_ADMISSION_EPOCHS`, its
  signer is an admin of epoch `n - 1` (directly or through a valid invite),
  and it was never used (section 8): **an admission is good for one join.**
  Its *anchor key*, which the joiner trusts, is the admin's key (kind 0) or
  the inviter's key (kind 1).
* **JoinRequest.** Signed by the joining device. `encryption_key` and
  `init_key` are distinct X-Wing keys that MUST pass the input check; the
  init key is used for one welcome. For a join creating epoch `n`,
  `n <= not_after_epoch <= n + MAX_ADMISSION_EPOCHS`. In a closed group the
  request MUST carry an admission; in an open group it MAY carry none. Its
  *token*, which the admission map records so that it enters once, is
  `admission_hash`, or `H(JoinRequest)` without admission; the joiner's
  leaf holds the token as its `admission_hash`.
* **RemoveProposal.** Signed by an admin of the previous epoch, or by the
  target itself (`proposer = target`).
* **Eviction.** Written by the DS. Valid in a window creating epoch `n` if
  the registry holds `policy_hash`, the policy object hashes to it, sets
  `max_idle_epochs`, and the target's leaf key has not changed for more
  than that: `n - updated > max_idle_epochs`.
* **GroupPolicy.** Signed by an admin of the previous epoch, or by the
  creator at genesis. It says whether the group is open and after how long
  an idle member may be evicted. A group without policy is closed and
  evicts nobody.
* **UpdateRequest** and **ReEntryRequest.** Signed with the member's device
  key. `replaces := kem_pk_hash(current leaf key)`: the request is valid
  only while that key is the member's leaf key, so it applies once and
  cannot be replayed after the key changed. A re-entry adds a one-time init
  key.
* **CatchUpRequest.** Signed with the member's device key. `prev_interim`
  is the interim transcript hash of the epoch the next window builds on:
  the request is valid for that window only, so it cannot be replayed to
  obtain a later epoch under an old init key.
* **Checkpoint.** Signed by an admin; states an epoch, its interim
  transcript hash, tree hash, registry hash, shape and
  `external_pk_hash := kem_pk_hash(external_pk)`. Admins SHOULD sign one
  every `CHECKPOINT_INTERVAL`.

Decoding checks encodings and key lengths only; signatures are checked by
whoever the rules of sections 10, 14 and 15 name.

### 6.1 Open and closed groups

A group is *closed* unless the group policy in force opens it. The registry
binds the policy's hash and the admission mode (section 8), so every member
knows the mode, and the mode changes only by a new policy signed by an admin
(section 12.2). In an open group:

* a device joins with its own signed request and no admission; nothing
  else about joining changes (placement, welcomes, anchoring);
* when no member is online, any new device can be the entrant of a window,
  including one the DS controls (section 12.7);
* the checks of sections 10 and 15 skip the admission of a join that has
  none, and keep all others: signatures, the device not already a member,
  the token unused, the request not expired.

The joiner of an open group trusts an admin key from the group's public
link to check checkpoints (section 12.9). Nothing in an open group is signed
per join by an admin.

<a id="7-rekey"></a>
## 7. Re-key

### 7.1 Node secrets and keys

```text
node key pair        := KemKey(secret, "tree node key")
chain(child_secret)  := DeriveSecret(child_secret, "tree path")
fresh(hedge)         := DeriveSecret(Extract(hedge, r), "fresh node")      r: 32 random bytes
```

`hedge` is the committer's `init_secret` of the previous epoch, or the
external init secret for an entrant (`ZERO32` at genesis): a weak
generator alone does not expose a fresh secret to an outsider.

### 7.2 Wraps

A *wrap* gives the new secret of node `v` to the holder of the key of its
child `t`:

```text
context := CBOR_det([gid, epoch, v.level, v.index, t.level, t.index, kem_pk_hash(t_pk)])
(ct, ss) := X-Wing.Encaps(t_pk)
sealed  := ChaCha20-Poly1305(key   = ExpandLabel(ss, "wrap key", context, 32),
                             nonce = ExpandLabel(ss, "wrap nonce", context, 12),
                             aad   = context, plaintext = secret)            (48 bytes)
Wrap    := [v.level, v.index, t.level, t.index, ct, sealed]
```

`epoch` is the epoch the window creates.

### 7.3 Plans

The *plan* of a re-key is its public structure: which nodes, blank or not,
the chain source and the wrap targets of each. It depends only on public
data, so the DS and every verifier recompute it.

**Re-key set.** For district `d`: every ancestor, at levels
`1..district_level`, of a changed leaf of `d`, and every forced node of
`d` (section 10.2) with its ancestors up to the district root. For the
city: every ancestor, at levels `L + 1..height`, of the root of each
district of the window, and every forced city node with its ancestors up
to the root.

**Order.** Nodes are processed by level, then index.

**Each node `v`.** A child `c` of `v` is *live* if: `c` is in the re-key set
and not blank after it; `c` is a leaf occupied after the window; `c` is a
district root whose new state the city plan is given; otherwise `c` is not
blank in the tree before the window. Then:

* if no child is live, `v` becomes blank;
* otherwise, unless `v`'s level is a *boundary*, the secret of `v` is
  `chain(secret of c)` for the first live child `c`, left first, that is in
  the re-key set and not blank; if there is none, or at a boundary, it is
  `fresh(hedge)`;
* the secret is wrapped to every live child except the one it was chained
  from.

The boundaries are level 1 in a district (the children are members'
leaves) and level `L + 1` in the city (the children are district roots
re-keyed by other committers).

**Keys of wrap targets.** The new key of a node this commit re-keyed; the
new leaf key of a changed leaf; in the city plan, the new key of a
district root from its district commit; otherwise the key in the tree
before the window.

**Following a plan.** A commit lists one node update per planned node, in
plan order: the new public key, or `null` exactly for the nodes the plan
blanks. Its wraps follow the plan: for each node, one wrap per target, in
target order. A verifier recomputes the plan and checks the list of nodes,
the keys (X-Wing input check), the wrap addresses and sizes. It cannot
check the ciphertexts; a member that cannot open its wrap rejects the
window (the tag check fails).

### 7.4 Member paths

A member holds the secret of each of its ancestors, by level. The *steps*
of a window along its path are, for each ancestor `v` at level `k` that
the window re-keys: `Wrap` if the window wrapped `v`'s secret to `v`'s
child toward the member, `Chain` otherwise. Bottom-up:

* `Wrap`: open it with the key of the child toward the member: its leaf key
  at level 1, else `KemKey(secret at level k - 1, "tree node key")`;
* `Chain`: `chain(secret at level k - 1)`, valid only if level `k - 1` was
  re-keyed by the same window (never at level 1);
* a level the window does not re-key keeps its secret;
* a re-keyed ancestor that becomes blank means the member was removed.

**Recovery.** A joiner, a member re-entering its leaf and a member jumping
to the present recover their whole path from the last step of each level,
each tagged with the epoch of the window that last re-keyed the node. A
`Chain` step is valid only if the child's step has the same epoch. The
member checks every recovered secret against the public key of its node in
the tree it enters (section 12.9). This works because a window that
re-keys a node re-keys all its ancestors: the last re-key of a node
happened at or after the last re-key of its child toward the member, and
either chained from that child (re-keyed in the same window) or wrapped to
the child's key of that time, which is still its key.

<a id="8-registry"></a>
## 8. Registry

```text
RegistryHeader := [admins, devices_root, admissions_root, policy_hash or null, open]
registry_hash  := H_L("registry", [[[admin, admin_pk], ...], devices_root,
                                   admissions_root, policy_hash or null, open])
```

* `admins`: occupancies of the admins with their device keys, in
  occupancy order;
* `devices`: a sparse Merkle map from the `device_id` of every member to
  its occupancy;
* `admissions`: a sparse Merkle map from the token of every join ever
  made (its admission's hash, or its request's hash without admission) to
  the occupancy it admitted. Entries are never removed;
* `policy_hash`: hash of the group policy in force, if any;
* `open`: 1 if the policy in force opens the group, else 0 (a group without
  policy is closed).

Members keep the header; the DS and committers keep the maps.

**Sparse Merkle maps.** Keys are 32-byte digests, read most significant
bit first; values are occupancies. The map is a binary trie in which a
subtree holding one entry is that entry:

```text
subtree(prefix) := ZERO32                                   no entry under prefix
                 | H_L("smm/leaf", [key, value])             one entry
                 | H_L("smm/node", [subtree(prefix‖0), subtree(prefix‖1)])
root            := subtree(empty prefix)
```

The root depends only on the set of entries. A proof for key `k` lists the
sibling hashes along `k`'s branch, from the root down to the first subtree
holding at most one entry, and that entry if any. It shows `k`'s value (the
entry's key is `k`) or `k`'s absence (no entry, or an entry with another
key that shares the prefix). A proof whose entry does not share the prefix
MUST be rejected.

**Changes of a window** creating epoch `n`, applied in this order:

1. every removed or evicted member leaves `devices`, and `admins` if it
   was an admin;
2. every join adds `device_id -> [leaf, n]` to `devices` and
   `token -> [leaf, n]` to `admissions`. The device MUST NOT be in
   `devices` before the window, and neither the device nor the token MAY
   appear twice in the window or be in the maps already;
3. a group policy in the seal body, signed by an admin of epoch `n - 1`,
   sets `policy_hash` and `open`;
4. if no admin is left, the sealer becomes admin, with its device key (the
   promotion rule).

<a id="9-key-schedule"></a>
## 9. Key schedule

One epoch per window. The window's root secret, which every member of the
new epoch derives from its path (section 7.4), feeds the schedule:

```text
GroupContext_n := CBOR_det(["city-g/group-context/v4", gid, n, tree_hash_n,
                            registry_hash_n, height_n, district_bits,
                            "city-g/v0.4", confirmed_transcript_hash_n])
commit_secret_n := DeriveSecret(root_secret_n, "commit")
joiner_secret_n := ExpandLabel(Extract(init_n-1, commit_secret_n), "joiner", H(GroupContext_n), 32)
epoch_secret_n  := DeriveSecret(joiner_secret_n, "epoch")
init_n, msg_secret_n, confirm_key_n, external_secret_n
                := DeriveSecret(epoch_secret_n, "init" | "msg" | "confirm" | "external")
external key pair_n := KemKey(external_secret_n, "external kem")
confirmed_transcript_hash_n := H_L("confirmed-transcript", [interim_transcript_hash_n-1, seal_hash_n])
confirmation_tag_n := MAC(confirm_key_n, confirmed_transcript_hash_n)
interim_transcript_hash_n := H_L("interim-transcript", [confirmed_transcript_hash_n, confirmation_tag_n])
```

* `init_-1` and `interim_transcript_hash_-1` are `ZERO32`.
* `seal_hash_n := H(SealHeader_n)` (section 10.4).
* **External init.** In a window sealed by an entrant, `init_n-1` is
  replaced by the external init secret:

  ```text
  (kem_output, ss) := X-Wing.Encaps(external_pk_n-1)
  external_init    := ExpandLabel(Extract(ZERO32, ss), "external init", H(kem_output), 32)
  ```

  Every member of epoch `n - 1` recovers it with its external key.
* A window that re-keys nothing (catch-ups or a policy only) keeps the root
  secret; its epoch is still fresh through the init chain.
* Members keep the secrets of epoch `n` while it is active, including
  `joiner_secret_n`, with which the window's welcomers seal their welcomes
  (section 11), and erase them when the next epoch is active.
* `msg_secret_n` is the root of the message plane of epoch `n`, which this
  version does not specify yet (section 19).

**Genesis.** The creator draws a nonce and computes `gid`. The tree has
height 1: the creator at leaf 0 (`since = 0`, `admission_hash = ZERO32`)
and the root `(1, 0)`, keyed from a fresh secret with the creator's
taint. The registry has the creator as admin and its device in `devices`,
and the group policy the creator chose, if any (an open group has one from
genesis). `init_-1 = ZERO32`. The genesis seal (kind 0, section 10.4)
carries in its body `[nonce, creator_pk, encryption_key, root_pk]` and that
policy, signed by the creator as admin `[0, 0]`; the DS rebuilds the state
from it and checks the hashes, `gid`, the policy's signature and the seal's
signature.

<a id="10-windows"></a>
## 10. Windows: district commits and seals

### 10.1 Changes

```text
Change := [kind, leaf, request_ref]
kind   := 0 removal | 1 eviction | 2 join | 3 update | 4 re-entry
```

A window creating epoch `n` lists changes sorted by `(leaf, kind,
request_ref)`. The changes of one leaf MUST be one of:

| Changes of the leaf | Condition in the tree before the window | New leaf |
| --- | --- | --- |
| join | the leaf is blank | `[device_pk, n, encryption_key, admission_hash, n]` |
| removal, or eviction | the leaf is occupied by the target | blank |
| removal or eviction, then join | the leaf is occupied by the target | the joiner's leaf: the join takes the leaf the removal empties |
| update, or re-entry | the leaf is occupied by the member, whose key `replaces` names | the same leaf with the new key and `updated = n` |

Catch-up requests are not changes (section 11).

### 10.2 Structure of a window

From the tree before the window and its changes:

* **Height.** The window's height MUST be the smallest height, not below
  the current one, whose width holds every changed leaf.
* **Affected members.** The occupancies the window removes, evicts, updates
  or re-enters. The *removed* ones are those it removes or evicts.
* **Forced nodes.** Every node an affected member taints in the tree before
  the window (the taint rule, E-4), and, if the window grows a non-empty
  tree, the nodes `(k, 0)` for `old_height < k <= height` (section 5.4). A
  forced node at or below the district level belongs to its district;
  above it, to the city.
* **Districts of the window.** Those with a changed leaf or a forced node.
  A window commits exactly these districts.

### 10.3 District commits

```text
DistrictCommit := ["city-g/district-commit/v4", gid, epoch, district, height,
                   prev_district_hash, committer, changes, nodes, wraps,
                   district_hash, signature]
  nodes := [[level, index, public_key or null], ...]       in plan order
  wraps := [Wrap, ...]                                     in plan order
```

Signed by the committer under `DISTRICT_COMMIT`. A verifier holding the
state before the window (the DS, the sealer) checks:

1. `gid`, `epoch = n`, `height` (section 10.2), `district` is a district of
   the window;
2. `changes` are exactly the window's changes of the district, in order;
3. `prev_district_hash` is the hash of the district root in the tree before
   the window, grown to the window's height;
4. the committer (section 10.5);
5. each change's request is available, of the change's kind and group, and
   names the leaf's occupant (except a join); the rest of section 10.1
   holds; the entry checks of section 6 hold if the verifier checks entries
   (the DS and the committer do, the sealer does not, section 15);
6. the nodes and wraps follow the district's plan (section 7.3), with the
   district's forced nodes;
7. `district_hash` is the hash of the district root after the new leaves
   and the nodes are set, each node tainted by `committer`;
8. the signature, under the committer's device key.

### 10.4 Seals

```text
SealHeader := ["city-g/seal/v4", gid, epoch, prev_interim, kind, sealer, height,
               district_bits, tree_hash, registry_hash, body_hash, time_ms,
               [kem_output, request_ref] or null]
SealBody   := ["city-g/seal-body/v4", [[district, H(district commit)], ...],
               city_nodes, city_wraps, group_policy or null,
               [nonce, creator_pk, encryption_key, root_pk] or null]
Seal       := [SealHeader, SealBody, confirmation_tag, external_pk, signature]

seal_hash := H(SealHeader)              body_hash := H(SealBody)
signature := ML-DSA-65.Sign(sealer_sk, CBOR_det([seal_hash, confirmation_tag, external_pk]), SEAL)
```

* `kind` is 0 (genesis), 1 (sealed by a member of the previous epoch) or 2
  (sealed by the window's entrant). The last header field is set exactly
  for kind 2: the external init ciphertext and the entrant's request.
* One signature covers the header, the confirmation tag and the next
  external key: a joiner that checks it knows the tag is authentic, so an
  unsigned welcome cannot be replaced (model
  `anchored_join_unsigned_tag.pv`).
* Members and joiners download *seal proofs*, `[SealHeader,
  confirmation_tag, external_pk, signature]`, not bodies.

The DS checks a seal against the state before the window:

1. `gid`, `epoch = n`, `prev_interim` is the current interim transcript
   hash, `district_bits`, `time_ms` not below the previous seal's;
2. the body lists the window's district commits, in district order, with
   their hashes;
3. the window's structure (section 10.2) from the union of the commits'
   changes; the districts listed are exactly the window's districts;
4. the sealer and every committer (section 10.5);
5. every district commit (section 10.3);
6. the last node of each district commit is its district root; the city
   nodes and wraps follow the city plan (section 7.3) with the city's forced
   nodes, each city node tainted by the sealer; with no city, both lists are
   empty;
7. `tree_hash` and `registry_hash` after the window (section 8);
8. `body_hash`, and no genesis field;
9. the signature, under the sealer's device key.

The confirmation tag cannot be checked without the epoch's secrets: members
check it (section 12.2).

### 10.5 Who may commit and seal

* **Member windows (kind 1).** The sealer and every committer MUST be
  members of epoch `n - 1` that the window does not affect: a committer
  never removes or updates itself. Their device keys come from the tree.
* **Entrant windows (kind 2).** The entrant's request MUST be a join or a
  re-entry among the window's changes. The sealer is the entrant: for a
  join, `[leaf, n]` where `leaf` is the join's leaf, with the key of the
  join request, whose signature and admission (none, in an open group) MUST
  be checked; for a
  re-entry, the member's occupancy and device key, and the request's
  signature MUST be checked. Every district commit of the window is by the
  entrant.

### 10.6 Applying a window

The tree grows to the window's height; changed leaves take their new
state; every node of a district commit takes its new key (or becomes
blank) with the committer's taint, and every city node with the sealer's;
the registry changes (section 8); the group policy of the body, if any,
comes into force; the epoch, interim transcript hash, external key and
time are those of the seal.

<a id="11-welcomes"></a>
## 11. Welcomes

```text
Welcome := ["city-g/welcome/v4", gid, epoch, request_ref, kem_ciphertext, sealed]
context := CBOR_det([gid, epoch, request_ref, kem_pk_hash(init_key)])
(ct, ss) := X-Wing.Encaps(init_key)
sealed  := ChaCha20-Poly1305(ExpandLabel(ss, "welcome key", context, 32),
                             ExpandLabel(ss, "welcome nonce", context, 12),
                             aad = context, joiner_secret_n)
```

A welcome gives `joiner_secret_n` to the holder of a one-time init key: a
joiner, a member re-entering its leaf, or a member that asked to jump
(catch-up). It is not signed: the joiner secret must reproduce the
confirmation tag the sealer signed.

**Who welcomes.** In a member window, the committer of the district of the
leaf welcomes joins and re-entries; the committer of the member's district
welcomes a catch-up if that district is in the window, and the sealer
otherwise. In an entrant window, the entrant welcomes everyone but itself.
A welcomer seals its welcomes once it has followed the window (it then
knows `joiner_secret_n` as a member of epoch `n - 1`).

**Welcomer's checks.** A welcomer takes the init key from the request, never
from the DS, and:

* welcomes a join or a re-entry only if it is a change of a district commit
  of its own that the seal lists (so that no device learns an epoch without
  being in its tree);
* welcomes a catch-up only if its member is in the tree of epoch `n`, the
  request is signed with that member's device key, and its `prev_interim`
  is the seal's (section 6).

<a id="12-members"></a>
## 12. Members

### 12.1 State

A member keeps:

* its device key, occupancy and leaf key (and the new leaf key of an update
  it requested, until a window applies it);
* the secrets of its path, by level;
* the secrets of its epoch (section 9) and the hash of the epoch's seal;
* the *header* of its epoch: `gid`, epoch, shape, `tree_hash`, the
  registry header, the interim transcript hash and the external public key;
  and the header of the previous epoch, against which it audits the last
  window (section 15).

This is O(log N) whatever the size of the group: no member needs the whole
tree.

### 12.2 Following a window

For the packet of the window creating epoch `n` (section 13.1), a member
of epoch `n - 1`:

1. checks `gid`, `epoch = n`, `prev_interim` (its interim transcript hash)
   and `district_bits`; the height is not below its own;
2. rebuilds the registry header from the update and checks it hashes to the
   header's `registry_hash`. If the policy changed, the update carries the
   new policy object: it MUST hash to the new `policy_hash`, match the new
   `open` flag, and be signed by an admin of epoch `n - 1`; if the policy
   did not change, `open` MUST NOT change either. So a closed group cannot
   be opened, even by a sealer that colludes with the DS;
3. takes `init_n-1`: its own for kind 1; for kind 2, the external init
   secret recovered from `kem_output` with its external key;
4. takes its leaf key: the current one, or the pending one if the packet
   names it (an update or re-entry of its own was applied);
5. derives its path from the packet's steps (section 7.4), then the root
   secret, `GroupContext_n`, the epoch secrets, and checks the
   confirmation tag;
6. for kind 2 only, rebuilds the seal proof with the external key it
   derived and checks the entrant evidence against its header of epoch
   `n - 1` (section 13.2): the entrant's request, its admission (none in an
   open group) or its leaf, and the seal signature;
7. only then replaces its state.

A member that cannot derive its path (a blank ancestor, a wrap it cannot
open) or whose tag does not check rejects the window. Members that follow
the group do not check the sealer's signature of a member window: the init
chain makes the tag sufficient (E-5; model `fabrication.pv`).

### 12.3 Checking the state it is shown

A committer, a sealer or an entrant works on the public state the DS shows
it. It MUST first check that state against its header (member) or its
anchor (entrant): tree hash, registry, epoch, interim transcript hash and
external key. Otherwise it could wrap secrets to keys the DS chose. The
implementation checks the whole state; a deployment would send the
districts concerned with proofs to the tree hash (section 19).

### 12.4 Committing a district

The committer of district `d`:

1. checks the entries of the district (section 6), E-12;
2. computes the district's new leaves and its plan (section 7.3), draws the
   secrets hedged with its `init_secret`, and wraps them;
3. signs the district commit (section 10.3);
4. erases every secret it drew once the commit is sent. It learns its own
   path's new secrets from the window like any member.

A committer need not belong to the district it commits (E-3).

### 12.5 Sealing

The sealer:

1. checks every district commit of the window (section 10.3, without the
   entry checks);
2. re-keys the city (section 7.3), hedged with its `init_secret`;
3. takes the root secret: from its city re-key; with no city, by
   following the single district commit along its own path; with nothing
   re-keyed, its current root secret;
4. computes the hashes, `GroupContext_n`, the epoch secrets from its
   `init_secret`, the confirmation tag and the external key;
5. signs the seal (section 10.4) and erases what it drew.

### 12.6 Updating

A member refreshes its leaf key with an `UpdateRequest` (section 6), keeps
the new key pending, and uses it once a packet names it. The window re-keys
its path and every node it taints. Members SHOULD update at least every
`UPDATE_INTERVAL`, and an admin MAY evict members that do not (section 14.7).

### 12.7 Sealing as an entrant

With no member online, the DS makes the window's entrant (a joiner or a
member re-entering its leaf) its only committer and sealer (section 14.4).
The entrant:

1. brings its anchor to the current epoch by following the chain of seals
   (section 12.9) and checks the state against it (section 12.3);
2. encapsulates to the current external key (section 9), and uses the
   external init secret as `init_n-1` and as its hedge;
3. commits every district of the window (section 12.4), then seals with
   kind 2 (section 12.5), its request in the header;
4. seals the welcomes of every other joiner, re-entering member and
   catch-up of the window (section 11);
5. keeps the secrets it drew on its own path (its whole path, since its
   leaf changed) and erases the rest.

### 12.8 Not sending while a removal waits

A member MUST NOT send a message in an epoch while a removal the DS
recorded more than `WINDOW_REMOVAL` ago waits: it applies the removal
first, as a committer or sealer of the next window. The DS lists the
recorded removals with their times (section 14.6); a DS that hides one can
also relay ciphertexts to the removed member, so the rule protects against
a DS that leaks later, not one that colludes now.

### 12.9 Joining

1. **Anchor.** The joiner trusts the anchor key of its admission (section
   6), or, for an open group, an admin key from the group's public link. It
   obtains a checkpoint signed with that key by an admin of the
   checkpointed registry, and from the DS the registry header and external
   key of the checkpointed epoch, which it checks against the checkpoint
   (`registry_hash`, `external_pk_hash`).
2. **Request.** It draws a leaf key and a one-time init key and records a
   join request, with its admission or, in an open group, without one.
3. **Chain of seals.** For every window from the checkpoint to the one it
   enters, it follows the seal link (section 13.3): the seal is signed by a
   member of the previous epoch, shown by a leaf proof against the previous
   tree hash, or by an admitted entrant, and the transcript and registry
   chain from the checkpoint.
4. **Entry.** For the window that places it, it receives an entry (section
   13.4): its leaf proof against the new tree hash, which MUST show its
   device key, its leaf key and its token at `[leaf, n]`; the parents of
   its path, checked against that proof; the steps of its path, from which
   it recovers its path secrets (section 7.4) and checks each against its
   node's key; and its welcome, whose joiner secret MUST reproduce the
   signed confirmation tag and external key of the seal.

If no member is online, the DS may instead make the joiner the window's
entrant (section 12.7).

### 12.10 Coming back

A member that missed windows has three ways back (E-8):

* **Replay.** It follows every packet it missed, in order.
* **Jump.** It records a `CatchUpRequest` bound to the current interim
  transcript hash, with a one-time init key. The next window welcomes it
  (section 11). It follows the chain of seals from its own last epoch, and
  recovers its path from the last step of each of its nodes (section 7.4),
  its leaf key unchanged. The epochs it skipped stay unreadable to it.
* **Re-entry.** It records a `ReEntryRequest` with a new leaf key and a
  one-time init key. A member window re-keys its path and welcomes it; with
  no member online, it seals the window itself as an entrant (section
  12.7).

### 12.11 Seeing who joined

Every join is a change of a district commit that the seal lists. A member
that holds the seal of an epoch it accepted can list the devices that
window let in: it checks that the seal hashes to its transcript, that the
body hashes to `body_hash`, that the body lists exactly the district
commits it was given, and that each join's request hashes to its reference.
In an open group this is how members see the devices of strangers, the DS's
included. A device can never take a member's place: it cannot sign with the
member's device key (a request claiming that key fails its signature), and
a device key already in `devices` cannot join again.

The protocol has no names. A client that shows names MUST bind each name
to a device key and show when a name appears with another key, as when a
contact's safety number changes.

<a id="13-packets"></a>
## 13. Packets, seal links and entries

This version fixes the content of these objects, not yet their encoding
(section 19). Sizes below are those of the scale test (section 16).

### 13.1 Packets

The packet of member `m` for the window creating epoch `n` holds:

* the seal header and the confirmation tag;
* for kind 2, the seal signature and the entrant evidence (section 13.2);
* the registry update: the new roots, policy hash and `open` flag, the
  admins only when they changed, and the new group policy object when the
  window set one;
* `kem_pk_hash` of `m`'s leaf key after the window;
* the steps of `m`'s path (section 7.4): for each ancestor the window
  re-keyed, the wrap to the child toward `m`, or `Chain`.

The member does not need the new public keys of its path: a wrong secret
fails the tag check. In the scale test (section 16), packets average 7.7 KB
for 2,000 changes among 16,384 members, and 8.3 KB for 4,000 among 65,536.

### 13.2 Entrant evidence

* For a joiner: its join request, and proofs against the registry of epoch
  `n - 1` that its device is not in `devices` and its token not in
  `admissions`. A verifier checks the request's reference in the header,
  `sealer.since = n`, the request's signature and validity, its admission
  against the admins of epoch `n - 1` (or, without admission, that the
  group of epoch `n - 1` is open), both proofs, and the seal signature
  under the request's device key.
* For a re-entering member: its re-entry request and its leaf proof against
  the tree hash of epoch `n - 1`. A verifier checks the request's reference,
  that the member is the sealer and is at the proven leaf, that `replaces`
  names the proven leaf key, the request's signature and the seal signature
  under the proven device key.

### 13.3 Seal links

A seal link holds the seal proof, the sealer evidence (the sealer's leaf
proof against the previous tree hash, or the entrant evidence), the
registry header after the window, and the group policy object if the
window set one. Following a link from the header of
epoch `n - 1`:

1. `gid`, `epoch = n`, `prev_interim`, `district_bits`, height not below;
2. kind 1: the leaf proof checks against the previous tree hash and shows
   the sealer; the seal signature checks under its device key. Kind 2: the
   entrant evidence (section 13.2). Other kinds are refused;
3. the registry header hashes to `registry_hash`, and a change of policy
   or of the `open` flag is checked as in section 12.2;
4. the next header takes the seal's hashes, height and external key, and
   `interim = H_L("interim-transcript", [H_L("confirmed-transcript",
   [prev_interim, seal_hash]), tag])`.

A link costs about a seal proof (4.8 KB), a leaf proof (3.2 KB plus 64
bytes per level) and the registry roots: 9.0 KB in a tree of `2^14`
leaves.

### 13.4 Entries

An entry holds the links from the entrant's anchor to the epoch it enters,
its welcome, the last step of each level of its path with the epoch of that
step, its leaf proof in the tree it enters, and the parents of its path in
that tree.

<a id="14-delivery-service"></a>
## 14. Delivery service

### 14.1 Recording requests

The DS checks every request against the current state before recording it:

* a join: its signature and validity, its admission (none needed in an
  open group, section 6.1), its device not a member, its token unused, no
  other queued join with the same device or token; for an invite, not
  expired and not used up (uses applied plus uses queued). In an open
  group, the DS SHOULD also limit the rate of joins, since anyone can
  request one;
* a removal: its target is a member, the proposer may remove it, the
  signature; one per target;
* an update or a re-entry: the member exists, `replaces` names its current
  key, the signature; the latest one per member;
* a catch-up: the member exists, `prev_interim` is current, the signature;
  the latest one per member;
* a group policy: signed by an admin, and not the policy in force;
* a checkpoint: signed by an admin of the current registry, and matching
  the epoch it names.

### 14.2 Closing windows

A window is due when its oldest request has waited `WINDOW_MAX`, or its
oldest removal or eviction `WINDOW_REMOVAL`. The DS builds the window from
the queue: removals and evictions (one per target), updates and re-entries
of members the window does not remove (if `replaces` still names their
key), joins, catch-ups bound to the current epoch whose member the window
does not affect, and the pending policy.

What may have changed since a request was recorded is checked again, so
that no committer is handed an entry it must refuse: a request's and an
admission's expiry, the admission's signer's admin status (or, without
admission, that the group is still open), a device or token used
meanwhile, a removal proposer's admin status, an eviction's policy and the
member's `updated` epoch, and the admin status of the pending policy's
signer. Signatures are not checked again. Entries that fail are
left out, and joins and catch-ups that can no longer be valid leave the
queue.

### 14.3 Placement

Joins go, in order (E-11):

1. into the leaves the window empties by removals and evictions (a join
   paired with a removal changes one leaf instead of two);
2. into the lowest free leaves;
3. into the leaves of a taller tree: the height is the smallest that holds
   them (section 5.4), at most `MAX_HEIGHT`.

### 14.4 Roles

* **Volunteers.** Members of the current epoch the DS knows to be online,
  that the window does not affect.
* **Member window.** Each district of the window goes to a volunteer of that
  district if there is one, otherwise to volunteers in turn. The sealer is a
  volunteer without a district, if any, else the first volunteer. Welcomes
  are assigned as in section 11.
* **Entrant window.** With no volunteer, the first join or re-entry of the
  window, in change order, makes its author the entrant: every district,
  the seal and every welcome go to it.
* **No window.** With no volunteer and no entrant, the window stays open.
* **Failover.** The DS MAY give a district of an open member window to
  another volunteer; a commit of the replaced committer is then refused,
  and the welcomes it owed for the district (joins, re-entries, and
  catch-ups of members of the district) go to the new committer. Districts
  are those of the window's height.

### 14.5 Checking and applying

The DS checks every district commit as it arrives (section 10.3, with its
committer) and the seal against them (section 10.4). It then applies the
window (section 10.6) and keeps, for later requests:

* the window: task, district commits, seal, requests, catch-ups, and the
  index of its re-keyed nodes and wraps;
* the sealer evidence of its seal link, and the registry header before and
  after it;
* for every node, its *latest re-key*: the epoch and the wraps by target,
  which serve jumps; a node the window blanks leaves the index;
* for every welcome of the window, the entry data: steps, leaf proof and
  path parents in the new tree;
* the audit records of its entries, with proofs against the state before
  the window (section 15);
* the leaf proofs of its committers and sealer in the new tree, for fraud
  proofs.

A welcome is accepted only for a request the window welcomes, and only from
the welcomer the window assigned it: welcomes are not signed, so the DS
authenticates their sender, and otherwise any member could replace a
joiner's welcome with one it cannot open. Packets, links and entries are
served as in section 13.

### 14.6 Recorded removals

From the moment it records a removal or an eviction until a window applies
it, the DS:

* refuses the target's messages, district commits and seals;
* serves it no packet;
* lists the recorded removals with their times to members (section 12.8).

When no member is online and no entrant comes, nothing more happens until
the first participant, member or entrant, whose window applies the removal
(E-7). Removal without any participant cannot be cryptographic: it would
need a non-interactive key agreement among the removed member's copath
subtrees.

### 14.7 Eviction

Under a group policy in force that sets `max_idle_epochs`, the DS MAY queue
an eviction of every member whose leaf key has not changed for more than
that (section 6). Otherwise it MUST NOT evict. Verifiers check the policy
and the leaf's `updated` epoch.

<a id="15-audits"></a>
## 15. Audits and fraud proofs

No single device can check every entry of a large window: two signatures
per join take about 210 s of CPU for 500,000 joins. Checking is split
(E-12):

| Who | Checks |
| --- | --- |
| DS | every request as it records it (section 14.1) |
| Committer of a district | every entry of the district (section 12.4) |
| Sealer | every district commit: signature, structure, taints, hashes (section 10.3 without entry checks) |
| Members | random entries of the window, `AUDIT_K` audits per entry on average |

**Audit records.** For each change of a window, the DS keeps the district,
the committer, the change, the request, and the proofs against the state
before the window: the changed leaf's proof (not for a join); for a join,
the proofs that its device is not a member and its admission unused; for an
eviction, the policy in force.

**Auditing.** A member of the window's epoch checks sampled records
against its header of the previous epoch. The verdict is:

* an error, if the record's proofs do not check (nothing can be
  concluded);
* *fraud*, if the entry fails the rules of section 6 or section 10.1: an
  invalid signature or admission, a join without admission in a closed
  group, an expired request, a device already a member, a token already
  used, a target that is not the leaf's occupant, a `replaces` that names
  another key, an eviction without policy or of a member not idle long
  enough;
* *valid* otherwise.

**Sampling.** With `E` entries and `M` auditing members, each member audits
`ceil(AUDIT_K·E / M)` distinct entries drawn at random (all of them if
fewer). With `AUDIT_K = 20`, an invalid entry escapes every auditor with
probability about `e^-20 ≈ 2·10^-9`.

**Fraud proofs.** A fraud proof holds the signed district commit, the audit
record of the invalid entry, and the committer's leaf proof in the tree
after the window. Anyone holding the headers before and after the window
checks: the commit is of that window and signed by the committer shown by
the leaf proof, it lists the change, the request matches the change's
reference, and the audit verdict is fraud. What the group does with a
fraud proof (removing the committer and the entry) is up to its admins.

<a id="16-parameters"></a>
## 16. Parameters

| Name | Value |
| --- | --- |
| `L` (`district_bits`) | 12 by default, fixed at genesis (the tests use 2) |
| `WINDOW_MAX` | 60 s |
| `WINDOW_REMOVAL` | 5 s |
| `UPDATE_INTERVAL` | 7 days |
| `CHECKPOINT_INTERVAL` | 1 hour |
| `AUDIT_K` | 20 audits per entry on average |
| `MAX_HEIGHT` | 24 (`2^24` leaves) |
| `MAX_ADMISSION_EPOCHS` | 65,536 |
| Invite / admission / other requests and checkpoints / welcome | 12 / 24 / 48 / 4 KiB |
| District commit / seal | 64 MiB each |

**Measured costs.** The scale test (`crates/cityg-core/tests/scale.rs`, one
core, release build) builds a full group and runs a window of half removals
and half joins paired with them. The number of wraps and new keys equals
the count of the cost model (`research/rekey_sim.py`) for the same leaves;
times vary with the machine:

| | N = 16,384, L = 10, 2,000 changes | N = 65,536, L = 12, 4,000 changes |
| --- | --- | --- |
| Wraps (against the bound `D·ln(N/D)`) | 5,333 (×1.27) | 12,475 (×1.12) |
| New keys | 4,349 | 10,506 |
| District commits | 16, 11.7 MB in all, busiest 852 KB | 16, 27.8 MB in all, busiest 1.9 MB |
| Seal | 51 KB | 51 KB |
| Packet per member | mean 7.7 KB, max 13.4 KB | mean 8.3 KB, max 14.6 KB |
| DS check of the whole window, every entry included | 0.8 s | 1.6 s |

<a id="17-labels"></a>
## 17. Label registry

### 17.1 Labelled hashes (`H_L`)

| Label | Arguments | Section |
| --- | --- | --- |
| `group-id` | `[creator_device_pk, group_nonce]` | 4 |
| `device-id` | `[gid, device_pk]` | 4 |
| `invite-id` | `[invite_pk]` | 4 |
| `kem-pk` | `[pk]` | 3 |
| `tree/leaf` | `[LeafNode or null]` | 5.3 |
| `tree/node` | `[encryption_key, taint]` | 5.3 |
| `tree/parent` | `[content or null, left_hash, right_hash]` | 5.3 |
| `smm/leaf` | `[key, occupancy]` | 8 |
| `smm/node` | `[left, right]` | 8 |
| `registry` | `[admins, devices_root, admissions_root, policy_hash or null, open]` | 8 |
| `confirmed-transcript` | `[prev_interim, seal_hash]` | 9 |
| `interim-transcript` | `[confirmed, confirmation_tag]` | 9 |

### 17.2 Derivation labels and object labels

| Kind | Labels |
| --- | --- |
| `ExpandLabel` / `DeriveSecret` / `KemKey` | `tree node key`, `tree path`, `fresh node`, `wrap key`, `wrap nonce`, `commit`, `joiner`, `epoch`, `init`, `msg`, `confirm`, `external`, `external kem`, `external init`, `welcome key`, `welcome nonce` |
| Framing tags | `city-g/v0.4` (H_L), `city-g/v0.4 expand`, `city-g/v0.4 mac`; profile identifier `city-g/v0.4` |
| Encoded objects | `city-g/group-context/v4`, `city-g/invite/v4`, `city-g/admission/v4`, `city-g/join-request/v4`, `city-g/remove/v4`, `city-g/eviction/v4`, `city-g/group-policy/v4`, `city-g/update/v4`, `city-g/catch-up/v4`, `city-g/re-entry/v4`, `city-g/checkpoint/v4`, `city-g/district-commit/v4`, `city-g/seal/v4`, `city-g/seal-body/v4`, `city-g/welcome/v4` |

### 17.3 Signature contexts (FIPS 204 `ctx`)

The context of a signed array is its label (section 3.4); the seal has a
context of its own.

| Context | Signed object |
| --- | --- |
| `city-g/district-commit/v4` | DistrictCommit, by its committer |
| `city-g/seal/v4` | `[seal_hash, confirmation_tag, external_pk]`, by the sealer |
| `city-g/invite/v4` | Invite, by the inviter |
| `city-g/admission/v4` | Admission, by an admin or an invite key |
| `city-g/join-request/v4` | JoinRequest, by the joining device |
| `city-g/remove/v4` | RemoveProposal, by an admin or the target |
| `city-g/update/v4` | UpdateRequest, by the member |
| `city-g/catch-up/v4` | CatchUpRequest, by the member |
| `city-g/re-entry/v4` | ReEntryRequest, by the member |
| `city-g/checkpoint/v4` | Checkpoint, by an admin |
| `city-g/group-policy/v4` | GroupPolicy, by an admin |

<a id="18-security-considerations"></a>
## 18. Security considerations

* **Windows sealed by an entrant.** The external public key is public, so
  the DS can compute a correct confirmation tag for a window it seals itself
  (model `external_tag_only.pv`). Members MUST check the entrant evidence of
  every kind-2 window: an admin-signed admission never used (or, in an open
  group, none) and a device not a member, or a re-entry signed by the
  member's device key, and the seal signature under the entrant's key
  (`external_checked.pv`). The DS refuses such a window too (section 10.5),
  but members cannot rely on it.
* **Open groups.** Anyone can join an open group, so it has no
  confidentiality against the DS or anyone else who joins: a device kept in
  the group reads from its join on (`open_group.pv`). Epochs before that
  join stay closed to it. What an open group keeps: joins are visible
  (section 12.11); nobody can speak as a member, since messages and
  requests are signed with the member's device key (`open_group.pv`);
  removals, evictions and admin rights keep their rules; and the admission
  mode changes only by an admin's policy, which members check themselves
  (section 12.2). A DS that seals a window with a device of its own acts as
  committer of every district: an invalid removal or update it places is
  caught by audits, as any committer's (section 15), and its victim sees
  it. Rate limits and abuse control belong to the DS and the application.
* **Removed members and the external init.** Every member of epoch `n - 1`
  can recover the external init secret of window `n`, including the members
  the window removes. The new epoch is secret from them only because the
  window re-keys every node they know: their path, and every node they
  taint (`entrant_removal.pv`, `taint.pv`).
* **Committers and entrants.** They learn the secrets they draw. Erasure is
  required; taints make a removed committer's knowledge useless, at the cost
  of re-keying what it drew (for an entrant, possibly the whole window).
  `taint_without_rule.pv` shows the attack without the rule, and the test
  `removing_a_committer_rekeys_the_nodes_it_drew` shows it on real commits.
* **No one online.** Removals then wait for the first participant; the DS
  enforces them meanwhile (section 14.6) and members do not send while one
  waits (section 12.8). A DS that colludes with a removed member can keep
  relaying to it until the removal is applied.
* **The state a role is shown** MUST be checked against a trusted header or
  anchor (section 12.3); otherwise the DS could have secrets wrapped to keys
  of its choosing.
* **Audits are probabilistic.** An invalid entry that escapes the DS, its
  committer and every sampled auditor enters the group. A fraud proof names
  the committer, but only after the fact: admins should remove both the
  committer and the entry. The probability of escape is about `e^-AUDIT_K`
  per entry, if members audit honestly. A fraud proof is checked against
  the verifier's own headers of the epochs around the window; it does not
  show by itself that the commit was sealed (section 19).
* **Forks.** The DS decides what each member sees and can split the group
  into branches. Joiners anchor on admin checkpoints and check the chain of
  seals (`anchored_join.pv`); a joiner that checked only the epoch it
  enters could be led into an epoch the DS fabricated
  (`join_without_anchor.pv`). Members that follow the group check only tags
  and would not notice a fork; they SHOULD compare the interim transcript
  hash out of band.
* **Replays.** A leaf-key request names the key it replaces; a catch-up is
  bound to one window; an admission admits once; occupancies are never
  reused. A welcome is bound to its epoch, request and init key.
* **Jumps.** A member that jumps checks every recovered path secret against
  the key of its node in the tree it enters, itself checked by its leaf
  proof against the tree hash of a seal it verified: stale or forged wraps
  are detected.
* **Placement and roles** do not affect security: a bad placement costs
  bandwidth, a bad role assignment delays a window.
* **Time.** `time_ms` of a seal is the sealer's clock, only required not to
  go backwards.

<a id="19-open-items"></a>
## 19. Open items

This version does not yet specify or implement:

* **The message plane.** The members of epoch `n` share `msg_secret_n`.
  The framing of application messages, per-sender ratchets derived from
  that secret, sender authentication with device keys, and messages that
  arrive after the next epoch remain to be specified. With millions of
  members, per-sender chains must be derived on demand (for instance from a
  secret tree over the leaves, as in MLS), not one per member at every
  epoch. The research note
  [`research/plan-de-messages-2026-09-26.md`](research/plan-de-messages-2026-09-26.md)
  proposes one, and
  [`research/parite-mls-2026-09-26.md`](research/parite-mls-2026-09-26.md)
  what a next profile needs for the guarantees of MLS (encrypted sender
  data, unique keys, a mode where the service authorizes joins, a
  membership log, urgent and ordinary removals); none of it is part of
  this profile.
* test vectors, an independent verifier and a conformance manifest;
* the encodings of packets, seal links, entries, audit records and fraud
  proofs, and district views with proofs for committers (section 12.3);
* the delivery service's API, persistence, and the clients;
* device-key rotation, admin changes beyond the promotion rule, invite
  revocation;
* reports of wraps a member cannot open, so that a malicious committer
  cannot silently cut members off (section 2.3);
* fraud proofs that also bind the district commit to the seal that listed
  it, so that a proof holds on its own across forks (section 15);
* shrinking the tree; pruning the admission map;
* for open groups, optional unique handles bound to device keys, so that a
  name cannot move to another key without every client noticing;
* newer checkpoints signed by later admins, so that a joiner holding an old
  checkpoint does not check a long chain;
* a formal model of this specification: the model of [`formal/`](formal/)
  checks the design choices it rests on.

<a id="20-mls"></a>
## 20. Relation to MLS

City-G keeps the structure of MLS (RFC 9420) where it can, and departs from
it where a group of millions of members needs something else.

| | MLS (RFC 9420) | City-G |
| --- | --- | --- |
| Key schedule | init secret chain, joiner secret from the init secret, the commit secret and the group context, epoch secret, confirmation tag over the confirmed transcript hash, interim transcript hash | the same structure (section 9), with the commit secret taken from the window's root secret |
| Tree | left-balanced array, unmerged leaves, resolutions of blank nodes | sparse, up to `2^24` leaves, split into districts under a city; a parent is blank exactly when its subtree is empty (section 5) |
| Changes | proposals, then one commit by one member per epoch | one window per epoch: district commits built in parallel by several members, then a seal (section 10) |
| Re-key | the committer's update path, encrypted to the resolutions of its copath | a multi-path re-key of each changed district and of the city, chained where possible (section 7.3) |
| Who knows a node's secret | a committer re-keys only its own path, which its removal blanks | a committer re-keys other members' nodes too; taints record who drew each node, and a removal or an update re-keys every node its member drew (section 10.2) |
| Joining | a welcome for a member added by a commit, or an external commit to the group's external key | a welcome for a join a member committed, or, with nobody online, an entrant that seals the window itself with an external init (sections 11 and 12.7) |
| What a joiner checks | the group information signed by a member | the chain of seals from an admin checkpoint (section 12.9) |
| What a member keeps | the public tree | its path, the secrets and the header of its epoch: O(log N) (section 12.1) |
| What a member receives per epoch | the commit | one packet with the steps of its own path (section 13.1) |
| Who validates changes | every member, every proposal | the DS and the committers every entry, the sealer every commit's structure, members random samples (section 15) |
| Suite | the cipher suites of RFC 9420 (classical KEMs and signatures) | X-Wing, ML-DSA-65, BLAKE3 and ChaCha20-Poly1305 (section 3) |
