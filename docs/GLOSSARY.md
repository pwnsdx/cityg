# Glossary (profile v0.3)

Section numbers refer to the [specification](specs.md).

**Admin.** A member whose leaf is in the registry's admin list. Admins sign
invites and admissions, revoke invites, remove members and change the
admins. A group has at most 64 admins; if a commit leaves none, its author
becomes one. Admin rights belong to the occupancy: they survive a resync and
a key rotation and end with a removal (sections 7, 9.4).

**Admission (`SignedAdmission`).** The signed statement that lets a device
join: signed by an admin for a known device (kind 0), or by the joiner
itself with an invite key whose invite an admin signed (kind 1). It names
the device (`device_id`) and its last epoch (`not_after_epoch`); its hash is
recorded in the joiner's leaf (section 10.2).

**Alias (`AliasBinding`).** A display name a member publishes for itself,
signed by its device key. Self-asserted and outside the group protocol;
clients pin the occupancy first seen for an alias (section 15.1).

**Capacity.** The largest number of leaves of a group, a power of two
between 2 and 8192 fixed at creation (section 6.1).

**Commit.** The signed object that moves a group from epoch `n - 1` to `n`.
Kinds: Genesis, Member, ExternalJoin, Resync. A CBOR map with a closed key
registry, one ML-DSA-65 signature by its author (two when it rotates the
author's key) and a confirmation tag (section 9).

**Confirmation tag.** `MAC(confirm_key_n, confirmed_transcript_hash_n)`:
proves that the commit's author derived the same epoch secrets as the
verifier (section 8).

**Cover failure (`CoverFailureReport`).** A signed report by a member that
could not process a commit (not covered, wrong path key, wrong confirmation
tag, lost state). The member then resyncs (section 10.5).

**Delivery service (DS).** The server: it verifies commits against public
state, orders them, relays envelopes, stores invites, proposals, join
requests, welcomes, reports, light-member proofs and aliases, and never holds
a group secret (section 12).

**Device key, `device_id`.** The ML-DSA-65 key pair of a device in a group.
It signs the device's commits, messages and other objects, and can be
replaced by a rotation. `device_id := H_L("device-id", [gid, device_pk])`
names the device in an admission, before it has a leaf (sections 5, 9.3).

**Entry leaf.** Where a member enters: the lowest blank leaf, or, when every
leaf is occupied, the first leaf of the doubled tree (section 6.1).

**Epoch.** The state of a group between two commits. Epoch `n` has its
GroupContext, epoch secrets and message chains.

**Epoch secrets.** `joiner_secret_n`, then `epoch_secret_n` and what derives
from it: `init_secret` (chains to the next epoch), `msg_secret` (message
chains), `confirm_key` (confirmation tag) and `external_secret` (external key
pair) (section 8).

**External commit, external init.** A commit whose author cannot use
`init_secret_{n-1}`: a joiner (ExternalJoin) or a member that lost its state
(Resync). It encapsulates to the epoch's external X-Wing key, published in
the GroupInfo, and uses the external init secret instead (section 8.1).

**Forward secrecy (FS).** Compromising a device does not reveal content of
epochs whose keys it erased. Members re-key their leaf at least every 24
hours (`FS_WINDOW`) and erase old keys (sections 2.2, 13.4).

**`gid`.** The group identifier, `H_L("group-id", [creator_device_pk,
group_nonce])`. It binds the creator, who is the first admin (section 5).

**Grace window.** For 10 minutes after an epoch ends, members and the DS
still accept its messages from senders that are still members, for up to
four previous epochs (sections 11.3, 12.1).

**GroupContext.** `["city-g/group-context/v3", gid, epoch, tree_hash,
registry_hash, "city-g/v0.3", confirmed_transcript_hash]`. Every epoch secret
derives from its hash, so members with different views derive different keys
(section 8).

**GroupInfo.** The public description of an epoch (GroupContext,
confirmation tag, external public key, signer leaf), signed by the author of
its commit. Joiners and resyncing members start from it (section 10.4).

**`H_L`.** The labelled hash `BLAKE3(CBOR_det(["city-g/v0.3", label,
args]))` (section 4.2).

**Invite, invite seed, invite link.** An admin-signed invite names an invite
public key, an expiry and a number of uses. The key pair derives from a
32-byte invite seed, shared out of band in an invite link
`cityg-invite:{"version":5,"server_url":…,"room_id":…,"invite_seed":…}`.
Anyone holding the link can join until the invite expires, is revoked or has
admitted its number of devices (sections 10.2, 15.3).

**Join request (`SignedJoinRequest`).** A joiner's signed request, carrying
its device key, the key of its future leaf, a one-time init key and its
admission. The DS records it; the next commit places it and seals a welcome
for it. `request_ref` names it (section 10.3).

**Joiner secret.** The secret a welcome carries: the epoch's secrets derive
from it, and nothing of the previous epoch does (section 8).

**Leaf proof.** A Merkle proof that a leaf of a tree holds a given member (or
is blank): the leaf, the width, the leaf node and 32 bytes per level,
checked against a tree hash (section 6.7).

**Light member.** A member that keeps the occupancies, the registry, its
own path and the device keys it verified instead of the tree, and checks
commits with the proofs of a LightCommit. It becomes full for the commits it
authors and relies on the DS for the new tree hash (section 14).

**LightCommit, LightJoin.** The data a light member needs for a commit (leaf
proofs, against the previous tree, of the members the commit's authorization
refers to) and for a join (registry, occupancies and its own leaf proof). The
DS computes and serves them (sections 14.3, 14.4).

**Log.** The ordered list of accepted commits, envelopes and recorded
proposals and join requests of a group, numbered by `seq` (section 12.2).

**Membership agreement.** Full members that accept the same commit agree on
the tree, the registry and the whole transcript (section 2.2).

**Member reference, occupancy.** `[leaf, since]`: the leaf a member occupies
and the epoch it entered. It names a member in messages, removal proposals
and admin changes, and is never reused; a resync starts a new occupancy of
the same leaf, a key rotation does not (sections 1, 5).

**Message chain (per-sender ratchet).** Each member derives, from
`msg_secret_n`, one chain per member of the epoch, keyed by its occupancy; a
sender uses its own chain with increasing generations, and keys are erased
once used (section 11.2).

**Overdue proposal.** A removal proposal or join request recorded before the
current epoch started. Every commit must include the oldest overdue ones, up
to 256 removals and 64 joins (section 12.1).

**Post-compromise security (PCS).** After a device whose state was
compromised re-keys its leaf from a fresh secret, the attacker loses access
to later epochs (section 2.2). It does not cover a stolen device key, which
lets the attacker act as the device until it is removed.

**Post-removal secrecy (PRS).** A removed member derives no secret of the
epochs after its removal. A member never commits its own removal (sections
2.2, 9.4).

**Profile.** `city-g/v0.3`: the set of encodings, labels, algorithms and
parameters of this specification. Any change to them is a new profile.

**Ratchet tree.** The tree of a group in the RFC 9420 array layout: leaves
hold the members (device key, entry epoch, X-Wing leaf key, admission hash),
parents hold an X-Wing key and their unmerged leaves. It doubles when a
member enters a full tree and halves when its right half empties. Each
commit re-keys its author's leaf and direct path (section 6).

**Registry.** The group-wide state beside the tree: capacity, admin leaves,
retired admissions and the retired floor; `registry_hash` commits to it
(section 7).

**Removal proposal (`SignedRemoveProposal`).** A signed request to end one
occupancy `[target_leaf, target_since]`, by its target (leave) or by an
admin. The DS records it, and a later commit, by another member or a joiner,
includes it (section 10.1).

**Resolution.** The smallest set of nodes whose private keys cover every
member below a node; path secrets are encrypted to the resolutions of the
copath (section 6.4).

**Resync.** Re-entering one's own leaf as a new occupancy with an external
commit, after losing state or failing to process a commit (section 9.3).

**Retired admission, retired floor.** The admission of a removed member,
kept in the registry while it could still be used so that it cannot be used
again. When more than 4096 are kept, the oldest goes and the retired floor
rises to its expiry: admissions whose last epoch is not above the floor are
refused (section 7).

**Rotation.** Replacing a device key with a Member commit signed by the old
key and by the new one; the occupancy, admission and admin rights stay
(section 9.3).

**Security code.** The transcript fingerprint the GUI shows (the interim
transcript hash): two members with equal codes have the same history
(see [fingerprints.md](fingerprints.md)).

**Session token.** A 32-byte bearer token the DS issues for a signed
`SessionAuth`; needed to read the log, send, and list aliases and reports.
It stops working when the member's occupancy ends or its key is rotated
(section 15.1).

**Transcript hashes.** The confirmed and interim transcript hashes chain
every commit of the group's history into the next GroupContext (section 8).

**Unmerged leaf.** A leaf that entered below a parent node after the node's
key was set, and so does not hold its private key; encryptors add it to the
node's resolution until a commit re-keys the node (section 6.2).

**Welcome.** The object that lets a joiner placed by someone else's commit
enter: the joiner secret of the epoch, encrypted to the joiner's one-time
init key. It is not signed; the joiner checks it against the commit's
confirmation tag and the GroupInfo (section 10.3).

**Width.** The number of leaves of the tree: the smallest power of two
covering the rightmost member (section 6.1).

**X-Wing.** The hybrid KEM of the profile, ML-KEM-768 combined with X25519:
it keeps confidentiality if either holds (section 3).
