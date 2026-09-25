# Glossary (profile v0.2)

Section numbers refer to the [specification](specs.md).

**Admin.** A member whose device key is in the roster's admin set. Admins
sign invites and admissions, remove members and change the admin set. A
group has at most 64 admins; the last one cannot be revoked; if no admin
remains, the member in the lowest occupied slot becomes admin (section 7).

**Admission (`SignedAdmission`).** The signed statement that lets a device
join: signed by an admin for a known joiner (kind 0), or by the joiner itself
with an invite key whose invite an admin signed (kind 1). Its hash is
recorded in the joiner's roster record (section 10.2).

**Alias (`AliasBinding`).** A display name a member publishes for itself,
signed by its device key. Self-asserted and outside the group protocol;
clients pin the key first seen for an alias (section 14.1).

**Barrier tree.** The ratchet tree of a group: `n_max` leaf slots in heap
order, whose nodes hold ML-KEM-768 public keys. Each commit re-keys its
author's leaf and direct path; the root path secret feeds the key schedule
(section 6).

**Commit.** The signed object that moves a group from epoch `n - 1` to `n`.
Kinds: Genesis, Member, ExternalJoin, Resync. A CBOR map with a closed key
registry, one ML-DSA-87 signature and a confirmation tag (section 9).

**Confirmation tag.** `MAC(confirm_key_n, confirmed_transcript_hash_n)`:
proves that the commit's author derived the same epoch secrets as the
verifier (section 8).

**Cover failure (`CoverFailureReport`).** A signed report by a member that
could not process a commit (not covered, wrong path key, wrong confirmation
tag, lost state). The member then resyncs (section 10.4).

**Delivery service (DS).** The server: it verifies commits against public
state, orders them, relays envelopes, stores invites, proposals, reports and
aliases, and never holds a group secret (section 12).

**Device key.** The ML-DSA-87 key pair of a device in a group. It signs the
device's commits, messages and other objects; `leaf_id` hashes it with the
`gid`.

**Epoch.** The state of a group between two commits. Epoch `n` has its
GroupContext, epoch secrets and message chains.

**Epoch secrets.** `epoch_secret_n` and what derives from it: `init_secret`
(chains to the next epoch), `msg_secret` (message chains), `confirm_key`
(confirmation tag) and `external_secret` (external key pair) (section 8).

**External commit, external init.** A commit whose author is not (or no
longer) able to use `init_secret_{n-1}`: a joiner (ExternalJoin) or a member
that lost its state (Resync). It encapsulates to the epoch's external
ML-KEM key, published in the GroupInfo, and uses the external init secret
instead (section 8.1).

**Forward secrecy (FS).** Compromising a device does not reveal content of
epochs whose keys it erased. Members re-key their leaf at least every 24
hours (`FS_WINDOW`) and erase old keys (sections 2.2, 13.4).

**`gid`.** The group identifier, `H_L("group-id", [creator_device_pk,
group_nonce])`. It binds the creator, who is the first admin (section 5).

**Grace window.** For 10 minutes after an epoch starts, members and the DS
still accept messages of the previous epoch from senders that are still
members (sections 11.3, 12.1).

**GroupContext.** `["city-g/group-context/v2", gid, epoch, tree_hash,
roster_hash, "city-g/v0.2", confirmed_transcript_hash]`. Every epoch secret
derives from its hash, so members with different views derive different keys
(section 8).

**GroupInfo.** The public description of an epoch (GroupContext,
confirmation tag, external public key), signed by the author of its commit.
Joiners and resyncing members start from it (section 10.3).

**`H_L`.** The labelled hash `BLAKE3(CBOR_det(["city-g/v0.2", label,
args]))` (section 4.2).

**Invite, invite seed, invite link.** An admin-signed invite names an invite
public key and an expiry. The key pair derives from a 32-byte invite seed,
shared out of band in an invite link
`cityg-invite:{"version":4,"server_url":…,"room_id":…,"invite_seed":…}`.
Anyone holding the link can join until the invite expires (sections 10.2,
14.3).

**Leaf, slot, generation.** A slot is a leaf position of the tree. An
occupancy of a slot is named by `(slot, generation)`: the generation counts
the occupants of the slot, so a proposal or a message cannot be replayed
against a later occupant (section 7).

**`leaf_id`.** `H_L("leaf-id", [gid, device_pk])`: the identity of a member
in a group.

**Log.** The ordered list of accepted commits, envelopes and recorded
proposals of a group, numbered by `seq` (section 12.2).

**Membership agreement.** Members that accept the same commit agree on the
tree, the roster and the whole transcript (section 2.2).

**Message chain (per-sender ratchet).** Each member derives, from
`msg_secret_n`, one chain per roster member; a sender uses its own chain with
increasing generations, and keys are erased once used (section 11.2).

**`n_max`.** The number of leaf slots of a group, a power of two between 2
and 1024 fixed at creation; the group's capacity.

**Post-compromise security (PCS).** After a device whose state was
compromised re-keys its leaf from a fresh secret, the attacker loses access
to later epochs (section 2.2). It does not cover a stolen device key, which
lets the attacker act as the device until it is removed.

**Post-removal secrecy (PRS).** A removed member derives no secret of the
epochs after its removal. A member never commits its own removal (sections
2.2, 9.4).

**Profile.** `city-g/v0.2`: the set of encodings, labels, algorithms and
parameters of this specification. Any change to them is a new profile.

**Removal proposal (`SignedRemoveProposal`).** A signed request to end one
occupancy, by its target (leave) or by an admin. The DS records it, and the
next commit, by another member, must include it (section 10.1).

**Resync.** Re-entering one's own slot under the next generation with an
external commit, after losing state or failing to process a commit.

**Retired device.** A device whose occupancy ended by a leave or a
removal. Its `leaf_id` stays in the roster's `retired` list (the last 4096)
and cannot join again, so an admission is good for one membership
(section 7).

**Roster.** The public list of member records `[leaf_id, device_pk, slot,
generation, admission_hash]`, the admin set, the last generation of each
slot and the retired devices; `roster_hash` commits to all of it
(section 7).

**Security code.** The transcript fingerprint the GUI shows (the interim
transcript hash): two members with equal codes have the same history
(see [fingerprints.md](fingerprints.md)).

**Session token.** A 32-byte bearer token the DS issues for a signed
`SessionAuth`; needed to read the log, send, and list aliases and reports
(section 14.1).

**Transcript hashes.** The confirmed and interim transcript hashes chain
every commit of the group's history into the next GroupContext (section 8).

**Vacant group.** A group whose every member has a recorded removal; the
next joiner commits them (section 12.1).
