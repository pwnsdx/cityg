# Glossary

Section numbers refer to the [specification](specs.md).

**Admin.** A member whose occupancy and device key are in the registry's
admin list. Admins sign admissions, invites, checkpoints and group
policies, and may remove any member. If a window leaves no admin, its
sealer becomes one (the promotion rule, section 8).

**Admission.** A signed permission for one device to join once, by an admin
(kind 0) or by the holder of an invite key (kind 1). It names the device
(`device_id`) and its last epoch. Its hash is recorded in the admission map
when it is used (sections 6 and 8).

**Anchor.** The epoch a joiner or a returning member checks the chain of
seals from: an admin checkpoint, or the last epoch a member followed
(section 12.9).

**Audit record.** One entry of a window with the proofs an auditor needs to
check it against the previous epoch's header (section 15).

**Blank.** A leaf without a member, or a parent node without a key. A parent
node is blank exactly when its subtree holds no member (section 5.2).

**Catch-up (jump).** A returning member's signed request for a welcome into
the next window; it recovers its path from the last step of each of its
nodes and skips the epochs in between (section 12.10).

**Change.** `[kind, leaf, request_ref]`: a removal, eviction, join, update
or re-entry that a district commit applies to one leaf (section 10.1).

**Checkpoint.** An admin's signed statement of an epoch: interim transcript
hash, tree hash, registry hash, shape and external key hash. Joiners anchor
on it (sections 6 and 12.9).

**City.** The levels of the tree above the districts, re-keyed by the
sealer (section 5.1).

**Closed group.** A group whose joins need an admission; every group
without a policy that opens it (section 6.1).

**Committer.** The member (or entrant) that re-keys one district of a window
and signs its district commit. It need not belong to the district
(sections 10.3 and 12.4).

**Confirmation tag.** `MAC(confirm_key_n, confirmed_transcript_hash_n)`:
proves that whoever computed it derived the same epoch secrets, which bind
the tree, the registry and the transcript (section 9).

**Delivery service (DS).** The server: it records and checks requests,
closes windows, assigns roles, checks commits and seals, and serves packets,
seal links and entries. It never draws a group secret and never signs a
group object (section 14).

**Device key.** The ML-DSA-65 key a device signs with in one group; its
hash with the group identifier is the `device_id` (section 4).

**District.** A subtree of `2^L` leaves, re-keyed by its own committer in
parallel with the others (section 5.1).

**Entrant.** With no member online, the joiner or returning member that
takes every role of a window: it commits every district, seals with an
external init and welcomes the others (section 12.7).

**Entry.** What a joiner or a returning member downloads to enter an epoch:
the chain of seals, its welcome, the steps of its path, its leaf proof and
its path's parent nodes (section 13.4).

**Epoch.** The state a window creates. Epoch `n` has a tree, a registry, a
transcript and its secrets (section 9).

**Eviction.** A removal the DS writes, under an admin-signed policy, for a
member whose leaf key has not changed for too long (sections 6 and 14.7).

**External init.** The init secret an entrant encapsulates to the external
key of the previous epoch, in place of that epoch's init secret, which it
does not know (section 9).

**Forced node.** A node a window must re-key besides the paths of its
changed leaves: the taints of the members it removes, evicts, updates or
re-enters, and the nodes above the old root when the tree grows (section
10.2).

**Fraud proof.** A signed district commit, an audit record of an invalid
entry and the committer's leaf proof: anyone can check that the committer
placed that entry (section 15).

**Group policy.** An admin-signed object stating whether the group is open
and after how many epochs an idle member may be evicted (section 6).

**Init key.** A one-time X-Wing key of a join, re-entry or catch-up
request, to which a welcome is sealed (section 11).

**Leaf proof.** A leaf and, for each level, the content of its ancestor and
the hash of the sibling subtree: it recomputes the tree hash (section 5.3).

**Occupancy.** `[leaf, since]`: a member, named by its leaf and the epoch it
entered it. It is never reused (section 1).

**Open group.** A group whose policy lets any device join with its own
signed request and no admission; every join stays visible (section 6.1).

**Packet.** What a member downloads for one window: the seal header, the
tag, the registry update and the steps of its path (section 13.1).

**Path.** A member's leaf and its ancestors up to the root; a member holds
the secret of each (section 7.4).

**Plan.** The public structure of a re-key: which nodes, which become blank,
where each secret is chained from and which children it is wrapped to. Any
verifier recomputes it (section 7.3).

**Re-entry.** A returning member's signed request to re-enter its own leaf
with a new leaf key (section 12.10).

**Registry.** The admins, the device map, the admission map and the group
policy's hash and mode; members keep its header (section 8).

**Removal, recorded and applied.** A removal is recorded when the DS accepts
its proposal, and applied by the next window, which re-keys everything the
member knew (sections 14.2 and 14.6).

**Seal.** The object that creates an epoch: the header (hashes, sealer,
external init of an entrant), the body (district commit hashes, the city's
re-key, a group policy) and one signature over the header, the tag and the
next external key (section 10.4).

**Seal link.** One step of a chain of seals: the seal proof, the evidence
that its signer was a member or an admitted entrant, and the registry header
(section 13.3).

**Sealer.** The member (or entrant) that checks the district commits of a
window, re-keys the city and signs the seal (section 12.5).

**Sparse Merkle map.** A map from 32-byte keys to occupancies whose root
depends only on its entries, with proofs of values and of absences (section
8).

**Step.** How a member gets the new secret of a re-keyed ancestor: `Wrap`
(opened with the key of the child toward it) or `Chain` (derived from the
child's new secret) (section 7.4).

**Taint.** The occupancy of the committer that drew a node's current secret,
public and hashed with the tree. Removing or updating a member re-keys every
node it taints (sections 5.2 and 10.2).

**Token.** What the admission map records for a join so that it enters
once: the admission's hash, or the request's hash without admission (section
6).

**Volunteer.** An online member the window does not affect, to which the DS
may give a role (section 14.4).

**Welcome.** The joiner secret of a window sealed to a one-time init key, for
a joiner, a re-entering member or a member that asked to jump (section 11).

**Window.** The requests the DS collects before one epoch; it closes after
`WINDOW_MAX`, or `WINDOW_REMOVAL` when a removal waits (section 14.2).

**Wrap.** A node's new secret for the holder of a child's key: an X-Wing
encapsulation and the secret under ChaCha20-Poly1305 (section 7.2).
