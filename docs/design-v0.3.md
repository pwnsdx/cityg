# Profile v0.3 design note

| | |
| --- | --- |
| Profile | `city-g/v0.3`, specified in [specs.md](specs.md) |
| Replaces | Profile v0.2 ([archived specification](legacy/v0.2/specs.md)) |
| Goal | Groups of thousands of members where people join and leave all the time, with a simpler protocol and no weaker guarantee |
| Status | Implemented in every crate of the workspace; decisions D-1 to D-9 below are cited by the requirement map [`kat/kat-v0.3-conformance-manifest.json`](../kat/kat-v0.3-conformance-manifest.json) |

The specification says what profile v0.3 is. This note records why it
changed what it changed, what each change costs, and what was left out.

## Starting point

Profile v0.2 closed the findings of the
[2026-09-25 audit](audits/audit-crypto-conformite-2026-09-25.md), but it was
built for groups of tens of members:

* **One join per commit.** A joiner entered with its own external commit.
  `N` people joining at once meant `N` epochs, `N` update paths for every
  member to process, and joiners racing each other for the same epoch (each
  lost race is a rebuilt commit).
* **A fixed tree.** The barrier tree had `n_max` slots fixed at genesis, at
  most 1024, and the members were listed in a separate roster with its own
  hash. Every update path was sized by `n_max`, however many members the
  group had.
* **Unbounded memory of removals.** The roster remembered the last 4096
  removed device ids; a removed device whose id fell off that list could
  come back with an admission it kept, since admissions did not expire.
* **Keys for life.** A device could not replace its signature key without
  leaving the group.
* **Every member holds everything.** Each member kept the whole tree and
  roster, which is fine at 50 members and not at 8000.
* **One previous epoch** of late messages. With frequent commits, messages
  in flight were lost.

## Decisions

<a id="d-1"></a>
### D-1 — Batched joins

**Decision.** A joiner records a signed join request with the delivery
service; the next commit, by any member, places every waiting request in the
tree at once, and each joiner receives a welcome holding the epoch's joiner
secret (RFC 9420 welcomes). A joiner that nobody commits within 1 to 2
seconds commits its own entry with an external commit, which also carries
the other waiting requests. Requests recorded before the current epoch are
*overdue*: every commit must include the oldest of them, up to 64 joins and
256 removals.

**Why.** A wave of joins costs one epoch instead of one per joiner; members
re-key once; joiners no longer race each other. The overdue rule keeps a
committer from starving a request, while a request that arrives during a
commit's construction never makes that commit fail.

**Cost.** Two new objects (join request, welcome), a request status on the
delivery service, and a join that needs someone online, or the joiner's own
external commit after the wait. Joiners are *unmerged* leaves until their
ancestors are re-keyed, which makes update paths larger for a while.

Specification: sections 9.4, 10.3, 12.1, 13.1.

<a id="d-2"></a>
### D-2 — Members in a growable ratchet tree

**Decision.** The ratchet tree follows the array layout of RFC 9420 and
holds the members in its leaves (device key, entry epoch, leaf key,
admission hash). The tree grows by doubling up to the capacity fixed at
genesis (at most 8192) and shrinks to the smallest width covering its
rightmost member. A member is named by its *occupancy* `[leaf, since]`. The
roster disappears; the registry keeps only what is not per-leaf: capacity,
admins and retired admissions.

**Why.** One structure and one hash instead of two; update paths sized by
the actual group, not by its capacity; the RFC 9420 layout keeps node
indices stable when the tree grows or shrinks and makes resolutions and
unmerged leaves standard. An occupancy reference cannot be reused, even
when a leaf is emptied and filled again.

**Cost.** The largest update of an 8192-leaf tree is under 10 MB, and a full
tree of 8192 members about 35 MB. Past a few thousand members, most devices
should be light members (D-7).

Specification: sections 5, 6, 7.

<a id="d-3"></a>
### D-3 — Admissions with a validity window, retired while valid

**Decision.** Admissions name their last epoch (at most 4096 epochs ahead).
When an occupancy ends by a removal, its admission hash is retired until
that admission could no longer be used, then forgotten. At most 4096 are
kept; when an entry that is still valid must go, a *retired floor* rises to
its expiry and every admission whose last epoch is not above the floor is
refused.

**Why.** The registry stays small, which light members need (D-7), and a
removed member never comes back with an admission it kept, however many
members leave: this closes the gap of v0.2 above.

**Cost.** Admissions expire: an admin's admission or an invite-signed one is
usable for about 1024 epochs with the reference clients. Under extreme
churn (more than 4096 removals within an admission's validity), new
admissions get a later last epoch, above the floor.

Specification: sections 7, 10.2, 13.1.

<a id="d-4"></a>
### D-4 — Invites with a use count and revocation

**Decision.** An invite names how many devices it may admit, and an admin can
revoke it. The delivery service counts uses when it records a join request
(or accepts an external join) and refuses revoked or used-up invites; a
revocation drops the waiting requests that rely on the invite.

**Why.** An invite link is a bearer secret. In large groups it is posted
widely, and an expiry alone does not limit how many devices it lets in.

**Cost.** Counting and revocation need a global view, so they are enforced by
the delivery service and not verified by members, like the invite expiry of
v0.2. Members still verify that every admission chains to a current admin.

Specification: sections 10.2, 12.1.

<a id="d-5"></a>
### D-5 — Device-key rotation

**Decision.** A Member commit may replace its author's device key. The old
key signs the commit as usual (it authorizes the rotation) and the new key
signs the same bytes under its own context (it proves possession). The
occupancy, the admission and the admin rights stay; messages of earlier
epochs verify under the key held then.

**Why.** A device that suspects its key store, or a long-lived member, can
move to a new key without leaving and re-joining, which in a large group
would mean new admissions and a new occupancy.

**Cost.** A rotation does not undo a compromise: whoever holds the key can
rotate it first. The table of section 2.2 keeps "no, until the device is
removed" for a compromised device key.

Specification: sections 2.2, 9.1 to 9.4, 11.3.

<a id="d-6"></a>
### D-6 — X-Wing and ML-DSA-65

**Decision.** Tree keys, welcomes and external init use X-Wing (ML-KEM-768
combined with X25519, draft-connolly-cfrg-xwing-kem-06). Signatures use
ML-DSA-65 instead of ML-DSA-87.

**Why.** The hybrid keeps confidentiality if either ML-KEM-768 or X25519
holds, at 32 extra bytes per key and ciphertext. ML-DSA-65 matches the
security category of ML-KEM-768; ML-DSA-87 cost 1.4 times the signature
size (4627 against 3309 bytes) and 1.3 times the public-key size (2592
against 1952 bytes) for a level the KEM did not reach, and a large group
signs and stores many of both.

Specification: section 3.

<a id="d-7"></a>
### D-7 — Light members

**Decision.** A member may keep, instead of the tree, the occupancies of the
group (a few bytes per member), the registry, its own leaf and private path,
and the device keys it verified. It checks commits with Merkle proofs of the
member records they rely on, which the delivery service computes when it
accepts the commit (a *LightCommit*), and joins with a *LightJoin* (registry,
occupancies, its own leaf proof). It proves the senders of messages with
leaf proofs on demand. To commit, it becomes full for that commit.

**Why.** A member of an 8000-member group should not have to download and
store 35 MB of public keys to read messages. A parent node's content is
hashed apart from its children (section 6.3), so a proof costs 32 bytes per
level.

**Cost and trust.** A light member verifies every signature, authorization,
entry leaf, the registry, the path secrets and the confirmation tag, but not
the new tree hash nor the uniqueness of device keys across the tree. Against
a delivery service colluding with a member, membership agreement holds for
it only up to the tree hash (section 14.6); the other properties are
unchanged.

Specification: sections 6.7, 12.1, 14.

<a id="d-8"></a>
### D-8 — Late messages over several epochs

**Decision.** Members keep the message keys of up to four previous epochs,
each for 10 minutes after the next epoch began, and the delivery service
accepts envelopes for them within the same bounds, from senders that are
still members.

**Why.** A large group commits often (batched joins, removals, self-updates):
a message sent just before two quick commits must still be readable.

**Cost.** Forward secrecy for those keys is bounded by the grace window, as
in v0.2, now for four epochs.

Specification: sections 11.3, 12.1.

<a id="d-9"></a>
### D-9 — Key schedule aligned with RFC 9420

**Decision.** A `joiner_secret` step sits between the commit secret and the
epoch secret, so that welcomes carry a secret from which nothing of the
previous epoch derives, and the commit secret is one derivation past the
root path secret, so that a one-member tree still gets a fresh one.

**Why.** Join secrecy with welcomes, and the RFC 9420 structure that
reviewers know.

Specification: sections 6.5, 8.

## Left out

* **The RFC 9420 wire format and OpenMLS.** City-G keeps its deterministic
  CBOR encodings, its post-quantum suite, its external commits for resync
  and the rules its delivery service enforces. It adopts RFC 9420 semantics
  (tree layout, unmerged leaves, welcomes, joiner secret) where they fit, but
  does not aim at MLS interoperability.
* **Commits by light members.** Authoring a commit needs the resolution of
  every node of the author's copath, that is most of the tree. A light
  member becomes full for one commit instead.
* **Proving the new tree hash to light members.** It would take a proof of
  every node the commit changes. Profile v0.3 states the trust assumption
  instead (section 14.6).
* **Anchored joins.** A joiner checks the epoch it enters but not the
  history before it, so a delivery service can make it enter a forked view
  (section 2.3 of the specification); comparing security codes detects it.
  A joiner could instead replay the public transitions since an epoch that
  the admin who invited it attested in the invite, as the delivery service
  does. It would need the tree of that epoch and every commit since, and a
  new invite format; profile v0.3 keeps the comparison of security codes.
* **Proposals by reference for admin changes and rotation.** Only removals
  and join requests wait in the delivery service; admin changes and rotations
  stay inside the commit of their author.
* **Sub-groups and federation.** Not needed up to 8192 members. Groups of
  millions of members are the subject of a separate
  [research note](research/grands-groupes-2026-09-25.md).

## Relation to the audit findings

Profile v0.3 keeps every rule that closed a finding of the 2026-09-25 audit:
the author of a commit never removes itself (C-03), every entry carries an
admission signed by an admin or an admin's invite (H-01), one signature per
commit over a closed key registry (H-04), per-sender message chains with
membership checks (H-10, M-01, M-02) and cover-failure reports (M-05). Three
findings are addressed further:

* **H-08** (size of updates): updates are sized by the group, the capacity
  goes up to 8192 with a bound under 10 MB, and light members avoid holding
  the tree (D-2, D-7).
* **M-03** (messages lost when the epoch changes): four previous epochs
  instead of one (D-8).
* **P-4** (verifiable admission): retired admissions with a validity window
  and a floor replace retired device ids, without the gap above (D-3).

The formal model of [`formal/`](formal/README.md) covers the v0.3 key
schedule, batched joins and welcomes, admission, removal and rotation (P-8).
