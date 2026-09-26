# Profile v0.4 design note (draft)

| | |
| --- | --- |
| Profile | `city-g/v0.4-draft`, drafted in [specs-v0.4-draft.md](specs-v0.4-draft.md) |
| Status | Draft. Profile [v0.3](specs.md) stays the normative profile; v0.4 does not interoperate with it and replaces nothing yet. |
| Goal | Groups of millions of members, waves of hundreds of thousands of joins and departures, and a group that keeps working when none of its members is online |
| Prototype | [`crates/cityg-cite`](../crates/cityg-cite): protocol core and an in-memory delivery service, no I/O |
| Research | [`research/grands-groupes-2026-09-25.md`](research/grands-groupes-2026-09-25.md) (in French): lower bounds, related work, cost model, measured costs; [`research/formal/`](research/formal/README.md): symbolic model of the security choices |

The research note says why this design and what it costs. This note
records the decisions of the draft profile (E-1 to E-13), what each one
costs, and what was left out.

## Starting point

Profile v0.3 serves thousands of members. Four limits stop it well before
a million:

* **A capacity of 8192 leaves.** It bounds the size of an update, not the
  size a group would need.
* **One chain of commits.** Each commit carries at most 64 joins and 256
  removals, one commit at a time. A wave of 100,000 joins and 100,000
  departures takes 1,563 commits, and the last removed member keeps access
  meanwhile.
* **Every member replays every commit,** and a full member holds the whole
  tree: about 4.5 GB for a million members.
* **Committing needs an online member.** A joiner can enter by itself with an
  external commit, but a removal waits for a member.

The lower bounds of the research note (section 2.1) show that the total
work of a wave cannot shrink below about D·ln(N/D) ciphertexts for D
changes among N members. What a design can choose is to pay it once per
window, to spread it over many devices, and to keep what each member
downloads in O(log N).

## Decisions

<a id="e-1"></a>
### E-1 — Epochs sealed per window

**Decision.** The delivery service collects requests (joins, removals,
updates, catch-up requests) during a window and closes it after at most
`WINDOW_MAX` (60 s by default). A pending removal closes it after
`WINDOW_REMOVAL` (5 s). One epoch per non-empty window. A window is sealed
in three phases:

1. one district commit per district that changes;
2. one seal, which re-keys the levels above the districts and creates the
   epoch;
3. the welcomes of the window's joiners.

**Why.** The whole queue of a window enters at once, with no cap per
commit, no race between joiners and no rebuilt commit.

**Cost.** A removal takes effect when its window is sealed, after at most
`WINDOW_MAX` plus a few seconds, instead of at the next commit.

<a id="e-2"></a>
### E-2 — Districts and a city, re-keyed along every changed path

**Decision.** The tree is split into *districts* of `2^L` leaves (L = 12 by
default) under a *city*.

A window re-keys every ancestor of a changed leaf, and nothing else:
* a re-keyed node takes the new secret of a re-keyed child through a one-way
  step, and wraps it to its other live child;
* where the committer knows no child's new secret, it draws a fresh one and
  wraps it to both children. That is just above the leaves, and just above
  the district roots for the sealer;
* a node is blank exactly when its subtree holds no member.

There are no unmerged leaves, no resolutions and no blanked paths to repair.

**Why.** Every district is a separate unit of work, so committers work in
parallel. The cost of a window stays within a factor 1.5 to 2.7 of the
lower bound (research note, section 4.1).

**Cost.** A district commit is at most about 12 MB, when the whole district
changes. A committer holds the public state of a district, about 18 MB with
L = 12.

<a id="e-3"></a>
### E-3 — Committers need no state of their own

**Decision.** Any member of the current epoch can commit any district and
seal a window: it needs the public state of what it re-keys and the
secrets every member holds. The delivery service assigns the roles of a
window among online volunteers. A committer is never among the members its
window removes (rule C-03 of v0.3).

**Why.** A district with no member online is committed by a member of
another district, and a failed committer is replaced at once.

**Cost.** A committer learns the secrets of the nodes it re-keys for others
(E-4).

<a id="e-4"></a>
### E-4 — Taints

**Decision.** Every parent node carries its *taint*: the occupancy of the
committer that drew its current secret, public and hashed with the tree.
* **Integrity.** The taint of every node a commit re-keys is the commit's
  signer, and verifiers check it.
* **Removal.** Removing a member re-keys its path and every node it still
  taints.
* **Update.** A member's update re-keys them as well.
* **Erasure.** An honest committer erases the secrets it drew off its own
  path once its commit is sent.

**Why.** Without the rule, a removed committer reads the next epoch
(research model, `taint_without_rule.pv`); with it, it does not
(`taint.pv`, `post_compromise.pv`).

**Cost.** Removing a committer right after its commit costs about one more
commit of its district.

<a id="e-5"></a>
### E-5 — Key schedule with the init chain

**Decision.** The key schedule is v0.3's, with the root secret of the
window in place of the commit secret: `joiner_secret` derives from the
previous `init_secret` and the window's commit secret. The seal carries one
signature over its content, the confirmation tag and the next external key.

A member that follows the group checks the confirmation tag of every
window. It does not have to check the sealer's signature. Signatures are
checked by:
* joiners;
* members that jump to the present;
* every member, for windows sealed by an entrant (E-7).

**Why.** Two things. First, a leaked leaf key no longer exposes past epochs
(`forward_secrecy.pv`), which it does without the chain
(`forward_secrecy_without_init.pv`). Second, the delivery service cannot
make a member accept an epoch it forged when the member checks only the
tag (`fabrication.pv`). This halves to quarters the traffic of a member
that follows every window (research note, section 4.5). A tag the signature
does not cover lets the service replace a welcome
(`anchored_join_unsigned_tag.pv`).

**Cost.** Joiners need welcomes (E-6). A member coming back after an
absence replays the windows it missed or jumps to the present (E-8).

<a id="e-6"></a>
### E-6 — District welcomes

**Decision.** Once the seal is out, the committer of each district
computes the window's joiner secret, as a member of the previous epoch, and
seals it to the one-time init key of each joiner of its district. The
joiner decrypts its path with its leaf key and derives the epoch from the
welcome.

**Why.** The work of a wave of joiners is spread over the districts: 38 to
61 ms of CPU per district in the largest simulated waves. The init key is
used once, so a later leak of the leaf key does not expose the epoch of the
join (`join.pv`).

**Cost.** A third phase in the window, and one wrap (1.2 KB) per joiner.

<a id="e-7"></a>
### E-7 — A group with no member online

**Decision.** The delivery service never draws a group secret and never
signs a group object. When no member is online at the end of a window:

* **Entrant-sealed window.** If the window holds a join request, or a
  re-entry request from a returning member, the first such device seals the
  whole window. It commits every district that changes, seals with an
  *external init* (it encapsulates to the external key of the current
  epoch, as a v0.3 external commit does), and seals every welcome. Members
  catch up later and derive the epoch with their external secret.
* **Deferred removal.** Otherwise the window stays open. A recorded removal
  is enforced at once by the delivery service: it refuses the removed
  member's messages and commits. The removal is applied cryptographically
  by the first participant that comes online, member or entrant.
  * A member does not send in an epoch that has a removal older than
    `WINDOW_REMOVAL` still waiting. Since nobody sends while nobody is
    online, the removed member reads no message sent after its removal.
* **Eviction policy.** The delivery service removes a member on its own
  only under an admin-signed eviction policy, for a member whose leaf key
  has not changed for longer than the policy allows. Verifiers check the
  policy and the leaf.

**Why.** A group keeps admitting joiners and enforcing removals with no one
online, and the server still reads nothing.

**Cost.** In an entrant-sealed window, the tag alone no longer proves
anything against the delivery service, because the external key is public.
Every member checks the entrant's signature and admission for such windows.
Also, removal without any online participant cannot be cryptographic: it
would take a non-interactive key agreement among the removed member's
copath subtrees, which no practical construction provides.

<a id="e-8"></a>
### E-8 — Catch-up: replay, jump, re-entry

**Decision.** A member coming back chooses between three ways:
* **Replay.** It processes every window it missed, about 7 KB each. It then
  reads everything sent meanwhile.
* **Jump.** It records a signed catch-up request with a one-time init key.
  The next window seals it a welcome, and the last wrap of each node of its
  path gives it its path secrets back: at most H wraps whatever the
  absence. The windows it skipped stay unreadable.
* **Re-entry.** With no member online, it seals a window itself as an
  entrant, with a fresh leaf key (E-7).

**Why.** Most members of a very large group are not online all the time.

**Cost.** The delivery service keeps the windows and an index of the
latest wraps of every node.

<a id="e-9"></a>
### E-9 — Registry as sparse Merkle maps

**Decision.** The registry holds three things:
* the admins, as occupancies with their device keys;
* two sparse Merkle maps: device ids to occupancies, and the hash of every
  admission ever used to the occupancy it admitted;
* the hash of the eviction policy, if any.

The seal applies the map changes that follow from the window's changes,
and the registry hash binds the map roots. An admission is good for one
join: it stays in its map for good.

**Why.** No cap and no floor, whatever the churn: v0.3 kept at most 4096
retired admissions, and a wave of removals pushed its floor up.

**Cost.** Checking that a device is new or an admission unused takes a map
proof instead of a list lookup. The admission map only grows: 64 bytes per
join ever made, at the delivery service and committers.

<a id="e-10"></a>
### E-10 — Anchored joins

**Decision.** An admin signs checkpoints: epoch, interim transcript hash,
tree hash and time. An invite carries the latest checkpoint. A joiner checks
the chain of seals from the checkpoint to its entry epoch. Each seal must be
signed by a member of the previous epoch, shown by a leaf proof against the
previous tree hash, or by an admitted entrant.

**Why.** It closes the forked entry of v0.3 (specification section 2.3):
`anchored_join.pv` is proved, and `join_without_anchor.pv` finds the attack.

**Cost.** For an hourly checkpoint and `WINDOW_MAX` = 60 s: about 60
seals to check, each with its sealer's leaf proof, about 9 KB per window
in the prototype: 0.55 MB and 13 ms of CPU for a joiner.

<a id="e-11"></a>
### E-11 — Placement of joins

**Decision.** The delivery service places joiners in three steps:
1. into the leaves removed in the same window;
2. into free leaves, lowest first;
3. into new districts, once the tree has grown by doubling.

**Why.** Pairing a join with a removal makes one changed leaf out of two.
This cuts a wave by 30 to 43 % (research note, section 4.2).

**Cost.** None for security: a bad placement only costs bandwidth.

<a id="e-12"></a>
### E-12 — Who checks what

**Decision.** Checking the entries of a wave is split:
* the delivery service checks every request as it records it;
* each district committer checks its queue;
* the sealer checks every district commit: signature, structure, taints;
* members audit random entries of the window.

An entry without a valid admission, in a signed district commit, is a
transferable fraud proof against its committer.

**Why.** No single device can check a wave: two signatures per join are 210
s of CPU for 500,000 joins. With each entry checked by 20 members on average,
a fraud escapes all of them with probability 2·10⁻⁹.

**Cost.** Checking the other districts becomes shared and probabilistic,
where v0.3 had every full member check everything.

<a id="e-13"></a>
### E-13 — One packet per member

**Decision.** For each window, a member downloads the wraps of its own path
and a header: epoch, hashes, sealed transcript hash, tag and external key.
The delivery service builds these packets; the member checks the tag.

**Why.** About 12 KB per member for a wave of 200,000 changes in a group of
a million (research note, section 4.1). SAIK showed the same slicing works
when only a small tag is authenticated.

**Cost.** The delivery service stores every window and serves a packet per
member.

## Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `L` (`district_bits`) | 12 | A district holds `2^L` leaves; fixed at genesis |
| `WINDOW_MAX` | 60 s | Longest window |
| `WINDOW_REMOVAL` | 5 s | Window length when a removal is pending |
| `UPDATE_INTERVAL` | 7 days | A member updates its leaf key at least this often (post-compromise security; forward secrecy comes from the init chain) |
| `CHECKPOINT_INTERVAL` | 1 hour | How often an admin should sign a checkpoint |
| `AUDIT_K` | 20 | Mean number of audits per entry |
| `MAX_HEIGHT` | 24 | Largest tree: `2^24` leaves |

## Left out

* **The HTTP API, the Worker, the clients and the GUI.** The draft has a
  core and an in-memory delivery service; the `/v3` stack stays as it is.
* **Light members.** Every v0.4 member keeps only its path, its epoch
  secrets and the headers, so the distinction disappears.
* **Multi-recipient KEMs.** Those on lattices that share randomness fall to
  malicious public keys, and members choose their own leaf keys (research
  note, section 3.10).
* **Updatable KEMs.** They would give forward secrecy to leaf keys without
  frequent updates, for ciphertexts nearly three times larger; the init
  chain already protects past epochs.
* **Shrinking the tree.** The tree grows by doubling; halving when the right
  half empties is left for a later draft.
* **Device-key rotation and admin changes other than the promotion rule.**
  They carry over from v0.3 as leaf and registry changes, and are not in
  the prototype yet.
* **The message plane.** Messages are unchanged from v0.3 section 11, keyed
  by the epoch's `msg_secret`.

## Relation to profile v0.3

The draft keeps from v0.3:
* the suite: X-Wing, ML-DSA-65, BLAKE3, ChaCha20-Poly1305;
* the deterministic CBOR encodings;
* occupancies;
* the structure of the key schedule;
* admissions and invites;
* the rule that a committer never removes itself;
* external init for entrants.

It changes the tree (districts and taints), the commit (district commits
and a seal per window), who commits (anyone, per window, including an
entrant), the registry (maps), the checks of a following member (tag
only), and the entry (welcomes per district, anchored on checkpoints).
