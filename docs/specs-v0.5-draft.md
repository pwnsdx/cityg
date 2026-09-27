# City-G protocol specification, v0.5 draft

| | |
| --- | --- |
| Profile | `city-g/v0.5-draft` |
| Status | Draft, written as a delta on v0.4. Stage 1 (section 2) is specified and implemented; stage 2 (section 3) is specified, except the proof system of disputes; stage 3 (section 4) is outlined, with its labels reserved. |
| Base | [specs.md](specs.md), profile `city-g/v0.4`: every rule this draft does not change holds, under the labels of section 5 |
| Implementation | [`crates/cityg-core`](../crates/cityg-core) (stage 1) |
| Design | [design.md](design.md) (decisions E-15 and E-16) |
| Research | the three stages, [`research/au-dela-0.4-2026-09-26.md`](research/au-dela-0.4-2026-09-26.md) (section 3.6); îlots, relays and the maintained city, [`research/ilots-2026-09-26.md`](research/ilots-2026-09-26.md) (sections 2.4 to 2.8); urgent and ordinary removals and the parity profile, [`research/parite-mls-2026-09-26.md`](research/parite-mls-2026-09-26.md) (section 3); symbolic models of relays and îlots, [`research/formal-parity/`](research/formal-parity/README.md) (all research notes in French) |
| Conformance | None yet: no test vectors (section 7) |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be
interpreted as in RFC 2119 and RFC 8174 when they appear in capitals.
"v0.4 §x" is section x of [specs.md](specs.md).

Above about `2^14` leaves, the levels of the tree above a few hundred
leaves change in almost every window. A v0.4 member reads a wrap for each
such level at every window, although the only thing it needs from them is
the window's root secret. This draft keeps the v0.4 tree, key schedule,
windows and roles, and changes how members read the tree:

* the tree is read in *islands* of `2^c` leaves (`c = 8` by default);
* an *island follower* takes the steps of its path inside its island, and
  the root secret from a *relay element* that a member of its island
  seals under the island root's secret: 52 bytes instead of the upper
  levels of its path;
* where no member of an island is online, a *flat element* wraps the root
  secret to the island root; with neither, the member *refreshes* its path
  from the latest re-key of each node above its island;
* *urgent* removals keep the 5-second windows of v0.4 and the rule that
  members do not send while one waits; *ordinary* removals (departures,
  evictions) wait for the next scheduled window.

## Contents

1. [Three stages](#1-stages)
2. [Stage 1: islands, relays and cadence](#2-stage-1)
3. [Stage 2: tasks](#3-stage-2)
4. [Stage 3: parity (outline)](#4-stage-3)
5. [Label registry](#5-labels)
6. [Changes from v0.4](#6-changes)
7. [Open items](#7-open-items)

<a id="1-stages"></a>
## 1. Three stages

The research synthesis (section 3.6) moves from v0.4 to the candidate
profile in three stages, each useful on its own. A later stage keeps the
earlier ones.

| Stage | What changes | What it brings | In this draft |
| --- | --- | --- | --- |
| 1. Relays and cadence | Members read the tree by island: the root secret comes from a relay of their island, a flat element or a refresh. Urgent and ordinary removals. Districts and the roles of v0.4 do not change. | At a million members, 1.7 changes per second and 5-minute windows, following the group costs about 94 KB per day, against 1.8 MB for whole paths with the same windows, and 44 MB for v0.4 with a window every 5 seconds per departure (research model, section 2.11). | Specified (section 2) and implemented |
| 2. Tasks | Islands become the districts; the city is re-keyed by sub-city tasks and a top task; joiners perform tasks first; the sealer draws nothing; entries by island; repairs; disputes. | No committer role beyond small tasks; a task cuts off at most 256 members; the heaviest task of a burst takes 42 ms instead of 0.6 s; a joiner no longer reads the upper levels. | Specified (section 3); disputes lack their proof system |
| 3. Parity | Authorized mode and its checkpoints, a message plane in the manner of MLS, split leaves, unique keys, a membership log, exporter and epoch authenticator. | The guarantees of MLS. | Outline (section 4) |

<a id="2-stage-1"></a>
## 2. Stage 1: islands, relays and cadence

### 2.1 Islands, and what binds their size

```text
c                := island_bits, fixed at genesis, 1 <= c <= L (8 by default)
island j         := the subtree of 2^c leaves under node (c, j), when height > c
island level     := min(c, height)
island of leaf i := i >> c when height > c, else 0
upper levels     := c + 1 .. height
```

* A tree no taller than `c` is one island whose root is the tree's root:
  it has no upper level, and its members follow as in v0.4.
* `c <= L`, so every island lies in one district. The steps of a member's
  path inside its island come from the district commit of its district;
  its upper levels are the upper levels of its district and the city.
* `c` is bound wherever v0.4 binds `L`:

  ```text
  SealHeader     := ["city-g/seal/v5", gid, epoch, prev_interim, kind, sealer, height,
                     district_bits, island_bits, tree_hash, registry_hash, body_hash,
                     time_ms, [kem_output, request_ref] or null]
  GroupContext_n := CBOR_det(["city-g/group-context/v5", gid, n, tree_hash_n,
                              registry_hash_n, height_n, district_bits, island_bits,
                              "city-g/v0.5-draft", confirmed_transcript_hash_n])
  Checkpoint     := ["city-g/checkpoint/v5", gid, epoch, interim, tree_hash, registry_hash,
                     height, district_bits, island_bits, external_pk_hash, time_ms,
                     admin, signature]
  ```

  The genesis seal sets `c`. The DS (v0.4 §10.4), members (v0.4 §12.2)
  and joiners following seal links (v0.4 §13.3) refuse a seal whose `c`
  differs from the previous epoch's, as they refuse another `L`. A member's
  header holds `c` with the shape.

### 2.2 Island followers

A member follows each window in one of two ways, and may change at any
window:

* as a **path follower**, as in v0.4: it takes every step of its path
  (v0.4 §7.4) and holds its whole path;
* as an **island follower**: it takes the steps of its path up to its
  island root, and the window's root secret `r_n` from the *top* of its
  packet: its island's relay element (section 2.3), flat element (section
  2.4), or a refresh (section 2.5).

Besides the state of v0.4 §12.1, a member keeps:

* the root secret of its epoch, `r_n`;
* for each secret of its path, the epoch of the window that set it: the
  latest re-key of the node that the member knows of. A `Chain` step at
  level `k` is valid only if the secret at level `k - 1` was set by the
  window of the step (v0.4 §7.4).

After a relay element or a flat element, an island follower keeps its
island path and `r_n`, and erases the secrets of its upper levels: the
window may have re-keyed them, so they no longer match the tree. After a
refresh, it holds its whole path again.

### 2.3 Relay elements

```text
RelayElement := ["city-g/relay/v5", gid, epoch, island, sealed]
context      := CBOR_det([gid, epoch, island_bits, island, interim_transcript_hash_n])
sealed       := ChaCha20-Poly1305(key   = ExpandLabel(s_j, "relay key", context, 32),
                                  nonce = ExpandLabel(s_j, "relay nonce", context, 12),
                                  aad   = context, plaintext = r_n)          (48 bytes)
```

`s_j` is the secret of the island root `(c, j)` after window `n`, `r_n`
the window's root secret, and `interim_transcript_hash_n` that of epoch
`n` (v0.4 §9), which covers the window's seal and its confirmation tag. A
member computes it from its packet before it opens the element.

* **Who makes it.** The *relay* the DS names for the island and the window
  (section 2.8): a member of the island that was a member of epoch `n - 1`.
  It follows the window (by refresh, if it is an island follower), then
  seals. A relay learns nothing: every member of the island knows `s_j`
  and `r_n`.
* **Not signed.** The DS accepts an element only from the relay it named,
  as it accepts welcomes only from their welcomer (v0.4 §14.5), and cannot
  check it. It cannot read or forge one either: it does not know `s_j`.
* **Checked by the tag.** A member opens the element of its own island and
  epoch with the island root secret it derived, then checks the
  confirmation tag (section 2.6). An element that does not open, or leads
  to a wrong tag, makes the member ask for the flat element or a refresh.
* **Keys.** `s_j` changes only when a window re-keys the island root, but
  the context binds the epoch and its transcript: the key and nonce change
  at every window, and each seals one plaintext.
* **Bound to the transcript.** The branches of a fork (v0.4 §2.3) share
  the epoch, and an island root that no branch re-keys keeps its secret in
  all of them. They differ by their seal, when two sealers sealed two
  windows, or only by their tag, when an insider that knows `init_n-1`
  leads a member into a root of its choice under the real seal. Bound to
  the epoch alone, or to the seal alone, the relays of that island in two
  branches would seal two root secrets under the same key and nonce: the
  XOR of the two elements is the XOR of the two roots, so whoever knows one
  root reads the other. With the DS, a member that one branch removes, and
  that knows the other branch's root, would derive the epoch that removes
  it, with the init secret it held. Members that accepted the same interim
  transcript hash hold the same root, so each key seals one plaintext, and
  an element of one branch does not open in another.
* **Size.** In a packet, the island index and `sealed`: 52 bytes.

### 2.4 Flat elements

The *flat element* of island `j` for window `n` is the wrap (v0.4 §7.2) of
`r_n` from the root to the island root, under the island root's key in the
tree of epoch `n`:

```text
FlatElement := Wrap with node v = (height_n, 0) and target t = (c, j)
```

* **Who makes it.** Any member of epoch `n` that holds `r_n`. The DS asks
  the window's relays for the flat elements of the islands that have no
  relay (section 2.8).
* **Checked keys.** A maker MUST take the island root keys from a state it
  checked against its header of epoch `n` (v0.4 §12.3). Otherwise it could
  wrap `r_n` to a key the DS chose, and a member the window removed, who
  knows `init_n-1`, would read epoch `n` with the DS.
* **The same wrap.** When `height = c + 1`, the flat element of island `j`
  is the root's wrap to its child `(c, j)`, with the same context: both
  carry the same secret to the same key.
* **Size.** A wrap: 1,184 bytes with its address, as in v0.4.

### 2.5 Refreshes

A *refresh* of member `m` as of epoch `e` holds, for each upper level `k`
of `m`'s path in the tree of epoch `e`, the last step of the node at that
level at or before `e`, with the epoch of the window that made it:

* `Wrap`: that window wrapped the node's secret to the node's child toward
  `m`;
* `Chain`: it did not, and chained the node's secret from that child.

The member walks up from its island root, as a jump recovers a path (v0.4
§7.4): a `Wrap` opens with the key of the level below, a `Chain` is valid
only if the level below was set by the same window. The walk is sound for
the reason recovery is: a window that re-keys a node re-keys all its
ancestors, so the last re-key of a node happened at or after the last
re-key of its child toward `m`, and either chained from that child in the
same window or wrapped to the child's key of that time, which is still its
key at `e`.

* **Cost.** At most `height - c` wraps, and no one needs to be online: the
  DS keeps every window.
* **In a packet**, as the top of window `n`: the member checks it through
  the confirmation tag of window `n`.
* **On its own**, as of the member's current epoch (before a role that
  needs its whole path, section 2.7): the member MUST check that the
  recovered root is the root secret it holds. The recovered root is right
  only if every wrap opened with the right key: a wrap on the member's path
  was made to the key of its child at the time, and binds the hash of that
  key in its context; a `Chain` step is right only if the level below is.

### 2.6 Following a window

For the packet of window `n`, a member of epoch `n - 1` runs steps 1 to 4
of v0.4 §12.2, with `island_bits` checked in step 1, then:

5. it derives `r_n`:
   * **a packet without top** gives every step of the member's path, which
     it MUST hold whole (v0.4 §7.4). A packet without any step, of a window
     that did not grow the tree, means the window re-keyed nothing: `r_n`
     is the root secret the member holds;
   * **a packet with a top** is valid only for a tree with islands
     (`height_n > c`), and its steps MUST be at levels up to `c`. The member
     advances its island path with them, then takes `r_n` from the relay
     element or the flat element of its island, opened with the new island
     root secret, or walks the refresh up from the island root;

   then it derives the epoch secrets from `r_n` and checks the
   confirmation tag (v0.4 §12.2, step 5);
6. for kind 2, it checks the entrant evidence (v0.4 §12.2, step 6);
7. only then it replaces its state: after a relay element or a flat
   element, its island path and `r_n`; otherwise its whole path and `r_n`.

A member whose top fails changes nothing, and asks for another top
(section 2.8).

### 2.7 Roles

* **Committers** need no path (E-3): unchanged.
* **The sealer** of a window with a city takes the root from its city
  re-key: unchanged. Without a city (`c < height <= L`), it follows the
  single district commit along its own path (v0.4 §12.5), so it MUST hold
  its whole path: an island follower refreshes first (section 2.5, on its
  own). For a window that re-keys nothing, the root is the one it holds.
* **Welcomers** follow the window in either way before they seal their
  welcomes (v0.4 §11).
* **Relays** and **flat makers**: sections 2.3 and 2.4.
* **Joiners, jumps, re-entries and entrants** are unchanged: an entry
  carries the whole path (v0.4 §13.4), and an entrant re-keys its whole
  path, so each starts as a path follower that holds `r_n`.

### 2.8 Delivery service

After it applies window `n` (v0.4 §14.5), for a tree with islands and a
window that re-keyed at least one node, the DS assigns the window's *top
task*:

* **Relays.** For each island that holds members after the window: a
  member of the island that was a member of epoch `n - 1`, is online, and
  has no removal recorded. The DS SHOULD rotate among them from window to
  window; the implementation takes the `(n mod k)`-th of the `k`
  candidates, in occupancy order.
* **Flat elements.** The islands with members but no relay get flat
  elements, spread over the relays. With no relay at all (an entrant
  window, nobody online), there are none, and members refresh.
* **What it accepts.** A relay element only from the relay of its island;
  a flat element only from the member it asked for, with the root and the
  island root as addresses and the sizes of a wrap.

It keeps the relay and flat elements of every window, and serves, for a
member and a window:

* the packet of v0.4 §13.1, which gives every step of the member's path;
* or an *island packet*: the steps up to the member's island root, and a
  top:
  * by default, the relay element of the member's island, else its flat
    element, else a refresh as of the window;
  * for a member whose relay element failed, the flat element, else a
    refresh;
  * for a relay, or a member that wants its whole path, a refresh.

A window that re-keyed nothing needs no top: its island packet is the
packet of v0.4, with no step. A refresh as of the current epoch comes from
the latest re-key of every node (v0.4 §14.5); as of an earlier epoch, from
the windows up to that epoch. A member that replays the windows it missed
therefore always gets a top, relay or not.

### 2.9 Urgent and ordinary removals

```text
RemoveProposal := ["city-g/remove/v5", gid, target, proposer, urgency, signature]
urgency        := 0 ordinary | 1 urgent
```

* **Urgent**: a removal by an admin, or by a member that reports its
  device compromised. The DS closes a window within `WINDOW_URGENT`
  (5 s), and a member MUST NOT send while an urgent removal recorded more
  than `WINDOW_URGENT` ago waits (the rule of v0.4 §12.8, now for urgent
  removals only).
* **Ordinary**: a member leaving, an admin's housekeeping, and evictions
  under the group policy (v0.4 §14.7). The removal waits for the window
  its age closes, at most `WINDOW_ORDINARY` (60 s by default; 5 minutes
  for a group of a million), and members keep sending meanwhile.
* **Signed.** The urgency is part of the signed proposal: the DS cannot
  lower it without the proposer.
* **One per target.** An urgent proposal replaces an ordinary one for the
  same target, and its recording starts the urgent clock.
* **Enforced at once.** Either kind is enforced at delivery from its
  recording (v0.4 §14.6): the DS refuses the target's messages, district
  commits and seals, and serves it no packet. It lists the recorded
  removals to members with their times and urgency.

**Closing windows** (replaces the first sentence of v0.4 §14.2). A window is
due when its oldest request has waited `WINDOW_ORDINARY`, or its oldest
urgent removal `WINDOW_URGENT`.

### 2.10 Security considerations

* **Relays can only delay.** A member checks the tag with its own init
  secret (E-5), so a relay element with another root, from a hostile relay
  working with the DS, fails (`ilot_relay.pv`); a member that did not check
  the tag could be led into an epoch nobody sealed
  (`ilot_relay_unchecked.pv`). A hostile relay, a flat maker or the DS can
  delay a member, not mislead it, and a member always has a refresh.
* **Who reads a relay element.** Its key derives from `s_j`, which only
  the members of the island after the window know, and the committer that
  drew it until it erases it. The taint rule (v0.4 §10.2) re-keys what a
  removed committer drew. The DS reads nothing.
* **Forks.** A relay element binds the interim transcript hash of its
  epoch (section 2.3): each branch of a fork has its own keys, and honest
  relays seal one root secret per key.
* **Removed members.** The window that removes a member re-keys its path,
  island root included, before anyone seals `r_n` to it: the relay
  element, the flat element and the refresh of that window are all under
  keys the removed member never knew (test
  `a_removed_member_opens_no_top_of_the_window_that_removes_it`, model
  [`formal/island_removal.pv`](formal/island_removal.pv)). Sealing the root
  secret to an island root the window did not re-key is the attack of
  `ilot_removal_unrekeyed.pv`, and a relay that seals under its island
  root's former secret that of
  [`formal/island_removal_stale_relay.pv`](formal/island_removal_stale_relay.pv).
* **The upper levels are still maintained.** Every window re-keys the
  upper levels along the paths it changes, as in v0.4; only the reading
  changes. A window that skipped them would leave nodes a removed member
  knows (`ilot_city_stale.pv`, and the maintained city, `ilot_city_maintained.pv`).
* **Flat makers** check the island root keys against their header (section
  2.4): a key the DS chose gives it the root secret, and a removed member
  brings the init secret ([`formal/flat_unchecked.pv`](formal/flat_unchecked.pv)).
* **Refreshes** are checked by the tag, or against the root secret the
  member holds (section 2.5): stale or forged steps are detected
  ([`formal/refresh_checked.pv`](formal/refresh_checked.pv); without the
  check, [`formal/refresh_unchecked.pv`](formal/refresh_unchecked.pv)). A
  member only opens wraps with its upper secrets, and checks the tag of
  every window, so a wrong refresh that went unnoticed would make it fail
  later, not accept another epoch; the check makes it ask for another
  refresh at once.
* **Forward secrecy and post-compromise security** come from the init
  chain and leaf updates, as in v0.4 (§9, E-5). An island follower holds a
  subset of what a path follower holds, and erases its upper secrets
  rather than keep them stale.
* **Ordinary removals.** A member that leaves may read, for at most
  `WINDOW_ORDINARY` after its request, what members send; MLS bounds this
  by nothing but the next commit. Admins' removals and reported
  compromises are urgent, and behave as every removal of v0.4.
* **Metadata.** To name relays, the DS learns which members are online in
  each island, as it learns the online members it gives roles to in v0.4.

### 2.11 Parameters and costs

| Name | Value |
| --- | --- |
| `c` (`island_bits`) | 8 by default, fixed at genesis, `1 <= c <= L` (the tests use 1 and 2) |
| `WINDOW_ORDINARY` | 60 s by default (was `WINDOW_MAX`); 5 minutes for a group of a million |
| `WINDOW_URGENT` | 5 s (was `WINDOW_REMOVAL`) |

The other parameters are those of v0.4 §16.

**Measured.** The scale test (`crates/cityg-core/tests/scale.rs`, release
build) runs a window of half removals and half joins paired with them, and
cuts the packets of 4,096 members with islands of `2^8`:

| | N = 16,384, L = 10, 2,000 changes | N = 65,536, L = 12, 4,000 changes |
| --- | --- | --- |
| Whole path, as in v0.4 | mean 7.7 KB, max 13.4 KB | mean 8.3 KB, max 14.6 KB |
| Island path and relay element | mean 3.6 KB, max 7.6 KB | mean 3.0 KB, max 6.4 KB |
| Island path and flat element | mean 4.7 KB | mean 4.1 KB |
| Wraps a relay reads above its island | 3.5 | 4.5 |

These windows change 12 % and 6 % of the group at once, so most islands
change too. In a group that changes steadily, most windows leave most
islands alone, and an island packet is a header and 52 bytes.

**Modelled** (`research/ilots_sim.py`; research notes îlots, section 4, and
synthesis, section 5). A million members, 1.7 changes per second, windows
of 5 minutes, islands of `2^8`:

* following the group costs about 94 KB per day with relays, 415 KB with a
  flat element at every window, 1.8 MB with whole paths, and 44 MB with
  whole paths and a window within 5 seconds of every departure;
* a relay reads about 5.5 KB per window, and there are about 1.1 relay
  tasks per member per day, spread over the members online.

<a id="3-stage-2"></a>
## 3. Stage 2: tasks

Stage 2 splits the work of a window into *tasks* that members of the
previous epoch and the window's joiners perform, so that no client re-keys
more than a sub-city, and a faulty task cuts off at most one district. The
tree, the key schedule, the windows and the reading of stage 1 do not
change. From the research synthesis (sections 3.3 and 3.6), the îlots note
(sections 2.2 to 2.8) and the notes on re-keys by the server and disputes.

### 3.1 Sub-cities

```text
subcity_bits (S)  := 8 by default, fixed at genesis, S >= 1
sub-city k        := the subtree of 2^S districts under node (L + S, k)
top               := the levels L + S + 1 .. height, when height > L + S
```

* Stage 2 sets the defaults to `L = c = 8`: a district is an island of 256
  leaves, and a district commit re-keys one island. A group MAY keep
  `c < L`.
* `subcity_bits` is bound where `island_bits` is: the seal header, the
  group context and checkpoints, after `island_bits`.
* A tree no taller than `L` has no city. A tree of height `L < height <= L
  + S` has one sub-city, whose root is the tree root, and no top. A taller
  tree has `2^(height - L - S)` sub-cities and a top. For a million members
  (`height = 20`), the sub-cities hold the city levels 9 to 16 and the top
  the levels 17 to 20.

### 3.2 City tasks

The city of v0.4 §7.3, which the sealer re-keyed alone, is re-keyed by one
*city task* per sub-city of the window, and one for the top:

```text
CityTask := ["city-g/city-task/v5", gid, epoch, part, height, prev_part_hash,
             performer, nodes, wraps, part_hash, signature]
  part   := k (sub-city k) or null (the top)
  nodes  := [[level, index, public_key or null], ...]       in plan order
  wraps  := [Wrap, ...]                                     in plan order
```

Signed by its performer (section 3.3) under `CITY_TASK`
(`city-g/city-task/v5`).

* **Sub-cities of a window.** Those holding a district of the window or a
  forced city node at levels `L + 1` to `L + S` (v0.4 §10.2).
* **The top of a window.** When `height > L + S` and the window has a
  sub-city, or a forced node above `L + S`.
* **Plans** (v0.4 §7.3). The plan of sub-city `k` re-keys every ancestor,
  at levels `L + 1` to `min(L + S, height)`, of the root of each district
  of the window in the sub-city, and every forced city node of those levels
  in it with its ancestors up to the sub-city root; its boundary is level
  `L + 1`. The top's plan re-keys every ancestor, at levels `L + S + 1` to
  `height`, of the root of each sub-city of the window, and every forced
  node above `L + S` with its ancestors up to the root; its boundary is
  level `L + S + 1`.
* **Keys of wrap targets.** As v0.4 §7.3, with the new key of a district
  root from its district commit in a sub-city task, and the new key of a
  sub-city root from its city task in the top's.
* **The root secret.** The task whose plan holds the root draws `r_n`: the
  top's, else sub-city 0's, else, with no city, the district commit.
* **Hashes.** `prev_part_hash` is the hash of the part's root (node `(L +
  S, k)`, or the tree root for the top) in the tree before the window,
  grown to the window's height; `part_hash` is its hash after the
  window's district commits and the task's nodes, each node tainted by the
  performer. They bind a task to the state it was built on, as
  `prev_district_hash` binds a district commit.

A verifier (the DS, the sealer) checks a city task as a district commit
(v0.4 §10.3): its fields, its performer, its plan with the new roots of
the tier below, its hashes, and its signature.

### 3.3 Performers

A district commit's `committer` and a city task's `performer` are an
occupancy:

* **a member**: `[leaf, since]`, a member of epoch `n - 1` that the window
  does not affect (v0.4 §10.5), with the device key of the tree;
* **a joiner**: `[leaf, n]`, where `leaf` is the leaf of a join of the
  window, with the device key of that join request, as for an entrant
  (v0.4 §10.5). Its join MUST be among the window's changes.

A joiner holds no group secret before its welcome. Before its task, it
follows the chain of seals from its anchor to epoch `n - 1` (v0.4 §12.9,
step 3) and checks the public state it is shown against the last header
(v0.4 §12.3). Its fresh secrets are hedged (v0.4 §7.1) with

```text
hedge := ExpandLabel(leaf_seed, "task hedge", CBOR_det([gid, epoch]), 32)
```

where `leaf_seed` is the seed of the leaf key of its join request, instead
of `init_n-1`, which it does not know. A member hedges with `init_n-1`, as
in v0.4.

The nodes a task re-keys are tainted by its performer: a joiner's taints
follow the occupancy `[leaf, n]` it takes (v0.4 §10.6).

### 3.4 Assigning tasks

Replaces the member window of v0.4 §14.4.

* **Joiners first.** Joiners are online when they ask to join. The DS
  gives each district of the window to a joiner of the window that takes a
  leaf of the district, if there is one, else to a joiner with no task,
  else to a volunteer of the district, else to volunteers in turn.
* **City tasks** go to joiners with no task, then to volunteers.
* **The sealer** is a volunteer: a member of epoch `n - 1` that the window
  does not affect. Welcomes are assigned as in v0.4 §11.
* **Failover.** A task not submitted in time goes to another performer, as
  a district in v0.4 §14.4; the replaced performer's task is refused.
* **Entrant windows** do not change: the entrant performs every task and
  seals (v0.4 §12.7).

### 3.5 Sealing

The sealer:

1. checks every district commit and city task of the window (v0.4 §10.3
   and section 3.2), and the joins of their joiner performers;
2. follows the tasks along its own path, from its leaf to the root, as a
   member follows a whole packet (v0.4 §7.4), and obtains `r_n`; an island
   follower refreshes first (section 2.5);
3. computes the key schedule and the confirmation tag, and signs the seal
   (v0.4 §10.4).

It draws nothing. The seal body lists the tasks:

```text
SealBody := ["city-g/seal-body/v5", [[district, H(district commit)], ...],
             [[part, H(city task)], ...], group_policy or null, genesis or null]
```

in district order, then sub-city order with the top last. It replaces
`city_nodes` and `city_wraps`. The DS checks a seal as in v0.4 §10.4,
with every city task in place of the city's nodes and wraps (item 6).

A window is applied as in v0.4 §10.6, every node of a city task taking its
performer's taint.

### 3.6 Entries by island

An entry (v0.4 §13.4) carries, instead of the whole path:

* the steps of the entrant's path up to its island root, with the parents
  of that part of its path, which it checks as in v0.4 §12.9;
* the root's node (its key and taint), whose content hash is the last step
  of the entry's leaf proof;
* a top for the window it enters (section 2.8): its island's relay
  element, else its flat element, else a refresh.

The entrant takes `r_n` from the top and MUST check that the root's key
derives from it (`KemKey(r_n, "tree node key")`). It then follows as an
island follower. An entry with a refresh is the entry of v0.4.

### 3.7 Repairs

A member whose packet it cannot follow with any top (section 2.8), because
a task's wrap to it does not open, asks the DS for a repair:

```text
Repair := ["city-g/repair/v5", gid, epoch, leaf, wrap]
  wrap := r_n wrapped (v0.4 §7.2) from the root (height, 0) to the leaf (0, leaf)
```

* **Who makes it.** Any member of epoch `n` holding `r_n` that the DS
  asks, with the leaf key of the tree of epoch `n`, checked against its
  header. A task that cuts off a district costs at most `2^L` repairs;
  one that cuts off a sub-city, one flat element per island (section 2.4).
* **Unsigned**, like a flat element: the member opens it with its leaf
  key, derives the epoch, and checks the tag.
* **After a repair**, the member holds `r_n` but no valid path: it MUST
  ask for an update at once (v0.4 §12.6), and follows by repair until the
  window of its update re-keys its path.

### 3.8 Disputes

A member that cannot open a wrap addressed to it proves so without
revealing its key or a past secret:

```text
Dispute := ["city-g/dispute/v5", gid, epoch, task, wrap_index, branch, proof,
            member, signature]
  task   := H(district commit) or H(city task)
  branch := 1 (the wrap does not open under the member's key in its context)
          | 2 (it opens to a secret whose node key is not the published one)
```

signed by the member under `DISPUTE`. `proof` is a zero-knowledge proof of
the branch's statement, over the member's key and the wrap in its context
(research notes on disputes: `litige-entier`, `litige-deux-branches`).

* The DS checks the signature, that the wrap is addressed to a node the
  member holds, and the proof. It then excludes the performer from tasks,
  and the next window treats the performer as affected: it re-keys every
  node the performer taints (v0.4 §10.2).
* **Not fixed by this draft**: the proof system and the encoding of
  `proof`. Until they are, a DS MAY exclude a performer on repairs it made
  necessary, without conviction.

### 3.9 Security considerations

* **Joiners draw secrets of the epoch they enter.** A joiner performer
  knows the secrets of the nodes it re-keys, `r_n` for the task that holds
  the root. It is a member of epoch `n`: it learns no more than its welcome
  gives it. Without `init_n-1`, `r_n` does not give the epoch.
* **The hedge of a joiner** rests on the seed of its leaf key, which no
  member of the group knows: a weak generator at task time alone exposes
  nothing to an outsider, as with the `init_n-1` hedge of members.
* **A joiner shown a false state** builds a task on it; the prev hashes
  bind the task to that state, so the DS and the sealer refuse it.
* **A faulty task** (wraps that do not open, or open to wrong secrets)
  cuts off at most its district, or for a city task the districts below
  it; the tag check keeps the cut-off members from accepting a wrong epoch.
  Repairs restore them within the window; disputes name the performer and
  the taint rule re-keys what it drew.
* **Taints** follow performers, joiners included: removing or updating a
  performer re-keys every node it drew (E-4).
* **The sealer draws nothing** and learns nothing its own path does not
  give it.
* **Forks.** Tasks bind the state they were built on; relay elements bind
  the transcript (section 2.3).

### 3.10 Parameters and costs

| Name | Value |
| --- | --- |
| `L` (`district_bits`), `c` (`island_bits`) | 8 and 8 by default (v0.4: `L = 12`) |
| `S` (`subcity_bits`) | 8 by default, fixed at genesis |

**Modelled** (research note îlots, section 2.3; synthesis, section 5). A
million members, 1.7 changes per second, 5-minute windows: a joiner that
takes a freed leaf re-keys its path in its island, 8 wraps; an island task
with several changes, 9 wraps on average, at most 181 (42 ms) in a burst
of 100,000 joins and 100,000 departures; the city costs 175 KB per
sub-city. The heaviest task of such a burst takes 42 ms, against 0.6 s for
a v0.4 district of `2^12`.

<a id="4-stage-3"></a>
## 4. Stage 3: parity (outline)

Not specified in detail and not implemented. From the parity note (section
3) and the synthesis (section 3.5):

* **Authorized mode.** A third admission mode in the group policy, with
  the authorizer's key. The authorizer signs, per window, the Merkle root
  of the join requests it authorizes (`AuthorizationBatch`), and a
  checkpoint of each epoch it created (`AuthorizerCheckpoint`) over
  `[gid, epoch, H(GroupContext), confirmation_tag, H(external_pk)]`. A
  joiner anchors on it; a member MAY require it before it accepts a window.
* **Message plane.** From `msg_secret_n`: `sender_data_secret`,
  `encryption_secret` (the root of a secret tree over the leaves),
  `exporter_secret` and `epoch_authenticator`. Encrypted sender data,
  signed burst chains delivered to the application once their signature
  checks, key commitments, and a sealed message log in the next seal.
* **Leaves.** A card (a compact signature key) and `device_id` in the
  leaf; the *split leaf*, whose hash takes `H_L("tree/leaf-key",
  [encryption_key])` instead of the key, so that a reader checking a card
  downloads 1,019 bytes of the leaf instead of 2,203.
* **Unique keys**, through a sparse Merkle map of key hashes in the
  registry; a **membership log** of each window's changes, committed by the
  seal.

Labels reserved for it: section 5.5.

<a id="5-labels"></a>
## 5. Label registry

### 5.1 Framing and profile

`H_L` is framed with `city-g/v0.5-draft`, `ExpandLabel` with
`city-g/v0.5-draft expand` and `MAC` with `city-g/v0.5-draft mac` (v0.4
§3.3). The profile identifier in the group context is `city-g/v0.5-draft`.

### 5.2 Labelled hashes (`H_L`)

Those of v0.4 §17.1, unchanged; they differ from v0.4's through the
framing.

### 5.3 Derivation labels

Those of v0.4 §17.2, `relay key` and `relay nonce` (section 2.3), and
`task hedge` (section 3.3).

### 5.4 Encoded objects and signature contexts

Every object label of v0.4 ends in `/v5` instead of `/v4`:
`city-g/group-context/v5`, `city-g/invite/v5`, `city-g/admission/v5`,
`city-g/join-request/v5`, `city-g/remove/v5`, `city-g/eviction/v5`,
`city-g/group-policy/v5`, `city-g/update/v5`, `city-g/catch-up/v5`,
`city-g/re-entry/v5`, `city-g/checkpoint/v5`, `city-g/district-commit/v5`,
`city-g/seal/v5`, `city-g/seal-body/v5`, `city-g/welcome/v5`, and the new
unsigned `city-g/relay/v5`; for stage 2, `city-g/city-task/v5` and
`city-g/dispute/v5` (signed) and `city-g/repair/v5` (unsigned).

The FIPS 204 context of every signed object is its label, as in v0.4
§17.3; the seal is signed under `city-g/seal/v5`.

### 5.5 Reserved for stage 3

| Kind | Labels |
| --- | --- |
| Encoded objects and signature contexts, stage 3 | `city-g/authorization-batch/v5`, `city-g/authorizer-checkpoint/v5` |
| Labelled hashes, stage 3 | `tree/leaf-key`, `msg-chain`, `msg-commit`, `membership-log` |
| Derivation labels, stage 3 | `sender data`, `encryption`, `exporter`, `authenticator` |

<a id="6-changes"></a>
## 6. Changes from v0.4

| v0.4 | Change |
| --- | --- |
| §3.3, §3.4, §17 | Framing tags `city-g/v0.5-draft`; every label ends in `/v5` (section 5) |
| §5.1 | The shape gains `island_bits` (section 2.1) |
| §6 | `RemoveProposal` gains `urgency`; `Checkpoint` gains `island_bits` (sections 2.9 and 2.1) |
| §9 | `GroupContext` gains `island_bits` (section 2.1) |
| §10.4 | `SealHeader` gains `island_bits` (section 2.1) |
| §12.1 | A member keeps the root secret and the epoch of each path secret; an island follower holds its island path (section 2.2) |
| §12.2 | A packet may carry a top (section 2.6) |
| §12.5 | Without a city, an island follower refreshes before it seals (section 2.7) |
| §12.8 | Members stop sending for urgent removals only (section 2.9) |
| §13.1 | Island packets: the steps up to the island root, and a top (section 2.8) |
| §14.2 | `WINDOW_ORDINARY` and `WINDOW_URGENT` replace `WINDOW_MAX` and `WINDOW_REMOVAL` (section 2.9) |
| §14.5 | Top tasks: relays and flat elements, kept with the window (section 2.8) |
| §5.1, §6, §9, §10.4 | Stage 2: the shape gains `subcity_bits`, bound in the seal header, the group context and checkpoints (section 3.1); defaults `L = c = 8` |
| §7.3 | Stage 2: the city is re-keyed by city tasks, one per sub-city and one for the top (section 3.2) |
| §10.3, §10.5 | Stage 2: a committer may be a joiner of the window, `[leaf, n]` (section 3.3) |
| §10.4, §12.5 | Stage 2: the seal body lists city tasks instead of the city's nodes and wraps; the sealer draws nothing (section 3.5) |
| §13.4 | Stage 2: entries by island (section 3.6) |
| §14.4 | Stage 2: joiners perform tasks first (section 3.4); repairs and disputes (sections 3.7 and 3.8) |

Nothing of v0.4 decodes under this draft: every label changed.

<a id="7-open-items"></a>
## 7. Open items

* **The formal models of stage 1.** The symbolic model
  ([`formal/`](formal/README.md)) covers the tops of the window that
  removes a member, the keys of flat elements and the refresh; that of
  [`research/formal-parity/`](research/formal-parity/README.md) the relay
  and its tag, the island that is not re-keyed and the maintained city;
  CryptoVerif ([`research/formal-computational/`](research/formal-computational/README.md))
  the relay and flat items, the tag check and the maintained city. Neither
  models the DS's choice of tops, relay rotation or the epochs of a
  refresh's steps.
* **The proof of the tree**, and its adaptive argument (research notes
  [`research/preuve-arbre-2026-09-26.md`](research/preuve-arbre-2026-09-26.md),
  [`research/argument-adaptatif-2026-09-27.md`](research/argument-adaptatif-2026-09-27.md)
  and [`research/extensions-gsd-2026-09-27.md`](research/extensions-gsd-2026-09-27.md)):
  written in full, not yet mechanized.
* **Relay choice.** Rotating among online members spreads the work; a DS
  may prefer members with a good network, and the window's joiners, once
  entries carry the island path (stage 2).
* **Encodings** of island packets and top tasks, and test vectors, as for
  the objects v0.4 leaves open (v0.4 §19).
* **The proof system of disputes** (section 3.8): the statements are
  measured in the research notes, in Longfellow; the encoding of `proof`,
  its verifier in the DS, and the size limits remain to be fixed.
* **The formal models of stage 2**: joiner performers and their hedge, city
  tasks bound to the prior state, repairs. The taint rule for tasks and the
  maintained city are modelled (`taint.pv`, `ilot_city_maintained.pv`).
* **Assignment under load**: how many tasks a joiner takes, and when a DS
  prefers a volunteer with a good network.
* Everything v0.4 §19 lists, except the lighter structure for continuous
  churn, which this stage begins.
