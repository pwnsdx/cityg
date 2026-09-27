# City-G protocol specification, v0.5 draft

| | |
| --- | --- |
| Profile | `city-g/v0.5-draft` |
| Status | Draft, written as a delta on v0.4. Stage 1 (section 2) is specified and implemented; stage 2 (section 3) is specified, except the proof system of disputes, and implemented, the proof system aside: the DS judges disputes with a verifier it is given (section 3.8); stage 3 (section 4) is specified, not yet implemented. |
| Base | [specs.md](specs.md), profile `city-g/v0.4`: every rule this draft does not change holds, under the labels of section 5 |
| Implementation | [`crates/cityg-core`](../crates/cityg-core) (stages 1 and 2; the proof system of disputes is plugged in, not included) |
| Design | [design.md](design.md) (decisions E-15 to E-18) |
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
4. [Stage 3: parity](#4-stage-3)
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
| 3. Parity | Authorized mode and its checkpoints, a message plane in the manner of MLS, cards in leaves hashed by their summary, unique keys, a membership log, exporter and epoch authenticator. | The guarantees of MLS. | Specified (section 4), not implemented |

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
| Whole path, as in v0.4 | mean 7.7 KB, max 13.4 KB | mean 8.2 KB, max 14.6 KB |
| Island path and relay element | mean 3.5 KB, max 7.6 KB | mean 2.9 KB, max 6.4 KB |
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
(v0.4 §12.3).

**Hedges.** Every device hedges what it draws for a window with the seed
of its leaf key (for a joiner, that of its join request; for an entrant,
its new leaf key), which only it holds: the fresh secrets of its tasks,
and the coins of every X-Wing encapsulation it makes, in a wrap, a flat
element, a welcome or an external init:

```text
hedge    := ExpandLabel(leaf_seed, "task hedge", CBOR_det([gid, epoch]), 32)
fresh    := DeriveSecret(Extract(hedge, r), "fresh node")                 r: 32 random bytes
coins    := ExpandLabel(Extract(hedge, r'), "encaps coins",
                        CBOR_det([context, kem_pk_hash(pk)]), 64)         r': 32 random bytes
(ct, ss) := X-Wing.EncapsulateDerand(pk, coins)
```

`epoch` is the epoch the window creates; `context` is the object's: the
wrap context (v0.4 §7.2) for a wrap or a flat element, the welcome context
(v0.4 §11) for each of a welcome's encapsulations, `CBOR_det([gid,
epoch])` for an external init. This replaces the `init_n-1` hedge of v0.4
§7.1, for two reasons (formal model, `task_hedge*.pv`): v0.4 takes the
coins of its encapsulations from the generator, so a weak generator
exposes every secret it wraps, the fresh ones included; and a member that
the window removes knows `init_n-1`.

The nodes a task re-keys are tainted by its performer: a joiner's taints
follow the occupancy `[leaf, n]` it takes (v0.4 §10.6).

### 3.4 Assigning tasks

Replaces the member window of v0.4 §14.4.

* **Joiners first.** Joiners are online when they ask to join. The DS
  gives each district of the window to a joiner of the window that takes a
  leaf of the district, if there is one, else to a joiner with no task,
  else to a volunteer of the district, else to volunteers in turn.
* **City tasks** go to joiners with no task, then to volunteers with no
  task, then to volunteers in turn.
* **The sealer** is a volunteer: a member of epoch `n - 1` that the window
  does not affect.
* **Welcomes.** A joiner cannot welcome: it learns `joiner_secret_n` from
  its own welcome. The welcomes of a district that a member commits go to
  that member (v0.4 §11); those of a district that a joiner commits go to
  volunteers in turn. A welcomer welcomes a join or a re-entry only if it
  is a change of a district commit that the seal lists, of its own or of a
  joiner of the window, instead of its own alone (v0.4 §11), and takes the
  init key from the request that hashes to the change's `request_ref`
  (v0.4 §10.1). The entries
  of a district that a joiner commits are checked by the joiner, like any
  committer's, and sampled by auditors (v0.4 §15).
* **Order.** The DS accepts a sub-city task once the district commits of
  that sub-city are in, and the top's once every sub-city task is: the
  sub-cities of a window proceed in parallel. It keeps the first commit or
  task it accepts for a district or a part, and refuses a different one.
* **Failover.** A task not submitted in time goes to another performer, a
  member or a joiner of the window, as a district in v0.4 §14.4; the
  replaced performer's task is refused. When a district changes hands, the
  tasks built on its commit, those of its sub-city and of the top, are
  performed again; the other sub-cities' are kept. A member that takes a
  district takes its welcomes; when a joiner takes a member's district, the
  member's welcomes go to the sealer.
* **Members only.** A DS MAY give every task to members, as in v0.4:
  performers and verifiers accept both.
* **Entrant windows** do not change: the entrant performs every task and
  seals (v0.4 §12.7).

### 3.5 Sealing

The sealer:

1. checks every district commit and city task of the window (v0.4 §10.3
   and section 3.2), and the joins of their joiner performers;
2. follows the tasks along its own path, from its leaf to the root, as a
   member follows a whole packet (v0.4 §7.4), and obtains `r_n`; an island
   follower refreshes first (section 2.5). It MUST check each secret of its
   path against the node key the tasks publish (`KemKey(secret, "tree node
   key")`), and not seal if one differs: a wrap that opens to another
   secret, in a task that holds the root, would otherwise make it seal an
   epoch that is not the tree's, which only its side of the tree follows
   (such a task is disputed, section 3.8);
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
island follower. An entry with a refresh is the entry of v0.4. An entrant
whose top does not open, from a relay that lied, keeps its state and asks
for the next: the flat element, then its whole path.

### 3.7 Repairs

A member whose packet it cannot follow with any top (section 2.8), because
a task's wrap to it does not open or opens to a wrong secret, asks the DS
for a repair of the latest window:

```text
RepairRequest := ["city-g/repair-request/v5", gid, epoch, seal_hash, member, level]
  seal_hash := H(SealHeader) of the window that created epoch n
  level     := the first level of the member's path whose secret the window
               does not let it derive, from 1
Repair := ["city-g/repair/v5", gid, epoch, leaf, wrap]
  wrap := r_n wrapped (v0.4 §7.2) from the root (height, 0) to the leaf (0, leaf)
```

**Repair requests** are signed by the member under `REPAIR_REQUEST`. To
find `level`, the member takes its leaf proof and the parents of its path
in the tree of epoch `n`, checks them against the header's `tree_hash`,
and walks its steps from the leaf up: its whole packet's, or its island
packet's with a refresh above the island. `level` is the first level whose
step does not open or does not chain, or gives a secret whose key is not
the published one; a level without a step keeps the secret the member
holds. If every level gives its published key, the member has nothing to
repair. The node at `level` bears the taint of the performer that drew it
(v0.4 §10.6): the request blames that performer, without proof. Without the
tag, the member cannot tell the header from a forgery; it MAY check it
against the seal's signature (its seal link, v0.4 §12.9) first. A member
cut off from an older window jumps instead (v0.4 §12.10).

The DS checks the signature with the member's device key in the tree of
epoch `n`, that `seal_hash` is the latest window's, and that the window
re-keyed the node at `level`. It then asks one member for the repair: an
online member outside the subtree of that node, neither the member nor the
blamed performer, nor excluded (section 3.8), in turn. It keeps a repair
from that maker alone. A second request for the same window, after a
repair that did not lead to the tag or a maker that did not answer, asks
the next maker and drops the repair kept.

* **Who makes it.** Any member of epoch `n` holding `r_n` that the DS
  asks, with the leaf key of the tree of epoch `n`, checked against its
  header, never a key the DS gives: the DS would open `r_n`, which with
  the `init_n-1` of a removed member gives the epoch (formal model,
  `repair.pv`, `repair_unchecked.pv`). A task that cuts off a district
  costs at most `2^L` repairs; one that cuts off a sub-city, one flat
  element per island (section 2.4).
* **Unsigned**, like a flat element: the member opens it with its leaf
  key, derives the epoch, and checks the tag.
* **After a repair**, the member holds `r_n` but no valid path: it MUST
  ask for an update at once (v0.4 §12.6), and follows by repair until the
  window of its update re-keys its path.
* **The DS** keeps a repair with its window, and serves it as the top of
  the member's packet, which then carries no steps.
* **What the DS learns**: which member could not follow, and which node it
  names; nothing of a secret.

### 3.8 Disputes

A member that a wrap addressed to it cuts off proves the wrap faulty,
without revealing its key or a past secret, and the DS convicts the
performer that made it:

```text
Dispute := ["city-g/dispute/v5", gid, epoch, seal_hash, member, task, wrap_index,
            statement, proof]
  seal_hash  := H(SealHeader) of the window that created epoch n
  task       := H(district commit) or H(city task), listed in that seal
  wrap_index := the wrap's index in the task's wraps
  statement  := 1  the wrap does not open (branch 1)
              | 2  its ciphertext's re-encryption differs: no X-Wing
                   encapsulation gives that ciphertext
              | 3  it opens to a secret whose node key differs from pk_v in its
                   matrix seed or its X25519 key (branch 2, short)
              | 4  it opens to a secret whose node key is not pk_v (branch 2)
  proof      := a proof of the statement, at most 2^20 bytes; empty when the
                public checks alone convict
```

signed by the member under `DISPUTE`. The statement's public inputs are
public data of epoch `n`:

```text
DisputeStatement := ["city-g/dispute-statement/v5", statement, context, pk_t,
                     kem_ciphertext, sealed, pk_v or null]
  context := the wrap's context (v0.4 §7.2)
  pk_t    := the key the wrap is addressed to: the member's leaf key, or the
             published key of the node of its path that the wrap targets
  pk_v    := the published key of the wrapped node, for statements 3 and 4
```

A proof binds its statement: the proof system's transcript absorbs the
encoded `DisputeStatement` before it draws any challenge. The statements,
their circuits and their costs are in the research notes on disputes
(`litige-entier`, `litige-deux-branches`): with Longfellow, without setup,
proofs of 573 to 787 KB that anyone can verify, proved in 1.4 to 3.7 s and
verified in 1.0 to 2.3 s at the pace of a Pixel 9. Their witness is the
member's key for `pk_t`; the member's seed and the wrapped secret stay out.

* **Which statement.** The member computes everything in the clear, then
  proves the first that holds: the re-encryption differs (2); the tag is
  wrong (1); the node key differs in its matrix seed or its X25519 key (3);
  it differs in `t` (4). Otherwise the wrap is good. A fault in a chained
  step (v0.4 §7.3) names no wrap and has no statement yet: the member's
  repair request blames its performer (section 3.7).
* **Public checks.** Before any proof, the verifier checks that `ct_X`, the
  ciphertext's X25519 part, is the canonical u-coordinate of a point of
  prime order, and, for statements 3 and 4, that `pk_v` is canonical (the
  FIPS 203 modulus check, and `pk_X` below `2^255 − 19`). No encapsulation
  and no key generation gives anything else: a failed check convicts
  without proof.
* **The DS** checks the signature with the member's device key in the tree
  of epoch `n`, that `seal_hash` is the latest window's and lists `task`,
  and that the wrap exists and is addressed to the member's leaf or to a
  node of its path. It builds the statement from its own copy of the task
  and of the tree, and verifies. A DS without a verifier refuses disputes.
* **A conviction** excludes the performer from every role at once,
  whatever `repair_threshold` (below). The DS keeps the dispute with its
  window and serves it to whoever asks: anyone can check it. An admin MAY
  remove the performer on it (v0.4 §6); its removal re-keys every node it
  tainted (v0.4 §10.2). A conviction re-keys nothing while the performer
  stays: it is a member of the epoch, and its path gives it the root again.
  A device whose key may have been stolen heals by its update, which
  re-keys its leaf and its taints (v0.4 §12.6).
* **Not fixed by this draft**: the proof system, that is the circuits of
  the four statements, their serialized form and the encoding of `proof`.
  Until a DS has a verifier, it MAY exclude a performer on repair requests,
  without conviction.

**Exclusion without conviction.** The DS counts, for each performer, the
distinct members whose repair requests blame it (section 3.7), and gives
no role to a performer that `repair_threshold` members blamed (2 in the
in-memory DS; 0 turns it off): no district commit, city task, seal, relay,
flat element or repair, nor a task it would take over. It binds no member,
since the requests prove nothing: members accept tasks from any performer
the rules allow (section 3.4), and the DS already chooses who performs.
It re-keys nothing either: the performer's taints stay until its next
update (v0.4 §10.2), which the DS MAY ask for, or an admin removes it. An
operator MAY lift an exclusion. The threshold bounds framing: members can
blame only the performers of nodes on their own paths, once each, so that
fewer than `repair_threshold` colluding members exclude no one. With every
online member excluded, windows wait for another member, or for an
entrant (v0.4 §12.7).

### 3.9 Security considerations

* **Joiners draw secrets of the epoch they enter.** A joiner performer
  knows the secrets of the nodes it re-keys, `r_n` for the task that holds
  the root. It is a member of epoch `n`: it learns no more than its welcome
  gives it. Without `init_n-1`, `r_n` does not give the epoch.
* **Hedges** rest on the seed of each device's leaf key: a weak generator
  at the time of a task, a welcome, a flat element or an external init
  exposes nothing to an outsider, nor to a member that the window removes
  (`task_hedge.pv`). Hedging the fresh secrets alone does not suffice: the
  coins of the encapsulation that wraps them would give them away
  (`task_hedge_coins.pv`); nor does the `init_n-1` hedge of v0.4 against
  a removed member (`task_hedge_init.pv`).
* **Tasks bind the state they build on.** A joiner checks the state it is
  shown against its chain of seals; a task's prev hashes and hash of the
  roots below bind it to that state. A performer that the DS shows a key
  of its own for a root of the tier below wraps to it; the sealer then
  refuses the task (`city_task_bound.pv`), which it would otherwise seal
  for a removed member to read (`city_task_unbound.pv`).
* **A faulty task** (wraps that do not open, or open to wrong secrets)
  cuts off at most its district, or for a city task the districts below
  it; the tag check keeps the cut-off members from accepting a wrong epoch.
  The sealer checks its path against the published keys (section 3.5), so
  a task that holds the root cannot make it seal an epoch that only its
  side of the tree follows. Repairs restore the cut-off members within the
  window; disputes convict the performer, and its removal re-keys what it
  drew.
* **Taints** follow performers, joiners included: removing or updating a
  performer re-keys every node it drew (E-4).
* **Repair requests** carry no secret, and a repair's maker takes the
  member's leaf key from its own checked state (`repair.pv`): a false
  request only costs a repair, and counts once against a performer. The
  exclusion they lead to is the DS's choice of performers, not a verdict;
  disputes (section 3.8) are what convict.
* **Disputes** reveal the fault and nothing else: the proof is
  zero-knowledge in the member's key, and the statement names only public
  data. A member convicts an honest performer only if its own key fails
  to decrypt an honest ciphertext: at most `2^−121.2` per ciphertext for
  the worst key the circuits admit (research note `litige-deux-branches`,
  section 2). The DS builds the statement from its own copy of the task,
  so that a member cannot convict on a wrap of its choosing.
* **A joiner that commits a district** checks its entries as a member
  committer does, and audits name it as they name a member (v0.4 §15). A
  faulty joiner can place entries it should not, as a faulty member can in
  v0.4, and is removed the same way. Members welcome such entries only from
  a commit the seal lists, to the init key of the request that hashes to
  the change's reference: without the first check the DS makes a commit of
  its own, without the second it hands a request of its own
  (`welcome_joiner.pv`, `welcome_unlisted.pv`,
  `welcome_request_unbound.pv`).
* **The sealer draws nothing** and learns nothing its own path does not
  give it.
* **Forks.** Tasks bind the state they were built on; relay elements bind
  the transcript (section 2.3).

### 3.10 Parameters and costs

| Name | Value |
| --- | --- |
| `L` (`district_bits`), `c` (`island_bits`) | 8 and 8 by default (v0.4: `L = 12`) |
| `S` (`subcity_bits`) | 8 by default, fixed at genesis |

**Measured.** The scale test (`crates/cityg-core/tests/scale.rs`, release
build, one performer for every city task) runs windows of half removals and
half joins paired with them, and checks the count of wraps and new keys
against the cost model, with boundaries above the leaves, the districts and
the sub-cities:

| Window | City tasks | Seal |
| --- | --- | --- |
| N = 16,384, L = 10, S = 8, 2,000 changes | one sub-city, no top: 48.9 KB, 23 wraps | 5.4 KB |
| N = 65,536, L = 12, S = 8, 4,000 changes | one sub-city, no top: 48.9 KB, 23 wraps | 5.4 KB |
| N = 16,384, L = 10, S = 2, 2,000 changes | 4 sub-cities and the top: 65.0 KB, 25 wraps | 5.5 KB |
| N = 4,096, L = 4, S = 3, 600 changes | 32 sub-cities and the top: 860 KB, 379 wraps | 12.8 KB |

Before stage 2, the seal carried the city: 51 KB in the first two windows.

**Modelled** (research note îlots, section 2.3; synthesis, section 5). A
million members, 1.7 changes per second, 5-minute windows: a joiner that
takes a freed leaf re-keys its path in its island, 8 wraps; an island task
with several changes, 9 wraps on average, at most 181 (42 ms) in a burst
of 100,000 joins and 100,000 departures; the city costs 175 KB per
sub-city. The heaviest task of such a burst takes 42 ms, against 0.6 s for
a v0.4 district of `2^12`.

<a id="4-stage-3"></a>
## 4. Stage 3: parity

Stage 3 gives the draft the guarantees of MLS (RFC 9420 §16, RFC 9750
§8), mapped as G1 to G12 in the parity note (section 3) and the synthesis
(sections 3.5 and 4), at the draft's scale. Stages 1 and 2 do not change.
It has four parts, implemented in this order:

| Part | Content | Sections |
| --- | --- | --- |
| 3a | Leaves with cards, their summary hash, unique keys | 4.1, 4.2 |
| 3b | The message plane: key schedule, secret tree, messages, burst chains, key commitments, the sealed message log, exporter and epoch authenticator | 4.3 to 4.8 |
| 3c | The authorized mode: authorization batches and authorizer checkpoints | 4.9 |
| 3d | The membership log | 4.10 |

### 4.1 Leaves with cards

```text
LeafNode    := [device_pk, since, encryption_key, card, admission_hash, updated]
Card        := [algorithm, public_key]
  algorithm := 1  ML-DSA-65 (FIPS 204), public_key of 1952 bytes
             | 2  FN-DSA-512, reserved until FIPS 206 is final
LeafSummary := [device_id, since, H_L("tree/leaf-key", [encryption_key]), card,
                admission_hash, updated]
leaf_hash(i) := H_L("tree/leaf", [LeafSummary or null])
```

* **The card** is the key a member signs its messages with (section 4.5),
  and nothing else. The device key, which may live in a hardware vault,
  keeps signing requests, tasks and seals.
* **A card changes with the leaf key**: join, update and re-entry requests
  carry the new card beside the new leaf key (`card` follows
  `encryption_key` in `JoinRequest`, `UpdateRequest` and
  `ReEntryRequest`), and `updated` dates both. A stolen card stops
  signing for the member at its next update: the healing of authentication
  (G4). A device MUST draw a fresh card for each leaf key.
* **The summary hash.** `leaf_hash` hashes the leaf's summary, which names
  the device by `device_id` (v0.4 §4) and the leaf key by its hash. A
  reader that checks a card downloads the summary, about 1.0 KB with an
  FN-DSA-512 card and 2.1 KB with an ML-DSA-65 card, instead of the whole
  leaf, 4.1 or 5.2 KB. Who needs the keys, the DS and the performers of
  tasks, takes the whole leaf and hashes its summary; the leaf keeps the
  device key, so that every rule of v0.4 that takes a device key from the
  tree still does. The binding does not change, under the collision
  resistance of `H_L`.
* **Checking a card.** A reader checks a signature of epoch `n` against the
  card in the sender's leaf in the tree of epoch `n`, or of a later epoch
  `m` whose leaf shows `since <= n` and `updated <= n`: the same occupancy
  then held the leaf from `since` to `m`, with the same card since
  `updated`. A leaf proof of epoch `m` (v0.4 §5.3) and the summary show
  it. A reader MUST NOT check a card against a cached leaf that no such
  proof covers: a removed member that keeps its card would otherwise speak
  through an insider (research models `card_revalidated.pv`,
  `card_cached.pv`).

### 4.2 Unique keys

```text
RegistryHeader := [admins, devices_root, admissions_root, keys_root,
                   policy_hash or null, admission_mode, authorizer_pk_hash or null]
registry_hash  := H_L("registry", [[[admin, admin_pk], ...], devices_root, admissions_root,
                                   keys_root, policy_hash or null, admission_mode,
                                   authorizer_pk_hash or null])
keys: a sparse Merkle map (v0.4 §8) from key_hash to the occupancy that holds it
key_hash := H_L("tree/leaf-key", [encryption_key]) | H_L("card", [card])
```

* Every leaf key and every card of the tree is in `keys`. A window changes
  the map in the order of v0.4 §8: the two keys of a removed or evicted
  member leave it; an update or a re-entry replaces the member's two keys;
  a join adds the joiner's two.
* A change MUST NOT set a key that is in the map after the removals, or
  that another change of the window sets. The DS, the committers and the
  auditors check it with the map (v0.4 §15); a member that copies another's
  card would otherwise make its messages attributable to two leaves (G5).
* `admission_mode` replaces `open`: 0 closed, 1 open, 2 authorized
  (section 4.9); `authorizer_pk_hash := H_L("authorizer", [authorizer_pk])`
  in an authorized group, else `null`.

### 4.3 The key schedule of the message plane

```text
sender_data_secret_n, encryption_secret_n, exporter_secret_n, epoch_authenticator_n
    := DeriveSecret(msg_secret_n, "sender data" | "encryption" | "exporter" | "authenticator")
```

A member erases `msg_secret_n` once it has derived the four, and
`encryption_secret_n` as it derives the secret tree (section 4.4). It
keeps the others while the epoch is active and until it has read the
epoch's messages, whose log the next seal closes (section 4.8), then
erases them.

* **Exporter.** An application derives its own secrets of epoch `n`, as
  with MLS's exporter:

  ```text
  Export_n(label, context, L) := ExpandLabel(DeriveSecret(exporter_secret_n, label),
                                             "exported", H(context), L)
  ```

* **Epoch authenticator.** `epoch_authenticator_n` is the same for every
  member of epoch `n`: two members that compare it out of band detect a
  fork (RFC 9750 §5.2). Authorizer checkpoints (section 4.9) make the
  comparison automatic.

### 4.4 The secret tree

Over the `2^height_n` leaves of the tree of epoch `n`:

```text
tree_secret(height_n, 0)   := encryption_secret_n
tree_secret(k - 1, 2i)     := DeriveSecret(tree_secret(k, i), "tree left")
tree_secret(k - 1, 2i + 1) := DeriveSecret(tree_secret(k, i), "tree right")
ratchet_0(i)               := DeriveSecret(tree_secret(0, i), "application")
key_g(i)                   := ExpandLabel(ratchet_g(i), "message key",    CBOR_det(g), 32)
nonce_g(i)                 := ExpandLabel(ratchet_g(i), "message nonce",  CBOR_det(g), 12)
ratchet_g+1(i)             := ExpandLabel(ratchet_g(i), "message secret", CBOR_det(g), 32)
```

* Each member sends from the chain of its leaf, `i`, generation `g` from
  0; it MUST NOT use a generation twice.
* **Deletion.** A member keeps a node's secret until it has derived both
  children, then erases it; it keeps `ratchet_g(i)` until it has derived
  `key_g`, `nonce_g` and `ratchet_g+1`, and a key and its nonce until the
  message is decrypted, or the epoch ends. It keeps the keys of skipped
  generations, at most `MAX_SKIP` ahead of the last it decrypted. A
  message read stays secret against a compromise later in the epoch
  (G4), which a chain derived directly from the epoch's secret would not
  give.
* Deriving one sender's chain takes `height_n` steps: 8.1 µs for `2^24`
  positions (research note on the message plane, section 3.4).

### 4.5 Messages

```text
Message    := ["city-g/message/v5", gid, epoch, encrypted_sender_data, ciphertext, commitment]
SenderData := [leaf, generation, reuse_guard]                   reuse_guard: 4 random bytes
Content    := [application_data, first_generation, signature or null, padding]
```

The sender at leaf `i`, at generation `g`:

```text
nonce                 := nonce_g(i), its first 4 bytes XORed with reuse_guard
aad                   := CBOR_det(["city-g/message/v5", gid, epoch])
ciphertext            := ChaCha20-Poly1305(key_g(i), nonce, CBOR_det(Content), aad)
commitment            := H_L("msg-commit", [key_g(i), nonce, H(ciphertext)])
sample                := ciphertext[0..32]
sender_data_key       := ExpandLabel(sender_data_secret_n, "sender data key", sample, 32)
sender_data_nonce     := ExpandLabel(sender_data_secret_n, "sender data nonce", sample, 12)
encrypted_sender_data := ChaCha20-Poly1305(sender_data_key, sender_data_nonce,
                                           CBOR_det(SenderData), aad)
```

* `padding` is a byte string of zeros, at the sender's choice; a
  ciphertext has at least 32 bytes.
* **The DS does not know who sends** (G2): the sender is under a key of
  the epoch, with the signature. It authenticates connections and limits
  their rates instead, as MLS provides (RFC 9420 §16.11) (research models
  `sender_hidden.pv`, and `sender_visible.pv` with the sender in clear).
* **A receiver** decrypts the sender data, checks that `leaf` is a member
  of epoch `n`, derives the key and nonce of `generation`, checks the
  commitment in constant time, then decrypts the content. It MUST refuse a
  generation it has already decrypted.
* **The reuse guard** keeps two devices that restored the same state from
  reusing a nonce, as in MLS.

### 4.6 Burst chains

A sender signs at most once per burst; the signature covers every message
of the epoch it sent so far:

```text
chain_-1  := ZERO32                                           for each sender, at each epoch
chain_g   := H_L("msg-chain", [chain_g-1, H(CBOR_det([application_data_g, first_generation_g]))])
signature := Card.Sign(CBOR_det([gid, epoch, leaf, first_generation, g, chain_g]))
```

under the context `city-g/message/v5`, carried by the content of message
`g`. `first_generation` is the first generation after the sender's
previous signature: every message of a burst carries it, and the signature
at `g` covers the burst `first_generation..g`.

* **Signing.** A sender whose last signature is older than `T_BURST` signs
  at once: a message alone is signed. Otherwise it sends unsigned, and
  signs at most `T_AUTH` after the first unsigned message of the burst,
  with its next message or alone in a message whose `application_data` is
  empty.
* **Delivery.** A receiver delivers the messages of a burst to the
  application only once it holds every message of the sender from
  generation 0 to `g`, recomputes `chain_g`, and checks the signature
  against the sender's card (section 4.1) (G3). It shows an unsigned
  message as waiting, or holds it back, at most `T_AUTH` and a delivery
  delay; without a signature by then, it drops the burst and reports it.
* An insider can forge an unsigned message, but no signature will cover it
  (research model `burst_chain.pv`); a chain authenticated by a key of the
  epoch alone would let any member speak for the sender
  (`burst_chain_mac_only.pv`).

### 4.7 Key commitments and reports

The commitment binds the message to its key: a receiver checks it, and a
ciphertext opens to one content only (no "invisible salamanders"). To
report message `g`, a member reveals `key` and `nonce` for the messages
`g` to `g'`, the message whose signature covers `g`, and `chain_g-1`. A
moderator (the DS or an admin) checks the commitments, decrypts, recomputes
the chain from `chain_g-1`, checks the signature against the card of the
sender's leaf of epoch `n`, and the messages' inclusion in the sealed log
(section 4.8). Revealing these keys reveals no other message. Messages are
signed: they are not deniable, as in MLS.

### 4.8 The sealed message log

```text
SealBody gains: message_log := [count, root]               the log of epoch n - 1
root := MTH("msg-log", [H(Message_1), ..., H(Message_count)])

MTH(label, [])  := H_L(label, [])
MTH(label, [d]) := H_L(label, [d])
MTH(label, D)   := H_L(label, [MTH(label, D[0..k]), MTH(label, D[k..|D|])])
                   k: the largest power of 2 below |D|
```

* **Order.** The DS numbers the messages of epoch `n - 1` in the order it
  accepts them. It closes the log when it gives the sealer of the window
  that creates epoch `n` its `message_log`, which the seal body carries;
  it refuses messages of epoch `n - 1` from then on, and their senders
  encrypt them again in epoch `n`.
* **Transcript consistency** (G12). `message_log` enters `body_hash`, so
  `seal_hash_n`, so every member's transcript: two members that accept
  epoch `n` with the same interim transcript hash agree on the set and the
  order of the messages of epoch `n - 1`. A sender cannot give two versions
  of a generation to two receivers, and a DS that shows two members
  different messages shows them two transcripts: a fork, which authorizer
  checkpoints reveal.
* **Verifiable delivery.** A sender checks that its messages are in the
  log, with an inclusion proof (RFC 6962 §2.1.1): 448 bytes among 10,000
  messages. A reader of a whole epoch recomputes the root.
* **Serving.** The log of a closed epoch does not change and is
  encrypted: caches can serve it without learning anything.
* The sealer cannot check the log: it signs what the DS gives it. What
  binds the DS is that every member accepts the same seal.

### 4.9 The authorized mode

```text
GroupPolicy          := ["city-g/group-policy/v5", gid, admission_mode,
                         max_idle_epochs or null, authorizer_pk or null, admin, signature]
  admission_mode     := 0 closed | 1 open | 2 authorized, with authorizer_pk
AuthorizationBatch   := ["city-g/authorization-batch/v5", gid, epoch, root, count, signature]
  root               := MTH("authorized", [H(JoinRequest_1), ..., H(JoinRequest_count)])
Authorization        := [batch, index, path]                    path: MTH inclusion proof
AuthorizerCheckpoint := ["city-g/authorizer-checkpoint/v5", gid, epoch, H(GroupContext_n),
                         confirmation_tag_n, kem_pk_hash(external_pk_n), signature]
```

Both authorizer objects are signed with `authorizer_pk` (an ML-DSA-65 key)
under their labels.

* **Joins.** In an authorized group a join carries no admission. The
  authorizer signs, for the window that creates epoch `n`, the root of the
  hashes of the join requests it authorizes; a join is valid with the
  inclusion of its request's hash in such a batch, which the DS attaches
  to it. Its token is `H(JoinRequest)`: it enters once. The DS, the
  committers and the auditors check the batch's signature and the proof,
  where v0.4 checks an admission (v0.4 §6, §10.3, §15). For 100,000 joins
  there is one signature instead of 100,000, and 544 bytes of proof per
  join instead of 3.3 KB (research model `batch_authorization.pv`; without
  the signature of the root, the DS lets its own devices in:
  `batch_authorization_unsigned.pv`).
* **Checkpoints.** After each window, the authorizer checks it and signs
  the checkpoint of the epoch it creates. It holds the group's public
  state, checks the window as the DS does (v0.4 §14.5), compares its joins
  with its batches, and recomputes the tree and registry hashes and the
  group context; it signs the confirmation tag and the external key that
  the seal carries, which it cannot compute. It needs no secret, and signs
  at most one checkpoint per epoch.
  * A joiner that trusts the authorizer's key checks this checkpoint and,
    with its welcome, the tag, instead of a chain of seals (research model
    `authorizer_anchor.pv`; unsigned, `authorizer_anchor_unsigned.pv`).
    Without an answer from the authorizer, it falls back to the chain of
    seals from the last checkpoint it trusts.
  * A member that follows MAY require the checkpoint of epoch `n` before it
    accepts the window that creates it. It has `H(GroupContext_n)` from
    the header, and computes the tag and the external key: it downloads
    the signature alone. No join its authorizer did not authorize passes,
    even with the DS and a committer in collusion, and an insider allied to
    the DS cannot lead it into an epoch the authorizer did not sign
    (research models `authorizer_follow.pv`, and
    `authorizer_follow_unchecked.pv` without the check). It pays in
    liveness, since it waits for the checkpoint, and in bytes: a
    checkpoint per window.
* **Removals.** A `RemoveProposal` whose `proposer` is `null` is signed by
  the authorizer; it is urgent (section 2.9).
* **Trust.** The authorizer holds the place of MLS's authentication
  service (G8): compromised, it lets in whom it wants, but every join
  stays visible, committed by the seal and listed in the membership log.
  It SHOULD be a service distinct from the DS, its key in a hardware
  module; the same server as the DS can authorize its own devices, visibly.

### 4.10 The membership log

```text
SealBody gains: membership_log := [count, root]              the window's changes
root   := MTH("membership-log", [H(CBOR_det(record_1)), ..., H(CBOR_det(record_count))])
record := [kind, leaf, device_id, card_prefix]               in change order (v0.4 §10.1)
  card_prefix := the first 8 bytes of H_L("card", [card])
```

* A removal or an eviction names the device and card that leave the leaf;
  a join, an update or a re-entry, those that the leaf holds after the
  window.
* A member downloads a window's records on demand and checks them against
  the root, as MLS has every member check every change (G10): about 50
  bytes per change, some 7 MB per day at 1.7 changes per second. A client shows the
  changes, or keeps a log its user can examine when there are too many
  (RFC 9750 §8.4.3.1). A proof that a device is a member costs 640 bytes.

### 4.11 Security considerations

* **What parity adds**, guarantee by guarantee: the sender hidden from the
  DS (G2); senders authenticated by cards checked against the leaf of the
  message's epoch, bursts delivered after their signature (G3); cards
  that change with the leaf key (G4); unique keys (G5); the authorizer's
  batches and checkpoints (G7 to G9); the membership log (G10); the
  sealed message log against replays and deletions within an epoch (G12).
* **What it does not change.** The DS can still fork the group, as with
  MLS; a member that checks the checkpoints of an authorizer distinct from
  the DS refuses the fork. Metadata: the DS sees the membership, since it
  checks the requests, as an MLS DS that sees handshake messages in clear
  (RFC 9750 §6.4). Fragmentation by an insider with a role stays bounded
  by the tasks and named by disputes (section 3.8).
* **The authorizer's availability** becomes the group's for members that
  require its checkpoints.
* **Readers outside the tree**, key bundles, public chains and custodians
  (research note on the message plane, sections 3.1 and 3.8) are not part
  of this profile: they do not have parity.

### 4.12 Parameters

| Name | Value |
| --- | --- |
| `T_BURST` | 2 s: a sender signs at once if its last signature is older |
| `T_AUTH` | 5 s: the longest a burst waits for its signature |
| `MAX_SKIP` | 1,024 generations kept ahead of the last decrypted |
| `MAX_MESSAGE_BYTES` | 64 KiB per message, padding included |

<a id="5-labels"></a>
## 5. Label registry

### 5.1 Framing and profile

`H_L` is framed with `city-g/v0.5-draft`, `ExpandLabel` with
`city-g/v0.5-draft expand` and `MAC` with `city-g/v0.5-draft mac` (v0.4
§3.3). The profile identifier in the group context is `city-g/v0.5-draft`.

### 5.2 Labelled hashes (`H_L`)

Those of v0.4 §17.1, unchanged; they differ from v0.4's through the
framing. Stage 3 adds `tree/leaf-key`, `card` and `authorizer` (sections
4.1, 4.2), `msg-chain`, `msg-commit` and `msg-log` (sections 4.6 to 4.8),
`authorized` (section 4.9) and `membership-log` (section 4.10).

### 5.3 Derivation labels

Those of v0.4 §17.2, `relay key` and `relay nonce` (section 2.3),
`task hedge` and `encaps coins` (section 3.3), and for stage 3 `sender
data`, `encryption`, `exporter`, `authenticator` and `exported` (section
4.3), `tree left`, `tree right`, `application`, `message key`, `message
nonce` and `message secret` (section 4.4), `sender data key` and `sender
data nonce` (section 4.5).

### 5.4 Encoded objects and signature contexts

Every object label of v0.4 ends in `/v5` instead of `/v4`:
`city-g/group-context/v5`, `city-g/invite/v5`, `city-g/admission/v5`,
`city-g/join-request/v5`, `city-g/remove/v5`, `city-g/eviction/v5`,
`city-g/group-policy/v5`, `city-g/update/v5`, `city-g/catch-up/v5`,
`city-g/re-entry/v5`, `city-g/checkpoint/v5`, `city-g/district-commit/v5`,
`city-g/seal/v5`, `city-g/seal-body/v5`, `city-g/welcome/v5`, and the new
unsigned `city-g/relay/v5`; for stage 2, `city-g/city-task/v5`,
`city-g/repair-request/v5` and `city-g/dispute/v5` (signed),
`city-g/repair/v5` (unsigned), and `city-g/dispute-statement/v5`, the
encoding of a dispute's public inputs; for stage 3,
`city-g/authorization-batch/v5` and `city-g/authorizer-checkpoint/v5`
(signed by the authorizer), and `city-g/message/v5`, the message and the
context of its card signatures.

The FIPS 204 context of every signed object is its label, as in v0.4
§17.3; the seal is signed under `city-g/seal/v5`.

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
| §10.4, §12.5 | Stage 2: the seal body lists city tasks instead of the city's nodes and wraps; the sealer draws nothing and checks its path against the published keys (section 3.5) |
| §7.1, §7.2, §11, §12.7 | Stage 2: every device hedges its fresh secrets and the coins of its encapsulations with its leaf seed (section 3.3) |
| §11 | Stage 2: a joiner does not welcome; members welcome the entries of a district that a joiner commits (section 3.4) |
| §13.4 | Stage 2: entries by island (section 3.6) |
| §14.4 | Stage 2: joiners perform tasks first (section 3.4); repair requests, repairs, exclusion without conviction and disputes (sections 3.7 and 3.8) |
| §5.2, §5.3 | Stage 3: leaves carry a card; the leaf hash takes the leaf's summary (section 4.1) |
| §6 | Stage 3: join, update and re-entry requests carry a card; the group policy gains the authorized mode and its key; the authorizer may propose removals (sections 4.1, 4.9) |
| §8 | Stage 3: the registry gains the map of keys, `admission_mode` and the authorizer's key hash (section 4.2) |
| §9, §19 | Stage 3: the message plane, from `msg_secret_n` (sections 4.3 to 4.8) |
| §10.4 | Stage 3: the seal body gains the message log of the previous epoch and the membership log of the window (sections 4.8, 4.10) |
| §12.9, §12.2 | Stage 3: joiners may anchor on an authorizer checkpoint, and members may require one (section 4.9) |

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
* **Excluding on repairs.** The threshold, whether counts should decay or
  weigh the requester's own history (a member that asks in many windows),
  and when a DS should ask an excluded performer for an update.
* **The proof system of disputes** (section 3.8): the object, the public
  inputs and the size limit are fixed, and the DS takes a verifier; the
  circuits of the four statements (measured in Longfellow in the research
  notes), their serialized form and the encoding of `proof` remain, as
  does a statement for faults in chained steps.
* **The formal models of stage 2**: hedges, city tasks bound to the state
  they build on, repairs and welcomes by members for joiner districts are
  modelled ([`formal/`](formal/README.md), `task_hedge*.pv`,
  `city_task_*.pv`, `repair*.pv`, `welcome_*.pv`), as are the taint rule
  for tasks and the maintained city (`taint.pv`,
  `ilot_city_maintained.pv`); disputes and the requests for repairs are
  not.
* **Assignment under load**: how many tasks a joiner takes, and when a DS
  prefers a volunteer with a good network.
* **Stage 3**, specified in section 4: not implemented. FN-DSA-512 cards
  wait for FIPS 206. The research models of the message plane and of
  parity (`research/formal-messages/`, `research/formal-parity/`) cover
  the sender hidden, burst chains, cards checked against the epoch's leaf,
  batches and authorizer checkpoints; the profile's own model does not yet,
  nor the sealed message log, the membership log or unique keys. The
  authorizer's availability for members that require its checkpoints, and
  how a DS replicates the message log for caches, are open.
* Everything v0.4 §19 lists, except the lighter structure for continuous
  churn, which this stage begins.
