# Workflows

Sequence diagrams of the main operations. "DS" is the delivery service;
section numbers refer to the [specification](specs.md). The DS checks
everything it records or receives against the public state, and never
holds a group secret.

## Creating a group

```mermaid
sequenceDiagram
    participant A as Alice (creator)
    participant DS
    A->>A: device key, nonce, gid = H_L("group-id", [pk_A, nonce])
    A->>A: tree of height 1: A at leaf 0, root keyed from a fresh secret
    A->>A: registry: A admin, and a group policy if the group is open
    A->>A: epoch-0 secrets, confirmation tag, external key
    A->>DS: genesis seal (kind 0), signed by A
    DS->>DS: rebuild the state, check gid, hashes, policy and signature
```

The genesis seal is section 9 ("Genesis").

## Joining a closed group

```mermaid
sequenceDiagram
    participant J as Joiner
    participant Ad as Admin
    participant DS
    participant C as Committer of J's district
    participant S as Sealer
    participant M as Members
    Ad->>J: admission for J's device (or an invite), out of band
    Ad->>DS: checkpoint of the current epoch
    J->>DS: checkpoint, registry header and external key of that epoch
    J->>J: check them against the admin key (anchor)
    J->>DS: join request (leaf key, one-time init key, admission)
    DS->>DS: check the request, then queue it
    Note over DS: window due (WINDOW_MAX)
    DS->>DS: place J (a freed leaf, else the lowest free leaf), assign roles
    DS->>C: window task, district state
    C->>C: check the entries, re-key the district, sign
    C->>DS: district commit
    DS->>S: district commits
    S->>S: check them, re-key the city, key schedule, tag
    S->>DS: seal
    DS->>M: one packet per member
    M->>M: derive the path and the epoch, check the tag
    C->>C: follow the window, then seal J's welcome
    C->>DS: welcome (joiner secret to J's init key)
    J->>DS: entry: seal links from the anchor, welcome, steps, leaf proof
    J->>J: check the chain of seals, recover the path, open the welcome
```

Sections 11, 12.9 and 14.

## A window of changes

Removals, evictions, key updates and re-entries go through the same window
as joins.

```mermaid
sequenceDiagram
    participant R as Requester
    participant DS
    participant C as Committers (one per district)
    participant S as Sealer
    participant M as Members
    R->>DS: removal proposal (admin or self) / update / re-entry
    DS->>DS: record it: a removal is enforced at once (no delivery to the target)
    Note over DS: window due (WINDOW_REMOVAL when a removal waits)
    DS->>C: tasks: changes, forced nodes (taints of affected members)
    par each district
        C->>C: plan, draw and wrap secrets, taint = committer
        C->>DS: district commit
    end
    DS->>DS: check every district commit
    S->>DS: seal (city re-key, hashes, tag, next external key)
    DS->>DS: check the seal, apply the window
    M->>DS: packet for my leaf
    DS-->>M: seal header, tag, registry update, steps of my path
```

Sections 10, 12.2 to 12.6 and 14.

## Nobody online

With no volunteer, the first joiner or re-entering member of the window
seals it alone.

```mermaid
sequenceDiagram
    participant E as Entrant (joiner or returning member)
    participant DS
    participant M as Members (offline)
    E->>DS: join or re-entry request
    Note over DS: window due, no volunteer
    DS->>E: every role: all districts, the seal, the welcomes
    E->>DS: seal links from its anchor, and the public state
    E->>E: check the chain of seals and the state
    E->>E: external init to the current external key
    E->>E: commit every district, seal (kind 2), welcome the others
    E->>DS: district commits, seal, welcomes
    Note over M: later
    M->>DS: packet, with the entrant's evidence and signature
    M->>M: recover the external init, derive the epoch, check the tag
    M->>M: check the entrant's admission (or re-entry) and its signature
```

With no volunteer and no entrant, the window stays open: recorded removals
are enforced by the DS at delivery until a participant comes (sections 12.7,
12.8 and 14.6).

## Coming back

```mermaid
sequenceDiagram
    participant R as Returning member
    participant DS
    participant W as Welcomer
    alt replay
        loop every missed window
            R->>DS: packet of the window
            R->>R: process it
        end
    else jump
        R->>DS: catch-up request (bound to the current interim, one-time init key)
        Note over DS: next window
        W->>DS: welcome for R, to its init key and to its leaf key from the tree
        R->>DS: entry: seal links from its last epoch, welcome, last steps
        R->>R: recover the path, check it against the tree, open the welcome with both keys
    else re-entry
        R->>DS: re-entry request (new leaf key, one-time init key)
        Note over DS: next window re-keys R's path, or R seals it as entrant
        R->>DS: entry
    end
```

Section 12.10.

## Seeing who joined an open group

```mermaid
sequenceDiagram
    participant M as Member
    participant DS
    M->>DS: seal, district commits and join requests of a window
    M->>M: seal hash = the one it accepted, then the body hash and the commits listed
    M->>M: each join request hashes to its change's reference
    M->>M: list the devices and occupancies the window let in
```

A device of the DS that joined is listed like any other, and cannot pose as
an existing member: its requests would not verify under that member's
device key (sections 6.1 and 12.11).
