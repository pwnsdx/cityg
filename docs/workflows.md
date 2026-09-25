# Workflows

Sequence diagrams of the main operations of profile v0.2. "DS" is the
delivery service; section numbers refer to the [specification](specs.md).
Every commit below is verified by the DS against public state (tree, roster,
transcript) and by each member, which also derives the epoch secrets and
checks the confirmation tag (section 9.5).

## Creating a group

```mermaid
sequenceDiagram
    participant A as Alice (creator)
    participant DS
    A->>A: device key, group_nonce, gid = H_L("group-id", [pk_A, nonce])
    A->>A: genesis commit (slot 0, fresh leaf secret) + epoch-0 secrets
    A->>A: GroupInfo of epoch 0, signed by Alice
    A->>DS: /v2/groups/create {commit, group_info}
    DS->>DS: verify genesis (gid binds pk_A), GroupInfo matches epoch 0
    DS-->>A: epoch 0, seq 1
```

## Inviting and joining

The joiner needs no online member: it joins with an external commit.

```mermaid
sequenceDiagram
    participant A as Alice (admin)
    participant DS
    participant B as Bob
    A->>A: invite_seed (32 random bytes), invite key = KeyGen(invite_seed)
    A->>DS: /v2/groups/invite {Invite signed by Alice}
    A-->>B: invite link (server URL, gid, invite_seed), out of band
    B->>DS: /v2/groups/invite/get {invite_id}
    B->>B: Admission signed with the invite key
    B->>DS: /v2/groups/info
    DS-->>B: GroupInfo, tree, roster, recorded removals
    B->>B: check GroupInfo against tree and roster
    B->>B: ExternalJoin commit: lowest free slot, encapsulate to the external key
    B->>DS: /v2/groups/commit {commit, group_info}
    DS->>DS: verify: admission from a current admin, invite not expired, transition
    DS-->>B: epoch n + 1
    A->>DS: /v2/groups/log
    DS-->>A: Bob's commit
    A->>A: decapsulate external init, derive epoch n + 1, check tag
```

## Sending and receiving

```mermaid
sequenceDiagram
    participant A as Alice
    participant DS
    participant B as Bob
    A->>A: next generation g of Alice's chain: key_g, nonce_g
    A->>A: sign FramedContent (city-g/msg/v3), seal envelope
    A->>A: persist the session (generation g is spent)
    A->>DS: /v2/groups/send {envelope} (session token)
    DS->>DS: sender = token member, member of the epoch and current roster, (epoch, sender, g) new
    DS-->>A: seq
    B->>DS: /v2/groups/log
    DS-->>B: envelope
    B->>B: derive key_g of Alice's chain, open, verify signature, erase key_g
```

## Leaving

A member never commits its own removal (section 9.4).

```mermaid
sequenceDiagram
    participant C as Carol (leaving)
    participant DS
    participant B as Bob
    C->>DS: /v2/groups/remove_proposal {RemoveProposal signed by Carol}
    DS->>DS: record it; refuse Carol's messages from now on
    DS-->>C: recorded
    B->>DS: /v2/groups/log (proposal entry) or /v2/groups/info
    B->>B: Member commit including the proposal: blank Carol's leaf and path, re-key Bob's path
    B->>DS: /v2/groups/commit
    C->>DS: /v2/groups/log
    DS-->>C: 403 (token of a removed member)
    C->>C: learn the removal from the roster, delete the group state
```

## Removing a member (admin)

```mermaid
sequenceDiagram
    participant A as Alice (admin)
    participant DS
    participant M as Mallory
    A->>A: RemoveProposal for Mallory's occupancy, signed by Alice
    A->>A: Member commit including it; Mallory's leaf and path blanked
    A->>DS: /v2/groups/commit
    DS->>DS: proposal authorized (Alice is an admin), transition verified
    Note over M: Mallory is not covered by the new path:<br/>she derives no secret of the new epoch
```

## Concurrent commits

```mermaid
sequenceDiagram
    participant A as Alice
    participant DS
    participant B as Bob
    A->>DS: commit for epoch n + 1
    B->>DS: commit for epoch n + 1
    DS-->>A: accepted (first valid commit wins)
    DS-->>B: 409 epoch mismatch
    B->>DS: /v2/groups/log
    B->>B: process Alice's commit, rebuild on epoch n + 1
    B->>DS: commit for epoch n + 2
```

## Resyncing

A member that cannot process a commit (lost state, a path it cannot
decrypt) or that finds a commit it needs gone from the log re-enters its own
slot.

```mermaid
sequenceDiagram
    participant C as Carol
    participant DS
    C->>DS: /v2/groups/cover_failure {report: epoch, reason, signed}
    C->>DS: /v2/groups/info
    C->>C: Resync commit: same slot, next generation, external init
    C->>DS: /v2/groups/commit
    DS->>DS: author is the member of that slot; identity, admission and admin rights kept
```

## Periodic maintenance

Every member, on a timer (the GUI's default is 30 seconds):

1. commits the recorded removal proposals of other members, after a random
   delay to avoid concurrent commits;
2. re-keys its own leaf if its last update is older than `FS_WINDOW`
   (24 hours), for forward secrecy and post-compromise security;
3. erases the previous epoch's message keys once the 10-minute grace window
   has passed.
