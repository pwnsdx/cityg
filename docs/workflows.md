# City-G Workflows and Sequence Diagrams

This document provides visual representations of key City-G workflows using sequence diagrams.

---

## Table of Contents

1. [Room Bootstrap](#room-bootstrap)
2. [Join Flow](#join-flow)
3. [Merge Flow](#merge-flow)
4. [Message Send and Receive](#message-send-and-receive)
5. [Epoch Acceptance](#epoch-acceptance)
6. [Forward Secrecy Pivot Rotation](#forward-secrecy-pivot-rotation)
7. [WebSocket Real-Time Notifications](#websocket-real-time-notifications)
8. [Member Roster Query](#member-roster-query)
9. [Visual Guides](#visual-guides)
   - [Two Proof Systems](#two-proof-systems)
   - [What the Server Sees (and Doesn't)](#what-the-server-sees-and-doesnt)
   - [Policy vs Cryptography](#policy-vs-cryptography)

---

## Room Bootstrap

**First member creates a new room**

```mermaid
sequenceDiagram
    participant Client
    participant API Server
    participant Database

    Note over Client: First member (room creator)

    Client->>Client: Generate broadcast key (kbroad)
    Client->>API Server: POST /v1/rooms/bootstrap<br/>{room_id, kbroad_public}
    API Server->>Database: Store room metadata
    API Server->>Database: Initialize empty member roster
    Database-->>API Server: OK
    API Server-->>Client: 200 OK {room created}

    Note over Client,Database: Room is now ready for members to join
```

**Key Points:**
- Only the first member bootstraps the room
- Broadcast key must be shared securely with all members
- Room ID becomes the persistent identifier

---

## Join Flow

**New member joins an existing room**

```mermaid
sequenceDiagram
    participant Client
    participant API Server
    participant cityg-server
    participant Database

    Note over Client: New member wants to join

    Client->>API Server: POST /v1/rooms/join_ticket<br/>{room_id, alias, identity_binding?}
    API Server->>cityg-server: Generate join ticket
    cityg-server->>Database: Fetch current window state
    Database-->>cityg-server: Window heads, parities
    cityg-server->>cityg-server: Build JoinTicketBundle<br/>(witness, parities, config)
    cityg-server-->>API Server: Join ticket
    API Server-->>Client: 200 OK {join_ticket}

    Note over Client: Client generates first epoch (2-5 sec)

    Client->>Client: Derive leaf_id from ticket
    Client->>Client: Generate CAPSS proof
    Client->>Client: Create Merkle witness
    Client->>Client: Build ClientEpochBundle

    Client->>API Server: POST /v1/accept_epoch<br/>{bundle_cbor}
    API Server->>cityg-server: Validate epoch bundle

    cityg-server->>cityg-server: Verify Merkle witness
    cityg-server->>cityg-server: Verify SPHF proof
    cityg-server->>cityg-server: Check parent root in window
    cityg-server->>cityg-server: Insert into window

    alt Epoch accepted
        cityg-server-->>API Server: Accepted {we_epoch_id}
        API Server->>Database: Store epoch bundle
        API Server->>Database: Update member roster
        Database-->>API Server: OK
        API Server-->>Client: 200 OK {accepted: true, we_epoch_id}
        Note over Client: Member joined successfully!
    else Epoch frozen
        cityg-server-->>API Server: Frozen {freeze_code, reason}
        API Server-->>Client: 409 Conflict {accepted: false, freeze_code}
        Note over Client: Join failed - see freeze code
    end
```

**Key Points:**
- Join ticket provides initial cryptographic material
- Client generates proof offline (no server interaction)
- Server validates all cryptographic proofs before accepting
- Identity binding is optional but recommended

### Detailed Join Flow (Bob's Perspective)

The following ASCII diagram shows the join flow from a new member's perspective, illustrating what Bob does step-by-step when joining a 7000-person group:

```
┌─────────────────────────────────────────────────────────────────┐
│              JOIN FLOW (Bob Joins 7000-Person Group)            │
└─────────────────────────────────────────────────────────────────┘

  Bob's Device                            Server
  (New Member)                        (Blind Validator)
       │                                     │
       │  1. Fetch group state               │
       │────────────────────────────-───────>│
       │   GET /groups/city-chat/state       │
       │                                     │
       │   Returns:                          │
       │   • parent_root (current members)   │
       │   • frontier (O(log N) hashes)      │
       │   • kbroad_pub (group key)          │
       │   • policy (e.g., "open_join")      │
       │<─────────────────────────────────-──│
       │                                     │
       │   Note: For 7000 members, frontier  │
       │   is ~13 hashes (log₂ 7000), not    │
       │   the full tree. Scales to millions.│
       │                                     │
       │  2. Bob creates anchor locally:     │
       │     • Adds his leaf_id to tree      │
       │     • Computes new_root (7001)      │
       │     • Generates hp, Y*, E_k         │
       │     • Creates proofs:               │
       │       - CAPSS Smallwood (≤16KB)     │
       │       - ZK-VRF (≤8KB)               │
       │     • Encrypts hp in KBROAD         │
       │     • Builds SRX witnesses          │
       │                                     │
       │  3. Submit anchor                   │
       │   POST /anchors                     │
       │   Body: complete anchor header      │
       │────────────────────────────-───────>│
       │                                     │
       │                                     │  4a. Crypto validation:
       │                                     │     (accept_anchor function)
       │                                     │     ✓ PoP signature valid?
       │                                     │     ✓ CAPSS Smallwood transcript valid?
       │                                     │     ✓ ZK-VRF proof valid?
       │                                     │     ✓ SRX witnesses correct?
       │                                     │     ✓ Merkle consistency?
       │                                     │     ✗ Never decrypts KBROAD
       │                                     │
       │                                     │  4b. Policy check:
       │                                     │     (your application code)
       │                                     │     ✓ join_leaf_ids.len()==1?
       │                                     │     ✓ Not in blocklist?
       │                                     │     ✓ Rate limit OK?
       │                                     │
       │                                     │     Accept & persist
       │  5. Success                         │
       │<────────────────────────────────-───│
       │                                     │
       │  6. Bob starts sending messages     │
       │     (encrypted with E_k)            │
       │                                     │

Bob knows: hp, Y*, E_k              Server knows:
Can read/write messages             • Merkle roots (7000→7001)
                                    • Bob's leaf_id: H(device_pk)
                                    • Timing metadata
                                    ✗ NOT hp, Y*, or E_k
                                    ✗ NOT Bob's device_pk
                                    ✗ NOT message content

Other 7000 members: Fetch anchor later, decrypt KBROAD, derive E_k
```

**Key insight**: Bob creates his own join anchor (he's the "publisher"). The server validates it cryptographically without learning secrets. No admin approval needed for open groups.

---

## Merge Flow

**Existing member resyncs after being offline**

```mermaid
sequenceDiagram
    participant Client
    participant API Server
    participant cityg-server
    participant Database

    Note over Client: Member has been offline, needs fresh state

    Client->>API Server: POST /v1/rooms/merge_ticket<br/>{room_id, leaf_id}
    API Server->>cityg-server: Generate merge ticket
    cityg-server->>Database: Fetch current window state
    cityg-server->>Database: Verify leaf_id exists in roster
    Database-->>cityg-server: Window heads, member data
    cityg-server->>cityg-server: Build MergeTicketBundle<br/>(fresh parities, witness)
    cityg-server-->>API Server: Merge ticket
    API Server-->>Client: 200 OK {merge_ticket}

    Note over Client: Client generates new epoch based on current state

    Client->>Client: Use fresh pivot parities
    Client->>Client: Generate CAPSS proof
    Client->>Client: Build ClientEpochBundle

    Client->>API Server: POST /v1/accept_epoch<br/>{bundle_cbor}

    Note over API Server,Database: Same validation as join flow

    alt Epoch accepted
        API Server-->>Client: 200 OK {accepted: true, we_epoch_id}
        Note over Client: Resynced successfully!
    else Epoch frozen
        API Server-->>Client: 409 Conflict {accepted: false, freeze_code}
    end
```

**Key Points:**
- Merge is for existing members (leaf_id already in roster)
- Fresh pivot parities ensure forward secrecy
- Current merge tickets encode requester self-revocation in `revoked_since`
- Accepted merge bundles therefore apply a leave/rekey-style roster delta

---

## Message Send and Receive

**Sending and fetching encrypted messages**

```mermaid
sequenceDiagram
    participant Alice
    participant API Server
    participant Database
    participant Bob

    Note over Alice: Alice wants to send a message

    Alice->>Alice: Encrypt message with epoch key<br/>(witness extraction)
    Alice->>API Server: POST /v1/send_message<br/>{we_epoch_id, ciphertext, sender}
    API Server->>Database: Store message for epoch
    Database-->>API Server: message_id, timestamp
    API Server-->>Alice: 200 OK {message_id, timestamp}

    Note over Alice,Bob: Message stored on server

    opt WebSocket connected
        API Server->>Bob: WS notification {new message available}
    end

    Note over Bob: Bob fetches messages (polling or WS trigger)

    Bob->>API Server: POST /v1/messages<br/>{we_epoch_id}
    API Server->>Database: Fetch all messages for epoch
    Database-->>API Server: List of messages
    API Server-->>Bob: 200 OK {messages: [{ciphertext, sender, timestamp}]}

    Bob->>Bob: Decrypt each message with epoch key
    Note over Bob: Bob sees Alice's plaintext message
```

**Key Points:**
- Messages are encrypted client-side before sending
- Server stores ciphertext only (zero-knowledge)
- Any client with the epoch key can decrypt
- WebSocket provides instant notifications (optional)

---

## Epoch Acceptance

**Detailed validation pipeline for epoch bundles**

```mermaid
sequenceDiagram
    participant Client
    participant API Server
    participant Validation Pipeline
    participant Window
    participant Database

    Client->>API Server: POST /v1/accept_epoch<br/>{bundle_cbor}
    API Server->>Validation Pipeline: Validate epoch bundle

    Validation Pipeline->>Validation Pipeline: 1. Deserialize CBOR
    Validation Pipeline->>Validation Pipeline: 2. Extract we_epoch_id

    Validation Pipeline->>Window: 3. Check duplicate epoch ID
    alt Duplicate found
        Window-->>Validation Pipeline: Duplicate!
        Validation Pipeline-->>API Server: Freeze code 7 (duplicate)
        API Server-->>Client: 409 Conflict {freeze_code: 7}
    end

    Validation Pipeline->>Validation Pipeline: 4. Verify Merkle witness
    alt Witness invalid
        Validation Pipeline-->>API Server: Freeze code 2 (witness failed)
        API Server-->>Client: 409 Conflict {freeze_code: 2}
    end

    Validation Pipeline->>Validation Pipeline: 5. Verify SPHF proof
    alt SPHF failed
        Validation Pipeline-->>API Server: Freeze code 3 (SPHF failed)
        API Server-->>Client: 409 Conflict {freeze_code: 3}
    end

    Validation Pipeline->>Window: 6. Check parent root exists
    alt Parent not found
        Window-->>Validation Pipeline: Not in window
        Validation Pipeline-->>API Server: Freeze code 5 (parent not found)
        API Server-->>Client: 409 Conflict {freeze_code: 5}
    end

    Validation Pipeline->>Window: 7. Check window capacity
    alt Window full (h >= h_max)
        Window-->>Validation Pipeline: Full!
        Validation Pipeline-->>API Server: Freeze code 11 (window full)
        API Server-->>Client: 409 Conflict {freeze_code: 11}
    end

    Note over Validation Pipeline: All checks passed!

    Validation Pipeline->>Window: Insert epoch as new head
    Window->>Database: Persist epoch bundle
    Database-->>Window: OK
    Window-->>Validation Pipeline: Inserted
    Validation Pipeline-->>API Server: Accepted {we_epoch_id}
    API Server-->>Client: 200 OK {accepted: true, we_epoch_id}
```

**Key Points:**
- Validation is multi-stage with specific freeze codes
- Each failure returns immediately (fail-fast)
- Window manages concurrency control (h_max)
- All epochs are persisted for future retrieval

---

## Forward Secrecy Pivot Rotation

**Automatic hourly pivot refresh for forward secrecy**

```mermaid
sequenceDiagram
    participant Client
    participant API Server
    participant FS Manager
    participant Database

    Note over Client: Client monitors epoch age

    loop Every 5 minutes
        Client->>Client: Check epoch timestamp
        alt Epoch age > 1 hour
            Note over Client: Trigger pivot rotation
            Client->>Client: Generate fresh pivot bundle<br/>(new randomness, commitment)
            Client->>API Server: POST /v1/pivot/refresh<br/>{bundle_cbor}

            API Server->>FS Manager: Process pivot refresh
            FS Manager->>FS Manager: Extract pivot commitment
            FS Manager->>FS Manager: Verify FS policy version
            FS Manager->>FS Manager: Update forward secrecy state
            FS Manager->>Database: Store new pivot parity
            Database-->>FS Manager: OK
            FS Manager-->>API Server: Refresh complete
            API Server-->>Client: 200 OK

            Note over Client: Old pivot discarded<br/>(forward secrecy achieved)
            Client->>Client: Update local epoch timestamp
        else Epoch age < 1 hour
            Note over Client: No rotation needed
        end
    end
```

**Key Points:**
- Automatic rotation every hour (configurable)
- Old pivot keys are permanently discarded
- Ensures past messages remain secure even if current keys leak
- No user intervention required

---

## WebSocket Real-Time Notifications

**Real-time message delivery via WebSocket**

```mermaid
sequenceDiagram
    participant Client
    participant WS Server
    participant Message Queue
    participant API Server

    Note over Client: After joining, establish WebSocket

    Client->>WS Server: WebSocket handshake<br/>GET /v1/ws
    WS Server-->>Client: 101 Switching Protocols

    Note over Client,WS Server: WebSocket connection established

    loop Periodic ping/pong
        WS Server->>Client: Ping
        Client-->>WS Server: Pong
    end

    Note over API Server: Another client sends message

    API Server->>Message Queue: Publish message event<br/>{we_epoch_id, message_id}
    Message Queue->>WS Server: Broadcast to subscribers
    WS Server->>Client: WS message {type: "message", we_epoch_id, message_id}

    Client->>Client: Trigger immediate fetch
    Client->>API Server: POST /v1/messages<br/>{we_epoch_id}
    API Server-->>Client: 200 OK {messages}

    Note over Client: Message displayed instantly!

    alt WebSocket disconnects
        WS Server->>WS Server: Detect disconnect
        Note over Client: Client falls back to polling (5 sec)
        Client->>Client: Reconnect attempt
        Client->>WS Server: WebSocket handshake
        WS Server-->>Client: 101 Switching Protocols
        Note over Client: Reconnected! Resume real-time
    end
```

**Key Points:**
- WebSocket provides instant notifications (no polling delay)
- Client still fetches messages via HTTP (notification is just a trigger)
- Automatic reconnection on disconnect
- Fallback to polling if WebSocket unavailable

---

## Member Roster Query

**Fetching and searching group members**

```mermaid
sequenceDiagram
    participant Client
    participant API Server
    participant Database

    Note over Client: Fetch member roster

    Client->>API Server: POST /v1/members<br/>{gid, parent_root?, offset?, limit?}
    API Server->>Database: Query members for group
    Database->>Database: Filter by parent_root (if specified)
    Database->>Database: Apply pagination (offset, limit)
    Database-->>API Server: Member list (default: 256 members)
    API Server-->>Client: 200 OK<br/>{members, total_count, has_more}

    Client->>Client: Display member roster

    alt More members exist (has_more = true)
        Note over Client: User clicks "Load More"
        Client->>API Server: POST /v1/members<br/>{gid, offset: 256, limit: 256}
        API Server->>Database: Query next page
        Database-->>API Server: Next 256 members
        API Server-->>Client: 200 OK {members, total_count, has_more}
        Client->>Client: Append to roster
    end

    Note over Client: User searches for specific member

    Client->>API Server: POST /v1/members/search<br/>{gid, query: "alice"}
    API Server->>Database: Search by alias substring
    Database-->>API Server: Matching members
    API Server-->>Client: 200 OK {members matching "alice"}

    Client->>Client: Display search results
```

**Key Points:**
- Default pagination: 256 members per page
- Maximum limit: 2000 members per request
- Search supports alias substring and exact leaf_id hex
- `parent_root` filter for historical roster queries

---

## Complete Join-to-Message Flow

**End-to-end workflow from joining to sending a message**

```mermaid
sequenceDiagram
    participant Alice
    participant Server
    participant Bob

    Note over Alice: Alice joins room "demo"

    Alice->>Server: Bootstrap room (if first)<br/>POST /v1/rooms/bootstrap
    Server-->>Alice: 200 OK

    Alice->>Server: Request join ticket<br/>POST /v1/rooms/join_ticket
    Server-->>Alice: Join ticket (witness, parities, config)

    Alice->>Alice: Generate epoch bundle (5 sec)
    Alice->>Server: Submit epoch<br/>POST /v1/accept_epoch
    Server-->>Alice: 200 OK {accepted: true}

    Alice->>Server: Establish WebSocket<br/>GET /v1/ws
    Server-->>Alice: 101 Switching Protocols

    Note over Alice: Alice is now joined!

    Note over Bob: Bob joins the same room

    Bob->>Server: Request join ticket<br/>POST /v1/rooms/join_ticket
    Server-->>Bob: Join ticket
    Bob->>Bob: Generate epoch bundle
    Bob->>Server: Submit epoch<br/>POST /v1/accept_epoch
    Server-->>Bob: 200 OK {accepted: true}
    Bob->>Server: Establish WebSocket

    Note over Bob: Bob is now joined!

    Note over Alice: Alice sends message to Bob

    Alice->>Alice: Encrypt "Hello Bob!" with epoch key
    Alice->>Server: POST /v1/send_message<br/>{we_epoch_id, ciphertext}
    Server-->>Alice: 200 OK {message_id}
    Server->>Bob: WS notification {new message}

    Bob->>Server: POST /v1/messages<br/>{we_epoch_id}
    Server-->>Bob: 200 OK {messages: [{ciphertext}]}
    Bob->>Bob: Decrypt with epoch key

    Note over Bob: Bob sees "Hello Bob!"

    Note over Bob: Bob replies

    Bob->>Bob: Encrypt "Hi Alice!"
    Bob->>Server: POST /v1/send_message
    Server-->>Bob: 200 OK
    Server->>Alice: WS notification

    Alice->>Server: POST /v1/messages
    Server-->>Alice: 200 OK {messages}
    Alice->>Alice: Decrypt

    Note over Alice: Alice sees "Hi Alice!"
```

**Key Points:**
- First member bootstraps, others join directly
- Each member generates their own epoch bundle
- Messages are encrypted end-to-end (server cannot read)
- WebSocket provides instant delivery

---

## Error Handling Workflow

**How the system handles validation failures**

```mermaid
sequenceDiagram
    participant Client
    participant API Server
    participant Validator
    participant Window

    Client->>API Server: POST /v1/accept_epoch
    API Server->>Validator: Validate bundle

    alt Freeze Code 2: Witness Failed
        Validator->>Validator: Verify Merkle proof
        Validator-->>API Server: Invalid witness!
        API Server-->>Client: 409 Conflict<br/>{freeze_code: 2, freeze_reason: "Witness validation failed"}
        Note over Client: Regenerate with correct parent
    else Freeze Code 5: Parent Not Found
        Validator->>Window: Find parent root
        Window-->>Validator: Not found
        Validator-->>API Server: Parent missing!
        API Server-->>Client: 409 Conflict<br/>{freeze_code: 5, freeze_reason: "Parent root not in window"}
        Note over Client: Wait or request merge ticket
    else Freeze Code 11: Window Full
        Validator->>Window: Check capacity
        Window-->>Validator: h >= h_max
        Validator-->>API Server: Window full!
        API Server-->>Client: 409 Conflict<br/>{freeze_code: 11, freeze_reason: "Window full"}
        Note over Client: Retry in a few seconds
    else Success
        Validator->>Window: Insert epoch
        Window-->>Validator: OK
        Validator-->>API Server: Accepted
        API Server-->>Client: 200 OK {accepted: true}
    end
```

**Key Points:**
- Each freeze code has a specific meaning and recovery strategy
- Client should handle all freeze codes gracefully
- Some errors are transient (code 11) - retry works
- Some errors require corrective action (code 2, 5)

---

## Window Management

**How the multi-head window handles concurrency**

```mermaid
sequenceDiagram
    participant Client A
    participant Client B
    participant Window
    participant Database

    Note over Window: Initial state: 2 heads (h_max = 10)

    Client A->>Window: Insert epoch E1<br/>(parent: head1)
    Window->>Window: h = 3 (< h_max)
    Window->>Database: Persist E1
    Window-->>Client A: Accepted

    Note over Window: Now 3 heads

    Client B->>Window: Insert epoch E2<br/>(parent: head2)
    Window->>Window: h = 4 (< h_max)
    Window->>Database: Persist E2
    Window-->>Client B: Accepted

    Note over Window: Now 4 heads (concurrent branches)

    loop Window cleanup (periodic)
        Window->>Window: Check TTL expiry
        alt Head age > ttl_ms
            Window->>Window: Evict expired head
            Window->>Database: Delete old epochs
            Note over Window: h decreases
        end
    end

    alt h reaches h_max
        Client A->>Window: Insert epoch E3
        Window->>Window: h = h_max (full!)
        Window-->>Client A: Freeze code 11 (window full)
        Note over Client A: Wait for eviction or merge
    end
```

**Key Points:**
- Window allows `h_max` concurrent branches
- TTL evicts old heads automatically
- When full, clients must wait or merge branches
- This prevents unbounded memory growth

---

## Visual Guides

These diagrams provide educational overviews of key City-G concepts.

### Two Proof Systems

City-G uses two complementary zero-knowledge proofs that work together to enable server-blind validation:

```
┌──────────────────────────────────────────────────────────────────┐
│  CAPSS Smallwood Transcript (~12KB)  ZK-VRF Proof (≤8KB)         │
│  ───────────────────────────────     ──────────────────────────  │
│  "I derived hp deterministically     "Y* is correct and unique   │
│   and bound the FS context"          for this context"           │
│                                                                  │
│  Prevents: Grinding attacks          Prevents: Forgery           │
│  + FS tampering (mismatched epoch)   (Can't fake Y* values)      │
│                                                                  │
│  Server checks:                      Server checks:              │
│  ✓ seed → hp was deterministic       ✓ Y* exists and is valid    │
│  ✓ FS tuple matches header (146)     ✗ Learns nothing about Y*   │
│  ✗ Learns nothing about hp/epoch_sk                              │
└──────────────────────────────────────────────────────────────────┘

Both proofs verify correctness without revealing secrets.
```

**See also**: [Proof Systems](./protocol/06-proof-systems.md), [CAPSS README](../crates/capss/README.md), [LB-VRF README](../crates/msphf-lb-vrf/README.md)

### What the Server Sees (and Doesn't)

This diagram explains the server's view of an anchor and what remains cryptographically hidden:

```
┌─────────────────────────────────────────────────────────────────┐
│ Server's View of an Anchor                                      │
├─────────────────────────────────────────────────────────────────┤
│ ✓ SEES (Public Metadata):                                       │
│   • Merkle root transitions (parent → join_delta)               │
│   • Leaf IDs: H(device_public_key) [32-byte hashes]             │
│   • Number of members added/removed (from SRX witnesses)        │
│   • Timing: when anchor occurred                                │
│   • Structure: CBOR fields, proof sizes                         │
│   • xk_hash: commitment to anchor context (group+roots)         │
│                                                                 │
│ ✓ CAN EXAMINE (Validated Anchor Fields):                        │
│   • join_leaf_ids: which device hashes were added               │
│   • PoP signer: who created this anchor (leaf_id)               │
│   • Merkle delta: how many members added/removed                │
│   • SRX witness counts: membership proof counts                 │
│                                                                 │
│ ✓ CAN ENFORCE (Application-Layer Policy):                       │
│   • Group policy: open_join vs admin_only (your logic)          │
│   • Delta limits: reject if join_leaf_ids.len() > 1             │
│   • Rate limits: join frequency, abuse controls                 │
│   • Allow/block lists: check PoP signer against lists           │
│   • Cryptographic validity: accept_anchor validates this        │
│                                                                 │
│ ✗ NEVER SEES (Cryptographically Hidden):                        │
│   • hp (hash projection key) - encrypted in KBROAD              │
│   • Y* (VRF output) - hidden by ZK-VRF output-hiding            │
│   • E_k (epoch key) - derived client-side from Y*               │
│   • Device secret keys - only public keys transmitted           │
│   • Human identities - not part of protocol                     │
│   • Message content - encrypted with E_k                        │
└─────────────────────────────────────────────────────────────────┘

accept_anchor validates CRYPTOGRAPHY (proofs, signatures, witnesses).
Your application enforces POLICY (who can join, rate limits, etc.) by
examining validated fields. The server remains cryptographically BLIND
to secret keys (hp, Y*, E_k). Identity linking (leaf_hash → user) is
APPLICATION-LEVEL.
```

**See also**: [Security Model](./protocol/10-security-model.md), [Server Acceptance](./protocol/07-server-acceptance.md)

### Policy vs Cryptography

City-G separates cryptographic validation (protocol-level) from policy enforcement (application-level):

```
┌─────────────────────────────────────────────────────────────────┐
│ Application Policy Layer (Your Server Logic)                    │
├─────────────────────────────────────────────────────────────────┤
│ Examines accepted anchor BEFORE persisting:                     │
│                                                                 │
│ Group: "city-announcements"                                     │
│   ✓ join_leaf_ids.len() == 1?      ← Only 1 member per anchor   │
│   ✓ PoP signer not in blocklist?   ← Check against allow list   │
│   ✓ Rate limit check?              ← Join once per hour         │
│   → Accept self-joins              ← Open policy                │
│                                                                 │
│ Group: "executive-team"                                         │
│   ✓ PoP signer in admin_list?      ← Check Alice's leaf_id      │
│   ✓ join_leaf_ids.len() <= 10?     ← Bulk adds allowed          │
│   → Reject self-joins              ← Admin-only policy          │
│                                                                 │
│ Group: "alice-inbox"                                            │
│   ✓ Sender not already member?     ← First-time senders only    │
│   ✓ join_leaf_ids.len() == 1?      ← Personal inbox pattern     │
│   → Accept sender_once             ← Inbox policy               │
│                                                                 │
│ NOTE: Policy is NOT in accept_anchor() — you implement this     │
│ by examining the cryptographically-validated anchor fields      │
│ (join_leaf_ids, PoP signer, etc.) before storing it.            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ Cryptographic Validation Layer (accept_anchor)                      │
├─────────────────────────────────────────────────────────────────────┤
│ Protocol ALWAYS validates:                                          │
│   ✓ CAPSS Smallwood transcript: seed→hp deterministic + FS binding  │
│   ✓ ZK-VRF proof: Y* correctness (output-hiding)                    │
│   ✓ PoP signature: device key ownership                             │
│   ✓ SRX witnesses: Merkle proofs (membership/non-membership)        │
│   ✓ KBROAD structure: valid envelope (never decrypts!)              │
│   ✓ Merkle consistency: roots computed correctly                    │
│                                                                     │
│ AcceptanceOptions (coarse policy hooks):                            │
│   • allowed_srx_modes: e.g., ["srx/v1-complete"]                    │
│   • allowed_params_ids: cryptographic suite allow-list              │
│   • bootstrap_policy: genesis anchor rules                          │
│   • min_policy_version: reject stale policy versions                │
│                                                                     │
│ Protocol NEVER learns (cryptographically enforced):                 │
│   ✗ hp, Y*, E_k (even if server compromised)                        │
│   ✗ Message content                                                 │
│                                                                     │
│ accept_anchor returns: Accept | Freeze(error_code)                  │
│ → Your app decides: persist or reject based on group policy         │
└─────────────────────────────────────────────────────────────────────┘

Cryptography = "Are the proofs valid?" (accept_anchor always checks)
Coarse policy = "Are the suites/modes allowed?" (AcceptanceOptions)
Fine-grained policy = "Should I persist this anchor?" (your app logic)
```

**Example Policy Patterns:**

| Scenario | Who Creates Anchor | Server Policy Check | Server Crypto Check |
|----------|-------------------|---------------------|---------------------|
| Bob joins open community | Bob (self) | ✓ Policy allows open_join? | ✓ Proofs valid? |
| Bob joins private team | Alice (admin) | ✓ Alice is allowed_admin? | ✓ Proofs valid? |
| Bob sends to Alice's inbox | Bob (sender) | ✓ Policy allows sender_once? | ✓ Proofs valid? |
| Malicious actor tries to join | Anyone | ✗ Policy denies | ✗ Invalid proofs |

**See also**: [Client Operations](./protocol/08-client-operations.md), [Deployment Guide](./protocol/14-deployment-guide.md)

---

## See Also

- [API Reference](./api-reference.md) - Complete HTTP API documentation
- [Protocol Documentation](./protocol/00-README.md) - Cryptographic protocol details
- [Error Reference](./protocol/12-error-reference.md) - Complete freeze code catalog
- [GUI User Guide](./gui-user-guide.md) - Desktop application guide

---

**Last Updated:** 2025-11-06
**Protocol Version:** v1
