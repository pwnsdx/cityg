# City-G HTTP API Reference

Complete reference for the City-G REST API server.

**Version:** 1.0
**Protocol:** HTTP/HTTPS
**Serialization:** Protocol Buffers (binary)
**Base URL:** `http://localhost:8080` (configurable)

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Authentication](#authentication)
3. [API Endpoints](#api-endpoints)
   - [Health Check](#health-check)
   - [Epoch Management](#epoch-management)
   - [Room Management](#room-management)
   - [Member Roster](#member-roster)
   - [Messaging](#messaging)
   - [Window Management](#window-management)
   - [Telemetry](#telemetry)
   - [Forward Secrecy](#forward-secrecy)
4. [Error Handling](#error-handling)
5. [Freeze Codes](#freeze-codes)
6. [WebSocket API](#websocket-api)
7. [Examples](#examples)

---

## Quick Start

### Prerequisites

```bash
# Install the City-G server
cargo build --release --bin cityg-api

# Run the server
./target/release/cityg-api
```

### First API Call

```bash
# Check server health
curl http://localhost:8080/health

# Expected response: HTTP 200 OK
```

### Using the Rust Client

```rust
use cityg_api_client::CitygApiClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = CitygApiClient::new("http://localhost:8080");
    client.health().await?;
    println!("Server is healthy!");
    Ok(())
}
```

---

### Wire Compatibility

- **Package namespace:** `cityg.api.v1`. Breaking wire changes require bumping the package suffix (`v2`, `v3`, ...).
- **Reserved field numbers:** Every protobuf message reserves the `1000–1999` range so deprecated fields can be retired without risking accidental reuse.

---

## Authentication

**Current Status:** Authentication and authorization are endpoint-specific.

City-G currently uses three distinct authorization modes:

- **Protocol/member flows** such as `accept_epoch`, `join_ticket`, `merge_ticket`,
  roster queries, and messaging do not use a legacy room admin token. These
  flows are authenticated by protocol proofs and, when supplied, TOFU
  `IdentityBinding` material.
- **Room bootstrap and room-governance flows** use a room-scoped signed
  `RoomAdminProof` bound to a persistent room identity. The first successful
  bootstrap claims the room and registers that identity as the initial room
  admin.
- **Operator/debug endpoints** such as window configuration and debug seeding
  still use the `x-cityg-admin-token` header.

Important rules:

- There is **no legacy token fallback** for room-scoped endpoints such as
  `/v1/rooms/bootstrap`.
- `CITYG_CLIENT_ADMIN_TOKEN` is **not** part of the normal public-room
  join/leave/refresh flow.
- Alias text is never an authority principal. Room authority is tied to the
  persisted room identity that signs `RoomAdminProof`.

See [Room-Scoped Administration Redesign](./room-admin-governance-redesign.md)
for the accepted governance model.

---

## API Endpoints

All endpoints except `/health` use **Protocol Buffers** encoding:
- Request: `Content-Type: application/x-protobuf`
- Response: `Content-Type: application/x-protobuf`

### Health Check

#### `GET /health`

Verifies the server is running and accepting requests.

**Request:**
```bash
curl http://localhost:8080/health
```

**Response:**
```json
{
  "status": "healthy"
}
```

**Status Codes:**
- `200 OK` - Server is operational
- `503 Service Unavailable` - Server is not ready

**Use Cases:**
- Kubernetes liveness/readiness probes
- Load balancer health checks
- Monitoring systems

---

### Epoch Management

#### `POST /v1/accept_epoch`

Submits a client epoch bundle for validation and insertion into the multi-head window.

**Protobuf Request:** `AcceptEpochRequest`
```protobuf
message AcceptEpochRequest {
  bytes bundle_cbor = 1;  // CBOR-encoded ClientEpochBundle
}
```

**Protobuf Response:** `AcceptEpochResponse`
```protobuf
message AcceptEpochResponse {
  bytes we_epoch_id = 1;
  bytes wid = 2;           // Window identifier used internally
  bytes parent_root = 3;   // Confirmed parent root
  bytes new_root = 4;      // Root after accepting the epoch
}
```

> ℹ️ **Freeze handling:** when validation fails (e.g., bad witness, stale parent, window full) the
> server returns an **HTTP error** with a JSON body that includes `freeze_code`/`freeze_reason`. No
> protobuf body is returned on errors; the client must inspect the HTTP status to distinguish
> success from freeze.

**Curl Example:**
```bash
# Encode your ClientEpochBundle to CBOR first
# Then send it as binary data

curl -X POST http://localhost:8080/v1/accept_epoch \
  -H "Content-Type: application/x-protobuf" \
  --data-binary @epoch_bundle.pb
```

**Rust Client Example:**
```rust
use cityg_api_client::CitygApiClient;
use cityg_client::ClientEpochBundle;

async fn submit_epoch(
    client: &CitygApiClient,
    bundle: &ClientEpochBundle,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.accept_epoch_bundle(bundle).await?;

    println!("✓ Epoch accepted: {}", hex::encode(&response.we_epoch_id));

    Ok(())
}
```

**Validation Pipeline:**

The server validates the epoch through multiple stages:

1. **CBOR Deserialization** - Parse the bundle
2. **Witness Validation** - Verify Merkle proofs
3. **SPHF Verification** - Check cryptographic proofs
4. **Parent Root Check** - Ensure parent is in window
5. **Duplicate Detection** - Reject replays
6. **Window Insertion** - Add to multi-head window

**Common Freeze Codes (reported via JSON error body):**
- `2` - Witness validation failed
- `3` - SPHF verification failed
- `5` - Parent root not found
- `7` - Duplicate epoch ID
- `11` - Window full (h_max exceeded)

See [Freeze Codes](#freeze-codes) for the complete catalog and mitigation steps.

#### `POST /v1/bundle`

Retrieves a previously accepted epoch bundle by its ID.

**Protobuf Request:** `GetBundleRequest`
```protobuf
message GetBundleRequest {
  bytes we_epoch_id = 1;  // 32-byte epoch ID
}
```

**Protobuf Response:** `GetBundleResponse`
```protobuf
message GetBundleResponse {
  bytes bundle_cbor = 1;  // CBOR-encoded ClientEpochBundle
}
```

**Rust Client Example:**
```rust
let response = client.get_bundle(&epoch_id).await?;
let bundle = ClientEpochBundle::from_cbor(&response.bundle_cbor)?;
println!("Retrieved bundle for epoch: {}", hex::encode(&bundle.we_epoch_id));
```

---

### Room Management

#### `POST /v1/rooms/bootstrap`

Initializes a new City-G room (group) on the server.

**Protobuf Request:** `BootstrapRoomRequest`
```protobuf
message RoomAdminProof {
  bytes pop_public_key = 1;  // Persisted room identity public key
  bytes signature = 2;       // Signature over CBOR([op, room_id, payload_bytes])
}

message BootstrapRoomRequest {
  string room_id = 1;         // Unique room identifier
  bytes kbroad_public = 2;    // Broadcast encryption public key
  optional RoomAdminProof admin_proof = 3;
}
```

**Protobuf Response:** `BootstrapRoomResponse`
```protobuf
message BootstrapRoomResponse {
  string status = 1;
}
```

**Rust Client Example:**
```rust
use cityg_api_client::{
    RoomAdminOperation, build_room_admin_proof, generate_room_admin_keypair,
};

// Generate or load the creator's persisted room-scoped admin identity.
let (pop_public_key, pop_secret_key) = generate_room_admin_keypair();

// Generate a KBROAD public key (using your crypto library)
let kbroad_public = generate_broadcast_key(); // Implementation-specific

let admin_proof = build_room_admin_proof(
    RoomAdminOperation::Bootstrap,
    "my-secure-room",
    &kbroad_public,
    &pop_public_key,
    &pop_secret_key,
)?;

client
    .bootstrap_room_as_admin("my-secure-room", &kbroad_public, admin_proof)
    .await?;
println!("Room bootstrapped successfully!");
```

**Notes:**
- Room ID must be unique
- The first successful bootstrap claims the room and registers the signing
  identity as the initial room admin
- There is no `x-cityg-admin-token` fallback for this endpoint
- The desktop GUI handles this automatically by persisting a room-scoped
  identity per `(server_url, room_id)`

#### `POST /v1/rooms/grant_admin`

Delegates room-admin authority to another persisted room identity.

**Protobuf Request:** `RoomAdminMutationRequest`
```protobuf
message RoomAdminMutationRequest {
  string room_id = 1;
  bytes target_pop_public_key = 2;  // Persisted room identity to grant
  optional RoomAdminProof admin_proof = 3;
}
```

**Protobuf Response:** `RoomAdminMutationResponse`
```protobuf
message RoomAdminMutationResponse {
  string status = 1;       // "granted" or "already_granted"
  uint64 admin_count = 2;  // Current number of room admins
}
```

**Notes:**
- Requires a valid room-admin proof from an existing room admin
- Authority is delegated to a persistent room identity, never to an alias
- There is no legacy token fallback for this endpoint

#### `POST /v1/rooms/revoke_admin`

Revokes room-admin authority from a persisted room identity.

**Protobuf Request:** `RoomAdminMutationRequest`

**Protobuf Response:** `RoomAdminMutationResponse`

**Notes:**
- Requires a valid room-admin proof from an existing room admin
- Returns `"revoked"` or `"already_revoked"`
- Rejects attempts to revoke the last remaining room admin
- There is no legacy token fallback for this endpoint

#### `POST /v1/rooms/list_admins`

Lists the persisted room identities that currently hold room-admin authority.

**Protobuf Request:** `ListRoomAdminsRequest`
```protobuf
message ListRoomAdminsRequest {
  string room_id = 1;
  optional RoomAdminProof admin_proof = 2;
}
```

**Protobuf Response:** `ListRoomAdminsResponse`
```protobuf
message ListRoomAdminsResponse {
  repeated bytes admin_pop_public_keys = 1;
}
```

**Notes:**
- Requires a valid room-admin proof from an existing room admin
- Returned identities are room-admin principals, not display aliases
- There is no legacy token fallback for this endpoint

#### `POST /v1/rooms/expel_member_ticket`

Requests a room-admin-authorized merge ticket that revokes another current
member leaf from the roster.

**Protobuf Request:** `ExpelMemberTicketRequest`
```protobuf
message ExpelMemberTicketRequest {
  string room_id = 1;
  bytes author_leaf_id = 2;   // 32-byte current leaf of the acting admin device
  bytes target_leaf_id = 3;   // 32-byte current leaf to revoke
  optional RoomAdminProof admin_proof = 4;
}
```

**Protobuf Response:** `MergeTicketResponse`

**Notes:**
- Requires a valid room-admin proof from an existing room admin
- The acting admin proof is bound to both `author_leaf_id` and `target_leaf_id`
- `author_leaf_id` must belong to the acting admin's current room membership
- `target_leaf_id` must be a different current member leaf
- Self-revocation is rejected here; use `merge_ticket` with `LEAVE` for a
  controlled leave
- There is no legacy token fallback for this endpoint

#### `POST /v1/rooms/rotate_kbroad`

Rotates the room KBROAD public key.

This endpoint remains available for transitional tooling and test coverage, but
normal GUI/join/leave/refresh flows should not call it directly. The server
automatically refreshes KBROAD metadata when ticket issuance detects that a
rotation is required.

**Protobuf Request:** `RotateRoomKbroadRequest`
```protobuf
message RotateRoomKbroadRequest {
  string room_id = 1;
  bytes kbroad_public = 2;
  optional RoomAdminProof admin_proof = 3;
}
```

**Protobuf Response:** `RotateRoomKbroadResponse`
```protobuf
message RotateRoomKbroadResponse {
  string status = 1;
  uint64 kbroad_generation = 2;
}
```

**Notes:**
- This endpoint requires a valid `RoomAdminProof`
- Normal room operation should rely on automatic/server-managed KBROAD
  maintenance instead of manual rotation
- There is no legacy token fallback for this endpoint

#### `POST /v1/rooms/join_ticket`

Requests a join ticket for a new member to enter the room.

**Protobuf Request:** `JoinTicketRequest`
```protobuf
message JoinTicketRequest {
  string room_id = 1;
  string alias = 2;                       // Deprecated; prefer identity_binding.alias
  optional IdentityBinding identity_binding = 3;
}

message IdentityBinding {
  string alias = 1;                      // TOFU display name
  bytes pop_public_key = 2;              // Persisted member identity public key
  bytes signature = 3;                   // Signature over CBOR([alias, pop_public_key])
}
```

**Protobuf Response:** `JoinTicketResponse`
```protobuf
message JoinTicketResponse {
  bytes gid = 1;
  bytes cat = 2;
  bytes parent_root = 3;
  bytes revoked_root = 4;
  bytes revoked_since_root = 5;
  bytes tswe_salt_hash = 6;
  bytes join_delta_root = 7;
  bytes leaf_id = 8;
  bytes pox_r_commit = 9;
  bytes witness_cbor = 10;
  bytes srx_cbor = 11;
  string msphf_crs_id = 12;
  string msphf_params_id = 13;
  string proof_mode = 14;
  string vrf_id = 15;
  string policy_version = 16;
  string fs_policy_version = 17;
  uint64 fs_epoch_base_ts = 18;
  bytes kbroad_public = 19;
  bytes bootstrap_public = 20;
  optional IdentityBinding confirmed_binding = 21;
  uint64 kbroad_generation = 22;
  uint64 barrier_version = 23;
  string profile_version = 24;
  uint64 cover_leaf_index = 25;
  reserved 26;                               // Legacy k_barrier field id
  bytes kem_tree_hash_after = 27;
  uint64 n_max = 28;
  uint64 max_barrier_update_bytes = 29;
  string history_authority_extension = 46;  // "global-history-authority-v1" in the base profile
}
```

**Rust Client Example:**
```rust
use cityg_api_client::IdentityBinding;

// Without identity binding
let ticket = client.join_ticket("my-room", "alice", None).await?;

// With ML-DSA-65 identity binding (recommended)
let identity = IdentityBinding {
    alias: "alice".to_string(),
    pop_public_key: dilithium_pubkey.to_vec(),
    signature: dilithium_signature_over_alias_and_key,
};

let ticket = client.join_ticket("my-room", "alice", Some(identity)).await?;

// Use ticket to generate your first epoch...
```

**Identity Binding (TOFU):**

- The server recomputes `leaf_id` in "PerGroup" mode from `(gid, "ML-DSA-65", pop_public_key)`.
  The alias is authenticated separately by the TOFU identity binding, but does not participate in
  leaf derivation.
- Signatures are Dilithium (ML-DSA-65) over the CBOR tuple `[alias, pop_public_key]`. Any change in
  alias or key invalidates the signature.
- On first use the alias is registered; later requests must reuse the same keypair or they are
  rejected as TOFU violations.

#### `POST /v1/rooms/merge_ticket`

Requests a merge ticket for an existing member during self-directed
merge/leave/refresh flow. Current server behavior includes requester
self-revocation in the merge SRX delta for `LEAVE`.

**Protobuf Request:** `MergeTicketRequest`
```protobuf
message MergeTicketRequest {
  string room_id = 1;
  bytes leaf_id = 2;  // 32-byte member leaf ID
  MergeTicketIntent intent = 3;  // leave or refresh
}

enum MergeTicketIntent {
  MERGE_TICKET_INTENT_LEAVE = 0;
  MERGE_TICKET_INTENT_REFRESH = 1;
}
```

**Protobuf Response:** `MergeTicketResponse`
```protobuf
message MergeTicketResponse {
  bytes we_epoch_id = 1;
  repeated bytes pivot_parity_cbor = 2;   // CBOR-encoded PivotParity structures
  bytes witness_cbor = 3;
  string proof_mode = 4;
  string vrf_id = 5;
  string policy_version = 6;
  bytes kbroad_public = 7;
  bytes cat = 8;
  bytes parent_root = 9;
  bytes join_delta_root = 10;
  bytes revoked_since_root = 11;
  bytes revoked_root = 12;
  bytes tswe_salt_hash = 13;
  bytes pox_r_commit = 14;
  bytes srx_cbor = 15;
  string msphf_crs_id = 16;
  string msphf_params_id = 17;
  string fs_policy_version = 18;
  uint64 fs_epoch_base_ts = 19;
  uint64 kbroad_generation = 20;
  uint64 barrier_version = 21;
  string profile_version = 22;
  uint64 cover_leaf_index = 23;
  reserved 24;                               // Legacy k_barrier field id
  bytes kem_tree_hash_after = 25;
  uint64 n_max = 26;
  uint64 max_barrier_update_bytes = 27;
  string history_authority_extension = 34;  // "global-history-authority-v1" in the base profile
}
```

`history_authority_extension` names the exact negotiated history-authority extension that governs
any accompanying `history_authority_descriptor`,
`current_global_history_attestation`, or helper-completeness objects. In the base profile this
field MUST equal `"global-history-authority-v1"`.

**Rust Client Example:**
```rust
let ticket = client.merge_ticket("my-room", &leaf_id).await?;

println!("Merge ticket pivots: {}", ticket.pivot_parity_cbor.len());

// Use ticket to create a new epoch based on current state...
```

**Use Cases:**
- Controlled leave/rekey transitions
- Refreshing parity context for merge-era state transitions
- Admin-driven expulsion uses `POST /v1/rooms/expel_member_ticket`, not this
  endpoint

---

### Member Roster

#### `POST /v1/members`

Retrieves the member roster for a group with pagination support.

**Protobuf Request:** `MembersRequest`
```protobuf
message MembersRequest {
  bytes gid = 1;                    // Group ID
  bytes parent_root = 2;            // Optional: filter by epoch root
  optional uint64 offset = 3;       // Pagination offset
  optional uint32 limit = 4;        // Max results (default: 256, max: 2000)
}
```

**Protobuf Response:** `MembersResponse`
```protobuf
message Member {
  bytes leaf_id = 1;
  optional string alias = 2;
  optional bytes pop_public_key = 3;
  optional uint64 join_date = 4;   // ms since UNIX epoch
  optional uint64 last_seen = 5;   // ms since UNIX epoch
}

message MembersResponse {
  repeated Member members = 1;
  bytes root = 2;                  // Roster root the listing was derived from
  uint64 total_count = 3;
  uint64 next_offset = 4;          // Pass as offset for the next page
}
```

> **Roster Consistency & TOFU alias bindings**
> - The server returns the authoritative alias + `pop_public_key` pair for every member. Clients
>   should persist those bindings locally (TOFU) and surface an alert whenever the same alias rebroadcasts
>   a different key.
> - When reconciling revocations, always paginate until `next_offset == total_count` on each refresh
>   and drop any locally-cached members that are not present in the server’s result set.
> - Large rooms are easier to manage if you maintain an alias-index so message senders can be resolved
>   even when the roster view is filtered (see `/v1/members/search` below).

**Rust Client Example:**
```rust
// Fetch all members (auto-paginated)
let response = client.members(&gid, None).await?;

for member in response.members {
    println!(
        "Member: {} (leaf_id: {})",
        member.alias,
        hex::encode(&member.leaf_id)
    );
}

if response.has_more {
    println!("Total members: {}", response.total_count);
}

// Custom pagination
let page2 = client.members_with_range(
    &gid,
    None,
    Some(100),  // offset
    Some(100)   // limit
).await?;
```

**Pagination:**
- Default limit: 256 members
- Maximum limit: 2000 members
- Pass the `next_offset` value from the previous response into the next request until it equals
  `total_count`

#### `POST /v1/members/search`

Searches for members by alias or leaf ID.

**Protobuf Request:** `SearchMembersRequest`
```protobuf
message SearchMembersRequest {
  bytes gid = 1;
  string query = 2;                 // Substring for alias OR hex leaf_id
  bytes parent_root = 3;            // Optional: filter by epoch root
  optional uint64 offset = 4;
  optional uint32 limit = 5;
}
```

**Protobuf Response:** `SearchMembersResponse`
```protobuf
// Same structure as MembersResponse
```

**Rust Client Example:**
```rust
// Search by alias substring
let results = client.search_members(
    &gid,
    "alice",
    None,
    None,
    None
).await?;

for member in results.members {
    println!("Found: {} ({})", member.alias, hex::encode(&member.leaf_id));
}

// Search by exact leaf_id (hex string)
let results = client.search_members(
    &gid,
    "a3b5c7d9e1f2...",  // Full or partial hex string
    None,
    None,
    None
).await?;
```

**Search Behavior:**
- Alias: Case-insensitive substring match over the registered alias (TOFU registry)
- Leaf ID: Case-insensitive substring match over the 64-char hex encoding (not exact-only)
- Results use the same pagination model as `/v1/members`
- Use this endpoint when implementing roster filters. It respects the same totals/offsets, so you can
  reuse the pagination + alias-reconciliation logic described above.

---

### Messaging

#### `POST /v1/send_message`

Stores an encrypted message associated with an epoch.

**Protobuf Request:** `SendMessageRequest`
```protobuf
message SendMessageRequest {
  bytes we_epoch_id = 1;        // 32-byte epoch ID
  bytes ciphertext = 2;         // Encrypted message payload
  bytes sender = 3;             // Optional sender identifier
}
```

**Protobuf Response:** `SendMessageResponse`
```protobuf
message SendMessageResponse {
  string status = 1;            // Always "stored" on success
}
```

**Rust Client Example:**
```rust
let ciphertext = encrypt_message(&plaintext, &epoch_key);

let response = client.send_message(
    &epoch_id,
    &ciphertext,
    Some(b"alice")  // Optional sender attribution
).await?;

println!("Message status: {}", response.status);
```

**Notes:**
- Messages are stored until epoch eviction
- Sender field is optional and unauthenticated
- Encryption is client-side (server stores ciphertext only)
- The City-G GUI wraps the plaintext in an authenticated envelope before encryption:
  - `0..4`: ASCII `"CGM1"` prefix (protocol tag)
  - `4..12`: Little-endian `timestamp_ms` supplied by the sender (milliseconds since UNIX epoch)
  - `12..16`: Little-endian plaintext length, followed by the plaintext bytes
  - Next `4` bytes: length of the ML-DSA-65 message-signing public key (always 1,952)
  - Next `pub_key_len` bytes: ML-DSA-65 message-signing public key
  - Next `4` bytes: length of the ML-DSA-65 signature (always 3,293)
  - Remaining bytes: ML-DSA-65 signature over `leaf_id || timestamp_ms || plaintext`
- Recipients verify the envelope by recomputing the signature from the decrypted fields; modifying
  the timestamp or plaintext invalidates the proof independent of the server-side timestamp.

#### `POST /v1/messages`

Retrieves all messages for a specific epoch.

**Protobuf Request:** `FetchMessagesRequest`
```protobuf
message FetchMessagesRequest {
  bytes we_epoch_id = 1;
}
```

**Protobuf Response:** `FetchMessagesResponse`
```protobuf
message ChatMessage {
  bytes ciphertext = 1;
  bytes we_epoch_id = 2;
  bytes sender = 3;
  uint64 timestamp_ms = 4;
}

message FetchMessagesResponse {
  repeated ChatMessage messages = 1;
}
```

**Rust Client Example:**
```rust
let response = client.fetch_messages(&epoch_id).await?;

for msg in response.messages {
    println!(
        "Message for {}: {} bytes (sent: {} ms)",
        hex::encode(&msg.we_epoch_id),
        msg.ciphertext.len(),
        msg.timestamp_ms
    );

    // Decrypt using your epoch key
    let plaintext = decrypt_message(&msg.ciphertext, &epoch_key)?;
    println!("Content: {}", String::from_utf8_lossy(&plaintext));
}
```

---

### Window Management

#### `POST /v1/window`

Retrieves the current multi-head window state.

**Protobuf Request:** `GetWindowRequest`
```protobuf
message GetWindowRequest {
  // Empty
}
```

**Protobuf Response:** `GetWindowResponse`
```protobuf
message WindowHead {
  bytes we_epoch_id = 1;
  bytes msphf_hp_commit = 2;
  bytes seed_ctx_hash = 3;
  bytes rho_commit = 4;
  bytes seed_commit = 5;
  bytes xk_hash = 6;
  uint64 accept_seq = 7;
  uint64 age_ms = 8;
}

message WindowEntry {
  bytes wid = 1;
  repeated WindowHead heads = 2;
}

message GetWindowResponse {
  repeated WindowEntry entries = 1;
}
```

**Rust Client Example:**
```rust
let window = client.window().await?;

for entry in window.entries {
    println!("Window {:?} has {} heads", hex::encode(&entry.wid), entry.heads.len());
    for head in entry.heads {
        println!("    Head {} (age {} ms, seq {})",
            hex::encode(&head.we_epoch_id),
            head.age_ms,
            head.accept_seq,
        );
    }
}
```

**Window Parameters:**
- Call [`/v1/config/window`](#post-v1configwindow) to adjust `h_max` and `ttl_ms`; the window snapshot
  itself only exposes the currently active heads and their metadata.

#### `POST /v1/config/window`

Configures window parameters at runtime.

**Protobuf Request:** `ConfigureWindowRequest`
```protobuf
message ConfigureWindowRequest {
  optional uint32 h_max = 1;
  optional uint32 ttl_ms = 2;
}
```

**Protobuf Response:** `ConfigureWindowResponse`
```protobuf
message ConfigureWindowResponse {
  uint32 h_max = 1;
  uint32 ttl_ms = 2;
}
```

**Rust Client Example:**
```rust
// Increase concurrency to 100 heads
let response = client.configure_window(Some(100), None).await?;
println!("Window h_max updated to: {}", response.h_max);

// Set TTL to 10 minutes
let response = client.configure_window(None, Some(600_000)).await?;
println!("Window TTL updated to: {} ms", response.ttl_ms);
```

**Typical Values:**
- `h_max`: 10-1000 (depends on expected concurrency)
- `ttl_ms`: 120000 baseline (increase to 300000-3600000 only if clients routinely exceed 2 minutes of jitter)

---

### Telemetry

#### `POST /v1/telemetry`

Retrieves server metrics and statistics.

**Protobuf Request:** `GetTelemetryRequest`
```protobuf
message GetTelemetryRequest {
  // Empty
}
```

**Protobuf Response:** `GetTelemetryResponse`
```protobuf
message TelemetryEntry {
  bytes gid = 1;
  bytes parent_root = 2;
  uint64 head_attempts = 3;
  uint64 head_insertions = 4;
  uint64 freeze_window_full = 5;
  uint64 freeze_rho_replay = 6;
  uint64 last_active_heads = 7;
}

message FreezeStat {
  uint32 code = 1;
  string reason = 2;
  uint64 count = 3;
}

message GetTelemetryResponse {
  repeated TelemetryEntry entries = 1;
  repeated FreezeStat freeze_stats = 2;
}
```

**Rust Client Example:**
```rust
let telemetry = client.telemetry().await?;

println!("Telemetry entries:");
for entry in telemetry.entries {
    println!("GID {} parent {} -> {} insertions / {} attempts",
        hex::encode(&entry.gid),
        hex::encode(&entry.parent_root),
        entry.head_insertions,
        entry.head_attempts,
    );
}

println!("\nFreeze statistics:");
for stat in telemetry.freeze_stats {
    println!("Code {} ({}): {}", stat.code, stat.reason, stat.count);
}
```

**Use Cases:**
- Monitoring dashboards
- Performance analysis
- Debugging freeze issues
- Capacity planning

---

### Forward Secrecy

#### `POST /v1/pivot/refresh`

Refreshes the pivot for forward secrecy epoch rotation.

**Protobuf Request:** `RefreshPivotRequest`
```protobuf
message RefreshPivotRequest {
  bytes bundle_cbor = 1;  // CBOR-encoded ClientEpochBundle
}
```

**Protobuf Response:** `RefreshPivotResponse`
```protobuf
message RefreshPivotResponse {
  // Empty on success
}
```

**Rust Client Example:**
```rust
// Generate a fresh pivot bundle (implementation-specific)
let pivot_bundle = generate_pivot_refresh(&config)?;

client.refresh_pivot(&pivot_bundle).await?;
println!("Pivot refreshed for forward secrecy");
```

**Refresh Schedule:**

The default forward secrecy policy rotates pivots every hour:
- Automatic rotation based on `fs_epoch_base_ts`
- Manual refresh recommended if > 1 hour since last pivot
- See `docs/protocol/14-deployment-guide.md` for automation

---

## Error Handling

### Error Response Format

All API errors return JSON with this structure:

```json
{
  "message": "Human-readable error description",
  "freeze_code": 5,              // Optional: City-G freeze code
  "freeze_reason": "Parent root not found in window"  // Optional
}
```

### HTTP Status Codes

| Status | Meaning | Example |
|--------|---------|---------|
| `200 OK` | Request succeeded | Epoch accepted, roster returned |
| `400 Bad Request` | Invalid request | Malformed protobuf, missing fields |
| `404 Not Found` | Resource not found | Bundle not found, unknown group |
| `500 Internal Server Error` | Freeze or server error | Epoch frozen (see `freeze_code`), server panic |
| `503 Service Unavailable` | Server not ready | Startup, shutdown, maintenance |

### Rust Error Handling

The `cityg_api_client::Error` enum provides structured error handling:

```rust
use cityg_api_client::{CitygApiClient, Error};

match client.accept_epoch_bundle(&bundle).await {
    Ok(response) => {
        println!("Epoch accepted: {}", hex::encode(response.we_epoch_id));
    }
    Err(Error::Http(e)) => eprintln!("Network error: {}", e),
    Err(Error::HttpStatus { status, message, freeze_code, .. }) => {
        eprintln!("HTTP {}: {}", status, message);
        if let Some(code) = freeze_code {
            eprintln!("Freeze code: {}", code);
        }
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

---

## Freeze Codes

Freeze codes indicate why an epoch was rejected during validation.

| Code | Reason | Description | Action |
|------|--------|-------------|--------|
| **1** | Generic error | Unspecified validation failure | Check server logs |
| **2** | Witness validation failed | Merkle proof is invalid | Verify witness generation |
| **3** | SPHF verification failed | Cryptographic proof rejected | Check proof parameters |
| **4** | Invalid delta roots | Delta commitment mismatch | Regenerate epoch bundle |
| **5** | Parent not in window | Parent root not found | Wait for parent or use merge ticket |
| **6** | VRF verification failed | VRF proof invalid | Check VRF configuration |
| **7** | Duplicate epoch ID | Epoch already exists | Generate new epoch (don't replay) |
| **8** | Invalid proof mode | Unsupported proof system | Use "smallwood" proof mode |
| **9** | Revocation conflict | Member was revoked | Member cannot create epochs |
| **10** | TTL expired | Epoch too old | Submit within TTL window |
| **11** | Window full | h_max exceeded | Wait for eviction or increase h_max |
| **12** | Policy version mismatch | Incompatible protocol | Upgrade client to match server |

### Complete Reference

See [`docs/protocol/12-error-reference.md`](./protocol/12-error-reference.md) for:
- Full freeze code catalog
- Resolution strategies
- Common error patterns
- Debugging guides

---

## WebSocket API

### `GET /v1/ws` (WebSocket Upgrade)

Establishes a WebSocket connection for real-time roster/message notifications.

**Required Query Parameters:**
- `gid` - 32-byte group identifier encoded as lowercase hex
- `leaf_id` - 32-byte member leaf identifier encoded as lowercase hex

**Authentication:**
- New clients MUST send the room/message auth token in the `x-cityg-message-token` header.
- WebSocket upgrades without the header are rejected. Query-string token compatibility has been
  removed.

**Upgrade Request:**
```http
GET /v1/ws?gid=<gid-hex>&leaf_id=<leaf-id-hex> HTTP/1.1
Host: localhost:8080
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
x-cityg-message-token: <message-auth-token>
```

**Notification Types (JSON):**
- **Message**
  ```json
  {
    "type": "message",
    "we_epoch_id": "a3b5c7d9...",
    "timestamp_ms": 1672531200000,
    "connection_healthy": true
  }
  ```
- **Membership**
  ```json
  {
    "type": "membership",
    "gid": "98b7c0...",
    "leaf_id": "f0ab12...",
    "event": "join",          // or "revoke"
    "timestamp_ms": 1672531200000
  }
  ```
- **Lag**
  ```json
  {
    "type": "lag",
    "lagged_messages": 42,
    "recommendation": "consider reconnecting"
  }
  ```

Clients should trigger an immediate roster refresh (including any active `/v1/members/search`
filters) whenever they receive a `membership` event for the room they are viewing. This keeps the GUI
in sync without waiting for the periodic polling loop.

**Rust WebSocket Example:**
```rust
use futures_util::StreamExt;
use http::Request;
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let request = Request::builder()
        .uri("ws://localhost:8080/v1/ws?gid=<gid-hex>&leaf_id=<leaf-id-hex>")
        .header("x-cityg-message-token", "<message-auth-token>")
        .body(())?;

    let (ws_stream, _) = connect_async(request).await?;

    let (_, mut read) = ws_stream.split();

    while let Some(msg) = read.next().await {
        let msg = msg?;
        if let Message::Text(text) = msg {
            let notification: serde_json::Value = serde_json::from_str(&text)?;
            println!(
                "New epoch {:?} at {}",
                notification["we_epoch_id"],
                notification["timestamp_ms"]
            );
        }
    }

    Ok(())
}
```

**Notes:**
- WebSocket notifications are best-effort (no delivery guarantee)
- Buffer capacity equals `CITYG_SERVER_WEBSOCKET_CAPACITY` (default 1000)
- Idle connections are kept alive with ping/pong; the server emits `lag` notices if the client falls
  behind

---

## Examples

### Complete Workflow: Join and Message

```rust
use cityg_api_client::{
    CitygApiClient, IdentityBinding, RoomAdminOperation, build_room_admin_proof,
    generate_room_admin_keypair,
};
use cityg_client::{CityGClient, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = CitygApiClient::new("http://localhost:8080");

    // 1. Check server health
    client.health().await?;

    // 2. Bootstrap room (first member only)
    let (admin_public_key, admin_secret_key) = generate_room_admin_keypair();
    let kbroad_public = generate_broadcast_key();
    let admin_proof = build_room_admin_proof(
        RoomAdminOperation::Bootstrap,
        "demo-room",
        &kbroad_public,
        &admin_public_key,
        &admin_secret_key,
    )?;
    client
        .bootstrap_room_as_admin("demo-room", &kbroad_public, admin_proof)
        .await?;

    // 3. Request join ticket with identity binding
    let identity = IdentityBinding {
        alias: "alice".to_string(),
        pop_public_key: my_dilithium_pubkey.to_vec(),
        signature: my_dilithium_signature.clone(),
    };

    let join_ticket = client.join_ticket(
        "demo-room",
        "alice",
        Some(identity)
    ).await?;

    // 4. Generate first epoch using join ticket
    let config = ClientConfig::from_join_ticket(&join_ticket)?;
    let cityg_client = CityGClient::new(config);
    let epoch_bundle = cityg_client.generate_epoch(/* ... */)?;

    // 5. Submit epoch to server
    let accept_response = client.accept_epoch_bundle(&epoch_bundle).await?;

    if !accept_response.accepted {
        eprintln!("Epoch frozen: {}", accept_response.freeze_reason.unwrap_or_default());
        return Ok(());
    }

    let epoch_id = &accept_response.we_epoch_id;
    println!("Joined successfully! Epoch: {}", hex::encode(epoch_id));

    // 6. Send encrypted message
    let message = b"Hello, City-G!";
    let ciphertext = encrypt_with_witness(&epoch_bundle, message)?;

    let send_response = client.send_message(
        epoch_id,
        &ciphertext,
        Some(b"alice")
    ).await?;

    println!("Message status: {}", send_response.status);

    // 7. Fetch messages
    let messages = client.fetch_messages(epoch_id).await?;

    for msg in messages.messages {
        let plaintext = decrypt_with_witness(&epoch_bundle, &msg.ciphertext)?;
        println!("Received: {}", String::from_utf8_lossy(&plaintext));
    }

    Ok(())
}
```

### Monitoring Dashboard

```rust
use cityg_api_client::CitygApiClient;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = CitygApiClient::new("http://localhost:8080");

    loop {
        // Fetch telemetry
        let telemetry = client.telemetry().await?;

        // Fetch window state
        let window = client.window().await?;

        println!("\n=== City-G Server Status ===");
        println!("Uptime: {}s", telemetry.uptime_ms / 1000);
        println!("Total epochs: {}", telemetry.total_epochs);
        println!("Acceptance rate: {:.1}%",
            100.0 * telemetry.accepted_epochs as f64 / telemetry.total_epochs as f64
        );

        println!("\nWindow status:");
        println!("  Current heads: {} / {}", window.heads.len(), window.h_max);
        println!("  Utilization: {:.1}%",
            100.0 * window.heads.len() as f64 / window.h_max as f64
        );

        println!("\nTop freeze codes:");
        let mut freeze_codes: Vec<_> = telemetry.freeze_by_code.iter().collect();
        freeze_codes.sort_by_key(|(_, count)| std::cmp::Reverse(**count));

        for (code, count) in freeze_codes.iter().take(5) {
            println!("  Code {}: {} occurrences", code, count);
        }

        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
```

---

## Protocol Buffer Definitions

The complete protobuf schema is available at:
[`crates/cityg-api/proto/cityg.proto`](../crates/cityg-api/proto/cityg.proto)

To generate bindings for other languages:

```bash
# Install protoc
# Install language-specific plugins

# Generate Python bindings
protoc --python_out=. crates/cityg-api/proto/cityg.proto

# Generate Go bindings
protoc --go_out=. crates/cityg-api/proto/cityg.proto

# Generate JavaScript bindings
protoc --js_out=import_style=commonjs,binary:. crates/cityg-api/proto/cityg.proto
```

---

## Rate Limits

**Current Status:** No rate limits enforced.

**Recommended for Production:**
- Epoch acceptance: 10 requests/second per IP
- Member roster: 100 requests/second per IP
- Messaging: 100 messages/second per epoch
- WebSocket connections: 1000 per server

Implement rate limiting at the reverse proxy level (nginx, Envoy, etc.).

---

## Deployment Considerations

### Production Checklist

- [ ] Enable TLS (HTTPS)
- [ ] Configure reverse proxy (nginx, Caddy)
- [ ] Set up monitoring (Prometheus, Grafana)
- [ ] Configure window parameters (h_max, ttl_ms)
- [ ] Implement backup strategy for server state
- [ ] Set up log aggregation
- [ ] Configure forward secrecy automation
- [ ] Disable debug endpoints (`debug-api` feature)

See [`docs/protocol/14-deployment-guide.md`](./protocol/14-deployment-guide.md) for complete deployment guide.

---

## See Also

- [City-G Protocol Documentation](./protocol/00-README.md)
- [Rust Client Library (`cityg-api-client`)](../crates/cityg-api-client/src/lib.rs)
- [Server Implementation (`cityg-api`)](../crates/cityg-api/src/lib.rs)
- [Error Reference](./protocol/12-error-reference.md)
- [Deployment Guide](./protocol/14-deployment-guide.md)
- [FAQ](./protocol/17-faq.md)

---

**Last Updated:** 2025-11-06
**API Version:** 1.0
**Protocol Version:** v1
