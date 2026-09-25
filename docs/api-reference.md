# Delivery-service API reference (profile v0.3)

This is the HTTP interface of the City-G delivery service (DS), served by
the native server [`cityg-api`](../crates/cityg-api) and by the Cloudflare
Worker [`cityg-worker`](../crates/cityg-worker). The normative rules are in
[`specs.md`](specs.md), sections 12, 14 and 15; the wire schema is
[`crates/cityg-proto/proto/cityg_v3.proto`](../crates/cityg-proto/proto/cityg_v3.proto).
Rust clients use [`cityg-api-client`](../crates/cityg-api-client)
(`DsClient` for single requests, `Member` for a full member, `LightMember`
for a light one).

## Conventions

* Every route is an HTTP `POST` of a protobuf message (package `cityg.v3`)
  with `Content-Type: application/x-protobuf`. Responses are protobuf too.
* Field 1 of every request is `gid`, the 32-byte group identifier. The DS
  routes a request to its group by that field alone.
* Protocol objects (commits, GroupInfo, welcomes, proposals, join requests,
  invites and revocations, envelopes, reports, bindings, leaf proofs and
  light-member data) travel as their exact deterministic-CBOR bytes. The DS
  verifies them with `cityg-core`, stores them and relays them unchanged.
* Request bodies are at most 16 MiB (`MAX_REQUEST_BYTES`); each object also
  has its own size bound (specs.md, section 16).
* Routes marked *token* need `Authorization: Bearer <token hex>`, a member
  session token (see [Sessions](#sessions)). The other routes authenticate
  through the signature of the object they carry, or are public reads.

## Routes

| Route | Request | Response | Token |
| --- | --- | --- | --- |
| `/v3/groups/create` | `CreateGroupRequest {gid, commit, group_info}` | `CreateGroupResponse {epoch, seq}` | |
| `/v3/groups/info` | `GroupInfoRequest {gid}` | `GroupInfoResponse {epoch, group_info, tree, registry, pending_removals, pending_joins, head_seq}` | |
| `/v3/groups/commit` | `PublishCommitRequest {gid, commit, group_info, welcomes}` | `PublishCommitResponse {epoch, seq}` | |
| `/v3/groups/log` | `FetchLogRequest {gid, after_seq, limit, light}` | `FetchLogResponse {entries, head_seq, first_seq}` | token |
| `/v3/groups/remove_proposal` | `SubmitRemoveProposalRequest {gid, proposal}` | `SubmitRemoveProposalResponse {status}` | |
| `/v3/groups/join_request` | `SubmitJoinRequestRequest {gid, request}` | `SubmitJoinRequestResponse {request_ref, status}` | |
| `/v3/groups/join_status` | `JoinStatusRequest {gid, request_ref, light}` | `JoinStatusResponse {status, epoch, welcome, commit, current_epoch, light_join}` | |
| `/v3/groups/leaf_proofs` | `LeafProofsRequest {gid, leaves}` | `LeafProofsResponse {epoch, proofs}` | |
| `/v3/groups/invite` | `PublishInviteRequest {gid, invite}` | `PublishInviteResponse {invite_id}` | |
| `/v3/groups/invite/get` | `GetInviteRequest {gid, invite_id}` | `GetInviteResponse {invite}` | |
| `/v3/groups/invite/revoke` | `RevokeInviteRequest {gid, revocation}` | `RevokeInviteResponse {dropped}` | |
| `/v3/groups/send` | `SendMessageRequest {gid, envelope}` | `SendMessageResponse {epoch, seq}` | token |
| `/v3/groups/cover_failure` | `CoverFailureRequest {gid, report}` | `CoverFailureResponse {recorded}` | |
| `/v3/groups/cover_failures` | `CoverFailuresRequest {gid}` | `CoverFailuresResponse {reports}` | token |
| `/v3/groups/session` | `OpenSessionRequest {gid, auth}` | `OpenSessionResponse {token, expires_at_ms}` | |
| `/v3/groups/alias` | `BindAliasRequest {gid, binding}` | `BindAliasResponse {count}` | |
| `/v3/groups/aliases` | `AliasesRequest {gid}` | `AliasesResponse {bindings}` | token |
| `GET /v3/ws?gid=<hex>&token=<hex>` | WebSocket upgrade | log-head notices | token (query) |

### Creating a group: `/v3/groups/create`

Publishes the genesis commit (epoch 0) and its GroupInfo, both built by the
creator (`GroupSession::create`). The DS verifies the genesis (the `gid`
binds the creator's device key and nonce, specs.md section 9.3) and that the
GroupInfo is signed by the creator and describes epoch 0. `409` if the group
exists, `413` if the capacity exceeds the configured `max_group_size`.

### Public state: `/v3/groups/info`

What a joiner, a resyncing member or a committer needs: the GroupInfo of the
current epoch, the public tree and registry (deterministic CBOR), the
recorded removal proposals and join requests in recording order, and the
log head. A joiner checks the GroupInfo signature and that the tree and
registry hash to the values of its GroupContext (specs.md, section 10.4). A
committer includes the overdue proposals (below).

### Commits: `/v3/groups/commit`

Publishes the commit of epoch `n + 1` with the GroupInfo its author signed
and one welcome per join request it includes, in order. The DS verifies the
commit against the public state of epoch `n` (key registry, signatures,
transcript, removals, admin changes, admissions, entries, rotation, update
path, tree and registry hashes; specs.md section 9), checks the welcomes
against the requests, and accepts the first valid commit of each epoch.

A commit must include every *overdue* removal proposal (recorded before the
current epoch started; the oldest 256 when more wait) and the oldest overdue
join requests, up to 64. Proposals recorded during the current epoch may
wait for the next commit.

| Status | Meaning | Client action |
| --- | --- | --- |
| `409` epoch mismatch | Another commit won the epoch. | Sync, rebuild on the new epoch. |
| `409` overdue proposals | The commit omits an overdue removal or join request. | Fetch `/v3/groups/info`, include them. |
| `403` | The author is not allowed (not a member, not an admin for admin changes, removing itself, an admission of a removed member). | Do not retry. |
| `413` | Too many removals or joins, or the group is full. | Split the commit, or wait for room. |
| `422` | The commit, a welcome or the GroupInfo fails verification. | Bug or forgery: do not retry. |

### Log: `/v3/groups/log`

Returns up to `limit` entries (default 256, at most 1024) with
`seq > after_seq`, in order. Each `LogEntry` has `seq`, `epoch`,
`accepted_at_ms` and one body:

* `commit {commit, group_info, light}`: an accepted commit; `light` holds its
  LightCommit (specs.md section 14.3) when the request sets `light`, and is
  empty otherwise;
* `envelope`: a message envelope (message plane v4);
* `proposal`: a recorded removal proposal;
* `join_request`: a recorded join request.

`head_seq` is the last entry of the log and `first_seq` the oldest one still
retained. Messages expire first, then old commits; the latest commit always
stays (specs.md section 12.2). A member that meets a commit of a later epoch
than the next one it needs has lost a commit and resyncs.

### Removal proposals: `/v3/groups/remove_proposal`

Records a `SignedRemoveProposal` for an occupancy `[target_leaf,
target_since]`, signed by its target (a leave) or by an admin and authorized
against the current epoch. `status` is `recorded` or `already_recorded`.
From then on, the DS refuses messages from the target, and a commit by
another member (or a joiner) includes the proposal. A member never commits
its own removal (specs.md section 10.1).

### Joins: `/v3/groups/join_request`, `/v3/groups/join_status`

A joiner records its `SignedJoinRequest` (device key, leaf key, one-time
init key, admission). The DS records it if it is authorized for the next
epoch, the device has no other pending request, the group has room for it,
and its invite (if any) is valid; it answers `request_ref`, the name of the
request, and `recorded` or `already_recorded`. `409` if another request of
the same device is pending, `413` if the group is full.

`/v3/groups/join_status` tells where a request stands: `pending`,
`committed` (with the epoch of the commit that included it, the joiner's
welcome, and that commit while the log still holds it) or `unknown`, and the
group's current epoch. With `light` set and while the commit's epoch is
still the current one, it also returns the LightJoin (registry, occupancies
and the joiner's leaf proof; specs.md section 14.4). Welcomes are kept for
the last 4096 requests of a group.

The reference driver records its request, polls its status for 1 to 2
seconds, enters with its welcome if a commit included it, and otherwise
commits its own entry with an ExternalJoin that brings the other waiting
requests (specs.md section 13.1).

### Leaf proofs: `/v3/groups/leaf_proofs`

Returns, for up to 64 leaves, their Merkle proofs against the current tree
hash, with the epoch of that tree. Light members use them to learn the
device key of a message's sender (specs.md sections 6.7, 14.5). `413` for
more than 64 leaves, `422` for a leaf outside the tree.

### Invites: `/v3/groups/invite`, `/v3/groups/invite/get`, `/v3/groups/invite/revoke`

An admin publishes a `SignedInvite` naming an expiry and a number of uses;
the DS stores it by `invite_id = H_L("invite-id", [invite_pk])` (at most 256
per group). A joiner holding the invite seed derives `invite_pk`, fetches
the invite by identifier and signs its own admission with the invite key.
The DS counts a use when it records a join request that relies on the
invite, or accepts an ExternalJoin that was not recorded as a request, and
refuses the invite once it expired (`422`), was revoked or has no use left
(`403`). `404` for an unknown invite.

An admin revokes an invite with a `SignedInviteRevocation`; the DS remembers
the last 1024 revocations and drops the pending join requests that rely on
the invite, whose references it returns.

### Messages: `/v3/groups/send`

Relays an envelope of the session's member. The DS checks that the
envelope's sender occupancy is the session member, that it is a member of
the current epoch and of the envelope's epoch without a recorded removal,
that the epoch is the current one or one of the four previous ones within
10 minutes after it ended, and that `(epoch, sender, generation)` is new. It
cannot read the ciphertext. `403` for a sender that is not a member or has a
recorded removal, `409` for a replay, `422` for an epoch that is no longer
active.

### Cover failures: `/v3/groups/cover_failure`, `/v3/groups/cover_failures`

A member that cannot process a commit signs a `CoverFailureReport` naming the
epoch and the reason (not covered, path key mismatch, confirmation tag
mismatch, state lost). The DS records reports of current members for the
current epoch (at most 256), where every member can read them.

### Sessions

`/v3/groups/session` exchanges a `SessionAuth` — `["city-g/session-auth/v1",
gid, device_pk, issued_at_ms]` signed by a current member's device key under
the context `city-g/session-auth/v1` — for a 32-byte bearer token. The DS
answers `422` to an auth for another group or whose timestamp is more than
`auth_skew_secs` (default 300 s) away from its clock, and `403` if the
signer is not a member. The token expires after `session_ttl_secs` (default
1 h); once a commit removes its member or rotates its key, requests with it
get `403`, from which the member driver learns its removal (or opens a new
session with its new key).

### Aliases: `/v3/groups/alias`, `/v3/groups/aliases`

A member publishes an `AliasBinding` — `["city-g/alias/v1", gid, device_pk,
alias]` signed by its device key — naming itself. Aliases are 1 to 64 bytes
of UTF-8 without control characters or surrounding whitespace, and are
self-asserted: clients pin the occupancy first seen for an alias and warn
when another claims it. `/v3/groups/aliases` returns the bindings of current
members; removed members lose theirs.

### Notifications: `/v3/ws`

`GET /v3/ws?gid=<hex>&token=<hex>` upgrades to a WebSocket after checking the
session token. The DS sends JSON text frames:

```json
{"type":"head","gid":"<hex>","head_seq":42}
{"type":"resync","gid":"<hex>"}
```

`head` is sent on connection and whenever the log grows; `resync` when
notices were dropped. Either way the client fetches the log. The DS pings
every 30 seconds; the Worker answers a text `ping` with `pong`.

## Errors

A non-2xx response carries a protobuf `ErrorResponse {code, message}`.

| Status | `code` | Typical causes |
| --- | --- | --- |
| 400 | `bad_request` | Malformed protobuf, `gid` not 32 bytes, non-deterministic CBOR, request `gid` differing from the object's. |
| 401 | `unauthorized` | Missing, unknown or expired session token, or a token of another group. |
| 403 | `forbidden` | Not a member (including the token of a removed member or of a rotated key), sender with a recorded removal, envelope of another member, admin action by a non-admin, admission of a removed member, revoked or used-up invite. |
| 404 | `not_found` | Unknown group or invite; unknown route. |
| 409 | `conflict` | Stale epoch, overdue proposals not committed, a pending request of the same device, replayed message, existing group. |
| 410 | `gone` | A route of a removed API version (`/v1/*`, `/v2/*`). |
| 413 | `payload_too_large` | Body over 16 MiB, object over its bound, capacity over `max_group_size`, a full group, too many removals, joins, invites, reports or leaf proofs. |
| 422 | `unprocessable` | A protocol object fails verification (signature, transition, hashes, welcome), a stale SessionAuth, a message for an inactive epoch, an expired invite, a leaf outside the tree. |
| 429 | `too_many_requests` | Reserved: the reference DS does not rate-limit; a deployment may, in front of it. |
| 500 | `internal` | Storage failure; the group is reloaded from its journal. |

## Operational endpoints

| Path | Server | Content |
| --- | --- | --- |
| `GET /health`, `/health/detailed` | native, Worker | JSON `{status, timestamp, version, uptime_seconds, checks}` |
| `GET /health/live`, `/health/ready` | native, Worker | liveness and readiness probes |
| `GET /healthz` | Worker | liveness |
| `GET /metrics` | native | Prometheus metrics (see [OBSERVABILITY.md](OBSERVABILITY.md)) |
| `GET /__cloudflare/policy` | Worker | JSON manifest of the routes the Worker serves |

## Example: members with the Rust drivers

```rust
use cityg_api_client::{DsClient, InviteLink, LightMember, Member};
use cityg_api_client::cityg_core::identity::DeviceIdentity;

# async fn demo() -> Result<(), cityg_api_client::ClientError> {
let server = "http://127.0.0.1:8080";
let new_device = || DeviceIdentity::generate(&mut rand_core::OsRng);
// Alice creates a group of up to 64 members and invites up to 10 devices
// for a day.
let mut alice = Member::create(DsClient::new(server)?, new_device(), 64).await?;
let link = alice.create_invite_link(server, 24 * 3_600_000, 10).await?;
let link = InviteLink::parse(&link.encode())?.expect("a City-G invite link");

// Bob joins: he records a join request and, if nobody commits it within a
// second or two, commits his own entry. Carol joins as a light member.
let mut bob = Member::join_with_invite(DsClient::new(server)?, new_device(), &link).await?;
let mut carol = LightMember::join_with_invite(DsClient::new(server)?, new_device(), &link).await?;

alice.sync().await?;
alice.send_text("hello").await?;
let report = bob.sync().await?;
assert!(report.messages.iter().any(|message| message.plaintext == b"hello"));
carol.sync().await?;
# Ok(()) }
```
