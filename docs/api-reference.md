# Delivery-service API reference (profile v0.2)

This is the HTTP interface of the City-G delivery service (DS), served by
the native server [`cityg-api`](../crates/cityg-api) and by the Cloudflare
Worker [`cityg-worker`](../crates/cityg-worker). The normative rules are in
[`specs.md`](specs.md), sections 12 and 14; the wire schema is
[`crates/cityg-proto/proto/cityg_v2.proto`](../crates/cityg-proto/proto/cityg_v2.proto).
Rust clients use [`cityg-api-client`](../crates/cityg-api-client)
(`DsClient` for single requests, `Member` for a complete member).

## Conventions

* Every route is an HTTP `POST` of a protobuf message (package `cityg.v2`)
  with `Content-Type: application/x-protobuf`. Responses are protobuf too.
* Field 1 of every request is `gid`, the 32-byte group identifier. The DS
  routes a request to its group by that field alone.
* Protocol objects (commits, GroupInfo, proposals, invites, envelopes,
  reports, bindings) travel as their exact deterministic-CBOR bytes. The DS
  verifies them with `cityg-core`, stores them and relays them unchanged.
* Request bodies are at most 16 MiB (`MAX_REQUEST_BYTES`); each object also
  has its own size bound (specs.md, section 15).
* Routes marked *token* need `Authorization: Bearer <token hex>`, a member
  session token (see [Sessions](#sessions)). The other routes authenticate
  through the signature of the object they carry, or are public reads.

## Routes

| Route | Request | Response | Token |
| --- | --- | --- | --- |
| `/v2/groups/create` | `CreateGroupRequest {gid, commit, group_info}` | `CreateGroupResponse {epoch, seq}` | |
| `/v2/groups/info` | `GroupInfoRequest {gid}` | `GroupInfoResponse {epoch, group_info, tree, roster, pending_removals, head_seq, vacant}` | |
| `/v2/groups/commit` | `PublishCommitRequest {gid, commit, group_info}` | `PublishCommitResponse {epoch, seq}` | |
| `/v2/groups/log` | `FetchLogRequest {gid, after_seq, limit}` | `FetchLogResponse {entries, head_seq, first_seq}` | token |
| `/v2/groups/remove_proposal` | `SubmitRemoveProposalRequest {gid, proposal}` | `SubmitRemoveProposalResponse {status, vacant}` | |
| `/v2/groups/invite` | `PublishInviteRequest {gid, invite}` | `PublishInviteResponse {invite_id}` | |
| `/v2/groups/invite/get` | `GetInviteRequest {gid, invite_id}` | `GetInviteResponse {invite}` | |
| `/v2/groups/send` | `SendMessageRequest {gid, envelope}` | `SendMessageResponse {epoch, seq}` | token |
| `/v2/groups/cover_failure` | `CoverFailureRequest {gid, report}` | `CoverFailureResponse {recorded}` | |
| `/v2/groups/cover_failures` | `CoverFailuresRequest {gid}` | `CoverFailuresResponse {reports}` | token |
| `/v2/groups/session` | `OpenSessionRequest {gid, auth}` | `OpenSessionResponse {token, expires_at_ms}` | |
| `/v2/groups/alias` | `BindAliasRequest {gid, binding}` | `BindAliasResponse {count}` | |
| `/v2/groups/aliases` | `AliasesRequest {gid}` | `AliasesResponse {bindings}` | token |
| `GET /v2/ws?gid=<hex>&token=<hex>` | WebSocket upgrade | log-head notices | token (query) |

### Creating a group: `/v2/groups/create`

Publishes the genesis commit (epoch 0) and its GroupInfo, both built by the
creator (`GroupSession::create`). The DS verifies the genesis (the `gid`
binds the creator's device key and nonce, specs.md section 9.3) and that the
GroupInfo is signed by the creator and describes epoch 0. `409` if the group
exists, `413` if `n_max` exceeds the configured `max_group_size`.

### Public state: `/v2/groups/info`

What a joiner or a resyncing member needs: the GroupInfo of the current
epoch, the public tree and roster (deterministic CBOR), the recorded removal
proposals that the next commit must include, the log head, and `vacant`
(every member has a recorded removal; the next joiner commits them). The
joiner checks the GroupInfo signature and that the tree and roster hash to
the values of its GroupContext (specs.md, section 10.3).

### Commits: `/v2/groups/commit`

Publishes the commit of epoch `n + 1` with the GroupInfo its author signed.
The DS verifies the commit against the public state of epoch `n`
(registry, signature, transcript, removals, admin changes, admission, update
path, tree and roster hashes; specs.md section 9) and accepts the first
valid commit of each epoch.

| Status | Meaning | Client action |
| --- | --- | --- |
| `409` epoch mismatch | Another commit won the epoch. | Sync, rebuild on the new epoch. |
| `409` pending removals | The commit omits a recorded removal proposal. | Fetch `/v2/groups/info`, include `pending_removals`. |
| `403` | The author is not allowed (not a member, not an admin for admin changes, removing itself). | Do not retry. |
| `422` | The commit or its GroupInfo fails verification. | Bug or forgery: do not retry. |

### Log: `/v2/groups/log`

Returns up to `limit` entries (default 256, at most 1024) with
`seq > after_seq`, in order. Each `LogEntry` has `seq`, `epoch`,
`accepted_at_ms` and one body:

* `commit {commit, group_info}`: an accepted commit;
* `envelope`: a message envelope (message plane v3);
* `proposal`: a recorded removal proposal.

`head_seq` is the last entry of the log and `first_seq` the oldest one still
retained. Messages expire first, then old commits; the latest commit always
stays (specs.md section 12.2). A member that meets a commit of a later epoch
than the next one it needs has lost a commit and resyncs.

### Removal proposals: `/v2/groups/remove_proposal`

Records a `SignedRemoveProposal` signed by its target (a leave) or by an
admin, authorized against the current roster. `status` is `recorded` or
`already_recorded`. From then on, the next commit must include it, and the
DS refuses messages from the target. A member never commits its own removal;
another member does (specs.md section 10.1).

### Invites: `/v2/groups/invite`, `/v2/groups/invite/get`

An admin publishes a `SignedInvite`; the DS stores it by `invite_id =
H_L("invite-id", [invite_pk])` (at most 256 per group) until it expires.
A joiner holding the invite seed derives `invite_pk`, fetches the invite by
identifier, signs its own admission with the invite key and publishes an
ExternalJoin commit. `404` for an unknown or expired invite.

### Messages: `/v2/groups/send`

Relays an envelope of the session's member. The DS checks that the
envelope's sender is the session member, that the sender is a member of the
current roster and of the envelope's epoch without a recorded removal, that
the epoch is the current one (or the previous one during the 10-minute
grace window), and that `(epoch, sender, generation)` is new. It cannot read
the ciphertext. `403` for a sender that is not a member or has a recorded
removal, `409` for a replay, `422` for an epoch that is no longer active.

### Cover failures: `/v2/groups/cover_failure`, `/v2/groups/cover_failures`

A member that cannot process a commit signs a `CoverFailureReport` naming the
epoch and the reason (not covered, path key mismatch, confirmation tag
mismatch, state lost). The DS records reports of current members for the
current epoch (at most 256), where every member can read them.

### Sessions

`/v2/groups/session` exchanges a `SessionAuth` — `["city-g/session-auth/v1",
gid, device_pk, issued_at_ms]` signed by a current member's device key under
the context `city-g/session-auth/v1` — for a 32-byte bearer token. The DS
answers `422` to an auth for another group or whose timestamp is more than
`auth_skew_secs` (default 300 s) away from its clock, and `403` if the
signer is not a member. The token expires after `session_ttl_secs` (default
1 h); once a commit removes its member, requests with it get `403`, from
which the member driver learns its removal.

### Aliases: `/v2/groups/alias`, `/v2/groups/aliases`

A member publishes an `AliasBinding` — `["city-g/alias/v1", gid, device_pk,
alias]` signed by its device key — naming itself. Aliases are 1 to 64 bytes
of UTF-8 without control characters or surrounding whitespace, and are
self-asserted: clients pin the device key first seen for an alias and warn
when it changes. `/v2/groups/aliases` returns the bindings of current
members; removed members lose theirs.

### Notifications: `/v2/ws`

`GET /v2/ws?gid=<hex>&token=<hex>` upgrades to a WebSocket after checking the
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
| 403 | `forbidden` | Not a member (including the token of a removed member), sender with a recorded removal, envelope of another member, admin action by a non-admin, join by a retired device. |
| 404 | `not_found` | Unknown group or invite; unknown route. |
| 409 | `conflict` | Stale epoch, recorded removals not committed, replayed message, existing group. |
| 410 | `gone` | A route of the removed v0.1.4 API (`/v1/*`, `/v2/barrier/*`; Worker). |
| 413 | `payload_too_large` | Body over 16 MiB, object over its bound, `n_max` over `max_group_size`, too many invites or reports. |
| 422 | `unprocessable` | A protocol object fails verification (signature, transition, hashes), a stale SessionAuth, a message for an inactive epoch, an expired invite. |
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

## Example: a member with the Rust driver

```rust
use cityg_api_client::{DsClient, InviteLink, Member};
use cityg_api_client::cityg_core::identity::DeviceIdentity;

# async fn demo() -> Result<(), cityg_api_client::ClientError> {
let server = "http://127.0.0.1:8080";
// Alice creates a group of up to 64 members and invites Bob.
let mut alice = Member::create(DsClient::new(server)?, DeviceIdentity::generate(&mut rand_core::OsRng), 64).await?;
let link = alice.create_invite_link(server, 24 * 3_600_000).await?;

// Bob joins with the link (an ExternalJoin commit); nobody needs to be online.
let link = InviteLink::parse(&link.encode())?.expect("a City-G invite link");
let mut bob = Member::join_with_invite(DsClient::new(server)?, DeviceIdentity::generate(&mut rand_core::OsRng), &link).await?;

alice.sync().await?;
alice.send_text("hello").await?;
let report = bob.sync().await?;
assert_eq!(report.messages[0].plaintext, b"hello");
# Ok(()) }
```
