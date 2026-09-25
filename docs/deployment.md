# Deployment

The delivery service (DS) of profile v0.3 comes in two transports that run
the same request handlers ([`cityg-runtime`](../crates/cityg-runtime)):

* **`cityg-api`**: a native HTTP server (axum) that keeps rooms in memory or
  journals them on disk;
* **`cityg-worker`**: a Cloudflare Worker where each room is a Durable Object
  backed by SQLite ([`crates/cityg-worker/README.md`](../crates/cityg-worker/README.md)).

Either way the DS orders commits, relays envelopes and enforces the rules
that need a clock or a global order (specs.md, section 12). It holds no
group secret: a compromised DS can deny service, drop or delay traffic, and
see metadata (who is in which group, who sends when, message sizes,
aliases), but it cannot read messages, add a member, or impersonate one.

## One writer per room

A room's commits are ordered by the one process that journals the room.
Two processes must never serve the same room at the same time:

* **Native, single instance.** One `cityg-api` per `state_path`. This
  covers most deployments: a room costs its public state (about 4 KB per
  member for the tree), the replay windows of the recent epochs, the
  pending join requests and welcomes, and its log.
* **Native, sharded.** Several instances, each with its own `state_path`,
  behind a router that sends every request of a room to the same instance.
  The routing key is the `gid`: field 1 of every protobuf request body, and
  the `gid` query parameter of `/v3/ws`.
* **Blue/green hand-off.** Stop the old instance, then start the new one on
  the same `state_path`: it replays each room's snapshot and journal.
  Clients resume from their log position and open new sessions
  ([`config/ha-bluegreen.toml`](../config/ha-bluegreen.toml)).
* **Cloudflare Worker.** The platform guarantees one Durable Object per
  name, hence one writer per room, and scales rooms independently.

## Storage

With `state_path` set, each room has a snapshot and a journal of records
(accepted commits with their welcomes, messages, proposals, join requests,
invites and revocations, aliases, reports). Light-member data (the
LightCommit of each commit) is recomputed at replay. A
record is written before the request is answered; a request whose record
cannot be written fails with `500` and the room is reloaded from disk on its
next request, so no acknowledged change is lost. Every `compact_every`
records the room is snapshotted and its journal truncated. A torn final
record (a crash during a write) is ignored at replay.

* Put `state_path` on local SSD storage and back it up: a lost journal loses
  the room's order of commits, and members of a lost room must create a new
  one.
* The journal holds only public protocol objects (ciphertexts, signed
  objects, public keys), but they are still metadata worth protecting.

Without `state_path`, rooms live in memory and a restart loses them.

## Network

* Terminate TLS in front of the DS. Protocol objects are signed and
  messages encrypted end to end, but session tokens are bearer secrets and
  invite links carry invite seeds.
* Expose only the API port. `/metrics` and `/health/*` can be restricted to
  the monitoring network.
* The WebSocket endpoint (`/v3/ws`) needs a proxy that allows upgrades and
  long-lived connections; the native DS pings every 30 seconds.
* A proxy may rate-limit (answering `429`): the clients back off and retry.

## Capacity planning

* **Group size.** `max_group_size` caps the capacity of new groups (at most
  8192). A commit carries one X-Wing ciphertext and one wrapped secret per
  node of its author's copath resolutions: about 1.2 KB × members in the
  worst case (under 10 MB at 8192), usually far less, and commits are
  frequent (a batch of joins, leaves, and a self-update of each member at
  least daily). The LightCommit kept with each commit holds a few leaf
  proofs (a few KB each).
* **Light members.** They fetch the log with `light` set and ask for leaf
  proofs of message senders they do not know; a room with many light
  members serves many small proof requests instead of full trees.
* **Log.** Messages stay `message_retention_secs`, commits
  `commit_retention_secs`, at most `max_log_entries` per room. A member
  offline for longer than the commit retention resyncs; messages older than
  the message retention are lost to it.
* **Sessions.** One token per member session, kept in memory
  (`session_ttl_secs`).
* **CPU.** Each commit is verified in full: its ML-DSA-65 signatures (one
  per join request and admission as well), the public transition and the
  tree hash, but no KEM decapsulation. Commits of large groups dominate.

## Upgrading

Profile v0.3 does not interoperate with earlier profiles: a v0.3 DS answers
`410` to the `/v1` and `/v2` routes, and earlier rooms are not migrated.
Clients and servers must run the same profile. Within v0.3, upgrades keep
the journal format; a change of profile (encodings, labels, algorithms) is a
new version with a new journal.

## Checklist

- [ ] `state_path` on durable storage, backed up; one process per state path.
- [ ] TLS in front; only the API port exposed.
- [ ] Health probes on `/health/live` and `/health/ready`.
- [ ] Prometheus scraping `/metrics` ([OBSERVABILITY.md](OBSERVABILITY.md)).
- [ ] The service runs as an unprivileged user with a read-only root
      filesystem (see [`docs/examples/`](examples/)).
- [ ] `./scripts/verify_no_secrets.sh` passes on the deployed revision.
