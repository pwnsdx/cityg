# cityg-worker

Cloudflare Worker transport of the City-G v0.2 delivery service.

## Topology

- The Worker entrypoint answers health checks (`/healthz`, `/health`,
  `/health/live`, `/health/ready`, `/health/detailed`) and the route policy
  manifest (`GET /__cloudflare/policy`).
- Every delivery-service request (`POST /v2/groups/*`) carries the group
  identifier `gid` as field 1 of its protobuf body; the Worker forwards it to
  the Durable Object named `v2-<gid hex>`. WebSocket subscriptions
  (`GET /v2/ws?gid=<hex>&token=<hex>`) go to the same object.
- The Durable Object runs `WorkerRoomHost`: the request handlers of
  `cityg-runtime` (the same ones as the native `cityg-api` server) over the
  object's SQLite storage. It is the single writer of its room, so commits
  are ordered without any cross-object coordination.
- After a request that appends to the room log, the object pushes a
  `{"type":"head","gid":…,"head_seq":…}` notice to the room's hibernatable
  WebSockets. A client that receives a notice fetches the log with its
  session token. A text `ping` is answered `pong` without waking the object.
- Paths of the removed v0.1.4 API (`/v1/*`, `/v2/barrier/*`) answer
  `410 Gone`.

The Worker, like the native server, only orders and relays protocol objects;
it never holds a group secret.

## Storage layout

One table, `cityg_room_state (key TEXT PRIMARY KEY, value BLOB)`:

```text
v2/<gid hex>/generation              current generation g (u64 big-endian)
v2/<gid hex>/snapshot/<g>            room snapshot of generation g
v2/<gid hex>/journal/<g>/<index>     records appended since that snapshot
```

Compaction writes snapshot `g + 1` and the new generation before it deletes
the keys of generation `g`: an interrupted compaction leaves a consistent
generation behind.

## Configuration

`wrangler.toml` (excerpt):

```toml
main = "build/worker/shim.mjs"

[build]
command = "cargo install -q worker-build && worker-build --release --features cloudflare"

[[durable_objects.bindings]]
name = "CITYG_ROOM"
class_name = "CityGRoomDurableObject"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["CityGRoomDurableObject"]
```

The optional variable `CITYG_WORKER_CONFIG_JSON` holds a serialized
`CityGConfig`; its `[server]` limits (largest group size, message and commit
retention, log length, session lifetime, SessionAuth clock skew, compaction
threshold) apply to every room. An invalid value makes the rooms answer
`500` rather than run with unintended limits.

### Upgrading a v0.1.4 deployment

The v0.1.4 Worker also bound `CITYG_ROUTING_INDEX`, `CITYG_ROOM_REGISTRY`
and `CITYG_ALIAS_INDEX`. Remove those bindings and delete their classes with
a migration:

```toml
[[migrations]]
tag = "v2"
deleted_classes = [
  "CityGRoutingDurableObject",
  "CityGRoomRegistryDurableObject",
  "CityGAliasDurableObject",
]
```

v0.1.4 rooms are not migrated: members create or join v0.2 rooms.

## Checks

```sh
cargo test -p cityg-worker
cargo check -p cityg-worker --features cloudflare --target wasm32-unknown-unknown
```

The storage and routing logic is tested natively (`MemoryDurableObjectStorage`,
`policy`), the Cloudflare glue is type-checked for `wasm32`.
