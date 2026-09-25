# Configuration

The delivery service (`cityg-api`), the GUI (`cityg-gui`) and the command-line
tools read one configuration, defined by
[`crates/cityg-config`](../crates/cityg-config). The Cloudflare Worker reads
the `[server]` section from a JSON variable
([`crates/cityg-worker/README.md`](../crates/cityg-worker/README.md)).

## Sources

Highest priority first:

1. environment variables `CITYG_<SECTION>_<KEY>`;
2. the first configuration file found among `cityg.toml` and `cityg.json` in
   the working directory, then `config.toml` and `config.json` under
   `<user config directory>/cityg/` (`~/.config/cityg/` on Linux,
   `~/Library/Application Support/cityg/` on macOS);
3. the defaults below.

Unknown keys are ignored: a v0.1.4 file with a `[protocol]` section still
loads, and its protocol settings have no effect. `cityg-api` validates the
result at startup and refuses to start on an invalid value. Sample files are
in [`config/`](../config) and [`docs/examples/`](examples/).

## `[server]`: delivery service

| Key | Variable | Default | Meaning |
| --- | --- | --- | --- |
| `address` | `CITYG_SERVER_ADDRESS` | `0.0.0.0:8080` | Bind address. |
| `state_path` | `CITYG_SERVER_STATE_PATH` | none | Directory of room journals and snapshots. Without it, rooms live in memory and are lost on restart. |
| `websocket_capacity` | `CITYG_SERVER_WEBSOCKET_CAPACITY` | `1000` | Capacity of the log-head notification channel; a subscriber that falls behind gets a `resync` notice. |
| `max_group_size` | `CITYG_SERVER_MAX_GROUP_SIZE` | `256` | Largest `n_max` a new group may declare, from 1 to 1024 (`MAX_N_MAX`). A commit of a group of `n` slots is about 1.2 KB × `n`. |
| `message_retention_secs` | `CITYG_SERVER_MESSAGE_RETENTION_SECS` | `604800` (7 days) | How long envelopes stay in a room log. |
| `commit_retention_secs` | `CITYG_SERVER_COMMIT_RETENTION_SECS` | `2592000` (30 days) | How long commits stay; the latest commit always stays. |
| `max_log_entries` | `CITYG_SERVER_MAX_LOG_ENTRIES` | `50000` | Most entries of a room log: messages and proposals go first, then the oldest commits. |
| `session_ttl_secs` | `CITYG_SERVER_SESSION_TTL_SECS` | `3600` | Lifetime of a member session token. |
| `auth_skew_secs` | `CITYG_SERVER_AUTH_SKEW_SECS` | `300` | Accepted difference between a SessionAuth timestamp and the server clock. |
| `compact_every` | `CITYG_SERVER_COMPACT_EVERY` | `256` | Journal records after which a room is snapshotted and its journal truncated. |

Every numeric value of this section must be positive.

A member whose log position falls behind the retention loses the messages
that expired and, if a commit it needs expired too, re-enters the group
with a Resync commit. Retention therefore bounds how long a device may stay
offline without resyncing.

## `[client]`: GUI and tools

| Key | Variable | Default | Meaning |
| --- | --- | --- | --- |
| `default_server_url` | `CITYG_CLIENT_DEFAULT_SERVER_URL` | empty | Server URL proposed by the GUI join form; default server of the `join_leave` CLI. |
| `fetch_poll_interval_secs` | `CITYG_CLIENT_FETCH_POLL_INTERVAL_SECS` | `3` | Interval between log polls; log-head notices trigger syncs sooner. |
| `fetch_retry_interval_secs` | `CITYG_CLIENT_FETCH_RETRY_INTERVAL_SECS` | `10` | Delay before retrying a failed sync. |
| `websocket_reconnect_delay_secs` | `CITYG_CLIENT_WEBSOCKET_RECONNECT_DELAY_SECS` | `5` | Delay before reconnecting the notification socket. |

## `[gui]`

| Key | Variable | Default | Meaning |
| --- | --- | --- | --- |
| `default_window_width` | `CITYG_GUI_DEFAULT_WINDOW_WIDTH` | `1160.0` | Initial window width. |
| `default_window_height` | `CITYG_GUI_DEFAULT_WINDOW_HEIGHT` | `760.0` | Initial window height. |
| `maintenance_interval_secs` | `CITYG_GUI_MAINTENANCE_INTERVAL_SECS` | `30` | Maintenance tick: commit other members' recorded removals, re-key this device's leaf every 24 hours (`FS_WINDOW`), erase previous-epoch message keys after the 10-minute grace window. |

## Other environment variables

| Variable | Used by | Meaning |
| --- | --- | --- |
| `RUST_LOG` | all | Log filter (`tracing` syntax), default `info`. |
| `LOG_FORMAT=json` | `cityg-api` | JSON logs instead of text. |
| `CITYG_GUI_CONFIG_DIR` | `cityg-gui` | Directory of the GUI's session, history and alias files, instead of `<user config directory>/cityg`. Two GUI instances on one machine need two directories. |
| `CITYG_GUI_SESSION_PASSPHRASE` | `cityg-gui` | Passphrase from which the key of the saved session and history files derives, instead of a random key file kept next to them. The derivation is BLAKE3 `derive_key`, not a password-hashing function: use a long random passphrase. |
| `CITYG_CLI_SERVER_URL` | `join_leave` | Server URL, before `[client] default_server_url`. |
| `CITYG_STRESS_*` | `cityg-stress` | Every option of the stress tool (`cargo run -p cityg-stress -- --help`). |

## Examples

Development, rooms in memory:

```bash
cargo run -p cityg-api
```

Durable rooms, larger groups:

```bash
CITYG_SERVER_STATE_PATH=/var/lib/cityg/rooms \
CITYG_SERVER_MAX_GROUP_SIZE=1024 \
cargo run --release -p cityg-api
```

A configuration file:

```toml
[server]
address = "0.0.0.0:8080"
state_path = "/var/lib/cityg/rooms"
max_group_size = 512
```

The same in JSON (`cityg.json`):

```json
{"server": {"address": "0.0.0.0:8080", "state_path": "/var/lib/cityg/rooms", "max_group_size": 512}}
```

## What is not configurable

The protocol parameters are fixed by the profile (specs.md, section 15):
`MAX_N_MAX` (1024), `MAX_ADMINS` (64), the 10-minute grace window, the
message-ratchet bounds, the object size bounds, the replay window and the
label and context registries. Changing any of them is a new profile.
