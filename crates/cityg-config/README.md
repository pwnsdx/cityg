# cityg-config

Configuration of the City-G v0.2 server, clients and GUI: TOML/JSON files, environment variables and validation.

## Features

- **Multiple Formats**: TOML and JSON configuration files
- **Environment Overrides**: All settings can be overridden via `CITYG_*` environment variables
- **Validation**: Comprehensive validation on load
- **Default Values**: Sensible defaults for all settings
- **Type-Safe**: Full Rust type safety with serde

## Usage

```rust
use cityg_config::CityGConfig;

// Load from default locations
let config = CityGConfig::load()?;

// Validate
config.validate()?;

// Access values
println!("Server: {}", config.server.address);
println!("Poll interval: {:?}", config.client.fetch_poll_interval());

// Load from specific file
let config = CityGConfig::from_file("production.toml")?;

// Save configuration
config.save("backup.json")?;
```

## Configuration structure

- **`[server]`** - delivery service: bind address, state path, notification
  capacity, largest group size, message and commit retention, log length,
  session lifetime, SessionAuth clock skew, compaction threshold.
- **`[client]`** - server URL proposed by the join form, poll, retry and
  reconnect intervals.
- **`[gui]`** - window size and maintenance interval.

Unknown keys are ignored: a v0.1.4 file with a `[protocol]` section loads,
but its protocol settings have no v0.2 equivalent.

## Example

```toml
[server]
address = "0.0.0.0:8080"
state_path = "/var/lib/cityg/rooms"
max_group_size = 256
message_retention_secs = 604800

[client]
default_server_url = "https://cityg.example.com"
fetch_poll_interval_secs = 3

[gui]
maintenance_interval_secs = 30
```

Every key has a `CITYG_<SECTION>_<KEY>` environment override, e.g.
`CITYG_SERVER_MAX_GROUP_SIZE=512`. See [config/](../../config/) for complete
examples.
