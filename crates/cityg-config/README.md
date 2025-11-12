# cityg-config

Configuration management for CityG with support for TOML/JSON files, environment variables, and runtime validation.

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

## Configuration Structure

The configuration is organized into four main sections:
- **`[server]`** - API server settings (address, WebSocket capacity, window TTL)
- **`[client]`** - Client connection behavior (server URL, timeouts, polling)
- **`[protocol]`** - Cryptographic protocol parameters (window duration, epoch rotation, proof size limits, forward-secrecy policy)
- **`[gui]`** - Desktop application settings (window dimensions, pagination)

**For complete parameter reference**, see [docs/configuration.md](../../docs/configuration.md)

## Example Configuration

**TOML:**
```toml
[server]
address = "0.0.0.0:8080"
websocket_capacity = 1000
window_ttl_secs = 120

[protocol]
window_duration_secs = 120
fs_policy_version = "fs-demo-policy"

[protocol.fs_policy]
h_seconds = 300
checkpoint_interval_seconds = 3600
```

**JSON:**
```json
{
  "server": {"address": "0.0.0.0:8080", "window_ttl_secs": 120},
  "protocol": {"window_duration_secs": 120}
}
```

**Environment Variables:**
```bash
export CITYG_SERVER_ADDRESS="0.0.0.0:9000"
export CITYG_PROTOCOL_EPOCH_ROTATION_INTERVAL_SECS=600
```

## Crash Recovery & Journaling

The `cityg-server` crate exposes an optional journaling path. When you set
`ServerConfig.state_path`, every accepted bundle is appended and fsync'd, and
the journal is replayed before the server accepts fresh traffic:

```rust
let mut cfg = cityg_server::ServerConfig::new();
cfg.state_path = Some("/var/lib/cityg/journal.cbor".into());
let server = cityg_server::CityGServer::new(cfg);
```

Use durable storage for the journal and include it in your backup/restore plan.
This satisfies the spec's crash-recovery requirement without relying on
wall-clock timestamps.

## Documentation

See [docs/configuration.md](../../docs/configuration.md) for comprehensive documentation.
