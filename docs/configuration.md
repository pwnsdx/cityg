# CityG Configuration Management

This document describes the comprehensive configuration system for CityG, implemented to address production readiness requirements.

## Overview

CityG now supports flexible configuration management with the following features:

- **TOML and JSON configuration files**
- **Environment variable overrides** for containerized deployments
- **Runtime configuration API** for dynamic updates
- **Validation on startup** to catch configuration errors early
- **Default values** for all settings

## Configuration Priority

Configuration values are resolved in the following order (highest to lowest priority):

1. **Environment variables** (`CITYG_*`)
2. **Configuration file** (`cityg.toml` or `cityg.json`)
3. **Default values** (hardcoded in `cityg-config` crate)

## Configuration File Locations

CityG searches for configuration files in the following order:

1. `./cityg.toml` or `./cityg.json` (current working directory)
2. `~/.config/cityg/config.toml` or `~/.config/cityg/config.json` (user config directory)

## Configuration Structure

The configuration is organized into four main sections:

### 1. Server Configuration (`[server]`)

Controls the API server behavior.

```toml
[server]
address = "0.0.0.0:8080"              # Server bind address
websocket_capacity = 1000              # WebSocket broadcast channel capacity
window_ttl_secs = 120                  # Window TTL (2 minutes baseline)
seed_demo_room = true                  # Seed demo KBROAD/bootstrap keys on startup
```

**Environment Variables:**
- `CITYG_SERVER_ADDRESS` - Server bind address
- `CITYG_SERVER_WEBSOCKET_CAPACITY` - WebSocket channel capacity
- `CITYG_SERVER_WINDOW_TTL_SECS` - Window time-to-live in seconds
- `CITYG_SERVER_SEED_DEMO_ROOM` - Enable/disable demo-room seeding (true/false)

> **Operational note:** The 120-second default absorbs normal client jitter while keeping stale heads bounded. Increase it only when real deployments routinely see join latency above two minutes; every extra minute inflates memory usage and lengthens the window attackers can try to exhaust head slots.

### 2. Client Configuration (`[client]`)

Controls client/GUI connection behavior.

```toml
[client]
default_server_url = "http://127.0.0.1:8080"   # Default server URL
fetch_poll_interval_secs = 3                    # Polling interval for updates
fetch_retry_interval_secs = 10                  # Retry interval for failures
websocket_reconnect_delay_secs = 5              # WebSocket reconnect delay
api_timeout_secs = 30                           # API request timeout
```

**Environment Variables:**
- `CITYG_CLIENT_DEFAULT_SERVER_URL` - Default server URL
- `CITYG_CLIENT_FETCH_POLL_INTERVAL_SECS` - Polling interval
- `CITYG_CLIENT_FETCH_RETRY_INTERVAL_SECS` - Retry interval
- `CITYG_CLIENT_WEBSOCKET_RECONNECT_DELAY_SECS` - WebSocket reconnect delay
- `CITYG_CLIENT_API_TIMEOUT_SECS` - API timeout

### 3. Protocol Configuration (`[protocol]`)

Controls cryptographic protocol parameters.

```toml
[protocol]
window_duration_secs = 120                      # Time window duration (match server TTL)
max_concurrent_heads = 16                       # Max concurrent heads
epoch_rotation_interval_secs = 300              # Epoch rotation (5 min)
default_srx_max_bytes = 1048576                 # Max SRX payload (1 MB)
max_hp_proof_bytes = 524288                     # Max HP proof (512 KB)
max_vrf_proof_bytes = 6144                      # Max VRF proof (6 KB)
fs_capss_max_bytes = 16384                      # FS CAPSS max (16 KB)
srx_smallwood_max_bytes = 16384                 # SRX Smallwood max (16 KB)
max_hp_envelope_bytes = 16384                   # Max HP envelope (16 KB)
min_srx_max_bytes = 262144                      # Min SRX max (256 KB)
receiver_cache_ttl_secs = 10                    # Receiver cache TTL
fs_policy_version = "fs-demo-policy"            # Expected FS policy label

[protocol.fs_policy]
h_seconds = 300                                 # Annex H base period (seconds)
checkpoint_interval_seconds = 3600              # Checkpoint interval (seconds)
checkpoint_head_threshold = 24                  # Heads required before checkpoint
slack_anchor = 0                                # Anchor slack
slack_first_device = 0                          # First-device slack
slack_device = 4                                # Device slack
```

**Environment Variables:**
- `CITYG_PROTOCOL_WINDOW_DURATION_SECS` - Window duration
- `CITYG_PROTOCOL_MAX_CONCURRENT_HEADS` - Maximum concurrent heads
- `CITYG_PROTOCOL_EPOCH_ROTATION_INTERVAL_SECS` - Epoch rotation interval
- `CITYG_PROTOCOL_DEFAULT_SRX_MAX_BYTES` - Default SRX max bytes
- `CITYG_PROTOCOL_MAX_HP_PROOF_BYTES` - Maximum HP proof size
- `CITYG_PROTOCOL_MAX_VRF_PROOF_BYTES` - Maximum VRF proof size
- `CITYG_PROTOCOL_FS_CAPSS_MAX_BYTES` - Maximum FS CAPSS proof size
- `CITYG_PROTOCOL_SRX_SMALLWOOD_MAX_BYTES` - Maximum SRX Smallwood proof size
- `CITYG_PROTOCOL_MAX_HP_ENVELOPE_BYTES` - Maximum HP envelope size
- `CITYG_PROTOCOL_MIN_SRX_MAX_BYTES` - Minimum SRX payload floor
- `CITYG_PROTOCOL_RECEIVER_CACHE_TTL_SECS` - Receiver cache TTL
- `CITYG_PROTOCOL_FS_POLICY_VERSION` - FS policy version label
- `CITYG_PROTOCOL_FS_POLICY_H_SECONDS`
- `CITYG_PROTOCOL_FS_POLICY_CHECKPOINT_INTERVAL_SECS`
- `CITYG_PROTOCOL_FS_POLICY_CHECKPOINT_HEAD_THRESHOLD`
- `CITYG_PROTOCOL_FS_POLICY_SLACK_ANCHOR`
- `CITYG_PROTOCOL_FS_POLICY_SLACK_FIRST_DEVICE`
- `CITYG_PROTOCOL_FS_POLICY_SLACK_DEVICE`

Keep `window_duration_secs` aligned with `server.window_ttl_secs`: the client/orchestrator logic assumes the two values describe the same retention window. Diverging them can cause the server to evict heads before clients expect it (or vice versa), resulting in unnecessary freezes.

#### Forward-Secrecy Policy Parameters

Forward-secrecy parameters come straight from Annex H/J. The orchestrator
publishes the current policy via `[protocol.fs_policy]`, and the API server
injects those values into `AcceptanceOptions` on startup. Use the knobs as
follows:

- `h_seconds` (`H` in Annex H) establishes the base window for device evolution.
- `checkpoint_interval_seconds` and `checkpoint_head_threshold` control when new
  CAPSS checkpoints become admissible.
- `slack_anchor`/`slack_first_device`/`slack_device` bound how far joins may lag
  behind the logical clock before the server freezes them.
- `fs_policy_version` must match exactly on both client and server; CityG rejects
  joins when the label drifts, which keeps mixed deployments from accidentally
  combining incompatible policies.

When these values change, clients automatically receive the new policy via the
API response metadata, and the `ForwardSecrecyState` inside `cityg-client`
updates its logical clock accordingly.

### Crash Recovery & Journaling

`cityg-server` persists every accepted bundle when `ServerConfig.state_path` is
set. The journal is append-only, flushed, and `sync_data`’d after each write so
the server can replay state after a crash before admitting new traffic.

```rust
use cityg_server::ServerConfig;
use std::path::PathBuf;

let mut server_cfg = ServerConfig::new();
server_cfg.state_path = Some(PathBuf::from("/var/lib/cityg/journal.cbor"));
// ... populate acceptance options / KBROAD registry ...
let server = CityGServer::new(server_cfg);
```

Place the journal on durable storage (e.g., ext4/XFS with barriers enabled) and
back it up alongside your roll-forward logs. On restart, the server replays the
journal to rebuild the multi-head window, pivot cache, and roster before it
accepts new joins, which satisfies the spec’s crash-recovery requirement.

### 4. GUI Configuration (`[gui]`)

Controls graphical interface settings.

```toml
[gui]
default_window_width = 1160.0                   # Window width (pixels)
default_window_height = 760.0                   # Window height (pixels)
members_page_limit = 200                        # Members per page
members_refresh_interval_secs = 30              # Auto-refresh cadence (seconds)
min_card_width = 320.0                          # Min card width (pixels)
max_card_width = 960.0                          # Max card width (pixels)
max_card_height = 780.0                         # Max card height (pixels)
```

**Environment Variables:**
- `CITYG_GUI_DEFAULT_WINDOW_WIDTH` - Default window width
- `CITYG_GUI_DEFAULT_WINDOW_HEIGHT` - Default window height
- `CITYG_GUI_MEMBERS_PAGE_LIMIT` - Members pagination limit
- `CITYG_GUI_MEMBERS_REFRESH_INTERVAL_SECS` - Automatic roster refresh cadence

## Usage Examples

### Using Configuration Files

**Development:**
```bash
cp config/development.toml cityg.toml
cargo run -p cityg-gui
```

**Production:**
```bash
cp config/production.toml cityg.toml
cargo run -p cityg-api
```

### Using Environment Variables

```bash
# Override server address
export CITYG_SERVER_ADDRESS="0.0.0.0:9000"

# Increase polling interval for production
export CITYG_CLIENT_FETCH_POLL_INTERVAL_SECS=5

# Longer epoch rotation interval
export CITYG_PROTOCOL_EPOCH_ROTATION_INTERVAL_SECS=600

# Run with overrides
cargo run -p cityg-api
```

### Docker/Container Deployments

**Dockerfile:**
```dockerfile
FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p cityg-api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl
COPY --from=builder /app/target/release/cityg-api /usr/local/bin/
ENV CITYG_SERVER_ADDRESS=0.0.0.0:8080
ENV CITYG_PROTOCOL_EPOCH_ROTATION_INTERVAL_SECS=600
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8080/health/ready || exit 1
CMD ["cityg-api"]
```

**docker-compose.yml:**
```yaml
version: '3.8'
services:
  cityg-api:
    image: cityg-api:latest
    ports:
      - "8080:8080"
    environment:
      CITYG_SERVER_ADDRESS: "0.0.0.0:8080"
      CITYG_SERVER_WEBSOCKET_CAPACITY: "5000"
      CITYG_PROTOCOL_EPOCH_ROTATION_INTERVAL_SECS: "600"
      CITYG_PROTOCOL_DEFAULT_SRX_MAX_BYTES: "2097152"
    volumes:
      - ./cityg.toml:/etc/cityg/config.toml:ro
```

## Configuration Validation

All configuration values are validated on startup. Invalid configurations will cause the application to exit with a descriptive error message.

**Validation Rules:**

- All capacity and limit values must be > 0
- `default_srx_max_bytes` must be >= `min_srx_max_bytes`
- All timeout values must be > 0
- Window dimensions must be > 0

**Example Error:**
```
Configuration validation failed: default_srx_max_bytes (100) must be >= min_srx_max_bytes (262144)
Please check your configuration and try again.
```

## Production Best Practices

### 1. Use Environment Variables for Sensitive Data

Don't commit production configurations to version control. Use environment variables instead:

```bash
export CITYG_SERVER_ADDRESS="${SERVER_ADDRESS}"
export CITYG_CLIENT_DEFAULT_SERVER_URL="${CLIENT_SERVER_URL}"
```

### 2. Tune Performance Settings

**Development:**
- Lower polling intervals (3 seconds) for responsive UI
- Smaller capacities to save resources

**Production:**
- Higher polling intervals (5+ seconds) to reduce load
- Larger capacities (5000+) for high traffic
- Longer epoch rotation intervals (10+ minutes) for stability

### 3. Adjust Payload Limits

- **Small deployments:** 1 MB SRX payload (default)
- **Large deployments:** 2-4 MB SRX payload
- Monitor actual usage and adjust accordingly

### 4. Configure Timeouts Appropriately

- **Development:** Short timeouts (30s) for quick feedback
- **Production:** Longer timeouts (60s+) for reliability

### 5. Use Configuration Files for Deployment Profiles

Maintain separate configuration files for each environment:

```
config/
  ├── development.toml
  ├── staging.toml
  ├── production.toml
  └── production-high-traffic.toml
```

## Runtime Configuration API

The `CityGConfig` struct provides a runtime API for programmatic configuration:

```rust
use cityg_config::CityGConfig;

// Load from default locations
let config = CityGConfig::load()?;

// Validate
config.validate()?;

// Access configuration values
println!("Server address: {}", config.server.address);
println!("Polling interval: {:?}", config.client.fetch_poll_interval());

// Load from specific file
let config = CityGConfig::from_file("config/production.toml")?;

// Save configuration
config.save("backup.toml")?;
```

## Migration from Hardcoded Values

Previously hardcoded values have been replaced with configuration:

| Old Constant | New Configuration | Default Value |
|--------------|-------------------|---------------|
| `FETCH_POLL_INTERVAL` | `client.fetch_poll_interval_secs` | 3 seconds |
| `FETCH_RETRY_INTERVAL` | `client.fetch_retry_interval_secs` | 10 seconds |
| `MEMBERS_PAGE_LIMIT` | `gui.members_page_limit` | 200 |
| `default_epoch_rotation_interval()` | `protocol.epoch_rotation_interval_secs` | 300 seconds |
| WebSocket reconnect (hardcoded 5s) | `client.websocket_reconnect_delay_secs` | 5 seconds |
| Server address (0.0.0.0:8080) | `server.address` | "0.0.0.0:8080" |
| WebSocket capacity (1000) | `server.websocket_capacity` | 1000 |

## Troubleshooting

### Configuration Not Loading

**Problem:** Application uses default values despite config file existing.

**Solution:** Check file location and format:
```bash
# Verify file exists
ls -la cityg.toml

# Validate TOML syntax
cargo run --bin toml-check cityg.toml

# Check JSON syntax
jq . cityg.json
```

### Environment Variables Not Applied

**Problem:** Environment variables seem ignored.

**Solution:** Verify variable names and format:
```bash
# Check variable is set
echo $CITYG_SERVER_ADDRESS

# Ensure no typos in name
env | grep CITYG_

# Restart application after setting variables
```

### Validation Errors

**Problem:** Application fails to start with validation error.

**Solution:** Check error message and fix invalid values:
```bash
# Example error:
# "Configuration validation failed: fetch_poll_interval_secs must be > 0"

# Fix in config file:
[client]
fetch_poll_interval_secs = 3  # Must be positive
```

## Architecture

The configuration system is implemented in the `cityg-config` crate with the following structure:

```
crates/cityg-config/
├── src/
│   └── lib.rs        # Main configuration implementation
├── Cargo.toml
└── tests/            # Configuration tests
```

**Key Components:**

- `CityGConfig` - Main configuration struct
- `ServerConfig` - Server-specific settings
- `ClientConfig` - Client-specific settings
- `ProtocolConfig` - Protocol-specific settings
- `GuiConfig` - GUI-specific settings
- `ConfigError` - Error types for configuration operations

## Future Enhancements

Potential improvements for the configuration system:

1. **Hot Reloading** - Reload configuration without restarting
2. **Remote Configuration** - Fetch config from remote source
3. **Configuration UI** - GUI for editing configuration
4. **Configuration Profiles** - Switch between profiles at runtime
5. **Configuration History** - Track configuration changes
6. **Schema Validation** - JSON Schema for configuration files

## References

- [TOML Specification](https://toml.io/)
- [JSON Specification](https://www.json.org/)
- [Twelve-Factor App Config](https://12factor.net/config)
- [Rust Serde Documentation](https://serde.rs/)
