# cityg-server

Dead-simple server helpers for accepting City-G epoch bundles with multi-head window management, crash recovery, and cryptographic validation.

## Overview

`cityg-server` provides a high-level Rust library for operating a City-G validation server. It handles:

> Tip: New to City-G terminology? The [Glossary](../../docs/GLOSSARY.md) provides one-line definitions for anchors, epochs, windows, and other concepts referenced in this README. For a visual overview of the protocol architecture, see [Protocol Overview §5](../../docs/protocol/01-overview.md#5-high-level-architecture).

- **Epoch validation** - Cryptographic verification of anchors without learning secrets
- **Multi-head window** - Concurrent branch tracking with configurable capacity
- **Crash recovery** - Journal-based state persistence
- **Membership tracking** - Roster management and delta computation
- **Pivot caching** - Forward secrecy parity caching

This crate wraps `msphf-orchestrator` (low-level protocol validation) with application-friendly APIs for building production servers.

## Quick Start

```rust
use cityg_server::{ServerConfig, CityGServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create server with default configuration
    let config = ServerConfig::new();
    let mut server = CityGServer::new(config);

    // Accept an epoch bundle
    let bundle_cbor = /* ... received from client ... */;
    match server.accept_epoch(&bundle_cbor) {
        Ok(result) => {
            println!("Accepted! Epoch ID: {:?}", result.we_epoch_id);
            println!("New root: {:?}", result.new_root);
        }
        Err(e) => {
            eprintln!("Rejected: {:?}", e);
        }
    }

    Ok(())
}
```

## Configuration

### ServerConfig

```rust
use cityg_server::ServerConfig;
use std::time::Duration;
use std::path::PathBuf;

let config = ServerConfig {
    // Multi-head window capacity (default: 16)
    h_max: Some(32),

    // Window time-to-live (default: 120 seconds)
    window_ttl: Some(Duration::from_secs(30)),

    // Acceptance policy options
    acceptance_options: Some(AcceptanceOptions {
        allowed_srx_modes: vec!["srx/v1-complete".to_string()],
        allowed_params_ids: vec![RLWE_PARAMS_ID_MOCK],
        // ... other options
    }),

    // Journal path for crash recovery
    state_path: Some(PathBuf::from("/var/lib/cityg/journal.cbor")),
};

let server = CityGServer::new(config);
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `h_max` | Maximum concurrent heads | 16 |
| `window_ttl` | Window time-to-live | 120 seconds |
| `acceptance_options` | Cryptographic policy | Permissive defaults |
| `state_path` | Journal persistence path | None (in-memory only) |

## Core Operations

### Accept Epoch

Validate and accept an epoch bundle:

```rust
let bundle_cbor: Vec<u8> = /* from client */;

match server.accept_epoch(&bundle_cbor) {
    Ok(result) => {
        println!("Accepted:");
        println!("  Epoch ID: {}", hex::encode(&result.we_epoch_id));
        println!("  Parent root: {}", hex::encode(&result.parent_root));
        println!("  New root: {}", hex::encode(&result.new_root));
        println!("  WID: {}", hex::encode(&result.wid));
    }
    Err(e) => {
        eprintln!("Frozen: {:?}", e);
        // See docs/protocol/12-error-reference.md for freeze codes
    }
}
```

### Query Membership

Get current group membership for a window:

```rust
let gid = "my-room";
let parent_root = [0u8; 32]; // from latest anchor

let membership = server.get_membership(gid, &parent_root)?;
println!("Members: {}", membership.members.len());
for leaf_id in &membership.members {
    println!("  - {}", hex::encode(leaf_id));
}
```

### Crash Recovery

Persist state to disk for crash recovery:

```rust
use std::path::PathBuf;

let mut config = ServerConfig::new();
config.state_path = Some(PathBuf::from("/var/lib/cityg/journal.cbor"));

let server = CityGServer::new(config);

// All accepted epochs are automatically persisted to journal
// On restart, server replays journal to rebuild state
```

The journal is append-only, flushed, and `sync_data`'d after each write for durability.

## Validation Pipeline

When `accept_epoch()` is called, the server:

1. **Deserializes** CBOR bundle
2. **Extracts** we_epoch_id, xk_hash, roots
3. **Checks** for duplicate epoch ID
4. **Validates** Merkle witnesses (SRX)
5. **Verifies** CAPSS Smallwood proof
6. **Verifies** ZK-VRF proof
7. **Checks** parent root exists in window
8. **Checks** window capacity (h < h_max)
9. **Inserts** as new head if all checks pass
10. **Persists** to journal (if configured)

**Critical**: The server **never learns**:
- `hp` (hash projection key)
- `Y*` (VRF output)
- `E_k` (epoch key)

All cryptographic material remains encrypted or hidden via zero-knowledge proofs.

## Error Handling

The server returns freeze codes for validation failures:

| Code | Meaning | Client Action |
|------|---------|---------------|
| 2 | Witness validation failed | Regenerate with correct parent |
| 5 | Parent root not found | Wait or request merge ticket |
| 7 | Duplicate epoch ID | Generate fresh epoch |
| 11 | Window full (h >= h_max) | Retry in a few seconds |

See [Error Reference](../../docs/protocol/12-error-reference.md) for complete freeze code catalog.

## Production Considerations

### Durability

For production deployments:

1. **Set `state_path`** to persistent storage (SSD/NVMe recommended)
2. **Use ext4/XFS** with barriers enabled
3. **Back up journal** alongside other application data
4. **Monitor journal size** and implement rotation if needed

### Performance Tuning

- **Increase `h_max`**: For high-concurrency scenarios (32-64)
- **Adjust `window_ttl`**: Longer TTL = more memory, better tolerance for delayed clients
- **Use SSD/NVMe**: Journal I/O is on critical path
- **Monitor window pressure**: If h frequently hits h_max, increase capacity

### Monitoring

Track these metrics:

- **Acceptance rate**: Accepted vs frozen epochs
- **Window utilization**: Current h vs h_max
- **Freeze code distribution**: Which validations fail most often
- **Journal size growth**: Disk space monitoring

## Integration Examples

### With Axum (HTTP Server)

```rust
use axum::{Router, routing::post, Json};
use cityg_server::CityGServer;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() {
    let server = Arc::new(Mutex::new(CityGServer::new(ServerConfig::new())));

    let app = Router::new()
        .route("/v1/accept_epoch", post(accept_epoch_handler))
        .with_state(server);

    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn accept_epoch_handler(
    State(server): State<Arc<Mutex<CityGServer>>>,
    body: Vec<u8>,
) -> Result<Json<AcceptEpochResponse>, StatusCode> {
    let mut srv = server.lock().unwrap();
    match srv.accept_epoch(&body) {
        Ok(result) => Ok(Json(AcceptEpochResponse {
            we_epoch_id: result.we_epoch_id,
            accepted: true,
        })),
        Err(e) => Err(StatusCode::CONFLICT),
    }
}
```

See `crates/cityg-api` for a complete HTTP API implementation.

### With tokio-console

```rust
use cityg_server::CityGServer;

#[tokio::main]
async fn main() {
    console_subscriber::init();

    let server = CityGServer::new(ServerConfig::new());

    // Server operations are now visible in tokio-console
    // for debugging and performance analysis
}
```

## Testing

```bash
# Run all tests
cargo test -p cityg-server

# Run specific test
cargo test -p cityg-server test_accept_valid_epoch

# Run with debug output
RUST_LOG=debug cargo test -p cityg-server -- --nocapture
```

## Security Considerations

### Server-Blindness Guarantees

This crate maintains cryptographic blindness to epoch secrets:

- ✅ No `MlKemSecretKey` in `AcceptanceContext`
- ✅ No `ml_kem_decapsulate()` in validation path
- ✅ Verification via `./scripts/verify_no_secrets.sh`

**If you modify this crate**, run:
```bash
./scripts/verify_no_secrets.sh
```

### Side-Channel Resistance

Validation operations use constant-time comparisons where secret-dependent:
- Challenge equality checks (CAPSS)
- Proof acceptance decisions (VRF)

Merkle witness validation and public polynomial operations are **not** constant-time (acceptable for public data).

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     cityg-server                            │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              CityGServer                              │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │  Multi-Head Window Management                   │  │  │
│  │  │  - Window tracking                              │  │  │
│  │  │  - Head eviction (TTL-based)                    │  │  │
│  │  │  - Concurrency control (h_max)                  │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │  Membership Tracking                            │  │  │
│  │  │  - Roster per parent_root                       │  │  │
│  │  │  - Delta computation                            │  │  │
│  │  │  - Leaf ID indexing                             │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │  Crash Recovery Journal                         │  │  │
│  │  │  - Append-only log                              │  │  │
│  │  │  - Replay on startup                            │  │  │
│  │  │  - fsync after write                            │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
│                          │                                  │
│                          ▼                                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │         msphf-orchestrator (Crypto Validation)        │  │
│  │  - accept_anchor()                                    │  │
│  │  - Witness verification                               │  │
│  │  - CAPSS/VRF proofs                                   │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Related Crates

- **[msphf-orchestrator](../msphf-orchestrator/)** - Low-level protocol validation
- **[cityg-client](../cityg-client/)** - Client-side epoch generation
- **[cityg-api](../cityg-api/)** - Complete HTTP API server

## See Also

- [Protocol Documentation](../../docs/protocol/00-README.md)
- [Server Acceptance](../../docs/protocol/07-server-acceptance.md)
- [Multi-Head Window](../../docs/protocol/09-multi-head-window.md)
- [Deployment Guide](../../docs/protocol/14-deployment-guide.md)

## License

MIT License - see [LICENSE](../../LICENSE) file.

---

**Status**: Alpha (0.1.0) - Research-grade implementation
**Last Updated**: 2025-11-12
