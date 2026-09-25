# City-G Troubleshooting Guide

This guide helps you diagnose and resolve common issues with City-G.

> **Note**: Unfamiliar with protocol terms like anchors, heads, or epochs? See the [Glossary](./GLOSSARY.md) for quick definitions.

**Quick Links:**
- [Installation Issues](#installation-issues)
- [Connection Problems](#connection-problems)
- [Epoch Validation Errors](#epoch-validation-errors)
- [Performance Problems](#performance-problems)
- [GUI Issues](#gui-issues)
- [Network & WebSocket](#network--websocket)
- [Cryptographic Errors](#cryptographic-errors)

---

## Installation Issues

### Rust Toolchain Not Found

**Symptom**: `cargo: command not found`

**Solution**:
```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Reload shell environment
source $HOME/.cargo/env

# Verify installation
cargo --version
```

### Build Fails with Missing Dependencies

**Symptom**: `error: linker 'cc' not found` or missing system libraries

**Solutions by Platform**:

**Linux (Ubuntu/Debian)**:
```bash
sudo apt update
sudo apt install build-essential pkg-config libssl-dev
sudo apt install libxcb-shape0-dev libxcb-xfixes0-dev  # For GUI
```

**macOS**:
```bash
# Install Xcode command line tools
xcode-select --install

# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install openssl
```

**Windows**:
```powershell
# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/downloads/
# Select "Desktop development with C++" workload
```

### Compilation Errors

**Symptom**: `error[E0433]: failed to resolve: use of undeclared crate or module`

**Solution**:
```bash
# Update Cargo.lock
cargo update

# Clean build artifacts
cargo clean

# Rebuild
cargo build --all
```

---

## Connection Problems

### "Failed to connect to server"

**Symptom**: Client cannot reach API server

**Diagnosis**:
```bash
# 1. Check if server is running
curl http://localhost:8080/health

# 2. Check server logs
RUST_LOG=info cargo run --bin cityg-api

# 3. Verify port is listening
netstat -an | grep 8080   # Linux/macOS
netstat -an | findstr 8080  # Windows
```

**Solutions**:

**Server not running**:
```bash
# Start the server
cargo run --release --bin cityg-api
```

**Wrong URL**:
```bash
# Ensure protocol is included
# ✓ Correct: http://localhost:8080
# ✗ Wrong: localhost:8080
```

**Firewall blocking**:
```bash
# Linux: Allow port 8080
sudo ufw allow 8080/tcp

# macOS: Check System Preferences > Security & Privacy > Firewall

# Windows: Add firewall rule
netsh advfirewall firewall add rule name="City-G API" dir=in action=allow protocol=TCP localport=8080
```

**Using wrong interface**:
```bash
# Server config should bind to correct interface
export CITYG_SERVER_ADDRESS="0.0.0.0:8080"  # All interfaces
# OR
export CITYG_SERVER_ADDRESS="127.0.0.1:8080"  # Localhost only
```

### Connection Timeout

**Symptom**: Requests hang or timeout

**Solution**:
```bash
# Increase API timeout
export CITYG_CLIENT_API_TIMEOUT_SECS=60

# Check network latency
ping server-hostname

# Test with curl
time curl -v http://localhost:8080/health
```

---

## Epoch Validation Errors

### Freeze Code 2: Witness Validation Failed

**Symptom**: `{freeze_code: 2, freeze_reason: "Witness validation failed"}`

**Cause**: Invalid Merkle proof or incorrect parent root

**Solutions**:

1. **Fetch fresh state**:
   ```rust
   // Request new join/merge ticket with current parent root
   let ticket = api.join_ticket(room_id).await?;
   ```

2. **Verify Merkle witness**:
   ```rust
   // Ensure witness corresponds to correct parent_root
   assert_eq!(witness.parent_root, ticket.parent_root);
   ```

3. **Check leaf ID computation**:
   ```rust
   // Leaf ID must be H(device_public_key)
   let leaf_id = blake3::hash(&device_pk).as_bytes();
   ```

### Freeze Code 5: Parent Root Not Found

**Symptom**: `{freeze_code: 5, freeze_reason: "Parent root not in window"}`

**Cause**: Parent root has been evicted from multi-head window (TTL expired)

**Solutions**:

1. **Request merge ticket** (includes current state):
   ```rust
   let merge_ticket = api.merge_ticket(room_id, leaf_id).await?;
   ```

2. **Increase window TTL** (server-side):
   ```bash
   export CITYG_SERVER_WINDOW_TTL_SECS=240  # Increase from 120s default when clients are very slow
   ```

3. **Retry immediately** (window may have just rotated):
   ```rust
   // Exponential backoff retry
   for attempt in 1..=3 {
       match api.accept_epoch(&bundle).await {
           Ok(response) => return Ok(response),
           Err(e) if e.freeze_code == 5 => {
               tokio::time::sleep(Duration::from_secs(2_u64.pow(attempt))).await;
           }
           Err(e) => return Err(e),
       }
   }
   ```

### Freeze Code 7: Duplicate Epoch ID

**Symptom**: `{freeze_code: 7, freeze_reason: "Duplicate epoch ID"}`

**Cause**: Epoch ID already exists in server state (replayed or retransmitted)

**Solution**:
```rust
// Generate fresh epoch bundle (don't reuse)
let new_bundle = CityGClient::generate_epoch(
    header,
    parts,
    params,
    &mut fs_state,
    None,  // New randomness
)?;
```

### Freeze Code 11: Window Full

**Symptom**: `{freeze_code: 11, freeze_reason: "Window full (h >= h_max)"}`

**Cause**: Multi-head window at capacity (too many concurrent branches)

**Solutions**:

1. **Wait for eviction** (automatic):
   ```rust
   // Retry after TTL period
   tokio::time::sleep(Duration::from_secs(10)).await;
   let response = api.accept_epoch(&bundle).await?;
   ```

2. **Increase h_max** (server-side):
   ```bash
   export CITYG_PROTOCOL_MAX_CONCURRENT_HEADS=32  # Increase from 16
   ```

3. **Trigger merge** (combine branches):
   ```rust
   // Admin operation to merge heads
   let merge_bundle = admin_client.merge_heads(room_id).await?;
   ```

---

## Performance Problems

### Slow Epoch Generation (>10 seconds)

**Symptom**: `generate_epoch()` takes >10 seconds

**Diagnosis**:
```rust
use std::time::Instant;

let start = Instant::now();
let bundle = CityGClient::generate_epoch(...)?;
println!("Generation took: {:?}", start.elapsed());
```

**Solutions**:

1. **Normal on first run** (CRS loading):
   - First epoch: ~500-700ms (CRS loading)
   - Subsequent epochs: ~90-150ms

2. **CPU bottleneck**:
   ```bash
   # Check CPU usage during generation
   top -p $(pidof cityg-gui)

   # Close other CPU-intensive apps
   ```

3. **Memory pressure**:
   ```bash
   # Check available memory
   free -h  # Linux
   vm_stat  # macOS

   # Ensure >4GB available
   ```

4. **Debug mode build**:
   ```bash
   # Use release mode for performance
   cargo build --release --bin cityg-gui
   ./target/release/cityg-gui
   ```

### High Memory Usage

**Symptom**: Process memory grows unbounded

**Diagnosis**:
```bash
# Monitor memory over time
watch -n 1 'ps aux | grep cityg'
```

**Solutions**:

1. **Leave and rejoin** (clears local state):
   ```rust
   client.leave_room()?;
   // State cleared, memory released
   ```

2. **Limit message history** (client-side):
   ```rust
   // Keep only last N messages
   if messages.len() > 1000 {
       messages.drain(0..messages.len() - 1000);
   }
   ```

3. **Server-side window eviction**:
   ```bash
   # Shorter TTL = less memory
   export CITYG_SERVER_WINDOW_TTL_SECS=5
   ```

### High Latency Fetching Messages

**Symptom**: `/v1/messages` endpoint slow (>1 second)

**Solutions**:

1. **Reduce polling frequency**:
   ```bash
   export CITYG_CLIENT_FETCH_POLL_INTERVAL_SECS=5  # From 3s
   ```

2. **Use WebSocket** (instant notifications):
   ```rust
   // Connect to /v1/ws for real-time updates
   let ws = api.connect_websocket().await?;
   ```

3. **Check server load**:
   ```bash
   # View server metrics
   curl http://localhost:8080/metrics | grep http_request_duration
   ```

---

## GUI Issues

### Window Doesn't Open

**Symptom**: Application starts but no window appears

**Solutions**:

**Linux**:
```bash
# Install X11/Wayland dependencies
sudo apt install libxcb-shape0-dev libxcb-xfixes0-dev libxcb-render0-dev libxcb-xfixes0-dev

# Check DISPLAY variable
echo $DISPLAY  # Should be :0 or similar

# Try with verbose logging
RUST_LOG=info ./target/release/cityg-gui
```

**macOS**:
```bash
# Check security permissions
# System Preferences > Security & Privacy > Privacy > Automation
# Ensure terminal/app has permission
```

**Windows**:
```powershell
# Run as administrator if needed
# Right-click executable > "Run as administrator"
```

### "Join failed: Proof generation failed"

**Symptom**: Join fails during epoch generation

**Solutions**:

1. **Ensure sufficient memory**:
   ```bash
   # Check available RAM
   free -h  # Should have >4GB available
   ```

2. **Verify CRS files**:
   ```bash
   # Check for corrupted config
   rm -rf ~/.config/cityg-gui/
   # Restart GUI (will regenerate)
   ```

3. **Check server compatibility**:
   ```rust
   // Ensure client and server use compatible parameters
   // Check cityg-config version matches
   ```

### Member List Not Loading

**Symptom**: Members panel shows "Loading members..." indefinitely

**Solutions**:

1. **Check server response**:
   ```bash
   # Test members endpoint directly
   curl -X POST http://localhost:8080/v1/members \
     -H "Content-Type: application/x-protobuf" \
     --data-binary @request.pb
   ```

2. **Verify parent_root**:
   ```rust
   // Ensure parent_root matches current server state
   let latest_state = api.get_group_state(room_id).await?;
   ```

3. **Increase page limit**:
   ```bash
   export CITYG_GUI_MEMBERS_PAGE_LIMIT=500  # From 200
   ```

---

## Network & WebSocket

### WebSocket Keeps Disconnecting

**Symptom**: `WebSocket connection lost` every few seconds

**Solutions**:

1. **Check network stability**:
   ```bash
   # Test connection quality
   ping -c 100 server-hostname
   ```

2. **Adjust ping/pong interval** (server-side):
   ```rust
   // Increase timeout in server config
   let ws_config = WebSocketConfig {
       ping_interval: Duration::from_secs(60),  // From 30s
       pong_timeout: Duration::from_secs(120),  // From 60s
   };
   ```

3. **Use client-side reconnection**:
   ```rust
   // Implement exponential backoff reconnection
   async fn connect_with_retry(url: &str) -> Result<WebSocket> {
       for delay in [1, 2, 4, 8, 16] {
           match connect_ws(url).await {
               Ok(ws) => return Ok(ws),
               Err(e) => {
                   eprintln!("Connection failed: {}, retrying in {}s", e, delay);
                   tokio::time::sleep(Duration::from_secs(delay)).await;
               }
           }
       }
       Err("Max retries exceeded".into())
   }
   ```

### Messages Not Appearing

**Symptom**: Sent messages don't show up in GUI

**Diagnosis**:
```bash
# 1. Check if message was accepted
curl -X POST http://localhost:8080/v1/send_message \
  -H "Content-Type: application/x-protobuf" \
  --data-binary @message.pb

# 2. Check if fetch returns messages
curl -X POST http://localhost:8080/v1/messages \
  -H "Content-Type: application/x-protobuf" \
  --data-binary @fetch_request.pb
```

**Solutions**:

1. **Verify epoch ID matches**:
   ```rust
   // Message and fetch must use same we_epoch_id
   assert_eq!(message.we_epoch_id, fetch_request.we_epoch_id);
   ```

2. **Check message encryption**:
   ```rust
   // Ensure E_k derivation is correct
   let epoch_key = derive_epoch_key(&xk, &y_star)?;
   let ciphertext = encrypt(&plaintext, &epoch_key)?;
   ```

3. **Force manual refresh**:
   - GUI: Click "Refresh" button
   - API: Call `/v1/messages` again

---

## Cryptographic Errors

### "SPHF verification failed"

**Symptom**: Proof validation fails during epoch acceptance

**Solutions**:

1. **Verify CRS compatibility**:
   ```rust
   // Client and server must use same CRS
   assert_eq!(client_crs_id, server_crs_id);
   ```

2. **Check parameter ID**:
   ```rust
   // Ensure params_id is in server's allowed list
   let allowed = vec![RLWE_PARAMS_ID_MOCK];
   assert!(allowed.contains(&params_id));
   ```

3. **Regenerate epoch**:
   ```rust
   // Generate fresh bundle
   let bundle = CityGClient::generate_epoch(...)?;
   ```

### "PoP signature invalid"

**Symptom**: Proof-of-Possession signature fails validation

**Solutions**:

1. **Verify device keys match**:
   ```rust
   // Public key in PoP must match device_pk
   let pop_pk = extract_pop_public_key(&anchor)?;
   assert_eq!(pop_pk, device_pk);
   ```

2. **Check signature generation**:
   ```rust
   // Ensure correct message signed
   let message = encode_pop_message(&anchor_context)?;
   let signature = sign_ml_dsa(&message, &device_sk)?;
   ```

### "Decryption failed"

**Symptom**: Cannot decrypt received messages

**Solutions**:

1. **Verify epoch key derivation**:
   ```rust
   // All members must derive same E_k
   let xk = compute_xk(&parts)?;
   let y_star = compute_y_star(&hp, &masks)?;
   let epoch_key = H_epoch(&xk, &y_star)?;
   ```

2. **Check barrier-sealed HP recovery**:
   ```rust
   // Ensure the client has the right authenticated barrier state
   let hp_key = derive_barrier_hp_key(&k_barrier, barrier_version, &xk_hash, &hp_commit)?;
   let hp = decrypt_hp_bytes(&hp_ciphertext, &xk_hash, &hp_commit, &hp_key)?;
   ```

3. **Verify message format**:
   ```rust
   // Check ciphertext structure
   assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);
   ```

---

## Common Error Messages

### "Room already exists"

**Cause**: Attempting to bootstrap a room that already exists

**Solution**: Join the room instead of bootstrapping:
```rust
let ticket = api.join_ticket(room_id).await?;  // Not bootstrap
```

### "Invalid room ID"

**Cause**: Room ID is not a 64-character hexadecimal identifier

**Solution**: Use a 64-hex room ID (or the GUI "Generate Random" button):
```rust
let room_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // Valid
// Not: "my-first-room" // Invalid
```

### "Rate limit exceeded"

**Cause**: Too many requests in short time

**Solution**: Implement exponential backoff:
```rust
tokio::time::sleep(Duration::from_secs(5)).await;
// Retry request
```

---

## Debugging Tools

### Enable Debug Logging

```bash
# Full debug output
export RUST_LOG=debug
cargo run --bin cityg-gui

# Specific module
export RUST_LOG=cityg_client=trace,msphf_orchestrator=debug

# JSON structured logs (production)
export LOG_FORMAT=json
```

### Inspect Epoch Bundle

```rust
// Decode CBOR bundle for inspection
let bundle_cbor: Vec<u8> = /* ... */;
let value: ciborium::value::Value = ciborium::from_reader(&bundle_cbor[..])?;
println!("{:#?}", value);
```

### Trace Request with Correlation ID

```bash
# Send request with custom ID
curl -H "X-Request-ID: debug-123" \
  http://localhost:8080/v1/accept_epoch

# Filter logs by correlation ID
cat server.log | jq 'select(.span.request_id == "debug-123")'
```

### Check Protocol Compliance

```bash
# Verify server-blindness
./scripts/verify_no_secrets.sh

# Run test suite
cargo test --all

# Check timing safety
cargo build --release
# Run dudect tests (see docs/timing-verification.md)
```

---

## Getting More Help

If you've tried the solutions above and still have issues:

1. **Search existing issues**: [GitHub Issues](https://github.com/pwnsdx/cityg/issues)

2. **Collect debugging information**:
   - OS and version (`uname -a` or `systeminfo`)
   - Rust version (`rustc --version`)
   - Error messages with full stack traces
   - Logs with `RUST_LOG=debug`

3. **Create minimal reproduction**:
   - Simplest code that reproduces the issue
   - Steps to reproduce
   - Expected vs actual behavior

4. **Ask for help**:
   - GitHub Issues for bug reports
   - GitHub Discussions for questions

---

## See Also

- [FAQ](./protocol/17-faq.md) - Frequently asked questions
- [Error Reference](./protocol/12-error-reference.md) - Complete freeze code catalog
- [GUI User Guide](./gui-user-guide.md) - Desktop application guide
- [Configuration Guide](./configuration.md) - Server and client configuration
- [Observability Guide](./OBSERVABILITY.md) - Logging and monitoring

---
**Applies to**: the current City-G repo state and base profile documented in [`./specs.md`](./specs.md)
