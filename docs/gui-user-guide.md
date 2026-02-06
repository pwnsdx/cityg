# City-G GUI User Guide

Welcome to the City-G desktop application! This guide will help you get started with secure, private group messaging using witness extraction and post-quantum cryptography.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Join Flow](#join-flow)
5. [Messaging](#messaging)
6. [Member Roster](#member-roster)
7. [Session Management](#session-management)
8. [Keyboard Shortcuts](#keyboard-shortcuts)
9. [Advanced Features](#advanced-features)
10. [Troubleshooting](#troubleshooting)
11. [FAQ](#faq)

---

## Introduction

The City-G GUI is a desktop application that provides a user-friendly interface for:
- **Joining secure groups** without server-based key distribution
- **Sending encrypted messages** using witness extraction
- **Managing group membership** with real-time roster updates
- **Automatic forward secrecy** through hourly epoch rotation
- **Post-quantum security** using RLWE and Dilithium signatures

### Key Features

✅ **No server-side key management** - All cryptography happens client-side
✅ **Post-quantum secure** - Protected against quantum computer attacks
✅ **Forward secrecy** - Automatic key rotation every hour
✅ **Real-time updates** - WebSocket notifications for new messages
✅ **Trust-on-first-use** - Optional identity binding with Ed25519
✅ **Cross-platform** - Runs on macOS, Linux, and Windows

---

## Installation

### Prerequisites

- **Rust toolchain** (1.70 or newer): [Install Rust](https://rustup.rs/)
- **City-G server** running locally or remotely
- **Operating System**: macOS, Linux, or Windows with X11/Wayland

### Build from Source

```bash
# Clone the repository
git clone https://github.com/pwnsdx/cityg.git
cd cityg

# Build the GUI application
cargo build --release --bin cityg-gui

# Run the application
./target/release/cityg-gui
```

### Platform-Specific Notes

**macOS:**
```bash
# No additional dependencies required
./target/release/cityg-gui
```

**Linux (Ubuntu/Debian):**
```bash
# Install X11/Wayland dependencies
sudo apt install libxcb-shape0-dev libxcb-xfixes0-dev

# Run the application
./target/release/cityg-gui
```

**Windows:**
```bash
# Ensure you have Visual Studio Build Tools installed
cargo build --release --bin cityg-gui
.\target\release\cityg-gui.exe
```

---

## Quick Start

### 1. Start the City-G Server

First, make sure you have a City-G server running:

```bash
# In a separate terminal
cargo run --release --bin cityg-api
```

The server will start on `http://localhost:8080` by default.

### 2. Launch the GUI

```bash
./target/release/cityg-gui
```

You'll see the join screen:

*(Screenshot: Join screen with room ID, alias, and server URL fields - to be added)*

### 3. Join Your First Room

Fill in the join form:

- **Room ID**: `8f7c...` (must be 64 hexadecimal characters; click "Generate Random" for a valid ID)
- **Your Alias**: `alice` (your username in the group)
- **Server URL**: `http://localhost:8080` (default)

Click **Join Room** and wait a few seconds for the cryptographic setup to complete.

### 4. Send a Message

Once joined, you'll see the messaging interface. Type your message in the composer at the bottom and press **Enter** or click **Send**.

Your encrypted message will appear in the chat panel!

---

## Join Flow

### Understanding the Join Form

The join form has three required fields:

#### Room ID
- **Purpose**: Identifies which group you're joining
- **Format**: 64 hexadecimal characters (32-byte room identifier)
- **Tips**:
  - Use the **"Generate Random"** button for unique room IDs
  - Share this ID securely with your group members
  - Case-sensitive

#### Your Alias
- **Purpose**: Your display name in the group
- **Format**: Any string (e.g., `alice`, `Bob Smith`)
- **Tips**:
  - Choose a memorable name (this is how others see you)
  - Cannot be changed after joining (would create a new identity)

#### Server URL
- **Purpose**: The City-G API server endpoint
- **Format**: HTTP/HTTPS URL (e.g., `http://localhost:8080`)
- **Default**: `http://localhost:8080`
- **Tips**:
  - Use `https://` for production deployments
  - Make sure the server is reachable before joining

### Field Navigation

You can navigate the form using:
- **Tab** - Move to next field
- **Shift+Tab** - Move to previous field
- **Escape** - Clear current field
- **Enter** - Submit the form (when all fields are filled)

### The Join Process

When you click **Join Room**, the following happens:

1. **Server Connection** - GUI connects to the City-G server
2. **Room Bootstrap** (first member only) - Creates the room with a broadcast key
3. **Join Ticket** - Server provides initial cryptographic material
4. **Epoch Generation** - Client creates the first epoch bundle (2-5 seconds)
5. **Proof Submission** - Server validates the epoch and accepts you into the group
6. **WebSocket Connection** - Establishes real-time message notifications

**Status Indicators:**
- **Joining...** - Join is in progress
- **✓ Joined!** - Successfully joined the room
- **✗ Join failed** - Check the error message below the form

### Identity Binding (Advanced)

The GUI currently uses **anonymous join** mode. For production use, you may want to enable identity binding with Ed25519 keys to prevent impersonation.

To enable identity binding:
1. Generate an Ed25519 keypair (outside the GUI)
2. Modify the join flow to include your public key
3. Store your private key securely for future sessions

See the [Protocol Documentation](./protocol/08-client-operations.md) for details.

---

## Messaging

### Sending Messages

**To send a message:**

1. Click in the message composer (bottom text area)
2. Type your message
3. Press **Enter** or click the **Send** button

**Keyboard Shortcuts:**
- **Enter** - Send message
- **Shift+Enter** - New line in message
- **Escape** - Clear composer

### Message Display

Each message shows:
- **Alias**: The sender's username
- **Timestamp**: When the message was sent (HH:MM:SS format)
- **Content**: The decrypted message text

**Message List Features:**
- **Auto-scroll** - Automatically scrolls to newest message
- **Chronological order** - Messages sorted by timestamp
- **Deduplication** - Duplicate messages are filtered out

### Ciphertext View (Debug)

For debugging or educational purposes, you can view the encrypted ciphertext:

1. Click the **"Show Ciphertext"** button (right side)
2. Messages will display as hex-encoded ciphertext
3. Click again to return to plaintext view

**Example:**
```
alice (12:34:56): 48656c6c6f20576f726c6421...
```

### Message Fetching

The GUI automatically fetches messages from the server every 5 seconds. You'll see a status indicator:

- **⟳ Fetching messages...** - Loading new messages
- **✓ Idle** - No active fetch
- **✗ Error** - Fetch failed (see error message)

**Manual Refresh:**
- Messages are fetched automatically
- No manual refresh button needed

---

## Member Roster

### Viewing Members

The **Members** panel (right sidebar) shows every leaf that belongs to the current parent root. Each entry highlights the best known alias, the full 32-byte leaf identifier, and lifecycle timestamps so you can see who most recently checked in.

```
alice (a3b5c7d9…)
  leaf: a3b5c7d9e1f2...
  joined 2025-11-07T13:05:44Z
  last seen 2025-11-07T13:07:12Z

bob (1f2e3d4c…)
  leaf: 1f2e3d4c5b6a...
  joined 2025-11-07T12:52:01Z
  last seen 2025-11-07T13:06:55Z
```

### Member Information

Each member entry displays:
- **Alias + short leaf prefix**: Helps you visually match people to their cryptographic IDs.
- **Leaf ID**: The complete 32-byte identifier (hex).
- **Joined**: When this leaf first appeared in the roster.
- **Last seen**: Timestamp of the most recent message or witness that referenced this leaf.

If an alias is unknown, the UI falls back to showing the hex leaf prefix; the rest of the metadata remains visible.

### Loading More Members

For large groups (>100 members), the roster is paginated:

1. Scroll to the bottom of the member list
2. Click **"Load More Members"**
3. The next page (100 members) will be fetched

**Pagination Status:**
- **Loading members...** - Fetching first page
- **Load More Members** - Click to fetch next page
- **X / Y members** - Shows current count vs. total

### Refresh Member List

- **Manual**: Click the **Refresh** button above the roster to fetch the latest root snapshot without leaving the room.
- **Automatic**: The GUI now polls the roster in the background (default every 30 seconds, configurable via `CITYG_GUI_MEMBERS_REFRESH_INTERVAL_SECS`). Whenever the parent root changes, the roster view updates automatically.

You will see a status banner (“Refreshing member roster…”) whenever a background refresh is in flight. Automatic refreshes are skipped while a manual page fetch is already running.

### Trust-On-First-Use Warnings

Alias → key bindings are stored locally. If a server ever reports the same alias with a different ML-DSA public key, the GUI raises a **TOFU alert** toast so you can treat that identity as suspicious. These bindings persist between sessions, ensuring you are warned even after restarting the app.

---

## Session Management

### Session Information

When you're in a room, the **Session Info** panel shows:

**Room Details:**
- **Room ID**: The current room identifier
- **Alias**: Your username
- **Server**: The API server URL
- **Joined**: How long ago you joined (e.g., "2 minutes ago")

**Epoch Details:**
- **Epoch ID**: Current epoch identifier (32-byte hex)
- **Epoch Age**: Time since epoch creation (e.g., "5 minutes ago")
- **Status**: Forward secrecy rotation status

### Leaving a Room

To leave the current room:

1. Click the **"Leave Room"** button (bottom-left)
2. Confirm your choice
3. You'll return to the join screen

**What happens when you leave:**
- Local session data is cleared
- Messages are removed from memory
- WebSocket connection is closed
- You can rejoin at any time

**⚠️ Note:** Leaving does NOT revoke your membership. Other members can still see you in the roster and send messages to your leaf ID.

### Automatic Epoch Rotation

**What is epoch rotation?**

For forward secrecy, the GUI automatically creates a new epoch every hour. This ensures that:
- Past messages remain secure even if current keys are compromised
- Old keys are discarded and cannot decrypt future messages

**How it works:**
1. GUI monitors the epoch age
2. When age exceeds 1 hour (3600 seconds), rotation triggers
3. Client generates a fresh epoch bundle
4. New epoch is submitted to the server
5. Messages continue seamlessly

**Status Indicators:**
- **Epoch age: 25 minutes** - Normal operation
- **Rotating epoch...** - Rotation in progress
- **✓ Epoch rotated** - Successfully rotated

**Manual Rotation:**
*(Not currently exposed in UI - automatic only)*

---

## Keyboard Shortcuts

### Global Shortcuts

| Shortcut | Action |
|----------|--------|
| **Cmd+Q** (macOS) / **Ctrl+Q** (Linux/Windows) | Quit application |

### Join Form

| Shortcut | Action |
|----------|--------|
| **Tab** | Next field |
| **Shift+Tab** | Previous field |
| **Enter** | Submit join (when form is complete) |
| **Escape** | Clear active field |
| **Cmd+R** (macOS) / **Ctrl+R** (Linux/Windows) | Generate random room ID |

### Message Composer

| Shortcut | Action |
|----------|--------|
| **Enter** | Send message |
| **Shift+Enter** | New line |
| **Escape** | Clear composer |
| **Cmd+A** (macOS) / **Ctrl+A** (Linux/Windows) | Select all text |

---

## Advanced Features

### WebSocket Real-Time Notifications

The GUI establishes a WebSocket connection to receive instant message notifications.

**Connection Status:**
- **Connected** - Real-time updates enabled
- **Disconnected** - Falling back to polling (5-second interval)

**How it works:**
1. After joining, GUI connects to `ws://server/v1/ws`
2. Server pushes notifications when new messages arrive
3. GUI fetches messages immediately
4. If connection drops, GUI reconnects automatically

**Troubleshooting WebSocket:**
- Check server logs for WebSocket errors
- Ensure firewall allows WebSocket connections
- Verify server URL uses correct protocol (`ws://` or `wss://`)

### Persistent Configuration

The GUI stores your last session configuration in the platform config directory:
```
macOS:   ~/Library/Application Support/cityg/gui/
Linux:   ~/.config/cityg/gui/
Windows: %APPDATA%\\cityg\\gui\\
```

**Stored data:**
- Last room ID
- Last alias
- Last server URL
- Encrypted session keypairs and forward-secrecy state (`session-<hash>.json`)
- Session key material (`session-key-v1.bin`) when no passphrase override is set

**⚠️ Security Note:** Session files are encrypted at rest, but the local key file is sensitive. Protect the directory accordingly:
```bash
chmod 700 ~/.config/cityg/gui
chmod 600 ~/.config/cityg/gui/session-key-v1.bin
```

For stronger protection, set `CITYG_GUI_SESSION_PASSPHRASE` before launching the GUI so encryption keys derive from your passphrase instead of the local key file.

**To reset configuration:**
```bash
rm -rf ~/.config/cityg/gui/
```

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
# Verbose logging
RUST_LOG=debug ./target/release/cityg-gui

# Trace-level logging (very verbose)
RUST_LOG=trace ./target/release/cityg-gui
```

Logs will show:
- API requests/responses
- Cryptographic operations
- WebSocket messages
- Epoch rotation events

---

## Troubleshooting

### Common Issues

#### "Failed to connect to server"

**Symptoms:** Join fails with connection error

**Solutions:**
1. Verify server is running:
   ```bash
   curl http://localhost:8080/health
   ```
2. Check server URL in join form (include `http://` or `https://`)
3. Ensure firewall allows connections to port 8080
4. Try `127.0.0.1:8080` instead of `localhost:8080`

#### "Epoch frozen: Parent root not found"

**Symptoms:** Messages fail to send, epoch rotation fails

**Solutions:**
1. Leave the room and rejoin
2. Wait a few seconds for server to accept epochs
3. Check server window configuration (`h_max`, `ttl_ms`)
4. Verify no other clients are flooding the server

#### "Failed to fetch messages"

**Symptoms:** Message list doesn't update

**Solutions:**
1. Check server is still running
2. Verify network connection
3. Wait 5 seconds for next automatic fetch
4. Leave and rejoin the room

#### GUI window doesn't open

**Symptoms:** Application starts but no window appears

**Solutions:**
1. **Linux**: Install X11/Wayland dependencies:
   ```bash
   sudo apt install libxcb-shape0-dev libxcb-xfixes0-dev
   ```
2. **macOS**: Check System Preferences > Security & Privacy
3. Check for error messages in terminal
4. Try running with `RUST_LOG=info` for debugging

#### "Proof generation failed"

**Symptoms:** Join fails during epoch generation

**Solutions:**
1. Ensure your machine has sufficient memory (>4GB recommended)
2. Check for corrupted CRS files in `~/.config/cityg-gui/`
3. Verify server provides valid join ticket
4. Try rejoining with a different alias

### Performance Issues

#### Slow join process (>10 seconds)

**Cause:** Proof generation is computationally intensive

**Solutions:**
- **Normal on first join** - CRS loading takes time
- Subsequent joins should be faster (~2-5 seconds)
- Use a faster machine with more CPU cores
- Close other CPU-intensive applications

#### High memory usage

**Cause:** Large member roster or many messages

**Solutions:**
- Leave and rejoin to clear message history
- Server-side: Reduce window TTL to evict old epochs
- Increase available RAM

### Error Messages

| Error | Meaning | Solution |
|-------|---------|----------|
| "Room already exists" | You're trying to bootstrap an existing room | Join without bootstrap (not first member) |
| "Invalid room ID" | Room ID is malformed | Use 64 hexadecimal characters (or Generate Random) |
| "Duplicate epoch ID" | Trying to resubmit same epoch | Generate a fresh epoch |
| "Window full" | Server h_max exceeded | Wait for eviction or increase h_max |
| "SPHF verification failed" | Cryptographic proof invalid | Check CRS compatibility, rejoin room |

### Getting Help

If you encounter issues not covered here:

1. **Check the logs** with `RUST_LOG=debug`
2. **Search GitHub Issues**: [github.com/pwnsdx/cityg/issues](https://github.com/pwnsdx/cityg/issues)
3. **Ask the community**: Post your issue with:
   - Error message
   - Steps to reproduce
   - OS and Rust version (`rustc --version`)
   - Server logs (if relevant)

---

## FAQ

### General

**Q: Is City-G ready for production use?**

A: City-G is a research prototype demonstrating witness extraction and post-quantum cryptography. It is NOT recommended for production use without a security audit.

**Q: How many people can join a room?**

A: Theoretically unlimited. The protocol scales to thousands of members. Practical limits depend on:
- Server resources (RAM, CPU)
- Window configuration (`h_max`)
- Network bandwidth

**Q: Can I use City-G without the GUI?**

A: Yes! Use the Rust client library (`cityg-client`) or the HTTP API directly. See the [API Reference](./api-reference.md).

### Security

**Q: Is City-G quantum-safe?**

A: Yes. City-G uses post-quantum cryptography:
- **RLWE** for smooth projective hash functions
- **Dilithium** for digital signatures
- **LB-VRF** for verifiable random functions

**Q: Does the server know my messages?**

A: No. The server only stores encrypted ciphertext. Only group members with valid witness extraction keys can decrypt.

**Q: What happens if the server is compromised?**

A: The server cannot decrypt messages (they're client-side encrypted). However, a malicious server could:
- Reject valid epochs
- Provide incorrect witness data
- Track join patterns

Use TLS and verify server authenticity in production.

**Q: How does forward secrecy work?**

A: The GUI rotates epochs every 5 minutes by default (configurable via policy/config). Old epoch keys are discarded, so past messages remain secure even if current keys leak.

### Messaging

**Q: Can I send images or files?**

A: Not currently. The GUI only supports text messages. File transfer could be added in the future.

**Q: Are messages stored on the server permanently?**

A: No. Messages are tied to epochs, which are evicted based on the window TTL (default: 1 hour). After eviction, messages are deleted.

**Q: Can I delete a message after sending?**

A: No. Once sent, messages cannot be deleted (distributed system limitation).

**Q: How do I know if my message was received?**

A: If the message appears in your chat panel after fetching, it was successfully stored on the server. Other clients will receive it on their next fetch.

### Membership

**Q: How do I remove a member from the room?**

A: Member revocation is not yet implemented in the GUI. This requires:
1. Creating a revocation proof
2. Submitting it to the server
3. Other members fetching the updated roster

**Q: Can someone impersonate me?**

A: Without identity binding, anyone can create a leaf with your alias. Use identity binding (Ed25519) to prevent this.

**Q: What's the difference between alias and leaf_id?**

A:
- **Alias**: Human-readable username (e.g., "alice")
- **Leaf ID**: Cryptographic identifier (32-byte hash)

Multiple members can have the same alias (not recommended) but leaf IDs are unique.

### Technical

**Q: What is an "epoch"?**

A: An epoch is a cryptographic snapshot of the group state at a specific point in time. It includes:
- Merkle tree root of all members
- Witness extraction key material
- VRF proofs

**Q: Why does joining take several seconds?**

A: The client must generate cryptographic proofs (CAPSS Smallwood), which involves:
- RLWE polynomial operations
- Merkle witness generation
- Post-quantum digital signatures

This is computationally intensive but ensures security.

**Q: Can I run multiple GUI instances?**

A: Yes, but each instance needs a separate config directory. Use:
```bash
HOME=/tmp/user1 ./target/release/cityg-gui
HOME=/tmp/user2 ./target/release/cityg-gui
```

**Q: What's the difference between join and merge?**

A:
- **Join**: First time entering a room (creates new leaf_id)
- **Merge**: Rejoining with existing leaf_id (not yet exposed in GUI)

---

## Appendix: Architecture Overview

### GUI Components

```
┌─────────────────────────────────────────┐
│           City-G GUI (GPUI)             │
├─────────────────────────────────────────┤
│  Join Form │ Message Panel │ Members    │
├─────────────────────────────────────────┤
│         cityg-api-client                │
│       (HTTP + WebSocket client)         │
├─────────────────────────────────────────┤
│         cityg-client                    │
│    (Epoch generation, crypto)           │
├─────────────────────────────────────────┤
│    msphf-orchestrator, capss, lb-vrf    │
│       (Cryptographic primitives)        │
└─────────────────────────────────────────┘
         ↕ HTTP/WebSocket
┌─────────────────────────────────────────┐
│         City-G Server (Axum)            │
│      (Epoch validation, storage)        │
└─────────────────────────────────────────┘
```

### Key Technologies

- **GPUI**: GPU-accelerated UI framework for Rust
- **Tokio**: Async runtime for networking
- **Axum**: HTTP server framework
- **Protocol Buffers**: Binary serialization
- **WebSocket**: Real-time notifications
- **RLWE, Dilithium, CAPSS**: Post-quantum cryptography

---

## Contributing

Want to improve the GUI? Contributions are welcome!

**Ideas for enhancements:**
- [ ] File transfer support
- [ ] Rich text formatting (Markdown)
- [ ] Message search
- [ ] Member invite links
- [ ] Profile pictures
- [ ] Custom themes
- [ ] Notification sounds
- [ ] Multi-room support

For contribution guidelines, see the [GitHub repository](https://github.com/pwnsdx/cityg).

---

**Last Updated:** 2025-11-06
**GUI Version:** 1.0
**Compatible Server:** cityg-api v1.0+

For more information, see:
- [City-G Protocol Documentation](./protocol/00-README.md)
- [API Reference](./api-reference.md)
- [GitHub Repository](https://github.com/pwnsdx/cityg)
