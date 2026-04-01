# cityg-client

Lightweight client helpers for producing City-G epoch bundles with witness generation, proof creation, and forward secrecy management.

## Overview

`cityg-client` provides client-side cryptographic operations for City-G:

> Tip: If you need a refresher on terms such as anchors, epochs, or witness types, consult the [Glossary](../../docs/GLOSSARY.md). For the end-to-end architecture context referenced below, see [Protocol Overview §5](../../docs/protocol/01-overview.md#5-high-level-architecture).

- **Epoch generation** - Create anchors for joins, merges, and revocations
- **Witness creation** - Merkle proofs and SRX witness bundles
- **Proof generation** - CAPSS Smallwood + ZK-VRF proofs
- **Forward secrecy** - Pivot rotation and epoch key derivation
- **KBROAD encryption** - Encrypt hash projection keys for server-blind delivery

This crate handles the **trusted client operations** that derive secrets (`hp`, `Y*`, `E_k`) which the server never learns.

## Quick Start

```rust
use cityg_client::{CityGClient, ClientEpochBundle};
use msphf_orchestrator::{AnchorInstanceParts, OrchestrationParams, ForwardSecrecyState};
use std::collections::BTreeMap;

// 1. Set up anchor parameters
let parts = AnchorInstanceParts {
    gid: b"my-room",
    cat: b"category",
    tswe_salt_hash: &[0xAA; 32],
    parent_root: &current_merkle_root,
    join_delta_root: &new_merkle_root,  // After adding your leaf
    revoked_since_prev_root: &[0; 32],
    revoked_root: &[0; 32],
    pox_r_commit: None,
};

// 2. Configure cryptographic parameters
let params = OrchestrationParams {
    msphf_crs_id: "rlwe-merkle/v1",
    params_id: "rlwe-params/mock",
    srx_mode: SrxMode::Complete,
    proof_mode: "lin+zkvrf",
    vrf_id: "lb-vrf/v1",
    fs_policy_version: "7",
    barrier_version: 0,
    // ... other params
};

// 3. Initialize forward secrecy state
let mut fs_state = ForwardSecrecyState::new(device_commitment);

// 4. Generate epoch bundle
let header = BTreeMap::new();  // Initial header fields
let bundle: ClientEpochBundle = CityGClient::generate_epoch(
    header,
    parts,
    params,
    &mut fs_state,
    None,  // Optional RNG seed for deterministic testing
)?;

// 5. Serialize and submit to server
let cbor_bytes = bundle.to_cbor()?;
// POST to /v1/accept_epoch
```

## Core Concepts

### ClientEpochBundle

The main output of client operations, containing:

```rust
pub struct ClientEpochBundle {
    pub we_epoch_id: [u8; 32],      // Unique epoch identifier
    pub xk_hash: [u8; 32],          // Anchor context commitment
    pub bundle_cbor: Vec<u8>,       // Complete CBOR-encoded anchor
    pub membership_delta: MembershipDelta,  // Who joined/left
}
```

### Witness Generation

Create Merkle witnesses proving membership/non-membership:

```rust
use cityg_client::witness;

// For a join (non-membership proof for new leaf)
let witness_bundle = witness::create_join_witness(
    &parent_tree,
    &new_leaf_id,
    &existing_members,
)?;

// For a merge (membership proof for existing leaf)
let witness_bundle = witness::create_merge_witness(
    &parent_tree,
    &existing_leaf_id,
)?;
```

Witnesses are canonical and grow O(log N) for N members.

### Forward Secrecy State

Track device-specific FS evolution:

```rust
use msphf_orchestrator::ForwardSecrecyState;

// Initialize with device commitment
let mut fs_state = ForwardSecrecyState::new(device_commit);

// State automatically updates each epoch generation
CityGClient::generate_epoch(..., &mut fs_state, ...)?;

// Check current epoch counter
println!("FS epoch: {}", fs_state.fs_ec);
```

## API Reference

### CityGClient::generate_epoch()

Generate a complete epoch bundle:

```rust
pub fn generate_epoch(
    header: BTreeMap<i128, Value>,  // Pre-filled header fields
    parts: AnchorInstanceParts,      // Anchor instance data
    params: OrchestrationParams,     // Crypto parameters
    fs_state: &mut ForwardSecrecyState,  // Forward secrecy state
    seed: Option<[u8; 32]>,          // Optional deterministic seed
) -> Result<ClientEpochBundle, CityGError>
```

**Steps performed**:
1. Derive `hp` (hash projection key) via RLWE-HPS
2. Compute `Y*` (VRF output) via ME-OR
3. Generate CAPSS Smallwood proof (~12KB)
4. Generate ZK-VRF proof (~8KB max, typically smaller)
5. Encrypt `hp` in KBROAD envelope
6. Build complete CBOR anchor header
7. Update forward secrecy state

**Returns**: ClientEpochBundle ready for server submission

### Witness Helpers

```rust
// Create witnesses for join operations
pub fn create_join_witness(
    parent_tree: &MerkleTree,
    new_leaf_id: &[u8; 32],
    existing_members: &[[u8; 32]],
) -> Result<WitnessBundle, CityGError>

// Create witnesses for merge/rejoin operations
pub fn create_merge_witness(
    parent_tree: &MerkleTree,
    existing_leaf_id: &[u8; 32],
) -> Result<WitnessBundle, CityGError>
```

### Pivot Management

```rust
use cityg_client::pivot;

// Refresh pivot for forward secrecy rotation
pub fn refresh_pivot(
    current_pivot: &PivotParity,
    fs_policy: &FsPolicy,
) -> Result<PivotParity, CityGError>
```

## Usage Examples

### Join a Group

```rust
use cityg_client::CityGClient;

async fn join_group(room_id: &str) -> Result<ClientEpochBundle, Box<dyn std::error::Error>> {
    // 1. Fetch join ticket from server
    let ticket = fetch_join_ticket(room_id).await?;

    // 2. Generate your leaf ID
    let device_pk = /* your ML-DSA public key */;
    let leaf_id = hash_leaf_id(&device_pk);

    // 3. Create witness (prove you're not in parent tree)
    let witness = witness::create_join_witness(
        &ticket.parent_tree,
        &leaf_id,
        &ticket.existing_members,
    )?;

    // 4. Build Merkle tree with you added
    let mut new_tree = ticket.parent_tree.clone();
    new_tree.insert(leaf_id);
    let new_root = new_tree.root();

    // 5. Generate epoch bundle
    let parts = AnchorInstanceParts {
        gid: room_id.as_bytes(),
        parent_root: &ticket.parent_root,
        join_delta_root: &new_root,
        // ... other fields from ticket
    };

    let mut fs_state = ForwardSecrecyState::new(device_commitment);

    let bundle = CityGClient::generate_epoch(
        BTreeMap::new(),
        parts,
        ticket.params,
        &mut fs_state,
        None,
    )?;

    Ok(bundle)
}
```

### Merge After Offline

```rust
async fn merge_after_offline(
    room_id: &str,
    leaf_id: &[u8; 32],
) -> Result<ClientEpochBundle, Box<dyn std::error::Error>> {
    // 1. Fetch merge ticket
    let ticket = fetch_merge_ticket(room_id, leaf_id).await?;

    // 2. Create witness (prove you're in parent tree)
    let witness = witness::create_merge_witness(
        &ticket.parent_tree,
        leaf_id,
    )?;

    // 3. Generate epoch with fresh pivot
    let parts = AnchorInstanceParts {
        gid: room_id.as_bytes(),
        parent_root: &ticket.parent_root,
        join_delta_root: &ticket.parent_root,  // Same root (merge)
        // ... other fields
    };

    let mut fs_state = ForwardSecrecyState::restore(/* saved state */);

    let bundle = CityGClient::generate_epoch(
        BTreeMap::new(),
        parts,
        ticket.params,
        &mut fs_state,
        None,
    )?;

    Ok(bundle)
}
```

### Periodic Forward Secrecy Rotation

```rust
use cityg_client::pivot;
use std::time::{Duration, Instant};

async fn auto_rotate_fs(
    client: &mut CityGClient,
    interval: Duration,
) {
    let mut last_rotation = Instant::now();

    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;

        if last_rotation.elapsed() >= interval {
            match pivot::refresh_pivot(&client.current_pivot, &client.fs_policy) {
                Ok(new_pivot) => {
                    client.current_pivot = new_pivot;
                    last_rotation = Instant::now();
                    println!("Pivot rotated for forward secrecy");
                }
                Err(e) => {
                    eprintln!("Pivot rotation failed: {:?}", e);
                }
            }
        }
    }
}
```

## Error Handling

```rust
use cityg_client::CityGError;

match CityGClient::generate_epoch(...) {
    Ok(bundle) => {
        // Submit to server
        submit_epoch(&bundle.bundle_cbor).await?;
    }
    Err(CityGError::InvalidWitness(msg)) => {
        eprintln!("Witness error: {}", msg);
        // Fetch fresh ticket and retry
    }
    Err(CityGError::ProofGeneration(msg)) => {
        eprintln!("Proof generation failed: {}", msg);
        // Check CRS availability
    }
    Err(e) => {
        eprintln!("Unexpected error: {:?}", e);
    }
}
```

## Testing

```bash
# Run all tests
cargo test -p cityg-client

# Run specific test
cargo test -p cityg-client test_join_epoch_generation

# Run with debug output
RUST_LOG=debug cargo test -p cityg-client -- --nocapture
```

## Security Considerations

### Client-Side Secrets

This crate handles secrets that **must never reach the server**:

- **hp** (hash projection key) - Encrypted in KBROAD before transmission
- **Y*** (VRF output) - Hidden via zero-knowledge proofs
- **E_k** (epoch key) - Derived locally, never transmitted

**Memory Safety**: Sensitive values implement `Zeroize` and are cleared on drop.

### Deterministic Seed (Anti-Grinding)

The optional `seed` parameter enables deterministic testing but **must be derived deterministically** in production to prevent grinding attacks:

```rust
// GOOD: Deterministic seed from context
let seed = blake3::hash(&encode_message(ctx, masks)).as_bytes();
let bundle = CityGClient::generate_epoch(..., Some(seed))?;

// BAD: Random seed allows selective disclosure
let seed = rand::random();  // DON'T DO THIS
```

### Side-Channel Resistance

Client operations include timing-sensitive computations:
- Polynomial sampling (constant-time via rejection sampling)
- VRF evaluation (timing-safe comparisons)

For high-security scenarios, audit with ctgrind/dudect.

## Performance

Typical epoch generation times (Apple M1):

| Operation | Time | Notes |
|-----------|------|-------|
| Witness generation | ~1ms | O(log N) for N members |
| CAPSS Smallwood proof | ~50ms | Polynomial operations |
| ZK-VRF proof | ~30ms | Lattice-based VRF |
| KBROAD encryption | ~5ms | ML-KEM-768 + ChaCha20 |
| **Total** | **~90ms** | For typical parameters |

First-time initialization (CRS loading) adds ~500ms.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                       cityg-client                           │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              CityGClient                               │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐ │  │
│  │  │  Epoch Generation Pipeline                       │ │  │
│  │  │  1. Derive hp (RLWE-HPS)                         │ │  │
│  │  │  2. Compute Y* (ME-OR)                           │ │  │
│  │  │  3. Generate proofs (CAPSS + VRF)                │ │  │
│  │  │  4. Encrypt KBROAD                               │ │  │
│  │  │  5. Build CBOR anchor                            │ │  │
│  │  └──────────────────────────────────────────────────┘ │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐ │  │
│  │  │  Witness Module (witness.rs)                     │ │  │
│  │  │  - Merkle proof generation                       │ │  │
│  │  │  - SRX witness bundling                          │ │  │
│  │  │  - Canonical encoding                            │ │  │
│  │  └──────────────────────────────────────────────────┘ │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐ │  │
│  │  │  Pivot Module (pivot.rs)                         │ │  │
│  │  │  - Forward secrecy rotation                      │ │  │
│  │  │  - Parity computation                            │ │  │
│  │  │  - Policy enforcement                            │ │  │
│  │  └──────────────────────────────────────────────────┘ │  │
│  └────────────────────────────────────────────────────────┘  │
│                          │                                   │
│                          ▼                                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │        msphf-orchestrator (Proof Generation)           │  │
│  │  - joiner_kgen_or()                                    │  │
│  │  - CAPSS Smallwood                                     │  │
│  │  - ZK-VRF                                              │  │
│  │  - KBROAD encryption                                   │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Integration

### With cityg-api-client

```rust
use cityg_client::CityGClient;
use cityg_api_client::CitygApiClient;

let api = CitygApiClient::new("http://localhost:8080");

// Generate epoch
let bundle = CityGClient::generate_epoch(...)?;

// Submit via API
let response = api.accept_epoch(&bundle.bundle_cbor).await?;
println!("Accepted! Epoch ID: {:?}", response.we_epoch_id);
```

### With GUI Applications

See `crates/cityg-gui` for a complete desktop application using this crate.

## Related Crates

- **[msphf-orchestrator](../msphf-orchestrator/)** - Low-level proof generation
- **[cityg-server](../cityg-server/)** - Server-side validation
- **[cityg-api-client](../cityg-api-client/)** - HTTP API client

## See Also

- [Protocol Documentation](../../docs/protocol/00-README.md)
- [Client Operations](../../docs/protocol/08-client-operations.md)
- [Witness Validation](../../docs/protocol/04-witness-validation.md)
- [GUI User Guide](../../docs/gui-user-guide.md)

## License

MIT License - see [LICENSE](../../LICENSE) file.

---
**Status**: Current implementation for the `v0.1.4` base profile.
