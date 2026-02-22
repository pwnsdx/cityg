# CityG Spec Verification Report (Updated 2026-02-22)

This report cross-references the `city-g unified spec v0.1.2` against the Rust implementation in `/crates/`.

## 1. Spec Violations Addressed
In recent commits, the following violations were resolved:

### 1.1 `H_L` Hash Function Implementation (RESOLVED)
**Previous Status:** The normative definition of `H_L` in the spec requested standard `BLAKE3`, but the codebase used BLAKE3 `derive_key` mode context `city-g|h_l|v1`. 
**Resolution:** The specification (`docs/specs.md`) was updated in commit `2e2b137` to explicitly mandate `BLAKE3_derive_key` with context `city-g|h_l|v1`, bringing the spec in line with the rigorous domain-separation implemented in `crates/msphf-core/src/hash.rs`.

### 1.2 KEM Implementation Mismatch (RESOLVED)
**Previous Status:** The spec mandated `ML-KEM-768` (FIPS 203 standard) but the application invoked the pre-standard `Kyber-768` algorithm via `pqcrypto-kyber`, breaking cryptographic interoperability.
**Resolution:** Commit `4e98d25` introduced a shim that wraps the FIPS-compliant `ml-kem` crate beneath the older `pqcrypto-kyber` API. The code now physically executes ML-KEM-768 internally, perfectly matching the spec.

### 1.3 FS Derivation Labels & Barrier Diagnostics (RESOLVED)
**Previous Status:** There were minor mismatch issues between spec and implementation regarding FS derivation labels and server error codes (Freezes instead of strings).
**Resolution:** Commits `2e2b137` and `89e9705` aligned the FS derivation labels (e.g. `fs/step/salt`, `city-g|fs/tau|v1`) strictly to the spec and fixed the server acceptance diagnostics to correctly emit the `9608` hash-chain freeze code.

## 2. Pending Optimizations & Suggestions

### 2.1 Msg_Index Strictly Monotonic State (S8.2) (PENDING)
**Implementation:**
`native.rs` maintains `session.next_msg_index` and performs a `persist_session` write to disk for *every single message* sent to guarantee crash-safe strictly monotonic indices.
**Improvement:**
While compliant with the spec, blocking synchronous disk I/O on every message send creates a major bottleneck. The spec explicitly permits a globally unique random 64-bit `msg_index` + anti-replay state instead. Adopting this would significantly improve message throughput in the GUI.

### 2.2 Deterministic CBOR Parsing & Barrier Threading (PARTIALLY ADDRESSED)
**Observation (updated):** In `native.rs`, deterministic-CBOR verification now parses once into `Value`, validates canonical encoding, then deserializes `Value` into typed structures. This removes the previous second raw-byte parse path, but still incurs DOM materialization and canonical re-encode costs for large barrier payloads.
**Progress:** Commit `4fafc99` offloaded the heavy `compute_barrier_tree_hash` chain checks to a background CPU worker thread (`spawn_blocking`), preventing GUI freeze issues under large barrier updates.
**Next Steps:** For very large `N_max`, further optimization is still possible via a deterministic CBOR streaming validator (to avoid full DOM materialization) while preserving strict S1.3 canonicality guarantees.
