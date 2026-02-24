# Server Benchmarks: Incremental Barrier Tree Hash vs Full Rehash

Date: 2026-02-24  
Profile: `cargo test -p cityg-server --release`  
Harness: manual ignored benchmark in `/Users/admin/Desktop/Repositories/cityg/crates/cityg-server/src/lib.rs`:
- `benchmark_barrier_tree_incremental_hash_vs_full_rehash`

## Command

- `cargo test -p cityg-server --lib benchmark_barrier_tree_incremental_hash_vs_full_rehash --release -- --ignored --nocapture`

## Environment

- OS: `Darwin 25.3.0 (arm64)`
- CPU: `Apple M3 Max`
- Rust: `rustc 1.91.1 (ed61e7d7e 2025-11-07)`

## Results

From `BENCH[server_barrier_hash]`:

- `N_max=1024`, `rounds=200`, `changed_nodes=8`
  - full rehash: `2.015 ms/round` (`403.05 ms` total)
  - incremental: `1.054 ms/round` (`210.84 ms` total)
  - speedup: `1.91x`

- `N_max=2048`, `rounds=120`, `changed_nodes=11`
  - full rehash: `3.717 ms/round` (`445.99 ms` total)
  - incremental: `2.031 ms/round` (`243.67 ms` total)
  - speedup: `1.83x`

## Conclusion

- Incremental hashing removes a substantial part of the second full-tree traversal cost in the barrier update validation path.
- In this measured range, validation-side after-hash computation improved by roughly `1.8x–1.9x`.
- The optimization is deterministic and preserves correctness (equivalence test between incremental and full hash is in-tree).

