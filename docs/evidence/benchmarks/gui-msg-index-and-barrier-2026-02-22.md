# GUI Benchmarks: `msg_index` Persistence and Barrier Chain-Check

Date: 2026-02-22  
Profile: `cargo test -p cityg-gui --features native-app --release`  
Harness: manual ignored test benchmarks in `/Users/admin/Desktop/Repositories/cityg/crates/cityg-gui/src/native.rs`:
- `benchmark_msg_index_persistence_cost_profile`
- `benchmark_send_throughput_with_vs_without_msg_index_persist`
- `benchmark_barrier_chain_check_latency_profile`

## Commands

- `cargo test -p cityg-gui --features native-app --release benchmark_msg_index_persistence_cost_profile -- --ignored --nocapture`
- `cargo test -p cityg-gui --features native-app --release benchmark_send_throughput_with_vs_without_msg_index_persist -- --ignored --nocapture`
- `cargo test -p cityg-gui --features native-app --release benchmark_barrier_chain_check_latency_profile -- --ignored --nocapture`

## Results

### 1) Strict durable `msg_index` persistence cost

From `BENCH[msg_index_persist]`:
- Iterations: `2000`
- Total: `43879.16 ms`
- Mean per persisted increment: `21.9396 ms/op`
- Effective persistence rate: `45.6 ops/s`

### 2) Send throughput impact (with vs without per-message persistence)

From `BENCH[send_throughput]`:
- No persist path: `1760.5 msg/s` (`68.16 ms` for `120` sends)
- Strict persist-before-send path: `37.7 msg/s` (`3179.44 ms` for `120` sends)

Computed slowdown:
- `1760.5 / 37.7 ≈ 46.7x` lower throughput with strict per-message durable persistence.

### 3) Large-N barrier chain-check core hash workload

From `BENCH[barrier_chain_check]`:
- `N_max=1024`
  - direct CPU: `2.081 ms/round`
  - `spawn_blocking`: `2.074 ms/round`
- `N_max=2048`
  - direct CPU: `4.162 ms/round`
  - `spawn_blocking`: `4.168 ms/round`

Observations:
- Hash workload scales near-linearly with `N_max` in this range.
- `spawn_blocking` adds negligible overhead while keeping heavy work off the UI path.

## Conclusion

- The current strict monotonic + durable-per-message `msg_index` persistence is spec-compliant but is a severe throughput bottleneck in GUI send path (measured ~46.7x slowdown vs non-persist send loop).
- Barrier chain-check CPU cost is moderate and `spawn_blocking` is effective for responsiveness.
- These data support considering the spec-permitted alternative: random 64-bit `msg_index` with anti-replay state to reduce hot-path disk I/O pressure.
