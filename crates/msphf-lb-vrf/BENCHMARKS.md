# LB-VRF Benchmarks (Criterion 0.5)

Measured on 2025-09-28 with `cargo bench --features bench --bench basic` on the current developer machine.

| Benchmark | Mean | Notes |
|-----------|------|-------|
| `one_time_lbvrf/paramgen` | ~142.7 µs | ChaCha20-based parameter generation |
| `one_time_lbvrf/keygen` | ~236.6 µs | Deterministic trinary key derivation |
| `one_time_lbvrf/prove` | ~1.75 ms | Includes rejection sampling loop |
| `one_time_lbvrf/verify` | ~712 µs | Constant-time norm check enabled |
| `poly_ops/mul_trinary` | ~8.26 µs | Constant-time scalar factor selection |
| `poly_ops/mul_general` | ~20.1 µs | School-book multiplication |

These numbers provide a baseline for future optimizations and regression checks. Re-run with the same command after substantial changes to the lattice arithmetic or proof plumbing.

## 2025-09-28 refresh

- Criterion `cargo bench --features bench --bench basic` (release):
  - `one_time_lbvrf/paramgen` mean **150 µs** (regression +~5% vs previous table)
  - `one_time_lbvrf/keygen` mean **242 µs**
  - `one_time_lbvrf/prove` mean **1.77 ms**
  - `one_time_lbvrf/verify` mean **718 µs** (still < Annex V budget of 2 ms server / 6 ms mobile)
- `ct_vrf` dudect_bencher harness (`cargo run -p msphf-orchestrator --release --example ct_vrf -- --filter vrf_verify_ct --out ct_vrf.csv`):
  - Max t-value **1.57**, max tau **0.0035**, implying `(5/τ)^2 ≈ 2.0×10^6`
  - No statistically significant timing difference detected between valid vs mask-corrupted proof verification.

The dudect harness lives in `crates/msphf-orchestrator/examples/ct_vrf.rs`; rerun it after modifying VRF verify/prove paths.
