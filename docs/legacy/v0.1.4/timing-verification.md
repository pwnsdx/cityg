# Timing Verification Plan

This note captures the steps required to empirically test the constant-time
properties of two critical subsystems:

1. RLWE arithmetic helpers (`msphf-core::rlwe::*`), introduced in October 2025.
2. CAPSS Smallwood prover / verifier (`crates/capss::smallwood`),
   now wired into the dudect harness.

## Scope

We will cover:

- `arithmetic::{barrett_reduce, montgomery_add, montgomery_sub, montgomery_reduce}`
- `matrix::generate_poly` (via a thin wrapper that invokes the rejection
  sampler with random seeds)
- `capss::smallwood::prove` and `capss::smallwood::verify` on the deterministic
  production pipeline.

## Tooling

- Workspace-local harness (`crates/dudect-harness`) that implements a simple
  Welch’s t-test over nanosecond timings.
- Optional: upstream [dudect](https://github.com/oreparaz/dudect) for deeper
  TVLA validation once the lightweight harness flags any suspicious results.
- We run in `--release` mode to avoid debug assertions skewing timings.

## Harness Layout

```
crates/
  dudect-harness/
    Cargo.toml
    src/main.rs
```

`dudect-harness` depends on `msphf-core` and `capss` (path deps) and evaluates
each target by:

1. Allocate fixed-size input buffers.
2. Invoke the function under test with two classes of inputs (e.g., all zeros vs.
   cryptographically random data) while measuring execution time.
3. Emit dudect’s statistical report to stdout.

The current default runs 100,000 samples per class with an inner loop of 128
iterations (configurable via CLI flags). For a full dudect-style run we should
scale to millions of samples; the harness already supports arbitrarily large
values if the host CPU is fast enough.

## Execution Instructions

```
# quick run (barrett_reduce)
cargo run -p dudect-harness --release -- --target barrett-reduce --samples 50000 --inner 512

# CAPSS Smallwood prover / verifier
cargo run -p dudect-harness --release -- --target smallwood-prove --samples 20000 --inner 8
cargo run -p dudect-harness --release -- --target smallwood-verify --samples 20000 --inner 8
```

The binary prints mean timings and the Welch t-statistic; any |t| > 4.5 should
be treated as a potential leak. Capture the stdout into
`artifacts/timing/<target>.txt` for audit records (current snapshots exist for
`barrett_reduce`, `montgomery_{reduce,add,sub}`, and `expand_a`; see
`artifacts/timing/summary.json` for aggregated results).

### Unsafe NTT Feature Flag

The `msphf-core` crate now exposes an `unsafe-ntt` feature that switches the
NTT implementation back to unchecked indexing. Run the same dudect harnesses
with this feature enabled to ensure both code paths stay constant-time:

```
cargo run -p dudect-harness --release --features unsafe-ntt -- --target barrett-reduce --samples 50000 --inner 512
```

Repeat for every target that touches the NTT routines (currently `barrett`,
`montgomery_*`, and `expand_a`).

### Latest Welch t-statistics

| target | samples | inner | Welch t |
|--------|---------|-------|---------|
| barrett_reduce | 200,000 | 16 | 1.22 |
| montgomery_reduce | 200,000 | 16 | 0.80 |
| montgomery_add | 200,000 | 16 | 0.89 |
| montgomery_sub | 200,000 | 16 | 1.75 |
| expand_a | 200,000 | 16 | 0.08 |
| smallwood_prove | 200,000 | 16 | 2.17 |
| smallwood_verify | 200,000 | 16 | 1.23 |

After the constant-time hardening, the Smallwood prover and verifier now land
comfortably below the |t| = 4.5 alert threshold.

## Remaining Work

- [x] Implement in-tree harness (`crates/dudect-harness`).
- [x] Run high-sample tests for each target (including Smallwood prove/verify)
      and archive the results.
- [x] Investigate and harden CAPSS Smallwood prove/verify so the dudect
      t-statistic falls below 4.5.
- [x] Integrate the harness into CI once the initial run succeeds.
- [ ] Mirror each run with `--features unsafe-ntt` to cover the unchecked path.
