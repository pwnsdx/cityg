# Annex V Evidence Capture Checklist

The cryptographic plumbing now enforces the Appendix VI bindings; the remaining compliance work is to collect
and archive runtime evidence on the target hardware. Use this checklist whenever you prepare a release build.

## 1. Constant-time analysis (dudect)

Run the dudect harness on the deployment platform and export the raw traces. Examples:

```bash
# runs the ct_vrf harness and records results in CSV form
cargo +nightly run -p msphf-orchestrator --release --example ct_vrf -- \
  --out docs/evidence/dudect/vrf_verify.csv --filter vrf_verify_ct

# runs the Smallwood prove/verify targets from the in-tree dudect harness
cargo run -p dudect-harness --release -- --target smallwood-prove --samples 200000 --inner 16 \
  > docs/evidence/dudect/smallwood_prove.txt
cargo run -p dudect-harness --release -- --target smallwood-verify --samples 200000 --inner 16 \
  > docs/evidence/dudect/smallwood_verify.txt
```

Archive the CSV together with the command line, machine model, and compiler version in
`docs/evidence/dudect/README.md` (create if missing). If the harness emits plain text
instead of CSV (e.g., for the CAPSS targets), archive the stdout logs.

## 2. ctgrind / cachegrind

Collect a per-instruction trace using ctgrind (or cachegrind if ctgrind is unavailable):

```bash
valgrind --tool=cachegrind --branch-sim=yes --log-file=docs/evidence/cachegrind/ct_vrf.log \
  cargo +nightly run -p msphf-orchestrator --release --example ct_vrf -- --filter vrf_verify_ct
```

Include the log file and a short note describing the hardware, valgrind version, and any anomalies.

## 3. Proof size & latency metrics on production workloads

Capture join and merge proof statistics from real telemetry (or a realistic workload):

```bash
cargo +nightly test -p msphf-orchestrator --lib -- --nocapture tests::vrf_proof_sizes_distribution \
  > docs/evidence/proof_metrics/proof_sizes.log
```

After running against real data, replace the fixture output with aggregates (min/mean/max) and the sample size.

For latency, re-use the `msphf-lb-vrf` bench feature:

```bash
cargo +nightly bench -p msphf-lb-vrf --features bench --bench basic \
  -- --save-baseline docs/evidence/benchmarks/msphf_lb_vrf
```

Document the hardware, operating system, and compiler flags in `docs/evidence/benchmarks/README.md`.

## 4. Audit trail

Once raw artefacts are collected, update `docs/annex_v_status.md` with:

- the location of the archived dudect CSV and summary statistics,
- ctgrind/cachegrind aggregate results,
- proof size / latency summaries for join and merge workloads.

Keep the raw files in this `docs/evidence/` tree so they can be attached to audit bundles.

## 5. E2E performance / chaos

For end-to-end runtime throughput and restart-chaos evidence on the current profile, see:

- [e2e-performance-validation-2026-03-30.md](/Users/admin/Desktop/Repositories/cityg/docs/evidence/e2e-performance-validation-2026-03-30.md)

## 6. System inventory

Run the helper script to capture hardware and toolchain information:

```bash
bash docs/evidence/system-info-commands.sh
```

This writes `docs/evidence/system-info.md`; include CPU, kernel, and rustc/valgrind versions for the audit trail.
