# Performance Benchmarks

- **GUI FS-Hybrid + Barrier benchmark note (2026-02-22)**:
  - `docs/evidence/benchmarks/gui-msg-index-and-barrier-2026-02-22.md`
  - Focus: strict durable `msg_index` persistence throughput impact and large-`N` barrier chain-check timing.

- **Command**: `cargo +nightly bench -p msphf-lb-vrf --features bench --bench basic -- --save-baseline docs/evidence/benchmarks/msphf_lb_vrf`
- **Summary**:
  - `paramgen`: ~155–158 µs (one_time_lbvrf/paramgen/chaos)
  - `keygen`: ~257–262 µs
  - `prove`: 1.72–1.80 ms
  - `verify`: 714–717 µs
- **Artifacts**: Criterion report under `target/criterion/` (see `target/criterion/report/index.html` for details).
- **Environment**: Linux target hardware (add CPU/kernel details here).
- **Notes**: Benchmarks ran with Criterion; gnuplot not installed so Plotters backend was used.
