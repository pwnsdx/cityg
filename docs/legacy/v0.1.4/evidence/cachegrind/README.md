# Cachegrind / ctgrind Run Log

- **Command**: `valgrind --tool=cachegrind --branch-sim=yes --log-file=docs/evidence/cachegrind/ct_vrf.log cargo +nightly run -p msphf-orchestrator --release --example ct_vrf -- --filter vrf_verify_ct`
- **Toolchain**: nightly Cargo / rustc (see `rustup show` on the host)
- **Environment**: Linux (target hardware; record CPU model/kernel here)
- **Notes**: command completed successfully; see `ct_vrf.log` for instruction and branch statistics.

- **cachegrind.out**: see `docs/evidence/cachegrind/cachegrind.out.2512` (inspect with `cg_annotate` on a host that has Valgrind tools installed).
