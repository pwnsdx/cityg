# Proof Size Metrics

- **Command**: `cargo +nightly test -p msphf-orchestrator --lib -- --nocapture tests::vrf_proof_sizes_distribution > docs/evidence/proof_metrics/proof_sizes.log`
- **Summary**:
  - Join proofs: min = 5336 bytes, max = 5336 bytes, avg ≈ 5336 bytes
  - Merge proofs: min = 5336 bytes, max = 5336 bytes, avg ≈ 5336 bytes
- **Environment**: Linux target hardware (record CPU/kernel when known)
- **Notes**: data currently based on test fixtures; update with live telemetry when available.

