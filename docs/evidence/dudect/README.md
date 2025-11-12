# Dudect Run Log

- **Command (VRF)**: `cargo +nightly run -p msphf-orchestrator --release --example ct_vrf -- --out docs/evidence/dudect/vrf_verify.csv --filter vrf_verify_ct`
- **Summary** (Apple M3 Max): `n == +0.188M, max t = -2.19476, max tau = -0.00507, (5/tau)^2 = 973119`
- **Output**: CSV stored at `docs/evidence/dudect/vrf_verify.csv`

- **Command (CAPSS Smallwood prove)**: `cargo run -p dudect-harness --release -- --target smallwood-prove --samples 200000 --inner 16 --seed 24237 > docs/evidence/dudect/smallwood_prove.txt`
- **Command (CAPSS Smallwood verify)**: `cargo run -p dudect-harness --release -- --target smallwood-verify --samples 200000 --inner 16 --seed 24237 > docs/evidence/dudect/smallwood_verify.txt`
- **Summary** (Apple M3 Max, Welch t > 4.5 ⇒ bias observed):
  - Prove (2025-10-28): `mean₀ = 462911.09 ns, mean₁ = 462694.63 ns, |t| = 2.17`
  - Verify (2025-10-28): `mean₀ = 193288.89 ns, mean₁ = 193240.39 ns, |t| = 1.23`
- **Output**: Logs stored at `docs/evidence/dudect/smallwood_prove.txt` and `docs/evidence/dudect/smallwood_verify.txt`

- **Command (RLWE primitives)**: `cargo run -p dudect-harness --release -- --target <target> --samples 200000 --inner 16 --seed 4242 > docs/evidence/dudect/<target>.txt`
- **Summary** (Apple M3 Max):
  - `barrett_reduce`: `mean₀ = 27.45 ns, mean₁ = 27.36 ns, |t| = 1.22`
  - `montgomery_reduce`: `mean₀ = 28.02 ns, mean₁ = 28.14 ns, |t| = 0.80`
  - `montgomery_add`: `mean₀ = 32.04 ns, mean₁ = 32.22 ns, |t| = 0.89`
  - `montgomery_sub`: `mean₀ = 31.82 ns, mean₁ = 32.60 ns, |t| = 1.75`
  - `expand_a`: `mean₀ = 268450.90 ns, mean₁ = 268454.68 ns, |t| = 0.08`
- **Output**: Logs stored under `docs/evidence/dudect/*.txt`

(Record the CPU model / kernel version here once confirmed.)
