# Upstream Sync Plan

The following changes diverge from the original `zhenfeizhang/lb-vrf` repository:

- Structured error handling (`error.rs`) and public `Result` alias.
- Zeroization and constant-time veneers for key material and equality checks.
- RNG API that accepts external `CryptoRng + RngCore` in addition to deterministic seeds.
- Property-based tests for polynomial arithmetic and updated benchmark harness.

To keep the fork maintainable, we should prepare a pull request against the upstream project summarizing these commits. Steps:

1. Rebase our changes onto the latest upstream `master` once the repository is active again.
2. Split the work into logical PRs (errors/zeroization, constant-time fixes, RNG API, tests/benchmarks).
3. Include benchmark numbers (see `BENCHMARKS.md`) and the security rationale for constant-time changes.
4. Coordinate with upstream maintainers for review.

Until that happens, treat this vendored copy as authoritative for the orchestrator build.
