# Legacy Surface Inventory (2026-03-30)

This inventory supports Workstream C in
[`repo-cleanup-plan-2026-03-29.md`](./repo-cleanup-plan-2026-03-29.md).
It classifies remaining legacy or compatibility surfaces against the current
normative profile in [`specs.md`](./specs.md).

## Status Legend

- `remove`: no longer needed for the current profile; delete in a future tranche.
- `adapt`: still useful, but wording, names, or examples must be updated.
- `historical`: keep for audit/transition traceability, but mark non-normative.
- `test-only`: retained only because the spec explicitly preserves a non-base
  identifier or negative-coverage surface.

## Current Inventory

| Surface | Location | Classification | Reason / next action |
|---|---|---|---|
| Stale active wording (`alpha`, `v0.1.0`, `legacy companion`) | [`README.md`](./../README.md), [`docs/README.md`](./README.md), [`docs/constraints.md`](./constraints.md), crate READMEs | `adapt` | Active reader entrypoints must describe the current `v0.1.4` base profile without stale maturity/version framing. |
| Historical profile-transition changelogs | [`spec-conformance-changelog-v0.1.2.md`](./spec-conformance-changelog-v0.1.2.md), [`spec-conformance-changelog-v0.1.3.md`](./spec-conformance-changelog-v0.1.3.md), [`spec-conformance-changelog-v0.1.4.md`](./spec-conformance-changelog-v0.1.4.md), [`todo-migration-0.1.2.md`](./todo-migration-0.1.2.md) | `historical` | Keep for audit traceability, but keep them clearly secondary to `specs.md` and the final verification report. |
| `local-history-authority-v1` identifiers and parsers | [`crates/cityg-api-client/src/lib.rs`](./../crates/cityg-api-client/src/lib.rs), [`crates/cityg-server/src/lib.rs`](./../crates/cityg-server/src/lib.rs), [`crates/cityg-gui/src/native/persisted/barrier.rs`](./../crates/cityg-gui/src/native/persisted/barrier.rs) | `test-only` | The current spec still retains this identifier as a non-base legacy/test-only extension. Keep fail-closed parsing/rejection paths, but do not treat it as an active production branch. |
| `pqcrypto-kyber` compatibility shim surface | [`crates/pqcrypto-kyber/Cargo.toml`](./../crates/pqcrypto-kyber/Cargo.toml) and crate body | `adapt` | The shim still exists to expose the `pqcrypto-kyber::kyber768` API over ML-KEM. Future cleanup should decide whether to rename/re-scope it now that the spec is explicit about ML-KEM-768. |
| Merkle compatibility helper | [`crates/msphf-core/src/merkle.rs`](./../crates/msphf-core/src/merkle.rs) (`hash_interval_binding_v1_compat`) | `remove` | Candidate for removal once all tests and fixtures confirm the old binding path is no longer needed. |
| Rejection-only “compat” guards | [`crates/cityg-api/src/lib.rs`](./../crates/cityg-api/src/lib.rs) (`websocket_handler_rejects_query_token_compat`) and related tests | `adapt` | Keep the fail-closed behavior, but rename the remaining helpers/tests to “legacy rejection” or similar to reduce ambiguity. |
| Protocol companion chapters with old compatibility notes | [`docs/protocol/`](./protocol/00-README.md) | `historical` / `adapt` | Companion chapters still carry older compatibility commentary. Keep useful explanation, but trim or archive duplicated/retired behavior as Workstream A continues. |
| Stale deployment example version markers | [`docs/examples/kubernetes-deployment.yml`](./examples/kubernetes-deployment.yml) | `adapt` | Example manifests must track the current profile naming unless intentionally historical. |
| `docs/legacy-specs.md` | [`docs/legacy-specs.md`](./legacy-specs.md) | `historical` | Keep as an archive only if explicitly marked retired; otherwise archive or move under a clearer historical path in a later tranche. |

## Recommended Next Code Tranches

1. Remove or retire compatibility helpers no longer required by the current
   profile, starting with Merkle binding compatibility code if tests allow it.
2. Rename rejection-only “compat” tests/helpers so they read as fail-closed
   guards rather than active compatibility support.
3. Continue trimming `docs/protocol/*` by moving retired behavior and obsolete
   compatibility notes into explicitly historical documents.
