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
| Stale active wording (`alpha`, `v0.1.0`, `legacy companion`) | [`crates/cityg-worker/README.md`](./../crates/cityg-worker/README.md) | `adapt` | The parallel worker migration tranche is still normalizing the worker-facing README. Keep the active repo entrypoints aligned with the current `v0.1.4` base profile. |
| Historical profile-transition changelogs | [`spec-conformance-changelog-v0.1.2.md`](./spec-conformance-changelog-v0.1.2.md), [`spec-conformance-changelog-v0.1.3.md`](./spec-conformance-changelog-v0.1.3.md), [`spec-conformance-changelog-v0.1.4.md`](./spec-conformance-changelog-v0.1.4.md), [`todo-migration-0.1.2.md`](./todo-migration-0.1.2.md) | `historical` | Keep for audit traceability, but keep them clearly secondary to `specs.md` and the final verification report. |
| `local-history-authority-v1` identifiers and parsers | [`crates/cityg-api-client/src/lib.rs`](./../crates/cityg-api-client/src/lib.rs), [`crates/cityg-server/src/lib.rs`](./../crates/cityg-server/src/lib.rs), [`crates/cityg-gui/src/native/persisted/barrier.rs`](./../crates/cityg-gui/src/native/persisted/barrier.rs) | `test-only` | The current spec still retains this identifier as a non-base legacy/test-only extension. Keep fail-closed parsing/rejection paths, but do not treat it as an active production branch. |
| Protocol companion chapters with old compatibility notes | [`docs/protocol/`](./protocol/00-README.md) | `historical` / `adapt` | Top-level framing is now standardized, but many chapters still contain deep historical `Alpha (0.1.0)` citations and duplicated blueprint commentary that should be trimmed or archived over time. |
| Stale deployment example version markers | [`docs/examples/kubernetes-deployment.yml`](./examples/kubernetes-deployment.yml) | `adapt` | Example manifests must track the current profile naming unless intentionally historical. |
| `docs/legacy-specs.md` | [`docs/legacy-specs.md`](./legacy-specs.md) | `historical` | Now explicitly marked as a retired archive; a later tranche can decide whether to move it under a clearer archive path. |

## Intentionally Retained Bridges

- [`crates/pqcrypto-kyber`](./../crates/pqcrypto-kyber/README.md):
  retained intentionally as a stable local Rust API bridge over `ml-kem-768`.
  It is no longer tracked here as a legacy surface because it does not imply a
  separate wire/profile mode.

## Recommended Next Code Tranches

1. Continue trimming `docs/protocol/*` by moving retired behavior and obsolete
   compatibility notes into explicitly historical documents.
2. Recheck remaining rejection-only helpers for wording that still implies
   active compatibility support rather than fail-closed legacy rejection.
3. Continue removing or reclassifying legacy-only comments and examples that
   still make active surfaces look older than the current `v0.1.4` profile.
