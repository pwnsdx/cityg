# Repository Cleanup Plan (2026-03-29)

## Goal

Make the repository cleaner, lighter, easier to review, and easier to maintain
without weakening the current protocol profile or breaking any existing tests,
gates, or evidence trails.

This plan is intentionally conservative:

- preserve current runtime behavior;
- preserve all passing tests and CI gates;
- reduce drift between spec, docs, code, scripts, and evidence;
- simplify the repository by extraction, archival, and normalization rather than
  by risky rewrites.

## Current Baseline

Repository signals observed on 2026-03-29:

- `357` tracked files.
- `137573` total Rust LOC under `crates/`.
- `docs/` is `6.6M`; `crates/` is `5.5M`; `kat/` is `2.5M`.
- Largest tracked code files:
  - `crates/cityg-server/src/lib.rs` (`16363` lines, `620K`)
  - `crates/cityg-gui/src/native/tests/mod.rs` (`14928` lines, `524K`)
  - `crates/cityg-api/src/lib.rs` (`8765` lines, `316K`)
  - `crates/cityg-api-client/src/lib.rs` (`8637` lines, `348K`)
  - `crates/msphf-orchestrator/src/accept/mod.rs` (`8178` lines, `304K`)
  - `crates/cityg-gui/src/bin/join_leave.rs` (`6714` lines, `236K`)
- Largest tracked non-code files:
  - `docs/evidence/dudect/vrf_verify.csv` (`4.6M`)
  - `kat/kat-rlwe-annex-k.json` (`2.4M`)
  - `docs/whitepaper/whitepaper.pdf` (`300K`)
  - `docs/evidence/cachegrind/cachegrind.out.2512` (`136K`)
- The normative spec is concentrated in `docs/specs.md` (`1989` lines), while
  `docs/protocol/` still contains `11642` lines of legacy companion material.
- Several top-level docs still carry stale "Last Updated" markers from
  `2025-11-*` or `2026-02-25`, despite the repo having moved materially since.
- Local developer state is operationally noisy:
  `.cargo-target/` contains many slot directories from prior validation runs.

## Cleanup Principles

1. Keep the spec authoritative and minimize parallel explanations.
2. Split by domain boundary, not by arbitrary line count.
3. Prefer extracting tests and fixtures over editing protocol logic unless
   behavior simplification is proven safe.
4. Keep evidence reproducible, but do not keep every generated artifact in git.
5. A cleanup change is complete only if formatting, clippy, CI gates, and the
   affected focused tests still pass.

## Workstream A: Spec and Documentation Consolidation

### A1. Normalize the documentation hierarchy

Problem:

- `docs/specs.md` is authoritative, but the repo still carries a large set of
  "legacy companion" chapters that overlap heavily with the spec.
- Readers have to cross-check multiple places to understand what is current.

Actions:

- Keep `docs/specs.md` as the only normative protocol source.
- Convert `docs/protocol/` into a smaller companion set:
  - keep only explanatory chapters that add value;
  - archive redundant chapters that mostly restate the spec;
  - replace duplicated sections with short "see spec section Sx.y" pointers.
- Create a single source-of-truth map from each companion doc to the spec
  sections it expands.

Exit criteria:

- Every protocol rule exists in exactly one normative place.
- Every companion doc states clearly whether it is:
  - normative;
  - explanatory;
  - historical;
  - roadmap/future work.

### A2. Remove stale metadata and drift markers

Problem:

- Multiple docs still advertise stale dates or older profile framing.
- This weakens reviewer trust even when the underlying content is correct.

Actions:

- Sweep all `Last Updated` markers in `README.md`, `docs/README.md`,
  `docs/GLOSSARY.md`, `docs/gui-user-guide.md`, `docs/workflows.md`,
  `docs/TROUBLESHOOTING.md`, crate READMEs, and similar docs.
- Replace date stamps that are hard to maintain with either:
  - a generated date policy; or
  - no date at all, when git history is a better source.
- Run a terminology sweep for:
  - `v0.1.2`
  - `v0.1.3`
  - `legacy companion`
  - stale audit references that should now point to the current profile state.

Exit criteria:

- No stale date/profile markers remain in active docs.
- Legacy profile references are either archived or explicitly historical.

### A3. Compress the audit surface

Problem:

- The audit files are useful but historically layered and verbose.
- They are hard to reread because the current verdict is mixed with tranche
  history.

Actions:

- Keep the current consolidated verdicts, but move tranche-by-tranche history
  into an archive directory or appendix.
- Reduce each `docs/audits/*.txt` to:
  - original findings summary;
  - final verdict table;
  - final code/spec proofs;
  - link to archived tranche history if needed.
- Keep `docs/audits/final-verification-report-2026-03-26.md` as the canonical
  index, but trim repeated narrative where it duplicates per-audit summaries.

Exit criteria:

- Audits remain evidence-grade, but an external reviewer can parse the final
  state without wading through every tranche note.

### A4. Tighten user/operator docs

Problem:

- `README.md`, `docs/README.md`, `api-reference.md`, `preproduction-validation`,
  and the protocol checklist each contain overlapping status framing.

Actions:

- Make `README.md` shorter and product-facing.
- Make `docs/README.md` the routing layer.
- Keep `docs/protocol/20-protocol-checklist.md` purely guarantee-to-flow.
- Keep `docs/preproduction-validation.md` purely operational.
- Move long explanatory duplication out of `README.md`.

Exit criteria:

- Each major doc has one job.
- Cross-links replace duplication.

## Workstream B: Codebase Modularization

### B1. Split `cityg-server`

Problem:

- `crates/cityg-server/src/lib.rs` is too large to review effectively.
- Runtime logic, persistence, room administration, recovery, and tests live in
  the same file.

Target split:

- `server_state.rs`
- `server_persistence.rs`
- `server_recovery.rs`
- `server_room_admin.rs`
- `server_acceptance_helpers.rs`
- `server_bundle_store.rs`
- `tests/` submodules by theme

Priority:

- Highest structural cleanup target in the repo.

Exit criteria:

- Main `lib.rs` becomes an index/orchestration layer, not the entire server.
- Server tests remain discoverable but move into themed modules.

### B2. Split `cityg-gui` native tests

Problem:

- `crates/cityg-gui/src/native/tests/mod.rs` is effectively a test suite
  database, not a maintainable module.

Target split:

- `tests/join_and_send.rs`
- `tests/replay_and_restart.rs`
- `tests/admin_and_expel.rs`
- `tests/recovery_and_epoch_sync.rs`
- `tests/hostile_inputs.rs`
- `tests/watch_and_backlog.rs`
- shared `tests/fixtures.rs` and `tests/helpers.rs`

Exit criteria:

- Named domains replace one giant test file.
- Shared builders/fixtures remove repeated setup logic.

### B3. Split API and API client monoliths

Problem:

- `cityg-api/src/lib.rs` and `cityg-api-client/src/lib.rs` each mix transport,
  validation, artifacts, paging logic, helpers, and tests.

Target split:

- `pb.rs`
- `routes/*.rs` or `handlers/*.rs`
- `validation/*.rs`
- `history_authority.rs`
- `deployment_manifest.rs`
- `pagination.rs`
- `tests/*.rs`

Exit criteria:

- Bundle validation and helper-page verification logic are isolated and easier
  to fuzz independently.

### B4. Split `join_leave` and `msphf-orchestrator` hotspots

Problem:

- `join_leave.rs` is both a binary, a harness, and a large test container.
- `msphf-orchestrator/src/accept/mod.rs` carries too much acceptance logic in
  one file.

Actions:

- Move reusable harness logic from `join_leave.rs` into a small library module.
- Leave the binary as thin CLI glue.
- Extract orchestrator acceptance stages into clearer thematic modules.

Exit criteria:

- The binary entrypoints are thin.
- Acceptance logic becomes navigable by stage.

## Workstream C: Legacy Surface Removal and Spec Conformance Purge

### C1. Inventory every legacy surface against `docs/specs.md`

Problem:

- The repo now has a much clearer current profile in `docs/specs.md`, but some
  old names, compatibility paths, test-only extensions, fallback wording, and
  comments may still survive in code or docs.
- Modularization alone is not enough if it merely preserves dead or ambiguous
  branches.

Actions:

- Build a concrete inventory of legacy surfaces that are no longer part of the
  current normative profile.
- Classify each item as one of:
  - remove entirely;
  - keep but mark `test-only` or `historical`;
  - adapt to current profile wording/behavior;
  - archive outside active code/docs.
- Use repo sweeps to find candidates such as:
  - old profile/version identifiers;
  - superseded extension IDs or aliases;
  - compatibility shims no longer needed by `docs/specs.md`;
  - stale comments that describe removed protocol states;
  - dead tests that only validate retired behavior;
  - old CLI/help text and script comments;
  - legacy docs references that still imply active support.

Exit criteria:

- Every remaining legacy surface has an explicit reason to exist.
- No ambiguous "maybe active, maybe historical" protocol surface remains.

### C2. Remove dead runtime code and obsolete compatibility paths

Problem:

- Old branches and compatibility helpers increase attack surface, review cost,
  and maintenance burden.
- Some paths may now be impossible or forbidden under the current profile, yet
  still exist in the codebase as dormant support.

Actions:

- Remove code paths that no current spec section, test, or supported runner
  requires.
- Collapse obsolete enum variants, helper wrappers, and fallback branches where
  the current profile now has only one valid behavior.
- Delete dead glue introduced only to support older profile transitions that are
  no longer accepted.
- Remove stale feature gates, compatibility env vars, and deprecated script
  toggles where they no longer serve the current profile.

Exit criteria:

- Active runtime behavior is a closer, smaller implementation of the current
  spec.
- The repo contains fewer dormant branches and fewer "compatibility-only"
  helpers.

### C3. Purge obsolete protocol mentions from active docs and code comments

Problem:

- Even when runtime behavior is correct, old names and comments create review
  drift and make auditors think the repo supports more than it really does.

Actions:

- Sweep active docs, READMEs, script help text, inline comments, and error
  strings for:
  - superseded profile names;
  - outdated extension framing;
  - removed guarantees;
  - old rollout assumptions;
  - comments that contradict `docs/specs.md`.
- Replace them with:
  - current terminology;
  - explicit `historical` or `test-only` framing;
  - links/pointers to the canonical spec section when helpful.

Exit criteria:

- Active docs and comments describe the current profile only.
- Historical wording is either archived or explicitly marked as such.

### C4. Add regression guards against legacy reintroduction

Problem:

- Without explicit guardrails, removed legacy names and code paths tend to
  creep back in through comments, scripts, or compatibility patches.

Actions:

- Add lightweight repo checks for disallowed legacy markers in active docs/code.
- Add a short allowlist for intentional survivors such as:
  - `historical` docs;
  - `test-only` extension identifiers;
  - archived audit/evidence material.
- Fold these checks into the cleanup/CI workflow once the purge is complete.

Exit criteria:

- The repo has a deliberate mechanism that catches reintroduction of retired
  protocol surface.

## Workstream D: Test and E2E Harness Cleanup

### D1. Normalize the runtime test taxonomy

Actions:

- Standardize naming patterns:
  - `*_preserves_*`
  - `*_rejects_*`
  - `*_recovers_*`
  - `*_without_duplicate_delivery`
- Introduce a compact index doc mapping guarantees to exact tests.
- Remove redundant tests where one stronger flow fully subsumes a weaker one.

Exit criteria:

- Fewer overlapping test names.
- Easier to identify which flow proves which guarantee.

### D2. Extract shared E2E fixtures

Problem:

- Large GUI/API tests likely carry repeated room/bootstrap/member setup.

Actions:

- Introduce shared builders for:
  - room bootstrap
  - multi-member setup
  - restart/reload sequences
  - admin grant/revoke/expel flows
  - hostile mutation helpers

Exit criteria:

- Lower test LOC without losing coverage.
- Less copy-pasted setup across GUI/API/server suites.

### D3. Reclassify long-running flows

Actions:

- Separate:
  - deterministic fast tests;
  - chaos runners;
  - soak runners;
  - mutation/property runners.
- Ensure docs and CI refer to the same categories and commands.

Exit criteria:

- Reviewers can tell which gates are per-PR and which are confidence campaigns.

## Workstream E: Repository Weight Reduction

### E1. Shrink tracked evidence

Problem:

- Some generated evidence files are much larger than their value in day-to-day
  review.

Highest candidates:

- `docs/evidence/dudect/vrf_verify.csv`
- `docs/evidence/cachegrind/cachegrind.out.2512`
- large generated whitepaper outputs

Actions:

- Keep a compact checked-in summary plus reproduction command.
- Move raw generated artifacts to:
  - compressed archives;
  - release artifacts;
  - CI-uploaded artifacts; or
  - a dedicated external evidence store.
- Keep only what is necessary for offline review.

Exit criteria:

- Evidence remains reproducible.
- Git clone/review footprint drops materially.

### E2. Clean historical/generated document clutter

Actions:

- Decide whether to keep generated `whitepaper.pdf`, `.log`, `.aux`, `.out`,
  `.bbl`, `.blg` in git.
- If the PDF is kept, remove auxiliary build outputs.
- Archive old migration/conformance changelog docs that are no longer active.

Exit criteria:

- The repo keeps source, not avoidable build byproducts.

### E3. Formalize local workspace cleanup

Problem:

- `.cargo-target/*` slot sprawl is operationally useful but visually noisy.

Actions:

- Add a supported cleanup script for stale local target slots.
- Document retention policy:
  - persistent slots worth keeping;
  - disposable slots safe to prune.
- Consider a naming convention that separates:
  - CI slots;
  - local debug slots;
  - campaign slots.

Exit criteria:

- Local disk state stops growing without bound.
- Developers know which target dirs are safe to remove.

## Workstream F: CI and Developer Experience

### F1. Simplify CI workflow structure

Problem:

- `.github/workflows/cityg.yml` is readable, but it now mixes strict PR gates,
  release matrix, nightly chaos, and artifact builds.

Actions:

- Split into separate workflows:
  - `ci.yml` for fast required checks
  - `release-matrix.yml`
  - `nightly-chaos.yml`
  - `artifacts.yml`
- Reuse shared setup via scripts or composite actions.

Exit criteria:

- Required CI is easier to reason about.
- Nightly and optional jobs stop cluttering the primary workflow.

### F2. Unify script contracts

Actions:

- Standardize script flags, environment variables, and output layout.
- Ensure every runner writes predictable:
  - `summary.txt`
  - `server.log`
  - `restarts.log`
  - `client-restarts.log`
  - health/metrics snapshots when relevant

Exit criteria:

- Every runner feels like the same tool family.

### F3. Tighten lint debt

Problem:

- The repo is passing clippy now, but it still contains multiple targeted
  `#[allow(...)]` pockets, large-argument functions, and some dead-code
  accommodations.

Actions:

- Triage every `#[allow(dead_code)]` and `#[allow(clippy::too_many_arguments)]`
  in production modules.
- Replace long argument lists with small config structs where it improves
  readability.
- Keep test-specific `allow` blocks only where they are truly justified.

Exit criteria:

- The remaining `allow` list is short, deliberate, and documented.

## Workstream G: Performance and Maintainability

### G1. Remove needless text duplication

Actions:

- Replace repeated protocol explanations with:
  - one canonical explanation;
  - short pointers elsewhere.
- Shorten README and operator docs to the minimum high-signal form.

Exit criteria:

- Less prose to maintain for the same meaning.

### G2. Reduce fixture and harness duplication

Actions:

- Identify repeated JSON/test fixture patterns across `kat/`, server tests, API
  integration, and GUI tests.
- Consolidate generators/builders where feasible.

Exit criteria:

- Fewer manually duplicated fixture blobs.

### G3. Re-measure after cleanup

Actions:

- Re-run:
  - `cargo fmt --all -- --check`
  - strict clippy
  - `cargo check --workspace --all-targets --locked`
  - focused protocol gates
  - chaos/mutation runners as needed
- Capture before/after:
  - top file sizes
  - total tracked artifact size
  - major doc sizes
  - LOC of the biggest modules

Exit criteria:

- Cleanup is measurable, not just aesthetic.

## Recommended Execution Order

### Phase 0: Freeze and Baseline

1. Capture current file/size/LOC baseline.
2. Freeze cleanup branch scope: no protocol redesign mixed into cleanup.

### Phase 1: Documentation Rationalization

1. Stale date/profile sweep.
2. Spec/companion doc boundary cleanup.
3. Audit compression and archival.
4. README/docs index simplification.

### Phase 2: Test Surface Cleanup

1. Inventory and classify legacy code/comments/names against `docs/specs.md`.
2. Remove obsolete compatibility branches and retired wording.
3. Split GUI tests.
4. Split API integration tests by domain.
5. Extract shared E2E fixtures/builders.
6. Normalize runner docs and artifact contracts.

### Phase 3: Code Modularization

1. Split `cityg-server`.
2. Split `cityg-api` and `cityg-api-client`.
3. Split `join_leave`.
4. Split orchestrator acceptance hotspots.

### Phase 4: Weight Reduction

1. Decide evidence retention policy.
2. Remove generated byproducts from git where safe.
3. Add local target-slot cleanup workflow.

### Phase 5: CI and Lint Cleanup

1. Split workflows.
2. Reduce remaining `allow(...)` debt.
3. Re-run strict gates and campaign runners.

## Success Metrics

The cleanup is done when the following are true:

- `docs/specs.md` remains the only normative protocol source.
- `README.md` and `docs/README.md` are shorter and non-redundant.
- The biggest runtime modules are materially smaller and domain-split.
- `cityg-server/src/lib.rs`, `cityg-api/src/lib.rs`,
  `cityg-api-client/src/lib.rs`, `cityg-gui/src/native/tests/mod.rs`, and
  `cityg-gui/src/bin/join_leave.rs` are no longer monoliths.
- The audit surface is easier to read without losing evidence.
- Large generated artifacts are minimized or moved out of git.
- Strict CI still passes.
- All currently valid tests remain valid.

## Immediate High-Value Tranches

If cleanup starts now, the best first tranches are:

1. stale docs/date/profile sweep;
2. inventory and classify legacy code/docs/comments against `docs/specs.md`;
3. remove obsolete compatibility paths and retired protocol wording;
4. split `cityg-gui` native tests by domain;
5. split `cityg-server` test modules out of `lib.rs`;
6. archive or compress oversized evidence artifacts;
7. split the single GitHub workflow into fast CI vs nightly/chaos.
