# CityG Spec Conformance Changelog (v0.1.2)

Last updated: 2026-02-24  
Scope: protocol/spec conformance and related hardening/performance work.

## Purpose
This changelog provides PR-ready traceability from shipped commits to the normative sections in `/Users/admin/Desktop/Repositories/cityg/docs/specs.md`.

## Conformance and Security Milestones

| Date | Commit | Change | Spec sections | Outcome |
|---|---|---|---|---|
| 2026-02-22 | `4e98d25` | Backed `pqcrypto-kyber` API with ML-KEM-768 shim | S2.5 | Aligns runtime KEM behavior with ML-KEM-768 requirement while preserving API compatibility. |
| 2026-02-22 | `2e2b137` | Aligned barrier diagnostics and SRX proofs-commit invariants; updated spec text | S2.2, S9.1, S13 | Removes ambiguity in H_L/diagnostics interpretation and enforces SRX all-or-none proofs inputs. |
| 2026-02-22 | `4fafc99` | Added S14 conformance manifest and linked tests | S14.1-S14.6 | Makes KAT/conformance coverage auditable from a single manifest. |
| 2026-02-22 | `89e9705` | Aligned FS derivation labels and emitted freeze `9608` for tree-hash-chain failure | S6.2, S6.3, S11.12.1(G), S13 | Restores FS label/info compatibility and makes hash-chain rejection code explicit. |
| 2026-02-23 | `e21bc67` | Switched GUI to randomized `msg_index` + replay-state persistence | S8.2 | Removes per-message durability bottleneck while keeping anti-replay semantics allowed by spec. |
| 2026-02-23 | `c04bbfd` | Enforced barrier updater identity binding and update-size checks in server validation | S4.4, S11.12.1(F) | Closes acceptance gap for updater mismatch and oversized barrier updates. |
| 2026-02-24 | `de7c0c1` | Surfaced freeze `9609` for barrier snapshot auth failures | S11.12.1(G/H), S13 | Distinguishes snapshot-auth failures from generic malformed cases in diagnostics. |

## Hardening and Performance Follow-through

| Date | Commit | Change | Notes |
|---|---|---|---|
| 2026-02-23 | `90884e3` | Optimized barrier CBOR parsing and device-chain lookup paths | Reduces overhead in barrier validation hot paths. |
| 2026-02-23 | `13b6065` | Avoided barrier tree hash clone on hot path | Shrinks unnecessary allocations during validation. |
| 2026-02-24 | `d82df78` | Optimized bundle staging and tightened malformed mapping | Better staging efficiency and stricter freeze mapping behavior. |
| 2026-02-24 | `a917919` | Optimized barrier validation snapshot handling | Reduces avoidable work across before/after snapshot checks. |
| 2026-02-24 | `88d5045` | Expanded malformed barrier error normalization | Improves consistent freeze-code emission. |
| 2026-02-24 | `0efc028` | Persisted device-chain state across kbroad restart | Protects continuity across process restarts. |
| 2026-02-24 | `f181c43` | Optimized barrier validation hash recomputation | Cuts redundant recomputation in validation flow. |
| 2026-02-24 | `9c68e29` | Added journal replay test for PCS refresh state | Verifies `last_pcs_refresh_ec` survives restart/replay. |
| 2026-02-24 | `e8a3ec8` | Mapped invalid barrier validation inputs to freeze `9607` | Stronger type-based malformed mapping in server path. |
| 2026-02-24 | `84cf81d` | Added malformed-roots freeze mapping test | Ensures malformed roots header normalizes to `9607`. |
| 2026-02-24 | `b40b195` | Avoided eager barrier tree entry clones on read paths (`Cow`) | Reduces clone pressure in fetch/hash read flows. |

## Benchmarks and Evidence

- Benchmark note commit: `33f5cb8`  
  Evidence path: `/Users/admin/Desktop/Repositories/cityg/docs/evidence/benchmarks/gui-msg-index-and-barrier-2026-02-22.md`
- S14 manifest path: `/Users/admin/Desktop/Repositories/cityg/kat/kat-s14-conformance-manifest-v0.1.2.json`

## Remaining Non-Blocking Item

1. Incremental barrier tree hashing for very large `N_max`:
   - Current behavior is already optimized versus earlier baselines.
   - A full incremental hash update algorithm (delta-apply over `new_public_keys`) is a broader refactor with performance upside at large scales.
   - No current spec conformance impact.

