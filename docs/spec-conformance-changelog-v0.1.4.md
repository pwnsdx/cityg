# CityG Spec Conformance Changelog (v0.1.4)

Last updated: 2026-03-22
Scope: protocol/spec conformance and related hardening/performance work.

## Purpose
This changelog provides PR-ready traceability from shipped commits to the normative sections in `docs/specs.md`.

Note on versioning:
- The implementation now advertises wire/API `profile_version = v0.1.4`.
- `v0.1.4` is a real wire-profile revision from `v0.1.3`, not a repository-only errata layer.
- The canonical repository references for this profile revision are `docs/specs.md` and this changelog, as of the repository revision being audited or released.

## Baseline and Conformance Milestones

The entries below include the carried-forward `v0.1.2` baseline and the `v0.1.4` profile revision point.

| Date | Commit | Change | Spec sections | Outcome |
|---|---|---|---|---|
| 2026-02-22 | `4e98d25` | Backed `pqcrypto-kyber` API with ML-KEM-768 shim | S2.5 | Aligns runtime KEM behavior with ML-KEM-768 requirement while preserving API compatibility. |
| 2026-02-22 | `2e2b137` | Aligned barrier diagnostics and SRX proofs-commit invariants; updated spec text | S2.2, S9.1, S13 | Removes ambiguity in H_L/diagnostics interpretation and enforces SRX all-or-none proofs inputs. |
| 2026-02-22 | `4fafc99` | Added S14 conformance manifest and linked tests | S14.1-S14.6 | Makes KAT/conformance coverage auditable from a single manifest. |
| 2026-02-22 | `89e9705` | Aligned FS derivation labels and emitted freeze `9608` for tree-hash-chain failure | S6.2, S6.3, S11.12.1(G), S13 | Restores FS label/info compatibility and makes hash-chain rejection code explicit. |
| 2026-02-23 | `e21bc67` | Switched GUI to randomized `msg_index` + replay-state persistence | S8.2 | Removes per-message durability bottleneck while keeping anti-replay semantics allowed by spec. |
| 2026-02-23 | `c04bbfd` | Enforced barrier updater identity binding and update-size checks in server validation | S4.4, S11.12.1(F) | Closes acceptance gap for updater mismatch and oversized barrier updates. |
| 2026-02-24 | `de7c0c1` | Surfaced freeze `9609` for barrier snapshot auth failures | S11.12.1(G/H), S13 | Distinguishes snapshot-auth failures from generic malformed cases in diagnostics. |
| 2026-02-24 | `5474dec` | Migrated to server-blind `K_barrier` provisioning | S11.13, S11.14, S12.2, S12.3 | Removes server-side barrier secret role and makes joiners wait for Kem-Tree recovery instead of server provisioning. |
| 2026-02-24 | `2faa66b` | Sender-scoped payload tuple and committed historical barrier tree fetch | S3.3(C), S8.2-S8.5, S10.3, S11.11.1-S11.11.2 | Eliminates cross-sender `msg_index` ambiguity and lets FULL clients fetch historical committed trees by hash. |
| 2026-02-24 | `fedce86` | Added restart-persistence test for historical barrier tree snapshots | S3.3(C), S11.11.1, S11.11.2 | Verifies historical committed tree fetch survives persisted-state reloads. |
| 2026-02-24 | `495eca8` | Added sender-scoped replay regression coverage | S8.2-S8.4 | Proves same `msg_index` from different senders does not collide in replay tracking or payload derivation. |
| 2026-03-13 | `2f475a3` | Tightened barrier recovery sequencing and patched remaining freeze blockers in spec text | S3.2, S3.3(B), S8.1-S8.5, S11.6, S11.11.1, S11.11.3, S11.13.3, S11.14.2, S12.0, S12.2, S12.3 | Adds explicit genesis provisioning artifact, removes invalid joiner-local `K_fs` option, blocks recover-only clients from originating updates before FULL verification, and hardens local recovery sequencing/reason checks. |
| 2026-03-14 | `00eb972` | Switched updater restart correlation from current-version heuristics to specific merge-history correlation | S11.14.1-S11.14.4 | Uses persisted pending merge identity and authenticated history instead of treating `current barrier_version > pending_barrier_version` as a loss signal. |
| 2026-03-15 | `2f36dee` | Forbade timeout-only pending-state discard without authenticated finality | S11.14.3, S11.14.4 | Prevents updater self-stranding when acceptance history is delayed or temporarily unavailable. |
| 2026-03-15 | `896c44c` | Clarified finality-vs-supersession discard rule for pending updater state | S11.14.3, S11.14.4 | Makes discard semantics explicitly disjunctive: either superseded by a committed update or dead by authenticated finality. |
| 2026-03-22 | `TBD` | Removed legacy HP transport, made `barrier-sealed-v1` the sole header[97] mode, and bumped the advertised wire profile to `v0.1.4` | S3.4, S10.4-S10.4C, S11.11.1, S11.11.3, S11.12.1, S11.14.2, S12.2, S12.3, S14.7-S14.8 | Makes `barrier-sealed-v1` the only in-profile HP transport, removes legacy room-secret interop, and keeps async-first self-finalizing joins as the sole supported flow. |

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
  Evidence path: `docs/evidence/benchmarks/gui-msg-index-and-barrier-2026-02-22.md`
- S14 manifest path: `kat/kat-s14-conformance-manifest-v0.1.4.json`
- Freeze-blockers manifest path: `kat/kat-freeze-blockers-manifest-v0.1.4.json`

## Remaining Non-Blocking Item

1. Incremental barrier tree hashing for very large `N_max`:
   - Current behavior is already optimized versus earlier baselines.
   - A full incremental hash update algorithm (delta-apply over `new_public_keys`) is a broader refactor with performance upside at large scales.
   - No current spec conformance impact.
