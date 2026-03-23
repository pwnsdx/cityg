# Security Audit Status (2026-03-23)

Scope: consolidation of the March 2026 security and spec-conformance review threads against the current `main` branch.

## Corrected

| ID | Status | Notes |
| --- | --- | --- |
| RT-LV-02 | Fixed | `check_norm(i64::MIN)` now fails closed and is regression-tested. |
| RT-LV-01 | Fixed | `hash_to_challenge` now guarantees exactly `KAPPA` distinct coefficients; regression inputs cover previously short-weight outputs such as `probe-8`. |
| RT-SRX-01 | Fixed | `compute_shadow_root` now disambiguates optional `None` vs all-zero payloads. |
| API-DEBUG-01 | Fixed | `/v1/debug/window/seed` requires admin auth in debug builds. |
| API-AUTH-01 | Fixed | Sensitive endpoints now require message auth. |
| API-ADMIN-01 | Fixed | `CITYG_SERVER_ALLOW_INSECURE_ADMIN=1` no longer opens admin endpoints without tokens. |
| API-WS-01 | Fixed | Native clients moved WebSocket auth off the query string. |
| API-MEM-01 | Fixed | Stored epoch bundles are pruned with their indexes. |
| API-DOS-01 | Mitigated | Expensive endpoints now have explicit concurrency budgets. |
| SPEC-DOC-01 | Fixed | Secondary protocol docs now use `fs/dev/chain/v2`. |
| SPEC-DOC-02 | Fixed | `HDR_PARENT_ROOT` and `HDR_JOIN_DELTA_ROOT` are named constants. |
| SPEC-DOC-03 | Fixed | `barrier/update/digest` is listed in the label registry doc. |
| SERVER-KBROAD-LIVE-01 | Fixed | Persisted restart now seeds KBROAD room state before replay, carries live pivot parities across new roots, and passes the canonical restart + survivor refresh + fresh join regression. |

## Not Confirmed

| ID | Status | Notes |
| --- | --- | --- |
| SERVER-KBROAD-REPLAY-01 | Not confirmed | The claimed replay failure path depends on `accept_epoch`, but recovery replays via `stage_bundle`. Existing persisted KBROAD restart tests are green. |
| CAPSS-BINCODE-01 | Mitigated | `decode_proof` now re-encodes and requires byte-for-byte canonical equality before accepting CAPSS proof bytes. |

## Still Open / Further Investigation

| ID | Status | Notes |
| --- | --- | --- |
| LBVRF-RS-BOUND-01 | Mitigated | `prove_with_rs` now hard-fails after a large deterministic cap; keep collecting empirical attempt counts if this path is exercised in practice. |
| API-RATE-02 | Fixed | Expensive endpoints now enforce a keyed sliding-window budget in addition to concurrency caps, with regression coverage on `accept_epoch`, `join_ticket`, and `search_members`. |
| TEST-FUZZ-01 | Mitigated | Added malformed `bundle_cbor` matrices for `accept_epoch` and `refresh_pivot`, a partial-length journal truncation regression, and broader canonical-Unicode alias coverage. Keep full fuzz/property jobs on the backlog. |

## Evidence

- `a3fc67c` `fix lb-vrf norm checks and rand 0.10 fallout`
- `40d266c` `secure api auth and absorb rand axum fallout`
- `a65d7c4` `prune expired bundles and epoch indexes`
- `e17705c` `move websocket auth off query string for native clients`
- `020af1e` `disambiguate srx shadow root optional fields`
- `12ad0ee` `bound expensive api endpoint concurrency`
- `13ad55b` `fail closed admin auth without configured tokens`
- `91268ec` `align v0.1.4 label docs and header constants`
- `647fd65` `fix lb-vrf challenge sampling and bound retries`
- `32690bf` `enforce canonical CAPSS proof transcripts`
