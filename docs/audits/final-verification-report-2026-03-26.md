# Final Verification Report (2026-03-26)

Scope: re-verify every finding from `docs/audits/1.txt` through `docs/audits/7.txt` against the current `docs/specs.md` and the current implementation.

Status legend:
- `Closed`: the original finding is now satisfied by the current spec and/or code, with concrete proof references.
- `Partial`: materially improved, but the underlying protocol or implementation gap is not fully closed.
- `Open`: still not corrected.
- `Reclassified`: not retained as a local defect in `docs/specs.md` or current code; usually a multi-doc boundary or an over-claimed finding.

Verification method:
- Re-read all seven audits and extracted each original finding.
- Correlated each point against the current spec and implementation.
- Verified live repo hygiene with `git status --short` clean, `git diff --check` clean, and `cargo metadata --locked --format-version 1 --no-deps` succeeding under `scripts/cargo_repo_env.sh`.
- Used existing targeted tests as proof anchors where they exist.

Scope-hardening addendum (same date, later tranche):
- `docs/specs.md` now explicitly defines `HistoryAuthorityScope` and states that authenticated acceptance/finality is scoped to one such authority, not to an implicit global/federated consensus object.
- `docs/specs.md` now also states explicitly that `current_barrier_full_verified` is a client-local predicate and that `header[180]` proves helper-state coherence, not FULL verification to the server.
- `docs/specs.md` and the server now reserve `header[181]` for a future FULL-verification-receipt extension and reject it in the base profile unless such an extension is explicitly enabled.
- `docs/specs.md` and the server now also reserve `header[182]` for a future global-history-attestation extension and reject it in the base profile unless such an extension is explicitly enabled.
- As a result, some previously listed `Open` items are now better interpreted as `extension required / intentionally out of base profile`, not as latent contradictions inside the base profile text. The per-item matrix below remains a conservative baseline unless otherwise noted in a later audit comment.

Summary:
- Total findings reviewed: `51`
- `Closed`: `18`
- `Partial`: `13`
- `Open`: `16`
- `Reclassified`: `4`

## Audit 1

- `1.1` `Closed` — bootstrap `join_finalize` no longer depends on a circular `H_prev`.
  Proof: `docs/specs.md:1111-1124` defines `H_prev_bootstrap` from the authenticated predecessor of `BU_current`.
- `1.2` `Closed` — `header[97]` now carries an explicit wire discriminator between `author-local` and `barrier-recovery`.
  Proof: `docs/specs.md:271-303`, `crates/msphf-orchestrator/src/lib.rs:737-845`, `crates/msphf-orchestrator/src/accept/stages.rs:210-244,714-736`.
- `1.3` `Closed` — exact CBOR array lengths are now normative and testable.
  Proof: `docs/specs.md:574-579`, `docs/specs.md:907-926`.
- `1.4` `Closed` — `ResolveJoinsSince` / `JoinSet` semantics are now explicit for the selected authenticated view.
  Proof: `docs/specs.md:197-213`.
- `1.5` `Reclassified` — “closed-world registry / merge profile” remains a documentation packaging problem, not a local implementation defect closed in this pass.
  Proof: no local wire or server patch changes this; the spec still spans multiple normative areas.
- `1.6` `Closed` — `960.11` vs `960.13` conflict is resolved by explicit partitioning.
  Proof: `docs/specs.md:754-758`, `docs/specs.md:1167-1184`, `docs/specs.md:1601-1624`.
- `1.7` `Closed` — `PayloadEnvelope.msg_index` position is explicit.
  Proof: `docs/specs.md:557-579`.

## Audit 2

- `2.1` `Closed` — `header[99]` must be recomputed after HP decryption before using `header[97]`.
  Proof: `docs/specs.md:309-323`; KAT coverage in `docs/specs.md:1643-1650`.
- `2.2` `Closed` — `profile_version` is now explicitly bound into `bind_fs` and therefore into ZK-VRF proof verification.
  Proof: `docs/specs.md:683-698`, `crates/msphf-orchestrator/src/proofs/zk_vrf/mod.rs:23-36`, `crates/msphf-orchestrator/src/proofs/zk_vrf/lb.rs:123-157`, `crates/msphf-orchestrator/src/lib.rs:121,3009-3023`, `crates/msphf-orchestrator/src/proofs/zk_vrf/lb.rs:455-466`.
- `2.3` `Reclassified` — the “missing `gid/weid` in bind_fs” claim is too strong as stated because `xk_hash` already carries handshake context; the remaining gap is documentary, not a confirmed local defect.
  Proof: `docs/specs.md:162`, `docs/specs.md:279-313`, `docs/specs.md:642-656`.
- `2.4` `Closed` — barrier/HP KDFs now bind `gid` directly in the spec and in the concrete barrier/HP derivation helpers.
  Proof: `docs/specs.md:324-338`, `docs/specs.md:1072-1127`, `docs/specs.md:1390-1402`, `docs/specs.md:1716-1731`, `crates/msphf-orchestrator/src/lib.rs:698-845`, `crates/cityg-gui/src/barrier_shared.rs:47-55`, `crates/cityg-gui/src/native/barrier_core.rs:33-39,689-706`, `crates/cityg-gui/src/native/tests/mod.rs:1484-1539`, `crates/cityg-client/src/lib.rs:699-705,718-735`, `crates/msphf-orchestrator/tests/end_to_end.rs:954-988`.
- `2.5` `Partial` — recover-only misuse is reduced by persistent `current_barrier_full_verified`, but still not protocol-enforced end-to-end.
  Proof: `docs/specs.md:1093-1096`, `docs/specs.md:1154-1157`, `crates/cityg-gui/src/native/session_types.rs:72-99`, `crates/cityg-gui/src/native/barrier_ops.rs:214-251`.
- `2.6` `Closed` — sender/device binding is enforced in code, and the message plane now signs with the same persisted device identity family that the sender-leaf binding checks derive from; the spec also makes `leaf_id(device_pk)` deterministic per `(gid, device_pk, device_pk_alg)` and non-reassignable across distinct device keys within a `gid`.
  Proof: `docs/specs.md:176-178`, `docs/specs.md:600-606`, `crates/cityg-gui/src/native/message_auth.rs:97-156,388-437`, `crates/cityg-gui/src/native/network_messages.rs:14-50,188-203`, `crates/cityg-gui/src/native/tests/mod.rs:7606-7659,8670-8740`, `crates/cityg-gui/src/bin/join_leave.rs:873-970,2311-2328`.

## Audit 3

- `3.1` `Open` — activation still does not require a globally final, non-equivocable history object.
  Proof: `docs/specs.md:1420-1434` improves local correlation, but `docs/specs.md:170` explicitly says `HistoryCommitment` is not a global consensus object.
- `3.2` `Open` — supersession/fork is still not defined as a globally canonical authenticated lineage.
  Proof: `docs/specs.md:165-170`, `docs/specs.md:225-233`.
- `3.3` `Partial` — restart correlation is now monotone locally through `LookupMergeAcceptance`, but only for a single server-local history.
  Proof: `docs/specs.md:1420-1434`, `crates/cityg-server/src/lib.rs:6384-6399`, `crates/cityg-gui/src/native/barrier_runtime.rs:594-655`.
- `3.4` `Open` — recover-only clients still rely on honest-client local gating, not on a server-verifiable protocol proof of FULL verification.
  Proof: `docs/specs.md:1154-1157`.
- `3.5` `Open` — “must ensure current state is covered” still lacks a globally authenticated head/finality mechanism.
  Proof: `docs/specs.md:170`, `docs/specs.md:180-189`, `docs/specs.md:1427-1434`.
- `3.6` `Open` — crash is handled, but storage rollback/fork detection is still not normatively closed.
  Proof: `docs/specs.md:1429-1434`; no equivalent rollback-resistant head requirement exists.
- `3.7` `Open` — FS/PCS reorder handling is still not fully specified as a client state machine with future/gap rules.
  Proof: no normative state machine was added for delayed `pcs_refresh` anchor order.

## Audit 4

- `4.1` `Open` — recover-only to updater / `pcs_refresh` remains mostly honest-client-enforced, not fully protocol-enforced.
  Proof: `docs/specs.md:1154-1157` restricts behavior normatively, but there is no server-verifiable FULL proof for reasons `0/1`.
- `4.2` `Partial` — `join_finalize` is now server-checkable via `header[179] join_finalize_auth`, and the end-to-end path now accepts the reserved helper headers and tolerates later same-tree re-attestation during bootstrap, but it still does not prove full public-state verification to the server.
  Proof: `docs/specs.md:1155-1174`, `docs/specs.md:1579-1583`, `crates/msphf-orchestrator/src/accept/mod.rs:1884-1949`, `crates/cityg-server/src/lib.rs:2381-2438,4022-4085,10705-10735`, `crates/cityg-gui/src/native/barrier_core.rs:568-589`, `crates/cityg-gui/src/native/tests/mod.rs:8589-8658,9070-9130`.
- `4.3` `Closed` — provenance that the current barrier state is not FULL-verified is now persisted and surfaced.
  Proof: `docs/specs.md:458-465`, `crates/cityg-gui/src/native/session_types.rs:72-99`, `crates/cityg-gui/src/native/persisted/barrier.rs:56-57,334-405`.
- `4.4` `Open` — recover-only to FULL promotion is still not backed by a globally authenticated head; the circularity is reduced but not eliminated.
  Proof: `docs/specs.md:1111-1124`, `docs/specs.md:1154-1157`.
- `4.5` `Open` — “FULL” still covers multiple meanings: local full-tree check, local current-state eligibility, and stronger active-server claims.
  Proof: the spec narrows usage but still lacks a single wire-visible proof object for FULL status.
- `4.6` `Open` — the “applicable `ek_n` verification” path is still not globally anchored enough to rule out vacuous server-steered contexts.
  Proof: `docs/specs.md:1115-1124` improves bootstrap checks, but relies on local/current authenticated artifacts rather than global canonity.
- `4.7` `Partial` — current version/current tree/current JoinSet binding is much tighter now through shared `HistoryCommitment`, `header[180]`, helper-state binding, and explicit current-commitment treatment for the immediate predecessor snapshot used by the normal FULL chain-check.
  Proof: `docs/specs.md:180-189`, `docs/specs.md:1157`, `docs/specs.md:1181-1190`, `crates/cityg-server/src/lib.rs:2396-2445,4443-4450,10749-10780`, `crates/cityg-gui/src/native/join_ops.rs:220-247`, `crates/cityg-gui/src/native/barrier_ops.rs:312-320,882-905`, `crates/cityg-gui/src/bin/join_leave.rs:376-416,1432-1440,1870-1878,5746-5761`, `crates/cityg-gui/src/native/tests/mod.rs:7636-7659`.
- `4.8` `Partial` — external history/provisioning dependencies are more constrained, but still not fully closed against a byzantine server.
  Proof: `docs/specs.md:1455-1478`; remaining lack of global finality/canonity is still explicit at `docs/specs.md:170`.

## Audit 5

- `5.1` `Closed` — A/B/C/D now require a shared `history_view_id` plus shared `HistoryCommitment`.
  Proof: `docs/specs.md:180-189`.
- `5.2` `Closed` — `JoinSet` semantics are now exact for the selected committed view.
  Proof: `docs/specs.md:197-213`.
- `5.3` `Partial` — the missing history/finality lookup was fixed locally with `LookupMergeAcceptance`, but not as a global byzantine-finality system.
  Proof: `docs/specs.md:225-233`, `docs/specs.md:1420-1434`, `crates/cityg-server/src/lib.rs:6384-6399`, `crates/cityg-api-client/src/lib.rs:2327-2331`.
- `5.4` `Reclassified` — room-admin authorization remains a multi-doc normative boundary, not a local defect of this file alone.
  Proof: this was intentionally scoped outside `docs/specs.md`.
- `5.5` `Closed` — sender identity is no longer optional in practice on the message plane, and the concrete send path now signs with the same persisted sender device key family that receivers bind back to `sender_leaf_id`.
  Proof: `docs/specs.md:566-572`, `crates/cityg-gui/src/native/message_auth.rs:97-156`, `crates/cityg-gui/src/native/network_messages.rs:14-50,188-203`, `crates/cityg-gui/src/native/tests/mod.rs:7606-7659,8670-8740`.
- `5.6` `Reclassified` — opaque external proof/KDF suites remain a registry/documentation issue; not enough evidence to call the current local implementation unsafely weak from this repo alone.
  Proof: `docs/specs.md:162-163`, `docs/specs.md:1479-1484`.
- `5.7` `Partial` — join provisioning now has nonce/issuance/expiry/current history commitment, and bootstrap verification no longer falsely rejects a same-tree later re-attestation, but it still is not a standalone globally authenticated lineage artifact.
  Proof: `docs/specs.md:1455-1478`, `docs/specs.md:1579-1583`, `crates/cityg-api/proto/cityg.proto:243,248-251`, `crates/cityg-api-client/src/lib.rs:988-1038`, `crates/cityg-gui/src/native/barrier_core.rs:568-589`.
- `5.8` `Partial` — retention/fetch/config contracts are better tied to history and now have hard helper paging / replay-state bounds, but still are not backed by one signed global deployment manifest and global canonity.
  Proof: `docs/specs.md:220-238`, `docs/specs.md:618-638`, `docs/specs.md:1532`, and the remaining open Audit 2 / Audit 3 findings.

## Audit 6

- `6.1` `Closed` — `N_max` is now bounded and enforced fail-closed across layers.
  Proof: `docs/specs.md:899-900`, `crates/cityg-server/src/lib.rs:11014-11032`, `crates/cityg-api-client/src/lib.rs:1914-1925,2440-2457,2987-3010`, `crates/cityg-gui/src/barrier_shared.rs:9-10`.
- `6.2` `Closed` — retained historical public-tree state is now normatively and concretely bounded.
  Proof: `docs/specs.md:229-231`, `crates/cityg-server/src/lib.rs:3143-3182`, `crates/cityg-server/src/lib.rs:10631-10680`.
- `6.3` `Closed` — payload envelope size is bounded in spec and code.
  Proof: `docs/specs.md:563-565`, `crates/cityg-gui/src/message_crypto.rs:816-846`.
- `6.4` `Open` — FULL chain-check still fundamentally needs whole-tree work in the general case.
  Proof: `docs/specs.md:1093-1104`, `docs/specs.md:1117-1122`.
- `6.5` `Closed` — A/B/C now have explicit page framing, bounded page size, and client-side aggregation checks tied to one `HistoryCommitment`.
  Proof: `docs/specs.md:194-238`, `crates/cityg-api/proto/cityg.proto:303-358`, `crates/cityg-api/src/lib.rs:197,900-942,2497-2618,6326-6354`, `crates/cityg-api-client/src/lib.rs:181,1188-1464,2358-2407,2757-2869`.
- `6.6` `Closed` — unresolved joins are now bounded by `N_max`, and resolved/revoked join activations are pruned from server state.
  Proof: `docs/specs.md:218`, `docs/specs.md:994-995`, `crates/cityg-server/src/lib.rs:1603`, `crates/cityg-server/src/lib.rs:2331`, `crates/cityg-server/src/lib.rs:3102-3141`, `crates/cityg-server/src/lib.rs:10203-10257`.
- `6.7` `Closed` — anti-replay durability cost is now normatively bounded per tuple/context, obsolete tuples are collectable, batching is explicitly allowed, and the GUI persists replay state before releasing fetched messages.
  Proof: `docs/specs.md:616-638`, `crates/cityg-gui/src/message_crypto.rs:9-120`, `crates/cityg-gui/src/native/network_messages.rs:85-118,147-149,225`, `crates/cityg-gui/src/native/session_fetch.rs:111-175`, `crates/cityg-gui/src/native/tests/mod.rs:2702-2753`.
- `6.8` `Closed` — CBOR determinism is now a rejection property, not one mandated re-encode algorithm.
  Proof: `docs/specs.md:83-92`.

## Audit 7

- `7.1` `Open` — snapshot authentication is still not a proof of globally canonical history.
  Proof: `docs/specs.md:165-170`, `docs/specs.md:215-223`.
- `7.2` `Partial` — clients now replay a mandatory client-visible subset of activation invariants before committing recovered or locally pending barrier state, but they still do not replay the full server-side S10 policy surface.
  Proof: `docs/specs.md:1168-1174`, `docs/specs.md:1470-1496`, `crates/cityg-gui/src/native/barrier_runtime.rs:486-655`, `crates/cityg-gui/src/native/epoch_sync.rs:65-206`, `crates/cityg-gui/src/native/barrier_ops.rs:107-171`, `crates/cityg-gui/src/native/tests/mod.rs:250-592,6200-6260,7184-7321`.
- `7.3` `Partial` — `ResolveJoinsSince` is now tied to an exact authenticated view and shared commitment, but not yet to a globally canonical target state with completeness proof.
  Proof: `docs/specs.md:180-189`, `docs/specs.md:197-213`, `crates/cityg-gui/src/bin/join_leave.rs:376-416,1432-1440,1870-1878`.
- `7.4` `Open` — omission/completeness proofs for joins/revocations are still missing.
  Proof: `docs/specs.md:183` leaves proof/object format deployment-defined; no completeness proof is mandated.
- `7.5` `Partial` — recover-only is now explicit, persisted, and escalates to `recovery_required`, but still remains a server-imposable degraded mode until FULL is re-established locally.
  Proof: `crates/cityg-gui/src/native/barrier_runtime.rs:91-99,603-655`.
- `7.6` `Partial` — policy/governance/provisioning are better bound to current history, but not yet to a globally canonical authenticated lineage.
  Proof: `docs/specs.md:1455-1478`.
- `7.7` `Partial` — fault reactions are more operationally meaningful through explicit recovery-required state, but still do not define cross-source/quarantine handling against a byzantine server.
  Proof: `crates/cityg-gui/src/native/barrier_runtime.rs:91-99,626-655`.

## Strongest closed proofs

- Shared authenticated view and local append-only history commitment:
  `docs/specs.md:180-189`, `crates/cityg-server/src/lib.rs:2574-2599`, `crates/cityg-server/src/lib.rs:10363-10395`.
- Server-checkable `join_finalize` exception:
  `docs/specs.md:1155-1157`, `docs/specs.md:1467-1469`, `crates/cityg-server/src/lib.rs:4022-4085`.
- Join provisioning freshness/binding:
  `docs/specs.md:1455-1478`, `crates/cityg-api/proto/cityg.proto:243,248-251`, `crates/cityg-api-client/src/lib.rs:988-1038`.
- Sender leaf binding on the message plane:
  `docs/specs.md:566-572`, `crates/cityg-gui/src/native/message_auth.rs:139-156`, `crates/cityg-gui/src/native/network_messages.rs:188-203`.
- Hard `N_max` and payload caps:
  `docs/specs.md:563-565`, `crates/cityg-server/src/lib.rs:11014-11032`, `crates/cityg-api-client/src/lib.rs:1914-1925`, `crates/cityg-gui/src/message_crypto.rs:816-846`.
- Explicit `profile_version` binding in `bind_fs`:
  `docs/specs.md:683-698`, `crates/msphf-orchestrator/src/proofs/zk_vrf/mod.rs:23-36`, `crates/msphf-orchestrator/src/proofs/zk_vrf/lb.rs:123-157`.
- Direct `gid` binding in barrier/HP KDFs:
  `docs/specs.md:324-338`, `docs/specs.md:1072-1127`, `docs/specs.md:1716-1731`, `crates/msphf-orchestrator/src/lib.rs:698-845`, `crates/cityg-gui/src/native/tests/mod.rs:1484-1539`.
- Self-describing HP transport forms and deterministic sender leaf semantics:
  `docs/specs.md:271-303`, `docs/specs.md:600-606`, `crates/msphf-orchestrator/src/lib.rs:737-845`, `crates/msphf-orchestrator/src/accept/stages.rs:210-244,714-736`, `crates/cityg-gui/src/native/message_auth.rs:139-156,388-437`.
- End-to-end sender/device signing and predecessor-snapshot helper coherence:
  `docs/specs.md:1181-1190`, `crates/cityg-gui/src/native/message_auth.rs:97-156`, `crates/cityg-gui/src/native/network_messages.rs:14-50`, `crates/cityg-server/src/lib.rs:2396-2445,10749-10780`, `crates/cityg-gui/src/native/tests/mod.rs:7606-7659,8670-8740`.
- Bounded and crash-safe anti-replay release path:
  `docs/specs.md:616-638`, `crates/cityg-gui/src/message_crypto.rs:9-120`, `crates/cityg-gui/src/native/network_messages.rs:107-118,147-149,225`, `crates/cityg-gui/src/native/session_fetch.rs:119-175`, `crates/cityg-gui/src/native/tests/mod.rs:2702-2753`.

## Highest-priority remaining work

1. Add a globally canonical, append-only, authenticated history/finality object, not just a server-local `HistoryCommitment`.
2. Decide whether FULL/recover-only is only an honest-client rule or must become a server-verifiable protocol property.
3. Add completeness proofs or equivalent fail-closed semantics for `ResolveJoinsSince` / `ResolveRevokedLeaves`.
4. Decide whether to add a bounded-cost authenticated-cache / proof path for FULL verification, instead of relying on whole-tree work in the general case.
