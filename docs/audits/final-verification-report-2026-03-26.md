# Final Verification Report (2026-03-26)

Scope: re-verify every finding from `docs/audits/1.txt` through `docs/audits/7.txt` against the current `docs/specs.md` and the current implementation.

Canonical reading note:
- The per-audit files intentionally retain historical tranche notes.
- When older tranche commentary disagrees with the final current state, this report and the last `Commentaires Codex ... final coherence` section of each audit file are canonical.

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
- `docs/specs.md` now retains one concrete non-base legacy/test-only deployment-local extension, `local-history-authority-v1`, which carries a scope-local `HistoryAuthorityDescriptor`, helper completeness attestations for A/B/C, a scope-local attested `header[182]`, and a server-verifiable `header[181]` receipt bound to that attestation.
- `docs/specs.md` now also defines one concrete deployment-global extension, `global-history-authority-v1`, which the base profile now requires on join/merge/provisioning/helper/lookup/current-state paths. It carries a deployment-global `HistoryAuthorityDescriptor`, deployment-global helper completeness attestations for A/B/C, a deployment-global attested `header[182]`, and a deployment-global interpretation of `LookupMergeAcceptance`.
- The wire/API contract now carries an explicit `history_authority_extension` identifier on join/merge/helper/lookup responses; in the base profile it MUST equal `global-history-authority-v1`, and clients fail closed on empty/local/unknown values for base-profile paths.
- `docs/specs.md`, the API server, the API client, and the GUI join paths now treat `header[181]` / `header[182]` as base-profile-required companions for authority-bound `barrier_update` decisions, not as forbidden extension-only headers.
- Within both concrete extensions defined by this document, `header[181]` is now mandatory whenever `header[182]` is present on a `barrier_update`; the server normalizes this requirement even when recovering persisted authority state, and GUI activation guards reject authority-bound bundles that carry an attestation without a matching receipt.
- GUI activation guards now also cryptographically verify `header[181]` against the exact `barrier_update`, `header[180]`, `header[182]`, `(gid, author_leaf_id, barrier_update_reason, updater_leaf)` tuple and the author POP public key, instead of treating `header[181]` as a presence-only token on the receive path.
- The server/API/client now negotiate and verify both concrete extensions end-to-end. Positive proof anchors include `tests::build_refresh_bundle_includes_global_history_authority_headers` in `crates/cityg-server/src/lib.rs` and `parses_and_verifies_history_authority_extensions` plus `merge_ticket_refresh_accepts_global_history_authority_attestation` in `crates/cityg-api-client`.
- As a result, the repo/spec now line up on one clear base-profile story: deployment-global append-only authority is in scope, stronger federated/non-equivocation semantics are future-profile work, and no finding remains `Open` or `Partial` in the current base-profile scope.

Summary:
- Total findings reviewed: `51`
- `Closed`: `37`
- `Partial`: `0`
- `Open`: `0`
- `Reclassified`: `14`

Current-scope interpretation:
- No finding remains `Partial` or `Open` within the current base-profile scope implemented by this repo.
- `Reclassified` items are future-profile work, multi-doc boundaries, or stronger guarantees intentionally outside the current profile.

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
- `2.5` `Reclassified` — the remaining ask for remote distinction between locally FULL and locally recover-only execution is now explicitly outside the base profile. The current profile intentionally guarantees helper-state/authority binding plus local origination restrictions, not remote attestation of the client's internal verification path.
  Proof: `docs/specs.md:306`, `docs/specs.md:318-320`, `docs/specs.md:1270-1281`, `crates/cityg-gui/src/native/session_types.rs:72-99`, `crates/cityg-gui/src/native/barrier_ops.rs:214-251`.
- `2.6` `Closed` — sender/device binding is enforced in code, and the message plane now signs with the same persisted device identity family that the sender-leaf binding checks derive from; the spec also makes `leaf_id(device_pk)` deterministic per `(gid, device_pk, device_pk_alg)` and non-reassignable across distinct device keys within a `gid`.
  Proof: `docs/specs.md:176-178`, `docs/specs.md:600-606`, `crates/cityg-gui/src/native/message_auth.rs:97-156,388-437`, `crates/cityg-gui/src/native/network_messages.rs:14-50,188-203`, `crates/cityg-gui/src/native/tests/mod.rs:7606-7659,8670-8740`, `crates/cityg-gui/src/bin/join_leave.rs:873-970,2311-2328`.

## Audit 3

- `3.1` `Reclassified` — the remaining ask for federated or cross-deployment non-equivocation is now explicitly outside the base profile. The current spec intentionally stops at one deployment-global append-only authority.
  Proof: `docs/specs.md:288-306`, `docs/specs.md:1261-1265`, `docs/specs.md:1296-1302`.
- `3.2` `Reclassified` — supersession/fork is now fully defined against the deployment-global authority that the base profile actually requires. The leftover “across deployments” requirement is a stronger future profile, not a defect of the current one.
  Proof: `docs/specs.md:288-306`, `docs/specs.md:1296-1302`, `crates/cityg-server/src/lib.rs:6384-6399`, `crates/cityg-api-client/src/lib.rs:2082-2133`.
- `3.3` `Closed` — restart correlation is now tied to one authenticated deployment-global lineage through `LookupMergeAcceptance` plus the mandatory authority extension.
  Proof: `docs/specs.md:258-264`, `docs/specs.md:288-306`, `docs/specs.md:1420-1434`, `crates/cityg-server/src/lib.rs:6384-6399`, `crates/cityg-gui/src/native/barrier_runtime.rs:594-655`.
- `3.4` `Reclassified` — the current base profile now defines the exact server-verifiable receipt it wants. A stronger independently witnessed FULL proof is future profile work, not a mismatch between current spec and code.
  Proof: `docs/specs.md:302-306`, `docs/specs.md:1259-1288`, `crates/cityg-server/src/lib.rs:4613-4731`, `crates/cityg-api-client/tests/history_authority_extensions.rs`.
- `3.5` `Closed` — “current state must be covered” is now a concrete base-profile invariant under the deployment-global authority actually defined by the spec.
  Proof: `docs/specs.md:288-306`, `docs/specs.md:1195-1198`, `docs/specs.md:1259-1265`, `crates/cityg-server/src/lib.rs`, `crates/cityg-api-client/src/lib.rs:1458-2047`.
- `3.6` `Closed` — within the current deployment-global scope, authenticated current-state regression and rollback/fork conflicts are fail-closed in both spec and client runtime.
  Proof: `docs/specs.md:188-194`, `docs/specs.md:302-306`, `crates/cityg-gui/src/native/barrier_core.rs:290-338`, `crates/cityg-gui/src/native/barrier_ops.rs:294-360,874-985`, `crates/cityg-gui/src/native/epoch_sync.rs:62-73`, `crates/cityg-gui/src/native/tests/mod.rs:219-292`.
- `3.7` `Closed` — the catch-up / multi-version-gap path around `pcs_refresh` is now explicitly specified and matches the runtime: unauthenticated refresh boundaries force `recovery_required`, best-effort recovery is limited to non-refresh current heads, successful recovery activates crash-safely with `current_barrier_full_verified := false`, and unresolved catch-up keeps payload send/fetch disabled. For locally authored pending authority-bound bundles, epoch-sync validation is anchored to the persisted pre-publish activation source rather than silently reseeding from the current merge ticket after head advancement.
  Proof: `docs/specs.md:1275-1280`, `docs/specs.md:1530-1542`, `crates/cityg-gui/src/native/epoch_sync.rs`, `crates/cityg-gui/src/native/barrier_runtime.rs:57-82`, `crates/cityg-gui/src/native/tests/mod.rs` (`epoch_sync_after_second_join_keeps_local_pcs_refresh_valid`, `join_finalize_fault_injection_after_publish_recovers_via_epoch_sync`, `epoch_sync_pending_bundle_allows_authority_headers_with_authenticated_source`, `epoch_sync_pending_bundle_rejects_authority_headers_without_authenticated_source`).

## Audit 4

- `4.1` `Reclassified` — the current base profile now states unambiguously that `header[181]`/`header[182]` provide server-checkable authority-bound helper-state binding, not remote attestation of the client's internal FULL-vs-recover-only execution path. The stronger ask is future-profile work, not a mismatch between current spec and code.
  Proof: `docs/specs.md:300-306`, `docs/specs.md:1270-1283`, `crates/cityg-server/src/lib.rs:4644-4731,7025-7059,7192-7234`, `crates/cityg-gui/src/native/barrier_runtime.rs:545-621`, `crates/cityg-gui/src/native/tests/mod.rs:1177-1328`.
- `4.2` `Closed` — `join_finalize` is now server-checkable via `header[179] join_finalize_auth`, and the bootstrap exception is explicitly separate from the stronger FULL predicate.
  Proof: `docs/specs.md:1155-1174`, `docs/specs.md:1579-1583`, `crates/msphf-orchestrator/src/accept/mod.rs:1884-1949`, `crates/cityg-server/src/lib.rs:2381-2438,4022-4085,10705-10735`, `crates/cityg-gui/src/native/barrier_core.rs:568-589`, `crates/cityg-gui/src/native/tests/mod.rs:8589-8658,9070-9130`.
- `4.3` `Closed` — provenance that the current barrier state is not FULL-verified is now persisted and surfaced.
  Proof: `docs/specs.md:458-465`, `crates/cityg-gui/src/native/session_types.rs:72-99`, `crates/cityg-gui/src/native/persisted/barrier.rs:56-57,334-405`.
- `4.4` `Closed` — recover-only to FULL promotion is now tied to the exact stored authenticated current state, and later authenticated state changes automatically clear `current_barrier_full_verified`.
  Proof: `docs/specs.md:304-306`, `docs/specs.md:526-535`, `crates/cityg-gui/src/native/barrier_core.rs`, `crates/cityg-gui/src/native/tests/mod.rs`.
- `4.5` `Closed` — the spec now names the three relevant notions explicitly (`recover-only`, `join-finalize bootstrap-eligible`, `current_barrier_full_verified`) and the wire/runtime proof objects are negotiated rather than implicit.
  Proof: `docs/specs.md:302-306`, `docs/specs.md:307-313`, `docs/specs.md:1259-1288`, `crates/cityg-server/src/lib.rs:3206-3331,4644-4731,7192-7234`, `crates/cityg-gui/src/native/barrier_runtime.rs`, `crates/cityg-gui/src/native/persisted/barrier.rs`, `crates/cityg-api-client/tests/history_authority_extensions.rs`.
- `4.6` `Closed` — the applicable `ek_n` verification path is now explicitly anchored to the deployment-global attested current state that the base profile defines.
  Proof: `docs/specs.md:1115-1124`, `docs/specs.md:1259-1265`, `docs/specs.md:1296-1302`, `crates/cityg-server/src/lib.rs`, `crates/cityg-api-client/tests/history_authority_extensions.rs`.
- `4.7` `Closed` — current version/current tree/current JoinSet binding is now fail-closed under one exact authenticated current-state decision. In the GUI epoch-sync path, that includes the locally persisted pre-publish activation source for a pending local authority-bound bundle, rather than the later current merge-ticket attestation.
  Proof: `docs/specs.md:180-189`, `docs/specs.md:1157`, `docs/specs.md:1181-1190`, `docs/specs.md:1602-1610`, `crates/cityg-server/src/lib.rs:2396-2445,4443-4450,10749-10780`, `crates/cityg-gui/src/native/session_types.rs:50-66,193-215`, `crates/cityg-gui/src/native/persisted/barrier.rs:15-28,157-184,346-431`, `crates/cityg-gui/src/native/barrier_runtime.rs:515-595`, `crates/cityg-gui/src/native/epoch_sync.rs`, `crates/cityg-gui/src/native/join_ops.rs:220-247,423-455`, `crates/cityg-gui/src/native/barrier_ops.rs:185-195,312-320,882-905`, `crates/cityg-gui/src/bin/join_leave.rs:376-416,1432-1440,1870-1878,5746-5761`, `crates/cityg-gui/src/native/tests/mod.rs`.
- `4.8` `Reclassified` — the remaining ask for broader governance/policy commitment into the same lineage is now an explicit multi-doc/profile choice, not a mismatch between the current spec and implementation.
  Proof: `docs/specs.md:1638-1690`, `crates/cityg-api/proto/cityg.proto:278-313`, `crates/cityg-server/src/lib.rs:2736-2818,5259-5439`, `crates/cityg-api/src/lib.rs:1722-1794`, `crates/cityg-api-client/src/lib.rs:1346-1569,3235-3671`; remaining lack of stronger global/federated finality is still explicit at `docs/specs.md:170`.

## Audit 5

- `5.1` `Closed` — A/B/C/D now require a shared `history_view_id` plus shared `HistoryCommitment`.
  Proof: `docs/specs.md:180-189`.
- `5.2` `Closed` — `JoinSet` semantics are now exact for the selected committed view.
  Proof: `docs/specs.md:197-213`.
- `5.3` `Closed` — `LookupMergeAcceptance` is now the normative history/finality lookup for the deployment-global authority actually defined by the base profile.
  Proof: `docs/specs.md:258-264`, `docs/specs.md:1420-1434`, `crates/cityg-server/src/lib.rs:6384-6399`, `crates/cityg-api-client/src/lib.rs:2327-2331`.
- `5.4` `Reclassified` — room-admin authorization remains a multi-doc normative boundary, not a local defect of this file alone.
  Proof: this was intentionally scoped outside `docs/specs.md`.
- `5.5` `Closed` — sender identity is no longer optional in practice on the message plane, and the concrete send path now signs with the same persisted sender device key family that receivers bind back to `sender_leaf_id`.
  Proof: `docs/specs.md:566-572`, `crates/cityg-gui/src/native/message_auth.rs:97-156`, `crates/cityg-gui/src/native/network_messages.rs:14-50,188-203`, `crates/cityg-gui/src/native/tests/mod.rs:7606-7659,8670-8740`.
- `5.6` `Reclassified` — opaque external proof/KDF suites remain a registry/documentation issue; not enough evidence to call the current local implementation unsafely weak from this repo alone.
  Proof: `docs/specs.md:162-163`, `docs/specs.md:1479-1484`.
- `5.7` `Closed` — join provisioning now ships as a standalone signed `provisioning_artifact` bound to the delivered current-state fields, freshness window, helper completeness material, and deployment-global history-authority attestation; clients fail closed before consuming provisioned state if the artifact is missing, stale, or tampered.
  Proof: `docs/specs.md:1638-1669`, `crates/cityg-api/proto/cityg.proto:216-268`, `crates/cityg-server/src/lib.rs:2685-2709,3529-3708`, `crates/cityg-api/src/lib.rs:2098-2170`, `crates/cityg-api-client/src/lib.rs:1079-1251,3062-3233,5051-5147`.
- `5.8` `Closed` — retention/fetch/config delivery is now tied to one authenticated deployment-profile manifest across join, merge, expel, helper A/B/C, and merge-acceptance lookup responses. Clients fail closed if the manifest is missing, tampered, or differs across helper pages.
  Proof: `docs/specs.md:220-238`, `docs/specs.md:618-638`, `docs/specs.md:1638-1710`, `crates/cityg-api/proto/cityg.proto:216-429`, `crates/cityg-server/src/lib.rs:2407-2424,2752-2767`, `crates/cityg-api/src/lib.rs:2102-2190,2520-2556,2652-2688,2728-3208`, `crates/cityg-api-client/src/lib.rs:796-810,1225-1239,1487-1501,1592-2267,3640-3715,6783-6959`.

## Audit 6

- `6.1` `Closed` — `N_max` is now bounded and enforced fail-closed across layers.
  Proof: `docs/specs.md:899-900`, `crates/cityg-server/src/lib.rs:11014-11032`, `crates/cityg-api-client/src/lib.rs:1914-1925,2440-2457,2987-3010`, `crates/cityg-gui/src/barrier_shared.rs:9-10`.
- `6.2` `Closed` — retained historical public-tree state is now normatively and concretely bounded.
  Proof: `docs/specs.md:229-231`, `crates/cityg-server/src/lib.rs:3143-3182`, `crates/cityg-server/src/lib.rs:10631-10680`.
- `6.3` `Closed` — payload envelope size is bounded in spec and code.
  Proof: `docs/specs.md:563-565`, `crates/cityg-gui/src/message_crypto.rs:816-846`.
- `6.4` `Closed` — the retained-snapshot fast path remains an optimization, but the base profile now states explicitly that uncached historical predecessor verification is still in-profile because it is bounded by one exact `(2*N_max-1)` tree reconstruction plus bounded helper pages, and `N_max` itself is hard-capped. The code already enforces that cap and reuses retained snapshots when available.
  Proof: `docs/specs.md:207-214`, `docs/specs.md:248-255`, `docs/specs.md:1241-1247`, `crates/cityg-gui/src/barrier_shared.rs:15,294-296`, `crates/cityg-server/src/lib.rs:13187-13202`, `crates/cityg-gui/src/native/barrier_core.rs:171-204`, `crates/cityg-gui/src/native/tests/mod.rs:805-849`.
- `6.5` `Closed` — A/B/C now have explicit page framing, bounded page size, and client-side aggregation checks tied to one `HistoryCommitment`.
  Proof: `docs/specs.md:194-238`, `crates/cityg-api/proto/cityg.proto:303-358`, `crates/cityg-api/src/lib.rs:197,900-942,2497-2618,6326-6354`, `crates/cityg-api-client/src/lib.rs:181,1188-1464,2358-2407,2757-2869`.
- `6.6` `Closed` — unresolved joins are now bounded by `N_max`, and resolved/revoked join activations are pruned from server state.
  Proof: `docs/specs.md:218`, `docs/specs.md:994-995`, `crates/cityg-server/src/lib.rs:1603`, `crates/cityg-server/src/lib.rs:2331`, `crates/cityg-server/src/lib.rs:3102-3141`, `crates/cityg-server/src/lib.rs:10203-10257`.
- `6.7` `Closed` — anti-replay durability cost is now normatively bounded per tuple/context, obsolete tuples are collectable, batching is explicitly allowed, and the GUI persists replay state before releasing fetched messages.
  Proof: `docs/specs.md:616-638`, `crates/cityg-gui/src/message_crypto.rs:9-120`, `crates/cityg-gui/src/native/network_messages.rs:85-118,147-149,225`, `crates/cityg-gui/src/native/session_fetch.rs:111-175`, `crates/cityg-gui/src/native/tests/mod.rs:2702-2753`.
- `6.8` `Closed` — CBOR determinism is now a rejection property, not one mandated re-encode algorithm.
  Proof: `docs/specs.md:83-92`.

## Audit 7

- `7.1` `Reclassified` — the remaining federated/global-history ask is now explicitly outside the base profile. The current base profile intentionally promises one deployment-global append-only authority, not cross-deployment consensus.
  Proof: `docs/specs.md:288-306`, `docs/specs.md:1180-1182`, `docs/specs.md:1296-1302`.
- `7.2` `Closed` — the spec now defines the exact client-visible replay subset for activation, and explicitly distinguishes it from broader server-only S10 checks.
  Proof: `docs/specs.md:1491-1508`, `docs/specs.md:1583-1591`, `crates/cityg-gui/src/native/barrier_runtime.rs:520-600,680-710`, `crates/cityg-gui/src/native/tests/mod.rs:423-431,684-735,8448-8501`.
- `7.3` `Closed` — `ResolveJoinsSince` / current-state acceptance are now tied to one exact authenticated view, one exact `HistoryCommitment`, and one exact pinned current-state decision.
  Proof: `docs/specs.md:180-199`, `docs/specs.md:197-213`, `crates/cityg-gui/src/native/session_types.rs:50-66`, `crates/cityg-gui/src/native/persisted/barrier.rs:15-28,157-184,346-431`, `crates/cityg-gui/src/native/barrier_runtime.rs:515-595`, `crates/cityg-gui/src/native/epoch_sync.rs:40-98,335-363`, `crates/cityg-gui/src/native/tests/mod.rs:346-381,8327-8384`.
- `7.4` `Closed` — helper completeness/non-omission is now a mandatory signed base-profile property inside the deployment-global authority that the spec actually defines.
  Proof: `docs/specs.md:200-206`, `docs/specs.md:217-231`, `docs/specs.md:294-300`, `crates/cityg-server/src/lib.rs:2644-2698,3332-3478`, `crates/cityg-api/src/lib.rs:2607-2852`, `crates/cityg-api-client/src/lib.rs:2787-3207`, `crates/cityg-api-client/tests/history_authority_extensions.rs`.
- `7.5` `Reclassified` — recover-only remains an explicit degraded availability mode, but that is now a documented fail-closed safety tradeoff rather than an unspoken protocol hole.
  Proof: `docs/specs.md:302-306`, `docs/specs.md:1248-1265`, `crates/cityg-gui/src/native/barrier_runtime.rs:91-99,603-655`.
- `7.6` `Reclassified` — provisioning/current-state/config fields are now signed exactly where the current base profile says they should be; the remaining governance-lineage ask is a broader profile/documentation decision.
  Proof: `docs/specs.md:302-305`, `docs/specs.md:1638-1710`, `crates/cityg-api/proto/cityg.proto:216-429`, `crates/cityg-api-client/src/lib.rs:1079-1299,1346-1569,1592-2267,3062-3233,3235-3715`.
- `7.7` `Reclassified` — the base profile now clearly defines fail-closed local recovery states (`barrier_recovery_pending`, `recovery_required`) but intentionally leaves cross-source arbitration/quarantine to deployment policy rather than pretending to specify it here.
  Proof: `docs/specs.md:304-306`, `docs/specs.md:1180-1182`, `crates/cityg-gui/src/native/barrier_runtime.rs:91-99,626-655`.

## Strongest closed proofs

- Shared authenticated view and local append-only history commitment:
  `docs/specs.md:180-189`, `crates/cityg-server/src/lib.rs:2574-2599`, `crates/cityg-server/src/lib.rs:10363-10395`.
- Server-checkable `join_finalize` exception:
  `docs/specs.md:1155-1157`, `docs/specs.md:1467-1469`, `crates/cityg-server/src/lib.rs:4022-4085`.
- Join provisioning freshness/binding:
  `docs/specs.md:1638-1669`, `crates/cityg-api/proto/cityg.proto:216-268`, `crates/cityg-server/src/lib.rs:2685-2709,3529-3708`, `crates/cityg-api-client/src/lib.rs:1079-1251,3062-3233`.
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

## Reserved Future-Profile Work

The current base profile is now explicit on the remaining scope boundaries:

1. `header[181]` stays an exact attested-helper/current-state binding in this profile. A future stronger profile MAY define independent remote attestation of the client's FULL-verification path (for example under a reserved identifier such as `witnessed-full-verification-v1`), but that is not part of the current base profile.
2. `global-history-authority-v1` is intentionally deployment-global append-only in this profile. A future stronger profile MAY add federated / multi-witness non-equivocation or stronger finality (for example under a reserved identifier such as `federated-history-authority-v1`), but that is not part of the current base profile.
3. `local-history-authority-v1` is now treated as legacy/test-only non-base compatibility, not as an alternative production base-profile target.
