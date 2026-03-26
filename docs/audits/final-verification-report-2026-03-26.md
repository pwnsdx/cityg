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
- `Closed`: `13`
- `Partial`: `14`
- `Open`: `20`
- `Reclassified`: `4`

## Audit 1

- `1.1` `Closed` — bootstrap `join_finalize` no longer depends on a circular `H_prev`.
  Proof: `docs/specs.md:1111-1124` defines `H_prev_bootstrap` from the authenticated predecessor of `BU_current`.
- `1.2` `Partial` — `header[97]` is normatively clarified, but still has the same wire shape across `author-local` and `barrier-recovery`.
  Proof: `docs/specs.md:271-276`.
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
- `2.2` `Open` — `profile_version` is still not explicitly cryptographically bound in the anchor itself.
  Proof: `docs/specs.md:642-656` defines `bind_fs` without `profile_version`.
- `2.3` `Reclassified` — the “missing `gid/weid` in bind_fs” claim is too strong as stated because `xk_hash` already carries handshake context; the remaining gap is documentary, not a confirmed local defect.
  Proof: `docs/specs.md:162`, `docs/specs.md:279-313`, `docs/specs.md:642-656`.
- `2.4` `Open` — several barrier/HP KDFs still bind through `xk_hash` / room-local constants rather than an explicit direct `gid` term everywhere the audit wanted it.
  Proof: `docs/specs.md:297-313`, `docs/specs.md:1042`, `crates/cityg-gui/src/barrier_shared.rs:11-12`.
- `2.5` `Partial` — recover-only misuse is reduced by persistent `current_barrier_full_verified`, but still not protocol-enforced end-to-end.
  Proof: `docs/specs.md:1093-1096`, `docs/specs.md:1154-1157`, `crates/cityg-gui/src/native/session_types.rs:72-99`, `crates/cityg-gui/src/native/barrier_ops.rs:214-251`.
- `2.6` `Partial` — sender/device binding is now enforced in code, but the stronger lifetime/non-reuse semantics are still only partially specified.
  Proof: `docs/specs.md:566-572`, `crates/cityg-gui/src/native/message_auth.rs:139-156`, `crates/cityg-gui/src/native/network_messages.rs:188-203`.

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
- `4.2` `Partial` — `join_finalize` is now server-checkable via `header[179] join_finalize_auth`, but still does not prove full public-state verification to the server.
  Proof: `docs/specs.md:1155-1157`, `docs/specs.md:1467-1469`, `crates/cityg-server/src/lib.rs:4022-4085`.
- `4.3` `Closed` — provenance that the current barrier state is not FULL-verified is now persisted and surfaced.
  Proof: `docs/specs.md:458-465`, `crates/cityg-gui/src/native/session_types.rs:72-99`, `crates/cityg-gui/src/native/persisted/barrier.rs:56-57,334-405`.
- `4.4` `Open` — recover-only to FULL promotion is still not backed by a globally authenticated head; the circularity is reduced but not eliminated.
  Proof: `docs/specs.md:1111-1124`, `docs/specs.md:1154-1157`.
- `4.5` `Open` — “FULL” still covers multiple meanings: local full-tree check, local current-state eligibility, and stronger active-server claims.
  Proof: the spec narrows usage but still lacks a single wire-visible proof object for FULL status.
- `4.6` `Open` — the “applicable `ek_n` verification” path is still not globally anchored enough to rule out vacuous server-steered contexts.
  Proof: `docs/specs.md:1115-1124` improves bootstrap checks, but relies on local/current authenticated artifacts rather than global canonity.
- `4.7` `Partial` — current version/current tree/current JoinSet binding is much tighter now through shared `HistoryCommitment`, `header[180]`, and helper-state binding.
  Proof: `docs/specs.md:180-189`, `docs/specs.md:1157`, `crates/cityg-server/src/lib.rs:4443-4450`, `crates/cityg-gui/src/native/join_ops.rs:220-247`, `crates/cityg-gui/src/native/barrier_ops.rs:312-320,882-905`.
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
- `5.5` `Closed` — sender identity is no longer optional in practice on the message plane.
  Proof: `docs/specs.md:566-572`, `crates/cityg-gui/src/native/message_auth.rs:139-156`, `crates/cityg-gui/src/native/network_messages.rs:188-203`.
- `5.6` `Reclassified` — opaque external proof/KDF suites remain a registry/documentation issue; not enough evidence to call the current local implementation unsafely weak from this repo alone.
  Proof: `docs/specs.md:162-163`, `docs/specs.md:1479-1484`.
- `5.7` `Partial` — join provisioning now has nonce/issuance/expiry/current history commitment, but still is not a standalone globally authenticated lineage artifact.
  Proof: `docs/specs.md:1455-1478`, `crates/cityg-api/proto/cityg.proto:243,248-251`, `crates/cityg-api-client/src/lib.rs:988-1038`.
- `5.8` `Partial` — retention/fetch/config contracts are better tied to history, but still lack hard global bounds/pagination.
  Proof: `docs/specs.md:220-223`, `docs/specs.md:1455`, and the remaining open Audit 6 findings.

## Audit 6

- `6.1` `Closed` — `N_max` is now bounded and enforced fail-closed across layers.
  Proof: `docs/specs.md:899-900`, `crates/cityg-server/src/lib.rs:11014-11032`, `crates/cityg-api-client/src/lib.rs:1914-1925,2440-2457,2987-3010`, `crates/cityg-gui/src/barrier_shared.rs:9-10`.
- `6.2` `Open` — historical retention is still not globally bounded.
  Proof: `docs/specs.md:220-223` still requires retention while history remains fetchable, without hard maxima.
- `6.3` `Closed` — payload envelope size is bounded in spec and code.
  Proof: `docs/specs.md:563-565`, `crates/cityg-gui/src/message_crypto.rs:816-846`.
- `6.4` `Open` — FULL chain-check still fundamentally needs whole-tree work in the general case.
  Proof: `docs/specs.md:1093-1104`, `docs/specs.md:1117-1122`.
- `6.5` `Open` — A/B/C still lack normative pagination / max-response bounds.
  Proof: `docs/specs.md:191-223`.
- `6.6` `Open` — there is still no hard cap on unresolved joins per barrier version.
  Proof: no `MAX_UNRESOLVED_JOINS_PER_BARRIER_VERSION` equivalent was added.
- `6.7` `Open` — anti-replay write amplification remains structurally present.
  Proof: `docs/specs.md:583-596`; local replay windowing in `crates/cityg-gui/src/message_crypto.rs:33-55` does not close the normative durability/cost issue.
- `6.8` `Closed` — CBOR determinism is now a rejection property, not one mandated re-encode algorithm.
  Proof: `docs/specs.md:83-92`.

## Audit 7

- `7.1` `Open` — snapshot authentication is still not a proof of globally canonical history.
  Proof: `docs/specs.md:165-170`, `docs/specs.md:215-223`.
- `7.2` `Open` — critical acceptance invariants are still not fully replayed client-side before activation.
  Proof: `docs/specs.md:1154-1157` and lack of a full client revalidation subset for all S10 guards.
- `7.3` `Partial` — `ResolveJoinsSince` is now tied to an exact authenticated view and shared commitment, but not yet to a globally canonical target state with completeness proof.
  Proof: `docs/specs.md:180-189`, `docs/specs.md:197-213`.
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

## Highest-priority remaining work

1. Add a globally canonical, append-only, authenticated history/finality object, not just a server-local `HistoryCommitment`.
2. Decide whether FULL/recover-only is only an honest-client rule or must become a server-verifiable protocol property.
3. Add completeness proofs or equivalent fail-closed semantics for `ResolveJoinsSince` / `ResolveRevokedLeaves`.
4. Bound history retention, A/B/C response sizes, unresolved joins, and replay persistence cost normatively.
5. Close the remaining wire/profile issues: explicit `profile_version` binding and, if desired, a real wire discriminator for `header[97]` contexts.
