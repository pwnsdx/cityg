CITY-G UNIFIED SPEC (FS-HYBRID + PRS BARRIER)

Version: v0.1.4
Date: 2026-03-23
Status: Active wire/API profile revision
Profile ID: tswe/msphf-we/fs-hybrid + prs-barrier (native async-first barrier transport)

PROFILE STATUS
* The wire/API `profile_version` exposed by the current implementation is `v0.1.4`.
* `v0.1.4` is a wire-profile revision from `v0.1.3`, because it removes the legacy HP envelope transport and makes `barrier-sealed-v1` the sole in-profile transport for header[97].
* For commit-level traceability of this profile revision, see `docs/spec-conformance-changelog-v0.1.4.md`.

IMPORTANT (label supersession / no mixing)
* All H_L label strings and HKDF info strings in THIS document are NORMATIVE for this profile version.
* Implementations MUST adopt the full label set in this document as a unit and MUST NOT mix label sets across versions.

SCOPE
This profile specifies:
* time-blind FS-hybrid epoch evolution and tau_e derivation,
* device-chain binding patched to bind barrier state,
* acceptance rules relevant to FS (time-blind) and SRX carve-out,
* payload envelope + key schedule patched to include PRS barrier state,
* PRS barrier (K_barrier) with cold-path KEM-Tree Cover for post-revocation secrecy,
* join provisioning requirements required by PRS barrier and FS-hybrid acceptance.

CONTROL-PLANE GOVERNANCE (normative subset for `v0.1.4`)
This unified spec is the normative source for the cryptographic/profile
behavior above. The room-scoped governance subset actually consumed by the
current wire/API profile is fixed here and matched by the current API/server
implementation; [`api-reference.md`](./api-reference.md) and
[`room-admin-governance-redesign.md`](./room-admin-governance-redesign.md) are
explanatory companions, not separate sources of truth for the subset below.

Room-scoped governance rules for the current profile:
* room bootstrap/governance uses room-scoped signed admin proofs tied to a
  persistent room identity (`RoomAdminProof`), not aliases,
* the creator becomes the initial room admin on the first successful room
  claim/bootstrap,
* room-admin lifecycle operations are `grant_admin`, `revoke_admin`, and
  `list_admins`, and room-admin member expulsion is exposed as a
  room-admin-authorized MERGE/revocation transition,
* there is no legacy `x-cityg-admin-token` fallback for room-scoped endpoints,
* KBROAD maintenance is automatic/server-managed in normal join/merge ticket
  flows rather than a manual client precondition.

Room admin proof registry for `v0.1.4`:
* `RoomAdminProof := { pop_public_key:bstr, signature:bstr }`.
* The only in-profile signature suite for `RoomAdminProof` is ML-DSA-87 /
  Dilithium5.
* The signed message MUST be `CBOR_det((operation:tstr, room_id:tstr, payload:bstr))`.
* `operation` is a closed-world registry in this profile:
  * `bootstrap_room_v1`
  * `rotate_room_kbroad_v1`
  * `grant_room_admin_v1`
  * `revoke_room_admin_v1`
  * `list_room_admins_v1`
  * `expel_room_member_v1`
* `payload` semantics are fixed as follows:
  * for `bootstrap_room_v1` and `rotate_room_kbroad_v1`: `payload == kbroad_public`
  * for `grant_room_admin_v1` and `revoke_room_admin_v1`: `payload == target_pop_public_key`
  * for `list_room_admins_v1`: `payload == EMPTY`
  * for `expel_room_member_v1`: `payload == CBOR_det((author_leaf_id:bstr32, target_leaf_id:bstr32))`
* The replay key for one proof is `H_L("room-admin/replay-key", [pop_public_key, signature])`.
* The server MUST reject replay of one previously accepted room-admin proof for
  the same room.
* Authorization principal for room-scoped governance is exactly
  `pop_public_key`; alias text is never an authorization principal.
* The server MUST reject a room-admin proof whose signing identity is not
  currently authorized for the requested room-scoped operation.

External proof / suite registry fixed by this profile:
* membership representation and verification (including `cover_leaf_index`
  mapping) remain external, but their consumed outputs are fixed by the fields
  named in this document,
* the in-profile generated ticket / provisioning suite identifiers are fixed to:
  * `proof_mode == "lin+zkvrf"`
  * `vrf_id == "lb-vrf/v1"`
  * `msphf_crs_id == "rlwe-merkle/v1"`
  * `msphf_params_id == "rlwe-params/mock"`
* the in-profile room-admin and history-authority signature suite is
  ML-DSA-87 / Dilithium5,
* any join/merge/provisioning artifact or ticket carrying different values for
  those closed-world suite identifiers is out of profile for `v0.1.4` and MUST
  be rejected by base-profile clients.

S0. NORMATIVE LANGUAGE
The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", "MAY" are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

S1. TYPES, ENCODING, AND NOTATION

S1.1 Byte strings
* bstrN: exactly N bytes
* bstr: variable length bytes

S1.2 Integers
* uint: non-negative integer representable in deterministic CBOR.
* uint64: uint in the inclusive range [0 .. 18446744073709551615]. If a field is typed uint64, any value outside this range MUST be rejected as out of profile.

S1.3 Deterministic CBOR (CBOR_det) (normative)
All CBOR encodings used in this profile for:
* anchor headers (canonical map form),
* any AAD arrays,
* PayloadEnvelope,
* BarrierUpdate and KemTreeCoverPayload,
* bind tuples (VRF bind, proof commits),
MUST use deterministic CBOR per RFC 8949 S4.2:
* shortest integer encodings
* shortest definite-length encodings
* map keys ordered by encoded byte sequence
* no indefinite-length items
* no floats (reject if encountered)
* no duplicate map keys

Deterministic-encoding verification rule (normative, MUST):
For any object that MUST be encoded as CBOR_det, verifiers MUST check that the received bytes are deterministic.
The reference conforming verification method is:
1. Parse the received CBOR bytes using a parser that:
   * rejects floats,
   * rejects indefinite-length items,
   * rejects duplicate map keys,
   * rejects malformed CBOR.
2. Re-encode the parsed data model using CBOR_det rules.
3. Require the re-encoded bytes to be byte-for-byte identical to the original received bytes.
Implementations MAY use any equivalent verification method (including parser-level or single-pass canonicality validation) provided it rejects exactly the same non-deterministic inputs as the reference method above.

If the check fails:
* for anchor headers or other profile-global CBOR_det items: reject with 907.1
* for BarrierUpdate and/or KemTreeCoverPayload: reject with 960.7
* for PayloadEnvelope: receivers MUST discard the message as malformed (transport/application error handling; out of scope for anchor acceptance codes)

S1.4 Hash constants
* ZERO32: 32-byte all-zero string
* ZERO16: 16-byte all-zero string

S1.5 Pseudocode notation aliases (normative)
To avoid ambiguity across implementations, the following aliases are normative throughout this document:
* BOTTOM means the blank marker (empty bstr), i.e., set/logic symbol `⊥`.
* EMPTYSET means the empty set, i.e., symbol `∅`.
* IN means set membership, i.e., symbol `∈`.
* NOT IN means non-membership, i.e., symbol `∉`.
* INTERSECT means set intersection, i.e., symbol `∩`.

S2. CRYPTOGRAPHIC PRIMITIVES (NORMATIVE)

S2.1 BLAKE3
* BLAKE3(message) -> 32 bytes by default output length
* BLAKE3_keyed(key32, message) -> 32 bytes

S2.2 H_L: domain-separated hash -> bstr32 (normative)
H_L(label, args[]) := BLAKE3_derive_key(
  context = "city-g|h_l|v1",
  message = "city-g|" || ASCII(label) || 0x00 || CBOR_det(args[])
)
* ASCII(label) MUST be bytes in 0x20..0x7E, MUST NOT include 0x00.
* output is exactly 32 bytes.

S2.3 HKDF-BLAKE3 (normative, L=32 only)
HKDF-BLAKE3.Extract(salt32, ikm) -> prk32:
  prk32 := BLAKE3_keyed(key=salt32, message=ikm)
HKDF-BLAKE3.Expand(prk32, info_bytes, L=32) -> okm32:
  okm32 := BLAKE3_keyed(key=prk32, message=(info_bytes || 0x01))[0..32]  /* first 32 bytes */
HKDF-BLAKE3(ikm, salt32, info_bytes, L=32) -> okm32:
  prk32 := Extract(salt32, ikm)
  okm32 := Expand(prk32, info_bytes, 32)
Any invocation with L != 32 MUST be rejected as out of profile.

S2.4 AEAD: ChaCha20-Poly1305 (normative)
* key: 32 bytes
* nonce: 12 bytes
* tag: 16 bytes
AEAD_Seal(key32, nonce12, aad_bytes, pt_bytes) -> ct_bytes
AEAD_Open(key32, nonce12, aad_bytes, ct_bytes) -> pt_bytes | FAIL

S2.5 KEM: ML-KEM-768 (normative)
KeyGen()                  -> (ek, dk)
KeyGen_internal(d32, z32) -> (ek, dk)
Encaps(ek)                -> (ct, ss32)
Decaps(dk, ct)            -> ss32
Sizes:
* ek: 1184 bytes
* dk: 2400 bytes
* ct: 1088 bytes
* ss: 32 bytes
Naming rule:
* Use ek (public/encapsulation) and dk (private/decapsulation).
* ML-KEM secrets MUST be named dk_* (never sk_*).
* When this spec uses pk_* in barrier context (pk_entries, pk_target), those byte strings are ML-KEM ek values.

S3. IDENTIFIERS, MEMBERSHIP/BARRIER INTERFACES, AND CONTEXT VALUES

S3.1 Core identifiers (inputs)
* gid : bstr    group identifier (stable for group lifetime)
* weid : bstr32 "window id" (FS context id)
* xk_hash : bstr32 transcript hash / handshake binding. For `v0.1.4`, this is not an opaque deployment-local convention: `xk_hash := H_L("msphf/xk", [CBOR_det(X_k)])`, where `X_k` commits at minimum `(gid, cat, we_epoch_id, anchor_hdr_ctx, tswe_salt_hash, parent_root, join_delta_root, revoked_since_prev_root, revoked_root, pox_r_commit when present)`.
* E_k : bstr    ME-OR derived value / binding (opaque here)
* history_view_id : bstr32 exact committed membership/checkpoint/barrier history view identifier
* HistoryAuthorityScope : one deployment-defined authenticated history authority domain for `(gid, deployment)` that issues the A)/B)/C)/D) responses consumed together by one client decision. In this base profile, the scope is the authenticated deployment/server context that vends those responses unless an extension defines a stronger explicit scope identifier.
* HistoryCommitment := [history_view_id:bstr32, history_commitment_id:bstr32, prev_history_commitment_id:bstr32, history_seq:uint]
  * `history_commitment_id` names one server-local append-only commitment step for the authenticated history view.
  * `prev_history_commitment_id` is all-zero only for the first locally committed history step for that `(gid, deployment)`.
  * `history_seq` is a server-local monotonically increasing append-only sequence number for that `(gid, deployment)`.
  * `history_commitment_id` MUST be computed as `H_L("barrier/history-commitment", [gid, history_view_id, prev_history_commitment_id, history_seq])`.
  * This object strengthens local append-only correlation for A)/B)/C)/D); it is NOT, by itself, a federated/global consensus object.
* Authenticated acceptance/finality in this document is always scoped to one `HistoryAuthorityScope` unless a later extension explicitly states stronger cross-scope consensus semantics.

S3.2 Membership/SRX anchor roots (inputs)
* header[110], header[111], header[112], header[113] : bstr32 roots (membership and revocation)
* membership mapping: cover_leaf_index(device_pk) -> uint, committed by membership state
* membership state also defines the current per-group membership leaf identifier `leaf_id(device_pk) -> bstr32` for each active device. This 32-byte `leaf_id` is distinct from `cover_leaf_index(device_pk)` and is the canonical `sender_leaf_id` used in S8.
* For this base profile, `leaf_id(device_pk)` MUST be a deterministic per-group function of `(gid, device_pk, device_pk_alg)` under the selected leaf-id mode. Re-deriving `leaf_id` for the same `(gid, device_pk, device_pk_alg)` tuple MUST yield the same 32-byte value.

S3.3 Interfaces REQUIRED by this profile (implementability requirement)
The membership/SRX/barrier subsystems MUST provide to any authenticated group member:

Shared authenticated-view rule (normative):
* Every successful response from A), B), C), and D) MUST be bound to a `history_view_id` naming the exact committed history/checkpoint view under which the response was computed.
* Every successful response from A), B), C), and D) MUST also carry a `HistoryCommitment` for that same view.
* The proof/object format is deployment-defined, but it MUST cryptographically bind `(gid, history_view_id, request selector(s), response payload)` to committed history/checkpoint state.
* The deployment MUST define one `HistoryAuthorityScope` for these authenticated responses. All A)/B)/C)/D) responses composed for one validation, activation, provisioning, or recovery decision MUST come from that same scope. Mixing authenticated responses from different scopes for one decision is out of profile and MUST fail closed.
* The returned `HistoryCommitment.history_view_id` MUST equal the top-level `history_view_id`.
* For responses computed against current state rather than a historical snapshot, the server MUST first advance/persist the current `HistoryCommitment` if the current committed state differs from the last emitted `HistoryCommitment`.
* `history_seq` MUST strictly increase whenever the server locally appends a new committed history/checkpoint/barrier state for that `gid`; `history_commitment_id` MUST be unique for each such step.
* A client that has already persisted an authenticated current state for one `HistoryAuthorityScope` MUST fail closed if a later join/merge/provisioning/helper current-state artifact for that same scope claims:
  * a lower `barrier_version`,
  * a lower `history_seq`,
  * or the same `history_seq` with a different `history_commitment_id`.
* If the same `HistoryCommitment` is presented again, `barrier_version` and `kem_tree_hash_after` MUST remain consistent with that previously authenticated local current state.
* Later sections may write `Resolve...(...)` / `Lookup...(...)` as shorthand for the payload component only; callers MUST also validate the accompanying `history_view_id`, `HistoryCommitment`, and authenticated proof/object per this section.
* Any procedure that composes outputs from more than one of A)/B)/C)/D) for a single validation, activation, provisioning, or recovery decision MUST require all referenced authenticated responses/objects to validate to the same `HistoryCommitment`, unless that procedure explicitly defines a safe cross-view comparison. Missing or mismatched authenticated view binding MUST fail closed. In the FULL/updater chain-check and acceptance-correlation contexts, this failure MUST surface 960.9.
* Historical snapshot fetches served from retained history MUST return the exact `HistoryCommitment` recorded when that snapshot became committed/fetchable, not a freshly recomputed current commitment.
* If the deployment cannot provide authenticated completeness/finality for one requested result inside its `HistoryAuthorityScope`, it MUST return an authenticated "insufficient history / not available / pending" style outcome rather than silently omitting records and claiming success.
* The base profile REQUIRES `global-history-authority-v1` on join/merge/provisioning/helper/lookup surfaces that carry authenticated current-state or helper objects.
* Therefore A), B), and C) MUST carry non-empty `helper_completeness_attestation` values verified under one negotiated `HistoryAuthorityDescriptor`.
* `local-history-authority-v1` remains defined only as a non-base legacy/test-only extension for explicitly scope-local deployments, fixtures, and compatibility tests; clients enforcing the base profile MUST reject it on base-profile API/wire paths.
* API/wire surfaces that carry `HistoryAuthorityDescriptor`, `global_history_attestation`, `current_global_history_attestation`, or `helper_completeness_attestation` MUST also carry an explicit extension identifier string `history_authority_extension`.
* In the base profile, `history_authority_extension` MUST equal exactly `"global-history-authority-v1"` on every successful join/merge/provisioning/helper/lookup response that carries any of those extension-defined objects.
* When `local-history-authority-v1` is explicitly negotiated outside the base profile, `history_authority_extension` MUST equal exactly `"local-history-authority-v1"` on every successful join/merge/provisioning/helper/lookup response that carries any of those extension-defined objects.
* Clients MUST fail closed if extension-defined objects are present while `history_authority_extension` is absent/empty, if `history_authority_extension` names an unsupported extension, if a base-profile path carries `"local-history-authority-v1"`, or if pages of one logical A)/B)/C) result drift across different `history_authority_extension` values.
* `MAX_BARRIER_N_MAX := 65_536`.
* `MAX_BARRIER_HELPER_PAGE_ENTRIES := 512`.
* A), B), and C) are paged interfaces in the base profile. Each request MUST accept an explicit `page_offset`/`entry_offset` and `max_entries`; `max_entries == 0` means "use the profile default page size", namely `MAX_BARRIER_HELPER_PAGE_ENTRIES`.
* A), B), and C) MUST reject requests whose effective page size exceeds `MAX_BARRIER_HELPER_PAGE_ENTRIES`.
* Every successful page of one logical A), B), or C) result MUST carry the same `history_view_id` and the same `HistoryCommitment` as every other page of that same logical result.
* Page ordering MUST be deterministic and gap-free. The response MUST identify the returned page's starting offset, the logical total number of entries, and whether another page exists. Clients composing multiple pages MUST fail closed on offset gaps, overlaps, `total_entries` drift, or authenticated-view mismatch.

A) ResolveRevokedLeaves(revocation_roots_hash, page_offset?, max_entries?) -> list of RevokedLeafRecord page
RevokedLeafRecord = [leaf_index:uint, slot_generation:uint64]
Returns revoked slot occupancies corresponding to revocation_roots_hash.
This enumeration MUST be integrity-protected by membership/SRX state referenced by header[112]/[113].
The authenticated response MUST carry `history_view_id`.
The authenticated response MUST carry the corresponding `HistoryCommitment`.
If the deployment defines a helper-completeness extension, that extension MUST bind any `helper_completeness_attestation` to `(gid, history_view_id, revocation_roots_hash, page_offset, total_entries, payload page)` and to one exact authenticated history object for that result.
Returned records MUST be strictly sorted by increasing `(leaf_index, slot_generation)`, MUST carry `leaf_index < N_max`, and the selected committed view MUST contain at most one active occupancy per `(leaf_index, slot_generation)`.

B) ResolveJoinsSince(prev_barrier_version, page_offset?, max_entries?) -> list of JoinLeafRecord page
JoinLeafRecord = [device_pk:bstr, leaf_index:uint, ek_leaf:bstr, slot_generation:uint64]
Returns exactly the join leaf allocations and leaf public keys that:
* were committed after prev_barrier_version,
* remain active at the selected `history_view_id`,
* and therefore MUST be applied by S11.6 before revocation blanking for that same `history_view_id`.
Activations that were never committed, were superseded before commitment, or are no longer active at the selected `history_view_id` MUST NOT be returned.
This enumeration MUST be integrity-protected by checkpoint history / membership state.
The authenticated response MUST carry `history_view_id`.
The authenticated response MUST carry the corresponding `HistoryCommitment`.
If the deployment defines a helper-completeness extension, that extension MUST bind any `helper_completeness_attestation` to `(gid, history_view_id, prev_barrier_version, page_offset, total_entries, payload page)` and to one exact authenticated history object for that result.
When later sections refer to `JoinSet` or `unresolved JoinSet`, they mean exactly this authenticated payload for the selected `history_view_id`.
Output constraints (normative):
* entries MUST be strictly sorted by increasing `(leaf_index, slot_generation)`,
* there MUST be at most one returned active occupancy per `leaf_index`,
* `leaf_index` MUST be `< N_max`,
* `slot_generation` MUST be a uint64 and MUST increase strictly on every reuse of the same `leaf_index`,
* `ek_leaf` MUST be exactly 1184 bytes,
* the number of returned records MUST be `<= N_max`,
* the server MUST prune or compact resolved, revoked, and superseded join activations so that `ResolveJoinsSince(...)` remains bounded by the currently active join activations needed for the selected `history_view_id`,
* if membership history is inconsistent (duplicate active allocation, out-of-range index, conflicting `ek_leaf` for the same activation), the implementation MUST fail closed and MUST NOT construct or accept a dependent `barrier_update`.

C) FetchBarrierPublicTree(kem_tree_hash_after, entry_offset?, max_entries?) -> pk_entries page
pk_entries is an array of length (2*N_max-1) of bstr, where each entry is either empty bstr (BOTTOM) or ML-KEM ek (1184 bytes).
The returned pk_entries MUST hash (per S11.4) to the requested kem_tree_hash_after.
The authenticated response MUST carry `history_view_id`.
The authenticated response MUST carry the corresponding `HistoryCommitment`.
Historical retention contract (normative):
* FetchBarrierPublicTree(kem_tree_hash_after) MUST work for any committed historical barrier public tree snapshot addressed by kem_tree_hash_after, not only the current one.
* `MAX_RETAINED_BARRIER_PUBLIC_TREE_SNAPSHOTS := 256` committed snapshots per `gid`, inclusive of the current committed snapshot.
* `MAX_RETAINED_LOCAL_PUBLIC_TREE_SNAPSHOTS := 8` locally retained authenticated public-tree snapshots per client/session; clients that implement a retained-snapshot fast path MUST evict older retained snapshots before exceeding this bound.
* `N_max` MUST be `<= MAX_BARRIER_N_MAX`.
* The server MUST retain the current committed snapshot plus the most recent committed historical snapshots up to `MAX_RETAINED_BARRIER_PUBLIC_TREE_SNAPSHOTS`.
* Older committed snapshots MAY be retired once they fall outside that bounded retained window. Retirement MUST fail closed: the server MUST return an authenticated "retired / not available" style outcome, or an equivalent deployment-defined typed error for that authenticated member request; it MUST NOT silently substitute the current snapshot.
* This contract constrains fetch semantics, not internal storage layout. Implementations MAY satisfy it via deltas, structural sharing, compression, or other equivalent internal representations, provided FetchBarrierPublicTree(kem_tree_hash_after) deterministically reconstructs the exact pk_entries array for the requested committed snapshot.
* `pk_entries` pages MUST enumerate heap indices in increasing order, starting at `entry_offset`, and `total_entries` MUST equal exactly `(2*N_max-1)` for every page of that same logical snapshot result.

D) LookupMergeAcceptance(merge_locator) -> MergeAcceptanceRecord
`merge_locator := [pending_barrier_version:uint, pending_barrier_update_digest:bstr32, pending_we_epoch_id:bstr32]`
`MergeAcceptanceRecord := [status, history_view_id, history_commitment, accepted_barrier_version?, accepted_fs_ec?, accepted_reason?, accepted_digest?]`
where:
* `status` is one of `{accepted, superseded, pending, final_rejected}`,
* `history_commitment` is the current authenticated `HistoryCommitment` under which `status` was evaluated,
* `accepted_*` fields MUST be present iff `status == accepted`,
* `accepted`, `superseded`, and `final_rejected` are statements about one `HistoryAuthorityScope`, not a cross-scope/global consensus claim.
* `final_rejected` means authenticated finality within that same `HistoryAuthorityScope` establishes that the specific merge identified by `merge_locator` can no longer become accepted there.
* A deployment that cannot establish scope-local authenticated finality for a locator MUST return `pending` rather than synthesizing `final_rejected`.
The authenticated response MUST bind `merge_locator`, `status`, `history_commitment`, and any populated `accepted_*` fields to the returned `history_view_id`.
Implementations MAY store additional stable identifiers, but any such identifier MUST be injectively bound to `merge_locator` within `gid`; it MUST NOT identify two distinct merge attempts.

E) Optional local history authority extension (legacy/test-only; not part of base profile)
Deployments MAY negotiate `local-history-authority-v1` only for explicitly scope-local legacy compatibility paths, fixtures, and tests. It strengthens one `HistoryAuthorityScope` with explicit signed objects for helper completeness, current-state attestation, and server-verifiable FULL-verification receipts, but it is not the recommended production profile and it does NOT claim federated/global canonity across scopes.
Requirements on that extension:
* One negotiated `HistoryAuthorityDescriptor` object MUST identify the scope and the public verification key for that scope-local history authority.
* `HistoryAuthorityDescriptor := [scope_id:bstr32, public_key:bstr]`.
* The signature suite for `public_key` MUST be fixed by the negotiated extension. The current implementation uses ML-DSA-87 / Dilithium5 for this scope-local authority.
* When this extension is negotiated, every successful A), B), C), and D) response consumed for one decision MUST carry the same non-empty `history_authority_descriptor`, and clients MUST reject descriptor drift across those responses.
* When this extension is negotiated, every successful join/merge/provisioning/helper/lookup response carrying extension-defined objects MUST also carry `history_authority_extension == "local-history-authority-v1"`.
* When this extension is negotiated, key `182` and the API fields named `global_history_attestation` / `current_global_history_attestation` carry a scope-local `GlobalHistoryAttestation` object rather than a federated/global consensus proof.
* Under `local-history-authority-v1`, `GlobalHistoryAttestation := [scope_id:bstr32, gid:bstr32, history_view_id:bstr32, history_commitment_id:bstr32, prev_history_commitment_id:bstr32, history_seq:uint, barrier_version:uint, kem_tree_hash_after:bstr32, parent_attestation_id:bstr32, finality_kind:tstr, signature:bstr]`.
* Under `local-history-authority-v1`, `finality_kind` MUST be exactly `"local-append-only"`.
* Under `local-history-authority-v1`, `parent_attestation_id` MUST equal `H_L("barrier/global-history/parent-attestation", [scope_id, gid, prev_history_commitment_id])`, except that it MUST be all-zero when `prev_history_commitment_id` is all-zero.
* Under `local-history-authority-v1`, the signed payload for `GlobalHistoryAttestation` MUST bind at minimum `(scope_id, gid, history_view_id, history_commitment_id, prev_history_commitment_id, history_seq, barrier_version, kem_tree_hash_after, parent_attestation_id, finality_kind)`.
* Under `local-history-authority-v1`, `helper_completeness_attestation` MUST be non-empty on successful A), B), and C) responses and MUST be signed over `(scope_id, helper_kind, history_view_id, history_commitment_id, page_offset, total_entries, selector/page payload)`.
* `helper_kind` MUST be one of `resolve_revoked_leaves`, `resolve_joins_since`, or `fetch_public_tree`.
* When this extension is negotiated, any join/merge/provisioning artifact that carries current-state helper payloads for a client decision SHOULD also carry the same `HistoryAuthorityDescriptor` and matching scope-local attestation objects for those helper payloads.
* This extension proves append-only correlation, current-state binding, and helper-page completeness only inside one `HistoryAuthorityScope`. It does NOT, by itself, prove non-equivocation across multiple servers, independent witnesses, or any stronger globally canonical finality.
* Production deployments conforming to the base profile defined by this document MUST prefer `global-history-authority-v1` instead. `local-history-authority-v1` is retained only so existing tests and explicitly negotiated non-base compatibility paths have a stable identifier.

F) Deployment-global history authority (REQUIRED in base profile)
The base profile REQUIRES `global-history-authority-v1`, a deployment-global extension that lifts one whole deployment onto one authenticated append-only history authority. It is stronger than `local-history-authority-v1` because it defines one deployment-global attested lineage, but it still does NOT claim federated cross-deployment consensus.
Requirements on that extension:
* Successful join/merge/provisioning/helper/lookup responses carrying objects from this extension MUST carry `history_authority_extension == "global-history-authority-v1"`.
* One negotiated `HistoryAuthorityDescriptor` object MUST identify the deployment-global history authority and its public verification key.
* `HistoryAuthorityDescriptor := [scope_id:bstr32, public_key:bstr]`.
* The signature suite for `public_key` MUST be fixed by the negotiated extension. The current implementation uses ML-DSA-87 / Dilithium5 for this deployment-global authority.
* Under `global-history-authority-v1`, `GlobalHistoryAttestation := [scope_id:bstr32, gid:bstr32, history_view_id:bstr32, history_commitment_id:bstr32, prev_history_commitment_id:bstr32, history_seq:uint, barrier_version:uint, kem_tree_hash_after:bstr32, parent_attestation_id:bstr32, finality_kind:tstr, signature:bstr]`.
* Under `global-history-authority-v1`, `finality_kind` MUST be exactly `"global-append-only"`.
* Under `global-history-authority-v1`, `parent_attestation_id` MUST equal `H_L("barrier/global-history/parent-attestation", [scope_id, gid, prev_history_commitment_id])`, except that it MUST be all-zero when `prev_history_commitment_id` is all-zero.
* Under `global-history-authority-v1`, the signed payload for `GlobalHistoryAttestation` MUST bind at minimum `(scope_id, gid, history_view_id, history_commitment_id, prev_history_commitment_id, history_seq, barrier_version, kem_tree_hash_after, parent_attestation_id, finality_kind)`.
* Under `global-history-authority-v1`, `helper_completeness_attestation` MUST be non-empty on successful A), B), and C) responses and MUST be signed over `(scope_id, helper_kind, history_view_id, history_commitment_id, page_offset, total_entries, selector/page payload)`.
* Under `global-history-authority-v1`, `accepted`, `superseded`, and `final_rejected` in D) MUST be interpreted as statements about that deployment-global append-only authority rather than one merely local server view.
* Under `global-history-authority-v1`, provisioning artifacts and `header[182]` / `header[181]` / `header[183]` decisions MUST bind to one exact deployment-global attestation lineage.
* A deployment MUST NOT describe itself as providing federated cross-deployment canonical/final history under this profile unless a stronger negotiated extension explicitly defines that property.

Security-scope clarifications (normative):
* In this document, "global" in `global-history-authority-v1` means deployment-global for one authenticated `HistoryAuthorityScope`. It does NOT mean federated across independently operated deployments or witnesses.
* Helper completeness, `LookupMergeAcceptance` finality, and `header[182]` / `header[181]` / `header[183]` statements are only claims about that one deployment-global append-only authority unless a stronger negotiated extension says otherwise.
* `header[181]` proves exact author/updater binding to one exact attested helper/current-state decision within the negotiated `HistoryAuthorityScope`.
* `header[183]` proves that the negotiated history authority replayed the exact `reason in {0,1}` `barrier_update` against the authenticated current tree plus authenticated A/B helper outputs and deployment-profile manifest for that same scope/current state. It is the stronger server-verifiable authoring witness used by the base profile for reasons `0` and `1`.
* The signed artifacts defined by this document commit only the fields they explicitly name: `provisioning_artifact`, `merge_ticket_artifact`, and `deployment_profile_manifest` cover the client-consumed provisioning/helper/profile fields carried by those surfaces. They do NOT, by themselves, commit broader admin/governance state unless another normative document or negotiated extension explicitly adds those fields.
* The base profile is fail-closed for safety inside one `HistoryAuthorityScope`; it does NOT guarantee liveness or progress when that authority withholds snapshots/history or otherwise refuses to serve authenticated helper material.
* Deployment-global non-equivocation across multiple independently operated history authorities is out of profile unless a stronger extension explicitly defines it.
* Reserved stronger-profile identifiers:
  * `witnessed-full-verification-v1` MAY be defined by a future profile to add independently authenticated remote attestation of the author's FULL-verification path beyond `header[181]`'s current helper-state binding semantics.
  * `federated-history-authority-v1` MAY be defined by a future profile to add multi-witness or cross-deployment non-equivocation/finality stronger than `global-history-authority-v1`.
* The current base profile does not define either reserved stronger-profile identifier. Implementations receiving them today MUST reject them as unsupported unless another negotiated profile explicitly defines them.

Snapshot-auth failure handling (normative; 960.9 wiring):
If FetchBarrierPublicTree(kem_tree_hash_after) returns pk_entries with TreeHash(root_node) != kem_tree_hash_after, the caller MUST treat the server as faulty/active, MUST NOT proceed with barrier_update creation/activation/verification that depends on that tree, and MUST surface local diagnostic code 960.9 barrier_tree_snapshot_auth_failure.

Verification levels (normative):
* A client that has A) and B) but not C) MUST NOT claim FULL barrier chain-check (it may still recover K_barrier via unique match).
* A client that has A), B), and C) and performs the MUST checks in S11.11.2 (FULL chain-check) and S11.13.6 (ek_n verification) is a FULL-verifying client.
Terminology clarification (normative):
* `recover-only` means the client may recover or correlate local state from authenticated headers and helper material, but has not established FULL verification of the current public tree for the exact stored current state.
* `join-finalize bootstrap-eligible` means a newly joined recover-only client that has satisfied the S11.11.1 bootstrap exception for the provisioned current state and therefore MAY originate reason 2 only.
* `current_barrier_full_verified` is a client-local predicate for one exact stored current state; it is not self-authenticating on the wire.

S3.4 Header[97] HP envelope transport (normative)
`header[97]` carries the opaque HP transport envelope used by merge/join-finalize publication and client recovery.

In profile `v0.1.4`, the only in-profile encoding is:
* `BarrierHpEnvelope := ["barrier-sealed-v1", hp_context:tstr, hp_ciphertext:bstr, "chacha20-poly1305"]`
* `BarrierHpPlaintext := hp_k:bstr`
* `HpArtifact := { hp_a:bstr, hp_b:bstr, m_a:bstr32, m_b:bstr32, params_id:tstr, hp_version:uint }`

Scope / presence clarification (normative):
* `header[97]` remains REQUIRED on all anchors by S4.2.1.
* On JOIN, REGULAR, and MERGE anchors, `BarrierHpPlaintext` is the exact `hp_k` byte string bound to that anchor's final authenticated header context.
* `BarrierHpPlaintext` MUST be non-empty.
* `hp_k` MUST equal `CBOR_det(HpArtifact)`. No additional outer wrapper is permitted inside `BarrierHpPlaintext`.
* `header[99]` MUST equal `H_L("msphf/hp/commit", [BarrierHpPlaintext])`.
* Receivers MAY ignore `header[97]` on code paths that do not perform HP recovery, but any implementation that attempts recovery from `header[97]` MUST apply the validation and binding rules below.

Normative constants:
* `MAX_HP_BYTES := 16384`                                          /* maximum BarrierHpPlaintext byte length */
* `AEAD_TAG_LEN := 16`
* `MAX_HP_ENVELOPE_BYTES := MAX_HP_BYTES + AEAD_TAG_LEN = 16400`  /* maximum hp_ciphertext byte length; excludes the surrounding CBOR array/tag overhead */

Constraints (MUST):
* the array length MUST equal 4,
* element 0 MUST equal the UTF-8 text string `"barrier-sealed-v1"`,
* element 1 MUST equal exactly one of the UTF-8 text strings `"author-local"` or `"barrier-recovery"`,
* element 2 MUST be a non-empty ciphertext byte string whose length is at least `AEAD_TAG_LEN` and at most `MAX_HP_ENVELOPE_BYTES`,
* element 3 MUST equal the UTF-8 text string `"chacha20-poly1305"`.

Publication contexts (normative):
* `header[97]` carries an explicit publication-context discriminator in `element 1`:
  * `author-local form`: `hp_context == "author-local"`; this is the form produced by the author while constructing a new JOIN/REGULAR anchor, and by a locally built MERGE bundle before it is rebound/sealed for peer recovery;
  * `barrier-recovery form`: `hp_context == "barrier-recovery"`; this is the form carried by a MERGE publication intended for cross-client recovery from serialized wire state.
* The initial JOIN anchor published by a pending joiner MUST use the `author-local form`; the joiner does not yet know `K_barrier`, and no server-side provisioning of `K_barrier` is permitted.
* Cross-client recovery from serialized wire state is defined only for the `barrier-recovery form`. A JOIN anchor by itself is not a peer-recoverable HP transport artifact.
* Any MERGE publication that is intended to remain peer-recoverable after acceptance/persistence MUST carry the `barrier-recovery form`. `author-local form` is ephemeral local construction state only and MUST NOT be treated as satisfying cross-client recovery from accepted wire state.

Author-local sealing algorithm (normative):
* Let `xk_hash` be the transcript hash / handshake binding for the published anchor.
* Let `hp_commit := header[99]`.
* Let `hp_key_local` be a fresh uniformly random 32-byte key sampled by the author for this authored bundle only.
* Let:
  * `hp_nonce := H_L("hp/nonce", [xk_hash, hp_commit])[0..11]`
  * `hp_aad := hp_commit`
* Then:
  * `hp_ciphertext := AEAD_Seal(hp_key_local, hp_nonce, hp_aad, BarrierHpPlaintext)`
* `hp_key_local` is author-local secret material and MUST NOT be transmitted. Any implementation consuming the author-local form from wire without retained local key material MUST treat it as non-recoverable.

Barrier-recovery sealing algorithm (normative):
* Let `barrier_version := header[176]`.
* Let `xk_hash` be the transcript hash / handshake binding for the published anchor.
* Let `hp_commit := header[99]`.
* Let `barrier_key` be the client's locally held barrier key for the authenticated barrier state selected for this recovery attempt.
* For a MERGE carrying `header[175]`, `barrier_key` MUST be the post-activation barrier key corresponding to the published `barrier_version = header[176]`.
* For a MERGE that does not carry `header[175]`, `barrier_key` MUST be the currently authenticated barrier key already bound locally to the published `barrier_version = header[176]`.
* Let:
  * `hp_salt := H_L("hp/barrier/salt", [gid, barrier_version, xk_hash])`
  * `hp_info := ASCII("city-g|hp/barrier/v1") || hp_commit`
  * `hp_key := HKDF-BLAKE3(ikm=barrier_key, salt32=hp_salt, info_bytes=hp_info, L=32)`
  * `hp_nonce := H_L("hp/nonce", [xk_hash, hp_commit])[0..11]`
  * `hp_aad := hp_commit`
* Then:
  * `hp_ciphertext := AEAD_Seal(hp_key, hp_nonce, hp_aad, BarrierHpPlaintext)`
  * `BarrierHpPlaintext := AEAD_Open(hp_key, hp_nonce, hp_aad, hp_ciphertext)`

Semantics / security properties (normative):
* `hp_ciphertext` is an opaque client-to-client transport blob.
* The server MAY store, replay, and authenticate this blob as part of the anchor header, but MUST treat it as opaque and MUST NOT claim knowledge of the underlying HP keying material.
* `header[99]` is the authenticated commitment to `BarrierHpPlaintext`. Implementations MUST freshly sample each authored `HpArtifact` and MUST NOT deliberately reuse a prior `BarrierHpPlaintext` for a distinct anchor publication.
* In `barrier-recovery form`, the confidentiality/binding tuple is `(gid, barrier_key, barrier_version, xk_hash, hp_commit)`.
* A cut-and-paste of `hp_ciphertext` into another anchor with a different `gid`, `barrier_version`, `xk_hash`, `hp_commit`, or barrier key MUST fail client recovery.
* `BarrierHpPlaintext` length MUST be in `[1, MAX_HP_BYTES]` both before encryption and after decryption.
* Any implementation that successfully decrypts `header[97]` MUST recompute `H_L("msphf/hp/commit", [BarrierHpPlaintext])` from the recovered plaintext and MUST require exact equality with `header[99]` before parsing or using `HpArtifact`.

Validation / rejection rules (normative):
* Server-side acceptance MUST validate `header[97]` during S10.1 pre-filters before JOIN/MERGE-specific acceptance logic continues.
* JOIN/MERGE validation that explicitly consumes `header[97]` MUST re-check the S3.4 shape/mode/size/AEAD constraints on the decoded value before using it.
* Any parse failure, wrong mode, wrong AEAD suite, empty ciphertext, ciphertext shorter than `AEAD_TAG_LEN`, or ciphertext longer than `MAX_HP_ENVELOPE_BYTES` MUST be rejected as malformed.
* A client recovery path that expects `barrier-recovery form` MUST derive `hp_key` exactly as above and MUST reject/ignore the envelope for recovery if:
  * `header[176]` is missing or malformed,
  * AEAD open fails,
  * the recovered plaintext length is zero or exceeds `MAX_HP_BYTES`,
  * recomputed `H_L("msphf/hp/commit", [BarrierHpPlaintext]) != header[99]`.
* A client MUST NOT silently substitute another transport mode or fall back to a legacy room-secret transport when `header[97]` validation fails.

Out-of-profile rule (normative):
* Any other header[97] transport mode is out of profile for `v0.1.4` and MUST be rejected as malformed.

S4. ANCHOR TYPES, HEADER-KEY REGISTRY, AND PRESENCE MATRIX (NORMATIVE)

S4.1 Anchor types (normative)
This profile defines three anchor types:
* JOIN anchor: introduces a new device leaf and MUST carry barrier_leaf_pk (key 177).
* MERGE anchor: carries merge/checkpoint state and MAY carry barrier_update (key 175) with barrier_update_reason (key 178); see predicates in S10.4, S10.4A, S10.4B, and S10.4C.
* REGULAR anchor: any anchor that is neither JOIN nor MERGE.

Anchor type determination (normative):
* If any key in S4.2.3 is present OR any key in S4.2.4 is present OR any key in S4.2.5 is present, anchor_type := MERGE.
* Else if key 177 is present, anchor_type := JOIN.
* Else anchor_type := REGULAR.

Mutual exclusivity (normative):
* JOIN anchors MUST NOT contain any merge-only keys (S4.2.3/S4.2.4) nor any SRX-only keys (S4.2.5).
* MERGE anchors MUST NOT contain key 177.
* REGULAR anchors MUST NOT contain key 177 and MUST NOT contain any merge-only/SRX-only keys.

S4.2 Closed-world registry (normative)
Anchors using keys outside this registry MUST be rejected with 907.1 malformed CBOR/unknown key.

S4.2.1 Keys REQUIRED on ALL anchors (JOIN, REGULAR, MERGE)
Core keys required:
20, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
104, 105, 106, 107, 108, 109,
110, 111, 112, 113,
116, 119, 125

FS keys (all anchors):
Key 139: fs_policy_version (uint)
Key 141: fs_ec (uint)
Key 142: fs_epoch_commit (bstr32)
Key 143: fs_epoch_base_ts (uint64)
Key 146: smallwood (bstr)

Device-chain keys (all anchors):
Key 152: fs_dev_prev_commit (bstr32)
Key 153: fs_dev_commit (bstr32)

Barrier keys (all anchors):
Key 176: barrier_version (uint)

S4.2.2 Keys REQUIRED on JOIN anchors and FORBIDDEN on REGULAR/MERGE (join-only)
Key 177: barrier_leaf_pk (bstr; ML-KEM ek; MUST be 1184 bytes)

S4.2.3 Keys PERMITTED only on MERGE anchors and FORBIDDEN on JOIN/REGULAR (merge-only)
Key 175: barrier_update (bstr; optional; only when permitted by S10.4, S10.4A, S10.4B, S10.4C, and S11)
Key 178: barrier_update_reason (uint; required iff key 175 is present)
Key 179: join_finalize_auth (bstr32; required iff key 178 == 2; opaque server-issued capability for reason-2 join_finalize)
Key 180: barrier_history_commitment (bstr; required iff key 175 is present; CBOR_det(HistoryCommitment) for the authenticated current-state snapshot_base/A/B view used to construct the barrier_update)
Key 181: barrier_full_verification_receipt (bstr; REQUIRED iff key 175 is present in the base profile; optional only for explicitly negotiated non-base variants such as `local-history-authority-v1`)
Key 182: barrier_global_history_attestation (bstr; REQUIRED iff key 175 is present in the base profile; optional only for explicitly negotiated non-base variants such as `local-history-authority-v1`)
Key 183: barrier_full_verification_witness (bstr; REQUIRED iff key 175 is present and key 178 ∈ {0,1} in the base profile; FORBIDDEN for reason 2 and optional only for explicitly negotiated non-base variants that define an equivalent witness)

S4.2.4 Merge/checkpoint keys (merge-only set)
130, 131, 132, 133, 134, 135, 136, 138, 144, 145, 148
Restriction: key 136 kbroad_replay is FORBIDDEN (presence -> reject 907.1).

Base-profile merge/checkpoint profile (normative):
* For `v0.1.4`, there is no unstated external "merge profile" document. The merge/checkpoint profile for this document is exactly the closed-world key set of S4.2.4 together with the per-key presence/absence rules stated in this document.
* Implementations MUST NOT rely on any deployment-local or out-of-document rule to decide the in-profile presence or absence of keys `130, 131, 132, 133, 134, 135, 136, 138, 144, 145, 148`.
* Key 136 is always FORBIDDEN in this profile.
* Key 135 is not a general-purpose extension point in this profile; when key 175 is present, key 135 MUST be absent and presence MUST be rejected per S11.12.1.A.
* No key outside S4.2.4 may be treated as a merge/checkpoint key in `v0.1.4`.

S4.2.5 SRX-only keys (MERGE-only, conditional)
Key 121: srx_commit (bstr32)
Key 122: srx_payload (bstr)
Key 160: srx_root_sw (bstr32)
Key 161: srx_smallwood (bstr)
Rules: FORBIDDEN on JOIN/REGULAR.
On MERGE: either all present (SRX applies) or all absent (SRX forbidden). See S9.3.

S4.3 Presence matrix summary (normative)
* JOIN: MUST include S4.2.1 + S4.2.2; MUST NOT include any of S4.2.3/S4.2.4/S4.2.5.
* REGULAR: MUST include S4.2.1; MUST NOT include any of S4.2.2/S4.2.3/S4.2.4/S4.2.5.
* MERGE: MUST include S4.2.1; MUST use only the S4.2.4 merge/checkpoint key set, with exact presence/absence determined only by this document's normative rules;
  MAY include S4.2.3 (subject to S10.4/S10.4A/S10.4B/S10.4C/S11) and MAY include S4.2.5 (subject to S9.3);
  MUST NOT include S4.2.2.
Additional presence rule (normative):
* key 178 MUST be present if and only if key 175 is present.
* key 179 MUST be present if and only if key 178 == 2; it MUST be absent for merge reasons 0/1 and on all non-MERGE anchors.
* key 180 MUST be present if and only if key 175 is present; it MUST be absent on anchors without barrier_update.
* In the base profile, keys 181 and 182 MUST both be present if and only if key 175 is present.
* In the base profile, key 183 MUST be present if and only if key 175 is present and key 178 ∈ {0,1}; it MUST be absent for key 178 == 2 and on anchors without barrier_update.
* Outside the base profile, key 181, key 182, or key 183 MUST be absent unless an explicitly negotiated history-authority extension enables them.

S4.4 Size limits (normative; deployments MAY tighten)
Max bytes per header field (unless otherwise specified by type):
* header[95]  max 8192
* header[146] max 16384
* header[161] max 16384
* header[122] max 1048576
* header[177] MUST be exactly 1184 bytes
* header[179] MUST be exactly 32 bytes
* header[181] is extension-defined and therefore has no universal size semantic beyond deterministic CBOR of the negotiated receipt object
* header[182] is extension-defined and therefore has no universal size semantic beyond deterministic CBOR of the negotiated attestation object
* header[183] is extension-defined and therefore has no universal size semantic beyond deterministic CBOR of the negotiated witness object

BarrierUpdate size policy (normative)
* Deployment MUST define max_barrier_update_bytes (a positive integer).
* header[175] MUST be present only if its byte length is <= max_barrier_update_bytes.
* Servers MUST reject anchors with header[175] length > max_barrier_update_bytes with 960.7.
* Clients MUST reject barrier_update bytes length > max_barrier_update_bytes locally with 960.7.

Consistency requirement (normative)
* max_barrier_update_bytes is a deployment configuration parameter and MUST be consistent across the server and all clients in the group.
* If a client detects a configuration mismatch (e.g., via provisioning metadata or policy channel), it MUST fail closed and MUST NOT process barrier_update bytes under an unknown limit.
Implementations SHOULD choose max_barrier_update_bytes to safely cover worst-case expected revocation patterns for the configured N_max, while bounding memory and CPU usage.

S5. GROUP AND DEVICE STATE (NORMATIVE)

S5.1 Server persistent group state
* fs_epoch_base_ts (T_base) : uint64 -- immutable
* last_checkpoint_ec : uint -- monotone
* last_accepted_ec (A) : uint -- monotone
* per-device map: DeviceState[device_pk] = (last_commit:bstr32, last_ec:uint, last_pcs_refresh_ec:uint/null)
* srx_root_sw : bstr32 -- durable SRX shadow root (if SRX used)
* last_pcs_refresh_ec : uint/null -- null if no accepted PCS refresh yet

PCS refresh policy state (time-blind; deployment-defined):
* pcs_refresh_min_delta_device_ec : uint (>=1)
* pcs_refresh_min_delta_group_ec : uint (>=1)
* pcs_refresh_slot_width_ec : uint (>=1)

Barrier public state:
* barrier_initialized : bool
* barrier_version : uint
* barrier_roots_hash : bstr32
* kem_tree_hash_after : bstr32
* N_max : uint (power of two; fixed group lifetime; deployment/profile MUST define and enforce a finite `N_max_max`, and groups with `N_max > N_max_max` are out of profile)
* Server MUST store pk_entries matching kem_tree_hash_after and a bounded retained historical map from committed `kem_tree_hash_after` values to their corresponding `pk_entries`, and MUST serve the current retained snapshot window via FetchBarrierPublicTree per S3.3.C.

S5.2 Client persistent secret state
FS state:
* K_fs : bstr32
* fs_ec : uint
* optional tau_e cache bounded by policy

Barrier secret state:
* barrier_initialized : bool
* barrier_version : uint
* barrier_roots_hash : bstr32 -- covered revocation-roots baseline for the client's current authenticated barrier state
* K_barrier : bstr32
* kem_tree_hash_after : bstr32
* current_barrier_full_verified : bool -- true iff the client's currently stored `(barrier_version, barrier_roots_hash, kem_tree_hash_after)` has been FULL-verified per S11.11.2 for that same stored state; false if the state was learned or advanced only via recover-only processing
* dk_leaf for the client's barrier leaf (join-generated)
* pkhash_leaf := H_pk(ek_leaf) for the client's barrier leaf (bstr32)
* dk_n keys for internal nodes on the client's SelfPath (derived per S11.13.5)
* pkhash_n := H_pk(ek_n) for each stored dk_n (bstr32)
* pending_barrier_recovery : bool -- true for a newly joined client until it has successfully derived `K_barrier` via S11.13/S12.3
Normative note:
* `pending_barrier_recovery == false` by itself MUST NOT be interpreted as FULL verification. Clients MUST persist `current_barrier_full_verified` (or an equivalent crash-safe marker) across restart.
* If a later authenticated helper / provisioning / merge-ticket / epoch-sync artifact changes the stored `(barrier_version, barrier_roots_hash, kem_tree_hash_after)` without the client completing S11.11.2 FULL verification for that exact new stored state as part of the same crash-safe decision, the client MUST set `current_barrier_full_verified := false`.

Updater-local pending activation state:
* If the client has published a local barrier_update that is not yet correlated/activated, it MUST persist the pending_* fields required by S11.14.1, including pending_barrier_version, pending_we_epoch_id (or equivalent stable merge identifier), pending_fs_ec, pending_revocation_roots_hash, pending_kem_tree_hash_after, pending_K_barrier_new, pending_barrier_update_reason, pending_K_fs_after_pcs (if any), pending_barrier_update_digest, and pending_on_path_key_material.

Clients MUST maintain, for each stored dk_t (leaf or internal), a corresponding pkhash_t value such that pkhash_t == H_pk(ek_t), where ek_t is the public key paired with dk_t.

Atomicity requirement (normative)
* Any update to a stored (dk_t, pkhash_t) pair MUST be written atomically (crash-safe) to persistent storage.
* If atomic persistence is not available, the client MUST treat barrier recovery capability as degraded and MUST fail closed on barrier_update processing (implementation-defined diagnostics).

Barrier verification state (optional but REQUIRED for FULL chain-check):
* ability to refetch and verify pk_entries for stored kem_tree_hash_after values

S6. FS-HYBRID CORE (NORMATIVE)

S6.1 FS epoch counter
t := header[141] (fs_ec).

S6.2 FS chain evolution (normative)
K_fs_next := HKDF-BLAKE3(
  ikm  = K_fs,
  salt = H_L("fs/step/salt", [weid, t+1]),
  info = "city-g|fs/step|v1",
  L=32
)
K_fs := K_fs_next
Devices SHOULD zeroize superseded K_fs material except for bounded offline cache policy.

S6.3 tau_e derivation (normative)
tau_e(t) := HKDF-BLAKE3(
  ikm  = K_fs_at_epoch_t,
  salt = H_L("fs/tau/salt", [weid, t]),
  info = "city-g|fs/tau|v1",
  L=32
)

S6.4 epoch_sk and fs_epoch_commit (normative)
epoch_sk(t) := HKDF-BLAKE3(
  ikm  = K_fs_at_epoch_t,
  salt = H_L("fs/epoch/sk_salt", [weid, t]),
  info = "city-g|fs/epoch/sk|v1",
  L=32
)
fs_epoch_commit := H_L("fs/epoch/commit", [epoch_sk(t)])
Requirement: header[142] MUST equal fs_epoch_commit.

S6.5 Time-blind base timestamp (normative)
Requirement: header[143] MUST equal GroupState.fs_epoch_base_ts else reject 945.0.
Server acceptance MUST NOT consult wall clocks for FS validity.

S6.6 PCS reseed of FS chain (normative; applies only to PCS refresh)
When processing an accepted MERGE anchor carrying key 175 with key 178 = 1 (pcs_refresh), clients MUST reseed K_fs at activation time:
K_fs := HKDF-BLAKE3(
  ikm  = (K_fs || K_barrier_new),
  salt = H_L("fs/pcs/salt", [weid, header[141], header[176]]),
  info = "city-g|fs/pcs|v1",
  L=32
)
This reseed MUST be applied atomically with barrier activation state updates (S11.13.7 for non-updater clients; S11.14.2 for updater activation).
This reseed takes effect immediately at activation time for the accepted pcs_refresh anchor. Therefore, after an accepted pcs_refresh at epoch t, any subsequent anchor in the group MUST use fs_ec > t; same-t anchors are invalid and MUST be rejected per S10.3.
Servers do not learn K_fs and do not execute this derivation.

S7. DEVICE-CHAIN BINDING + BARRIER DIGEST PATCH (NORMATIVE)

S7.1 revocation_roots_hash binding
revocation_roots_hash := H_L("barrier/roots", [header[112], header[113]])

S7.2 barrier_update raw-bytes rule
raw_barrier_update_bytes :=
  if header[175] absent: empty bstr
  else: header[175] bytes exactly as transmitted/stored
MUST treat raw_barrier_update_bytes as opaque for digest purposes (no parse/re-encode).

S7.3 barrier_update_digest
barrier_update_digest :=
  if header[175] absent: ZERO32
  else: H_L("barrier/update/digest", [raw_barrier_update_bytes])

S7.4 fs_dev_commit (normative v2; REQUIRED)
fs_dev_commit := H_L("fs/dev/chain/v2", [
  header[108],   /* author_device_pk */
  header[141],   /* fs_ec */
  header[152],   /* fs_dev_prev_commit */
  header[176],   /* barrier_version */
  barrier_update_digest
])
Requirement: header[153] MUST equal fs_dev_commit.
Anchor authentication MUST bind to header[153] and to the canonical header map.

S8. PAYLOAD ENVELOPE + KEY SCHEDULE (FS-HYBRID + PRS BARRIER) (NORMATIVE)

S8.1 PayloadEnvelope wire format
PayloadEnvelope = [
  "fs-hybrid-msg-v2",
  msg_index : uint,
  ct_payload : bstr
]
Normative constants:
* `MAX_CT_PAYLOAD_BYTES := 1048576`
* `MAX_PAYLOAD_ENVELOPE_BYTES := 1048640`  /* total serialized PayloadEnvelope size, including CBOR wrapper */
Define sender_leaf_id (normative):
* sender_leaf_id is the authenticated 32-byte current membership `leaf_id` of the sending device for this group, supplied by the outer message transport / authenticated sender context for this payload. It is NOT `cover_leaf_index(device_pk)`.
* Every in-profile payload transport MUST carry an authenticated sender device identifier (for example `author_device_pk`) and an authenticated membership view sufficient to derive that device's current `leaf_id` for this group. A transport that omits authenticated sender device identity is out of profile for S8.
* The same sender_leaf_id MUST be supplied to both the encrypt and decrypt paths for S8.3/S8.4 derivations.
* If sender_leaf_id is missing, malformed, or not exactly 32 bytes, the implementation MUST fail closed and MUST NOT attempt payload decryption.
* Implementations MUST verify that `sender_leaf_id` corresponds to the authenticated sender device's current membership `leaf_id` in the authenticated membership view for this payload; mismatch -> drop payload.
* The membership subsystem MUST ensure `leaf_id(device_pk)` is injective within a `gid` across distinct authenticated device public keys. Re-using the same `device_pk` in the same `gid` MUST re-derive the same `leaf_id`; assigning that same `leaf_id` to a different `device_pk` at any later time in the same `gid` is out of profile.
Wire encoding requirement (normative, MUST):
* PayloadEnvelope MUST be encoded as CBOR_det array of length exactly 3.
* `PayloadEnvelope[0]` MUST be the CBOR text string exactly equal to `"fs-hybrid-msg-v2"`.
* `PayloadEnvelope[1]` MUST be the cleartext `msg_index:uint`.
* `PayloadEnvelope[2]` MUST be `ct_payload:bstr`.
* `ct_payload` length MUST be in `[1, MAX_CT_PAYLOAD_BYTES]`.
* The total serialized `PayloadEnvelope` length MUST be in `[1, MAX_PAYLOAD_ENVELOPE_BYTES]`.
* Receivers MUST verify CBOR_det determinism per S1.3 for PayloadEnvelope bytes; if invalid, receivers MUST discard the message as malformed.

S8.2 msg_index uniqueness rule (CRITICAL)
For any fixed sender-scoped tuple (gid, weid, t, xk_hash, E_k, barrier_version, sender_leaf_id), implementations MUST keep the probability of `msg_index` reuse negligible across all payloads encrypted under that tuple.
Normative anti-replay bounds:
* `MAX_MSGS_PER_TUPLE := 4096`
* `MAX_REPLAY_TUPLES_PER_CONTEXT := N_max`
Implementations MUST enforce:
* fresh uniformly random uint64 `msg_index` sampled independently per payload from a cryptographically secure random source local to the sender, plus anti-replay state.
* `msg_index` MUST be obtained at send time from the platform CSPRNG or an equivalent entropy source; it MUST NOT be derived from rollback-prone persisted local state.
* counter-based, timestamp-based, boot-identifier-based, or otherwise deterministic `msg_index` generation MUST NOT be used in this profile.
Collision-risk rule (normative):
* Senders MUST provision tuple rotation so the probability of a same-tuple `msg_index` collision remains negligible for the maximum expected send volume under that tuple.
* Deployments SHOULD rotate to a fresh tuple well before same-tuple send volume approaches the birthday bound of the 64-bit space. As an operational reference point, keeping same-tuple sends at or below 2^20 yields a random-collision bound below approximately 2^-25.
Crash-safety requirement (normative, MUST):
Receiver-local anti-replay state for accepted `(tuple_tag, msg_index)` pairs MUST be persisted durably (crash-safe) before the accepted payload is released to the application, or as part of the same logical transaction that makes the accepted payload durable to the application. If crash-safe anti-replay persistence is not available, this profile MUST NOT be used.
Receivers MAY persist multiple accepted `(tuple_tag, msg_index)` pairs in one crash-safe batch, provided that no payload covered by that batch is released to the application before the whole batch is durable.
If sender-side collision risk cannot be kept negligible, or receiver-side anti-replay cannot be enforced, this profile MUST NOT be used.
Receiver duplicate-rejection rule (normative, MUST):
Define `tuple_context_id` (normative):
* `tuple_context_id := H_L("fs/msg/replay/context", [gid, weid, t, xk_hash, E_k, header[176]])`
Define `tuple_tag` (normative):
* `tuple_tag := H_L("fs/msg/replay/tuple", [gid, weid, t, xk_hash, E_k, header[176], sender_leaf_id])`
Receivers MUST derive this exact `tuple_tag` and MUST reject a payload if the pair `(tuple_tag, msg_index)` has already been accepted locally. Duplicate detection MUST occur before the payload is released to the application.
Receivers MUST retain at most `MAX_MSGS_PER_TUPLE` accepted indices per `tuple_tag`.
Receivers MUST make persisted tuple state collectable once its `tuple_context_id` no longer matches the authenticated receive context for the current local session state. Under the base profile, receivers MUST retain at most `MAX_REPLAY_TUPLES_PER_CONTEXT` sender-scoped tuples for one current `tuple_context_id`; any excess or obsolete tuple state MUST be pruned before further accepted payloads are released.

S8.3 K_msg_epoch
K_msg_epoch := HKDF-BLAKE3(
  ikm  = E_k,
  salt = H_L("fs/msg/epoch_salt", [weid, t, xk_hash, E_k, header[176], K_barrier, sender_leaf_id]),
  info = "city-g|fs/msg/epoch|v2",
  L=32
)
Where `E_k` is the locally derived epoch key for the active `weid`.
`tau_e(t)` remains normative for FS chain/proof context per S6, while payload encryption in this profile binds to `E_k` in S8.

Security note (informative):
K_msg_epoch depends on E_k (ME-OR derived, independent of K_fs) and K_barrier (PRS derived, independent of K_fs). Compromise of K_fs alone does NOT yield K_msg_epoch or any payload decryption capability. Payload confidentiality requires compromise of both E_k and K_barrier for the authenticated epoch. Within an epoch, K_msg_epoch is shared across all messages; compromise of K_msg_epoch enables derivation of all K_msg values for that epoch via the deterministic msg_index binding in S8.4.

S8.4 K_msg, nonce, and AAD
K_msg := HKDF-BLAKE3(
  ikm  = K_msg_epoch,
  salt = H_L("fs/msg/key_salt", [weid, t, sender_leaf_id, msg_index]),
  info = "city-g|fs/msg/key|v2",
  L=32
)
nonce_msg := H_L("fs/msg/nonce", [gid, weid, t, xk_hash, E_k, header[176], sender_leaf_id, msg_index])[0..11]
aad_msg := CBOR_det([gid, weid, t, xk_hash, E_k, header[176], sender_leaf_id, msg_index])
ct_payload := AEAD_Seal(key=K_msg, nonce=nonce_msg, aad=aad_msg, pt=payload_plaintext)
payload_plaintext := AEAD_Open(key=K_msg, nonce=nonce_msg, aad=aad_msg, ct=ct_payload)

S8.5 No-fallback rule (CRITICAL)
Receivers MUST derive K_msg_epoch only with the barrier_version authenticated in the anchor (header[176]) and MUST NOT try alternate cached K_barrier values to "make decryption succeed".

Delayed-delivery rule (normative)
This profile defines payload decryption only for the receiver's current authenticated `(barrier_version, K_barrier)` state. Payloads bound to an older barrier_version are stale and MUST be discarded. Implementations MUST NOT retain or probe cached old `K_barrier` values unless a future profile explicitly standardizes old-version payload support.

S9. PROOFS, BIND TUPLES, AND SRX (NORMATIVE INTERFACE)

S9.1 proofs_commit
Define proofs_commit_args (normative):
* If header[160] is absent (SRX absent), then:
  proofs_commit_args := [header[95], header[146]]
* If header[160] is present (SRX present), then (by S4.2.5 rules, header[161] is also present):
  proofs_commit_args := [header[95], header[146], header[160], header[161]]
Requirement (normative, MUST):
header[125] MUST equal H_L("msphf/proofs", proofs_commit_args).
Server MUST verify header[125] before expensive proofs.

S9.2 VRF bind_fs tuple (values not key-IDs)
bind_fs := CBOR_det([
  xk_hash,
  header[93], header[94], header[98], header[99], header[106],
  header[110], header[111], header[112], header[113],
  proof_mode,
  profile_version,
  header[139],
  meor_vrf_id,
  header[142],
  header[141],
  header[152],
  header[153],
  (header[160] if present)
])
ZK-VRF verification MUST be performed against bind_fs.

S9.3 SRX carve-out (normative; pivot clarified)
SRX applies only on MERGE anchors.
* JOIN and REGULAR anchors MUST NOT carry any of keys 121/122/160/161 (else reject 930).

Define (normative):
pivot_revocation_roots_hash :=
  if GroupState.barrier_initialized == true then GroupState.barrier_roots_hash
  else revocation_roots_hash

On MERGE anchors:
* SRX is REQUIRED iff revocation_roots_hash != pivot_revocation_roots_hash.
* Otherwise (revocation_roots_hash == pivot_revocation_roots_hash), SRX is FORBIDDEN.

When SRX is REQUIRED:
* merge MUST carry 121/122/160/161 and satisfy SRX/Smallwood-v1 verification.

When SRX is FORBIDDEN:
* merge MUST NOT carry any of 121/122/160/161.

SRX raw-bytes binding:
raw_srx_payload_bytes := header[122] bytes exactly as transmitted
srx_payload_digest := H_L("srx/payload/digest", [raw_srx_payload_bytes])
srx_bridge_ctx := H_L("srx/bridge/v1", [
  header[110], header[111], header[112], header[113],
  header[121], srx_payload_digest, header[160]
])
Verifier MUST source srx_root_sw_before from persisted GroupState.srx_root_sw.

S10. ACCEPTANCE (SERVER-SIDE) -- TIME-BLIND + BARRIER INTEGRATION (NORMATIVE)

S10.1 Pre-filters
* Parse header as CBOR_det map; reject floats/indefinite/duplicate keys.
* Reject unknown keys (closed-world registry).
* Enforce size limits.
* Validate required `header[97]` against S3.4 before JOIN/MERGE-specific acceptance logic continues.
* Determine anchor_type per S4.1 and enforce mutual exclusivity.
* header[139] fs_policy_version MUST be supported by the deployment/profile. Unsupported values MUST be rejected with 944.6.

S10.2 Presence rules by anchor type
Presence MUST follow S4.3 exactly.

S10.3 FS base + device-chain integrity + Forward-Leap Guard (FLG)
FS base:
* header[143] MUST equal GroupState.fs_epoch_base_ts else reject 945.0.

Device-chain:
* Look up (stored_last_commit, stored_last_ec, stored_last_pcs_refresh_ec) by header[108] author_device_pk.
* New device: header[152] MUST equal ZERO32.
* Known device: header[152] MUST equal stored_last_commit AND header[141] MUST be >= stored_last_ec else reject 947.0.
* header[153] MUST equal H_L("fs/dev/chain/v2", [header[108], header[141], header[152], header[176], barrier_update_digest]) else reject 947.2.
* PCS epoch-boundary rule: if GroupState.last_pcs_refresh_ec is not null and header[141] == GroupState.last_pcs_refresh_ec, the server MUST reject the anchor with 947.0. This prevents the same fs_ec value from spanning both pre-reseed and post-reseed K_fs meanings.

Forward-Leap Guard (time-blind; normative):
Deployment defines integers: H (>0), checkpoint_interval (>=H), S_anchor, S_first, S_device (>=0).
Configuration invariant check (normative):
If (H <= 0) OR (checkpoint_interval < H) OR (S_anchor < 0) OR (S_first < 0) OR (S_device < 0), the server is misconfigured and MUST reject anchors with 948.0.
W := ceil(checkpoint_interval / H)
D_anchor_max   := W + S_anchor
D_first_device := W + S_first
D_device_max   := W + S_device
Let A := GroupState.last_accepted_ec.
Enforce:
* header[141] MUST be <= A + D_anchor_max else reject 947.6.
* If device is new: header[141] MUST be <= A + D_first_device else reject 947.5.
* If known: header[141] MUST be <= stored_last_ec + D_device_max else reject 947.4.

S10.4 Barrier version gating (normative)
Let BV := GroupState.barrier_version.
Define barrier_update_reason:
* If header[175] is absent: header[178] MUST be absent.
* If header[175] is present: header[178] MUST be present and MUST be one of:
  * 0 = revocation_or_bootstrap
  * 1 = pcs_refresh
  * 2 = join_finalize

Genesis (barrier_initialized == false):
* Reject JOIN or REGULAR with 960.10.
* First accepted anchor MUST be MERGE and MUST include header[175].
* header[178] MUST equal 0.
* header[176] MUST equal 0.
* BarrierUpdate.barrier_version MUST equal 0 and BarrierUpdate.prev_barrier_version MUST equal 0.
* After acceptance: barrier_initialized := true; barrier_version := 0.

Non-genesis:
* JOIN and REGULAR: header[176] MUST equal BV and header[175] MUST be absent.
* MERGE without barrier_update: header[176] MUST equal BV.
* MERGE with barrier_update: header[176] MUST equal BV + 1.

S10.4A Revocation-change gating (PRS-critical)
Let RRH := revocation_roots_hash computed per S7.1.
Let BV := GroupState.barrier_version.
If GroupState.barrier_initialized == true AND RRH != GroupState.barrier_roots_hash, then:
* The anchor MUST be a MERGE anchor.
* header[175] MUST be present (barrier_update required).
* header[178] MUST equal 0 (revocation_or_bootstrap).
* header[176] MUST equal BV + 1.
* If the anchor is not a MERGE, OR header[175] is absent, OR header[176] != BV + 1, the server MUST reject with 960.11 barrier_update_required_on_revocation_change.
* If header[175] is present but header[178] != 0, the server MUST reject with 960.13.

Clarification (normative):
* Since JOIN and REGULAR anchors MUST NOT carry header[175] by S4.3, any JOIN or REGULAR anchor for which RRH != GroupState.barrier_roots_hash MUST be rejected with 960.11.
* Clients MUST ensure that revocation roots have been barrier-covered (i.e., GroupState.barrier_roots_hash updated via an accepted MERGE with barrier_update) before emitting JOIN or REGULAR anchors.

If GroupState.barrier_initialized == true AND RRH == GroupState.barrier_roots_hash, then:
* JOIN and REGULAR anchors proceed under S10.4.
* MERGE anchors MAY omit header[175] and proceed under S10.4 and S11.12 gating.
* If MERGE carries header[175], same-RRH proactive barrier behavior is controlled by S10.4B and S10.4C.

S10.4B Proactive PCS refresh gating (time-blind; normative)
This section applies only when:
* GroupState.barrier_initialized == true
* RRH == GroupState.barrier_roots_hash
* header[175] is present
* the server-observable S10.4C JoinSet predicate does NOT hold for the author

Then:
* header[178] MUST equal 1 (pcs_refresh), else reject 960.5.
* The anchor MUST be a MERGE anchor.
* header[176] MUST equal BV + 1.

Policy parameters (deployment-defined; from GroupState):
* pcs_refresh_min_delta_device_ec >= 1
* pcs_refresh_min_delta_group_ec >= 1
* pcs_refresh_slot_width_ec >= 1

Let t := header[141].
Let g_last := GroupState.last_pcs_refresh_ec (or null if none yet).
Let d_last := stored_last_pcs_refresh_ec for header[108] (or null if none yet).

Rate-limit checks (MUST):
* If g_last is not null and t < g_last + pcs_refresh_min_delta_group_ec: reject 960.12.
* If d_last is not null and t < d_last + pcs_refresh_min_delta_device_ec: reject 960.12.
* If g_last is not null and floor(t / pcs_refresh_slot_width_ec) == floor(g_last / pcs_refresh_slot_width_ec): reject 960.12.

Client behavior note:
* Clients SHOULD back off and retry with jitter after 960.12 to avoid synchronized refresh storms.

S10.4C Join-finalize gating (normative)
This section applies only when:
* GroupState.barrier_initialized == true
* RRH == GroupState.barrier_roots_hash
* header[175] is present
* the server-observable JoinSet predicate below holds for the author

Then:
* header[178] MUST equal 2 (join_finalize), else reject 960.5.
* The anchor MUST be a MERGE anchor.
* header[176] MUST equal BV + 1.
* Revocations MUST NOT be pending for this update; if RRH != GroupState.barrier_roots_hash, reject 960.13.
* Let JoinSet := ResolveJoinsSince(prev_barrier_version), where prev_barrier_version is the value carried in the BarrierUpdate under header[175].
* The author's updater leaf MUST appear in JoinSet for that prev_barrier_version, else reject 960.5.
* join_finalize is exempt from S10.4B PCS rate-limit checks and MUST NOT be treated as pcs_refresh for S6.6.

S10.5 Proof verification order (normative)
* Verify proofs_commit.
* If header[175] is present, the server MUST execute S11.12.1 steps A through H before running expensive cryptographic proof verification in this section.
* Verify Smallwood (FS) -> ZK-VRF -> SRX (if applies).
* Any failure rejects with deployment registry codes (e.g., 923/930).

S10.6 Atomic commit (normative)
On acceptance:
* DeviceState[author_device_pk].last_commit := header[153]
* DeviceState[author_device_pk].last_ec := header[141]
* GroupState.last_accepted_ec := max(GroupState.last_accepted_ec, header[141])
* If SRX applies: update GroupState.srx_root_sw := header[160]
* If barrier_update accepted: update barrier public state per S11.12.1 step I
* If barrier_update accepted and header[178] == 1:
  * GroupState.last_pcs_refresh_ec := header[141]
  * DeviceState[author_device_pk].last_pcs_refresh_ec := header[141]
All updates MUST commit atomically.

S11. PRS BARRIER (K_barrier + KEM-TREE COVER) (NORMATIVE)

S11.1 Barrier derived bindings
revocation_roots_hash := H_L("barrier/roots", [header[112], header[113]])
pending_revocations :=
  (barrier_initialized == false) OR (revocation_roots_hash != barrier_roots_hash)

S11.2 Barrier tree parameters and indexing (normative)
Fixed size:
* N_max fixed for group lifetime, power of two, MUST NOT be extended.

Heap indexing:
nodes indexed 0..(2*N_max - 2)
root_node := 0
left(i)   = 2*i+1
right(i)  = 2*i+2
parent(i) = floor((i-1)/2) for i > 0
leaf_base = N_max - 1
leaf_node(l) = leaf_base + l

Leaf predicates (normative):
is_leaf(i) := (i >= leaf_base)
is_internal(i) := (i < leaf_base)
Shorthand: throughout this document, the condition "i is leaf" is equivalent to is_leaf(i).

sibling(i) = i+1 if i odd, else i-1 for i > 0

Blank marker:
pk_i is bstr: empty bstr means blank (BOTTOM), else ML-KEM ek (1184 bytes).

Path helper (normative):
direct_path(i) :=
  if i == root_node then [i]
  else [i] ++ direct_path(parent(i))
The result is the ordered node sequence from i (inclusive) to root_node (inclusive)
following parent links.

Direct path blanking on revocation:
Revoke leaf l -> blank pk at leaf_node(l) and all nodes on direct_path(leaf_node(l)) including root_node.

Resolution:
resolution(i):
  if pk_i != BOTTOM then {i}
  else if i is leaf then EMPTYSET
  else union(resolution(left(i)), resolution(right(i)))

Deterministic enumeration note (normative):
If an implementation needs to enumerate resolution(i) as an ordered list (e.g., to iterate targets),
it MUST use increasing node-index order.

S11.3 Public key hash (normative)
H_pk(ek) := H_L("barrier/pk-hash", [ek])
target_pk_hash := H_pk(ek)[0..15]

NOTE (defense-in-depth):
* target_pk_hash is a 16-byte hint used only for matching/filtering.
* Security MUST NOT depend on target_pk_hash collision resistance: the full pkhash_t (32 bytes) is bound into AAD in S11.13.4,
  and AEAD_Open MUST fail if the wrong key is used.

S11.4 kem_tree_hash commitment (normative; internal pk included)
TreeHash(i):
  if i is leaf:
    H_L("barrier/tree/leaf-hash", [N_max, i, pk_i])
  else:
    H_L("barrier/tree/node-hash", [N_max, i, pk_i, TreeHash(left(i)), TreeHash(right(i))])
kem_tree_hash := TreeHash(root_node)

S11.5 Wire structures (normative)
BarrierUpdate (CBOR bytes in header[175]):
BarrierUpdate = [
  "barrier-v1",
  barrier_version        : uint,
  prev_barrier_version   : uint,
  tree_size              : uint,
  revocation_roots_hash  : bstr32,
  kem_tree_hash_before   : bstr32,
  kem_tree_hash_after    : bstr32,
  cover_payload          : bstr
]
`BarrierUpdate` MUST be a CBOR array of length exactly 8.
KemTreeCoverPayload (CBOR bytes inside cover_payload):
KemTreeCoverPayload = [
  updater_leaf               : uint,
  path_nodes                 : [* uint],
  revoked_leaf_indices_hint  : null / [* uint],
  node_ciphertexts           : [* NodeCiphertext],
  new_public_keys            : [* [uint, bstr]]
]
`KemTreeCoverPayload` MUST be a CBOR array of length exactly 5.
NodeCiphertext:
NodeCiphertext = [
  source_node      : uint,
  target_node      : uint,
  target_pk_hash   : bstr16,
  kem_ct           : bstr,       1088 bytes
  wrapped_ps       : bstr        48 bytes (32 secret + 16 tag)
]
`NodeCiphertext` MUST be a CBOR array of length exactly 5.
Each `new_public_keys` entry MUST be a CBOR array of length exactly 2.
SRX privacy default:
* revoked_leaf_indices_hint MUST be null unless deployment explicitly allows it.
* Security MUST NOT depend on it.

S11.5.1 Canonicalization and duplicate rules (normative, MUST)
All CBOR for BarrierUpdate and KemTreeCoverPayload MUST be CBOR_det per S1.3, including deterministic-encoding verification.
A) path_nodes: MUST pass S11.7.
B) revoked_leaf_indices_hint (if not null): MUST be strictly increasing, no duplicates.
C) node_ciphertexts:
* MUST be lexicographically sorted by (source_node, target_node).
* MUST contain no duplicate (source_node, target_node) pairs.
* MUST contain only indices in range [0..2*N_max-2].
* Each kem_ct MUST be 1088 bytes.
* Each wrapped_ps MUST be 48 bytes.
* Each target_pk_hash MUST be 16 bytes.
D) new_public_keys:
* MUST be strictly increasing by node_index.
* MUST contain no duplicate node_index.
* Each node_index MUST be in range [0..2*N_max-2].
* Each ek MUST be exactly 1184 bytes.
* Each node_index MUST be an internal node (node_index < leaf_base) and MUST NOT be a leaf.
Violations:
* server reject 960.7
* clients reject locally

S11.6 Canonical pre-update tree construction (normative)
Source of prev_barrier_version (normative):
* For validation of a received barrier_update: prev_barrier_version := BU.prev_barrier_version.
* For updater construction of a to-be-published barrier_update: prev_barrier_version := local barrier_version before increment.

RevokedLeafSet := ResolveRevokedLeaves(revocation_roots_hash)
JoinSet        := ResolveJoinsSince(prev_barrier_version)
Canonical-view requirement (normative):
* When S11.6 is executed for FULL client chain-check, updater chain-check, join-finalize eligibility, or server acceptance, `RevokedLeafSet`, `JoinSet`, and the non-genesis `snapshot_base` MUST all be authenticated under the same `HistoryCommitment`.
* If the non-genesis `snapshot_base` is the caller's locally stored current committed tree for the same `barrier_version` being validated or incremented, equality with that current-state `HistoryCommitment` is mandatory, not optional.
Genesis convention:
When barrier_initialized == false, prev_barrier_version MUST be treated as 0 for JoinSet enumeration, and ResolveJoinsSince(0) MUST return the complete active leaf set for genesis.
Leaf-allocation invariant (normative):
* `N_max` defines concurrent slot capacity, not lifetime slot consumption.
* cover leaf indices MAY be reused after revocation or leave, but only with a strictly increasing `slot_generation`.
* For any selected committed `history_view_id`, the authenticated unresolved `JoinSet` returned by `ResolveJoinsSince(prev_barrier_version)` MUST contain at most one active occupancy record per currently active leaf and therefore at most `N_max` records.
* Servers MUST prune or compact historical join-activation state so that `ResolveJoinsSince(...)` depends only on activations that remain active at the selected committed view.

Concurrent-capacity note (informative):
Because cover leaf indices are reusable under versioned `slot_generation`, churn alone does not exhaust address space. Deployments SHOULD monitor concurrent occupancy `(active + pending)` relative to `N_max`. When concurrent demand approaches saturation, the deployment SHOULD either reject further joins or retire/re-create the group with a larger `N_max`. This profile still does not define an in-protocol `N_max` extension mechanism; such a mechanism MAY be defined by a future profile.
snapshot_base:
* genesis: all-blank tree (every pk_i := empty bstr for all 2*N_max-1 nodes)
* non-genesis: current committed pk_entries
snapshot_pre construction (order is normative):
1. Apply JoinSet:
   For each JoinLeafRecord (device_pk, leaf_index=l, ek_leaf, slot_generation):
   * set pk at leaf_node(l) := ek_leaf
   * for each internal node on direct_path(leaf_node(l)) excluding the leaf: set pk := empty bstr
2. Apply RevokedLeafSet:
   For each revoked occupancy (leaf_index=r, slot_generation):
   * blank pk at leaf_node(r)
   * blank pk at every node on direct_path(leaf_node(r)) including root_node
kem_tree_hash_before := TreeHash(root_node) over snapshot_pre (per S11.4)

S11.7 Mandatory path_nodes validation (normative)
Let pn := path_nodes and u := updater_leaf.
All checks MUST hold:
* len(pn) >= 1
* pn[0] == leaf_node(u)
* pn[last] == root_node
* For all i in [0..len(pn)-2]: parent(pn[i]) == pn[i+1]
* All pn[i] in range [0..2*N_max-2]
* No duplicates (strictly unique sequence)
Failure: reject 960.7.

S11.8 On-path-only cover semantics (normative, critical)
For each step i from 0 to len(pn)-2:
child_node  := pn[i]
source_node := pn[i+1]
targets     := resolution(sibling(child_node)) on snapshot_pre
NodeCiphertext MUST wrap path_secret[source_node] to each target in targets.

S11.9 new_public_keys contract (normative)
ExpectedNodeSet := { pn[i] | i in [1..len(pn)-1] }
Requirements (MUST):
* new_public_keys MUST contain exactly len(pn)-1 entries.
* For each i in [1..len(pn)-1], new_public_keys MUST contain exactly one entry [pn[i], ek].
* new_public_keys MUST contain NO other nodes besides ExpectedNodeSet.
* Order MUST be strictly increasing by node_index (also required by S11.5.1.D).
Updater generation requirement (MUST):
The updater MUST compute path_secret[n] for every n in ExpectedNodeSet and MUST populate ek for each [n, ek] as the deterministic ek_n derived from S11.10.
Client verifiability requirement (MUST for FULL clients):
Any client that derives path_secret[n] for some n in ExpectedNodeSet (see S11.13.5) MUST verify that the corresponding ek in new_public_keys equals ek_n derived from S11.10; mismatch -> reject barrier_update (fail closed).

S11.9.1 Updater generation of path_secret, wraps, and K_barrier_new (normative)
This subsection normatively specifies the updater procedure required for interoperability (seed -> path -> wrap). It does not change the cover semantics of S11.8.
Definitions:
* v_new := BarrierUpdate.barrier_version (the new barrier version to activate on acceptance)
* RRH := revocation_roots_hash
* u := cover_payload.updater_leaf
* pn := cover_payload.path_nodes
* snapshot_pre is constructed per S11.6 using the authenticated snapshot_base (see S11.11.1)
Requirements (MUST):
U1) Updater leaf seed (fresh entropy):
* The updater MUST sample a fresh 32-byte uniformly random secret ps_leaf32 from a cryptographically secure RNG.
* Set path_secret[leaf_node(u)] := ps_leaf32.
* ps_leaf32 MUST be freshly sampled for each barrier_update; it MUST NOT be derived solely from K_barrier or other values potentially known to revoked members.
U2) Derive path_secret upward on pn:
* For k = 1 .. len(pn)-1:
  parent_node := pn[k]
  child_node  := pn[k-1]
  path_secret[parent_node] := HKDF-BLAKE3(
    ikm  = path_secret[child_node],
    salt = H_L("barrier/tree/path", [gid, parent_node]),
    info = "city-g|barrier/tree|v1",
    L=32
  )
This derivation MUST be used so that client Recover (S11.13.4) computes identical path_secret values.
U3) Compute K_barrier_new:
* Set K_barrier_new := HKDF-BLAKE3(
    ikm  = path_secret[root_node],
    salt = H_L("barrier/derive/salt", [gid, v_new, RRH]),
    info = "city-g|barrier/key|v1",
    L=32
  )
U4) Populate new_public_keys deterministically:
* For each n in ExpectedNodeSet (which is pn[1..last]), the updater MUST derive (ek_n, dk_n) using S11.10 with path_secret[n] and MUST output ek_n in new_public_keys for node n.
* The updater MUST retain dk_n for nodes on its SelfPath for local activation per S11.14.
U5) Create NodeCiphertext entries:
For each step i from 0 to len(pn)-2:
  child_node  := pn[i]
  source_node := pn[i+1]
  targets := resolution(sibling(child_node)) computed over snapshot_pre
  For each target_node t in targets:
  * Let ek_t := snapshot_pre.pk_entries[t] (the ML-KEM ek at node t). It MUST be non-blank.
  * Compute target_pk_hash := H_pk(ek_t)[0..15].
  * Compute (kem_ct, ss32) := ML-KEM-768.Encaps(ek_t).
  * Define aad := CBOR_det([gid, v_new, BU.prev_barrier_version, BU.tree_size, RRH, BU.kem_tree_hash_before, BU.kem_tree_hash_after, u, source_node, t, H_pk(ek_t)]).
  * Define nonce := H_L("barrier/wrap/nonce", [source_node, t])[0..11].
  * Define wrapped_ps := AEAD_Seal(
      key32     = ss32,
      nonce12   = nonce,
      aad_bytes = aad,
      pt_bytes  = path_secret[source_node]   /* 32 bytes */
    ).
  The NodeCiphertext entry MUST be:
    [source_node, t, target_pk_hash, kem_ct, wrapped_ps]
All node_ciphertexts MUST then be sorted lexicographically by (source_node, target_node) and MUST satisfy S11.5.1.C (no duplicates, correct sizes).

S11.10 Deterministic internal-node key derivation (normative)
Applicability:
* applies ONLY to internal nodes whose ek is distributed via new_public_keys and whose dk may be stored on SelfPath.
* Does NOT apply to barrier leaf keys generated at join (header[177]) and stored as dk_leaf.
For node index n with context (gid, barrier_version=v, revocation_roots_hash=RRH, tree_size=N_max):
d_n := HKDF-BLAKE3(
  ikm  = path_secret[n],
  salt = H_L("barrier/keygen/d_salt", [gid, v, RRH, N_max, n]),
  info = "city-g|barrier/keygen-d|v1",
  L=32
)
z_n := HKDF-BLAKE3(
  ikm  = path_secret[n],
  salt = H_L("barrier/keygen/z_salt", [gid, v, RRH, N_max, n]),
  info = "city-g|barrier/keygen-z|v1",
  L=32
)
(ek_n, dk_n) := ML-KEM-768.KeyGen_internal(d_n, z_n)
Constraints (MUST):
* new_public_keys entries MUST use ek_n produced by this derivation.
* Implementations MUST reject any ek in new_public_keys that is not 1184 bytes.

S11.11 Active-server resistance (normative; 960.9 wired)

Threat-model scope clarification (normative):
* The base profile's "active-server resistance" means fail-closed resistance to tampering, stale/mismatched helper state, and local append-only history steering within one authenticated `HistoryAuthorityScope` when the client actually performs the required S11.11.2 checks.
* The base profile does NOT by itself define a federated/global consensus object across multiple independent history authorities. Cross-scope canonity/finality is therefore out of scope unless a deployment-specific extension defines it.
* A client that later observes authenticated but incompatible lineage claims for the same `gid` from different `HistoryAuthorityScope`s, or incompatible append-only lineage claims within one claimed scope, MUST enter `recovery_required/history_inconsistent` and MUST NOT treat either lineage as a valid base for barrier activation or origination until reprovisioned or otherwise repaired by deployment-defined recovery.

S11.11.1 Updater MUST authenticate snapshot_base (CRITICAL)
Before constructing any barrier_update, the updater MUST:
* already hold FULL-verified current barrier state at its locally stored current `barrier_version`, OR satisfy the join_finalize bootstrap exception below.
* A client whose current `kem_tree_hash_after` was learned only via recover-only processing MUST first re-establish FULL verification at the current version before originating any `barrier_update` with reason 0 or 1, acting as updater generally, or originating any pcs_refresh merge. This rule does not by itself forbid a just-joined client from originating reason 2 under the join_finalize bootstrap exception below.
* In the base profile, any client originating reason `0` or `1` MUST also obtain a fresh key `183` `FullVerificationWitness` for the exact `(gid, header[175], header[178], header[180], header[181], header[182])` tuple before publish. Absence of that witness means the client is not authoring-eligible for reasons `0` or `1` under the base profile.
* Let H_prev := updater's locally stored kem_tree_hash_after for current barrier_version.
* Genesis special case:
  * if barrier_initialized == false (genesis updater), H_prev is the TreeHash(root_node) of the all-blank tree of size N_max.
  * This value is deterministic and MUST be computed locally without fetching from the server.
* Non-genesis:
  * Fetch `pk_entries_prev := FetchBarrierPublicTree(H_prev)`, OR use a locally retained authenticated current public-tree snapshot for the same `(gid, barrier_version, H_prev, N_max)` if the client previously authenticated and retained that exact current committed tree while on the same current committed state.
  * In either case, compute `TreeHash(root_node)` over `pk_entries_prev` per S11.4 and require it equals `H_prev`.
  * If `pk_entries_prev` came from `FetchBarrierPublicTree(H_prev)`, the authenticated `HistoryCommitment` returned with `pk_entries_prev` MUST equal the authenticated current-state `HistoryCommitment` used for `ResolveJoinsSince(...)` and `ResolveRevokedLeaves(...)`; mismatch -> 960.9.
  * If `pk_entries_prev` came from a locally retained authenticated current snapshot, the client MUST already hold the authenticated current-state `HistoryCommitment` for that same current committed state locally, and the A/B responses used for this origination MUST validate to that same local current-state `HistoryCommitment`; otherwise the retained-snapshot fast path is forbidden and the client MUST refetch.
  * If the deployment exposes a merge-ticket helper/API for this current state, that helper MUST also identify the same current-state `HistoryCommitment`; clients MUST reject the helper result if the fetched current snapshot/A/B responses do not match it.
  * The emitted MERGE anchor MUST carry that exact current-state `HistoryCommitment` as `header[180]`.
  * H_prev MAY refer to a historical committed tree snapshot; the server MUST support this per S3.3.C and S5.1.
Join-finalize bootstrap exception (normative):
* A newly joined client with `pending_barrier_recovery == true` MAY originate reason 2 (`join_finalize`), and no other barrier-update reason, while pending if, and only if, it has:
  * the S12.2 provisioned current barrier metadata for the current committed state,
  * the S12.2 provisioned `join_finalize_auth` capability bound to its `(gid, leaf_id, slot_index, slot_generation)`,
  * authenticated access to S3.3.A/B for that same current committed state, with those A/B responses validating to the provisioned `current_history_commitment`,
  * authenticated access to `FetchBarrierPublicTree(current kem_tree_hash_after)` for that same current committed state,
  * the authenticated accepted current `barrier_update` bytes for that same current committed state, together with authenticated history material sufficient to authenticate the predecessor snapshot named by that accepted update,
  * and has executed the bootstrap verification context below for that accepted current committed state,
  * successfully performed the FULL public-tree checks of S11.11.2 and the applicable `ek_n` verification of S11.13.6 for that current committed state.
Bootstrap verification context (normative):
* For this exception only, the `H_prev` used by the S11.11.2-style checks is NOT the joiner's locally stored current `kem_tree_hash_after`.
* Instead, define `BU_current :=` the authenticated accepted current `barrier_update` bytes provisioned for the current committed state, and define `H_prev_bootstrap :=` the provisioned committed predecessor `kem_tree_hash_after` used as `snapshot_base` when authoring `BU_current`.
* The joiner MUST fetch/authenticate `snapshot_current := FetchBarrierPublicTree(current kem_tree_hash_after)` and require that its tree bytes validate to the provisioned current `kem_tree_hash_after`.
* Exact equality of `snapshot_current`'s returned `HistoryCommitment` to the provisioned `current_history_commitment` is NOT required if the returned tree bytes validate to that provisioned current `kem_tree_hash_after`; after the JOIN itself is accepted, the same current tree MAY legitimately be re-attested under a later `HistoryCommitment` from the same `HistoryAuthorityScope`.
* The joiner MUST fetch/authenticate `snapshot_base := FetchBarrierPublicTree(H_prev_bootstrap)`.
* `snapshot_base` MAY be a retained historical predecessor snapshot whose own `HistoryCommitment` predates the provisioned current commitment; this retained snapshot MAY come either from `FetchBarrierPublicTree(H_prev_bootstrap)` or from a bounded local retained-snapshot cache populated from a previously authenticated snapshot for the same `(gid, H_prev_bootstrap, N_max)` within the same `HistoryAuthorityScope`. For this bootstrap exception, authenticity of `snapshot_base` is established by `TreeHash(snapshot_base) == H_prev_bootstrap`, not by requiring `snapshot_base` to carry the same current `HistoryCommitment`.
* The joiner MUST execute the S11.11.2 chain-checks against `BU_current`, the provisioned predecessor `H_prev_bootstrap`, the provisioned `current_history_commitment`, and the corresponding authenticated current-state A/B responses for that same provisioned `HistoryCommitment`.
* A joiner MUST NOT treat its provisioned current `kem_tree_hash_after` alone as a sufficient trust root for this bootstrap check.
* Satisfying the bullets above establishes FULL public-state verification sufficient for join_finalize eligibility even though the client has not yet derived the current `K_barrier`.
* A pending joiner admitted under this exception MUST still NOT originate reason 0 or reason 1 while `pending_barrier_recovery == true`.
If this check fails, the updater MUST abort barrier_update creation, MUST NOT sign/emit an anchor containing barrier_update, and MUST surface 960.9.

S11.11.2 FULL clients MUST chain-check (CRITICAL)
A FULL-verifying client processing a barrier_update MUST:
* Let H_prev := client's locally stored kem_tree_hash_after.
* Fetch `pk_entries_prev := FetchBarrierPublicTree(H_prev)`, OR use a locally retained authenticated current public-tree snapshot for the same `(gid, barrier_version, H_prev, N_max)` if the client already authenticated and retained that exact current committed tree for the same current committed state.
* If `pk_entries_prev` came from `FetchBarrierPublicTree(H_prev)`, record its authenticated `HistoryCommitment := hc_tree`; if it came from a locally retained authenticated current snapshot, set `hc_tree :=` the client's locally stored authenticated current-state `HistoryCommitment`. In either case, verify `TreeHash(pk_entries_prev) == H_prev`; failure -> 960.9.
* H_prev MAY refer to a historical committed tree snapshot; the server MUST support this per S3.3.C and S5.1.
* If `H_prev` is the immediate predecessor committed tree of the current accepted barrier state within the same `HistoryAuthorityScope`, `FetchBarrierPublicTree(H_prev)` MUST return that predecessor tree authenticated under the current-state `HistoryCommitment` used by A/B for the current committed state.
* The retained-snapshot fast path above always applies to the client's current committed tree.
* Additionally, a client MAY satisfy an explicitly named historical predecessor snapshot dependency from a bounded local retained-snapshot cache instead of refetching if, and only if, that exact `(gid, H_prev, N_max)` snapshot was previously authenticated and retained locally either as:
  * a fetched historical predecessor snapshot, or
  * a formerly current FULL-verified committed tree within the same `HistoryAuthorityScope`.
* Clients that implement this retained historical predecessor fast path MUST bound the local cache to `MAX_RETAINED_LOCAL_PUBLIC_TREE_SNAPSHOTS`.
* For uncached historical predecessor snapshots, S3.3.C fetch/authentication remains required.
* The base profile's worst-case work for one uncached historical predecessor chain-check is therefore the exact reconstruction and hashing of one `pk_entries` array of size `(2*N_max-1)`, plus the bounded A)/B) helper pages for that same result. Because `N_max <= MAX_BARRIER_N_MAX`, this path is normatively bounded even when no retained-snapshot fast path applies. Proof/subtree shortcuts are optional optimization extensions, not required for base-profile conformance.
* Obtain `RevokedLeafSet := ResolveRevokedLeaves(revocation_roots_hash)` and `JoinSet := ResolveJoinsSince(BU.prev_barrier_version)` and record their authenticated view identifiers `hv_revoked` and `hv_join`.
* Require `hv_revoked == hv_join`; mismatch or missing authenticated current-state view binding -> 960.9.
* In this FULL-client flow, `H_prev` is the client's locally stored current committed tree, so `hc_tree` MUST equal the current-state `HistoryCommitment` authenticated by A/B; mismatch -> 960.9.
* The weaker rule where `TreeHash(pk_entries_prev) == H_prev` is sufficient without current-state commitment equality applies only to explicitly historical predecessor snapshots such as the join-finalize bootstrap exception, where the spec calls that exception out by name.
* Using pk_entries_prev as snapshot_base, construct snapshot_pre using S11.6 (with verifiable JoinSet and RevokedLeafSet).
* Verify BU.kem_tree_hash_before equals hash(snapshot_pre).
* Parse CP := KemTreeCoverPayload from BU.cover_payload bytes and enforce CBOR_det determinism per S1.3; parse or determinism failure -> 960.7.
* Apply CP.new_public_keys to snapshot_pre to obtain snapshot_post.
* Verify BU.kem_tree_hash_after equals hash(snapshot_post).
Error precedence (normative):
* Snapshot-auth failures (FetchBarrierPublicTree failure, or TreeHash(root_node) != H_prev) MUST surface 960.9 and MUST terminate processing.
* If snapshot-auth succeeds but kem_tree_hash_before/kem_tree_hash_after chain-checks fail, the client MUST reject locally (fail closed) with 960.8.

S11.11.3 Non-full clients (recover-only)
A client that cannot fetch/verify snapshot_base MAY still attempt recovery (unique match) but MUST:
* enforce S11.7 path_nodes validation,
* enforce S11.5.1 canonicalization rules,
* enforce unique-match fail-closed semantics (S11.13.1),
* enforce deterministic storage rule (S11.13.5),
* treat barrier_update as untrusted for public-tree correctness beyond its local recovery.
Additional restriction (normative):
* A recover-only client MUST NOT originate `barrier_update`, MUST NOT act as updater, and MUST NOT originate pcs_refresh merges until it has obtained FULL verification of the current public tree at the current `barrier_version`.
* In the base profile, acceptors independently enforce the same safety boundary for reasons `0` and `1` by requiring a valid key `183` witness under `global-history-authority-v1`; client honesty is not the only line of defense for those reasons.
* Exception: a newly joined client with `pending_barrier_recovery == true` MAY originate reason 2 (`join_finalize`), and no other barrier-update reason, after satisfying the S11.11.1 join_finalize bootstrap exception. Until then, and for all other reasons, the restriction above remains absolute.
* A client originating reason 2 MUST carry the exact provisioned `header[179] join_finalize_auth` value from S12.2. Clients MUST NOT reuse a cleared or zero value.
* Any client originating a `barrier_update`, including reason 2 under the bootstrap exception, MUST carry `header[180]` equal to the authenticated current-state `HistoryCommitment` used for the A/B/current-snapshot checks that justified origination.
* `current_barrier_full_verified` remains a client-local safety predicate even in the base profile.
* `header[180]` proves only that the author claims one authenticated current-state `HistoryCommitment` for its helper inputs; it does NOT, by itself, prove to the server that the author actually executed S11.11.2 correctly.
* In the base profile, `header[181]` + `header[182]` make that helper-state binding wire-visible and server-checkable within `global-history-authority-v1`, but they still do NOT, by themselves, prove federated consensus or any stronger cross-deployment finality than S3.3.F defines.
* The base profile intentionally does NOT remotely attest whether the author reached that attested helper/current-state decision via a locally FULL path or a locally recover-only path. The remote/server-visible guarantee in this profile is exact binding to one authenticated helper/current-state decision plus the local origination restrictions above. Deployments that require a stronger remote distinction MUST define an extension with an independently authenticated verifier for that distinction.
Catch-up over multi-version gaps (normative):
* If the client knows that the currently accepted head is newer than `local barrier_version + 1`, it is in catch-up mode.
* In catch-up mode, if the currently observed accepted bundle itself carries `header[178] == 1 (pcs_refresh)` and the client lacks authenticated lineage sufficient to order the intervening accepted heads, it MUST enter `recovery_required/insufficient_authenticated_history` (or an equivalent fail-closed state). It MUST NOT best-effort apply that bundle and MUST NOT reseed `K_fs`.
* In catch-up mode, if the currently observed accepted bundle does NOT carry `header[178] == 1`, the client MAY attempt best-effort recovery of that exact currently accepted head via the unique-match rules of S11.13 only.
* If that best-effort recovery succeeds, the client MAY activate the recovered barrier state using S11.13.7, but MUST set `current_barrier_full_verified := false` for that post-state unless it also completed S11.11.2 for that exact post-state in the same crash-safe decision.
* If best-effort recovery yields no unique match, or if authenticated history remains insufficient to prove ordering/completeness for the current head, the client MUST remain in `barrier_recovery_pending` or `recovery_required`, and MUST keep payload send/fetch disabled until a later authenticated sync or targeted barrier update resolves the state.

S11.11.4 FULL-verification receipt
In the base profile, key `181` is bound to `global-history-authority-v1`. Additional non-base deployments MAY define stronger receipts, but they MUST satisfy the generic requirements below.
Generic requirements on any such extension:
* The extension MUST define negotiation / profile identification so both client and server know that key `181` is in use.
* The receipt carried in key `181` MUST be cryptographically bound, at minimum, to `(gid, HistoryAuthorityScope, current HistoryCommitment, current barrier_version, current kem_tree_hash_after, author leaf_id, barrier_update_reason, header[180])`.
* The extension MUST define freshness / anti-replay for the receipt. A static reusable blob is insufficient.
* The extension MUST define who signs or authenticates the receipt and why that authenticator can distinguish FULL verification from recover-only processing.
* A mere restatement of helper inputs, or a client self-assertion without an authenticated verifier/challenge, MUST NOT be documented as sufficient proof of FULL verification.

Concrete extensions defined by this document:
* `local-history-authority-v1` and `global-history-authority-v1` are two concrete extensions satisfying these requirements within one deployment-local or deployment-global `HistoryAuthorityScope`, respectively.
* Under `local-history-authority-v1`, key `181` MUST carry `FullVerificationReceipt := { author_leaf_id:bstr32, barrier_update_reason:uint, updater_leaf:uint, updater_slot_generation:uint64, signature:bstr }` encoded as deterministic CBOR.
* Under `local-history-authority-v1`, the signed receipt payload MUST bind exactly `(gid, author_leaf_id, barrier_update_reason, updater_leaf, updater_slot_generation, header[180], header[182], header[175])`.
* Under `local-history-authority-v1`, the receipt MUST be signed by the author's POP signing key that is currently and uniquely bound to `author_leaf_id` in the server's authenticated membership view.
* Under `local-history-authority-v1`, the server MUST verify that `author_leaf_id`, `barrier_update_reason`, `updater_leaf`, and `updater_slot_generation` in key `181` match the actual author/current update being accepted.
* Under `local-history-authority-v1`, key `181` MUST NOT appear without a matching key `182` for the same current `HistoryCommitment`; receipt validation fails closed if the attestation or commitment differs.
* Under `local-history-authority-v1`, any accepted `barrier_update` originated under that extension MUST carry both key `181` and key `182`; a bundle carrying key `182` without key `181`, or vice versa, is malformed for this extension.
* Under `local-history-authority-v1`, this receipt proves only that the author bound its `barrier_update` to one exact scope-local attested helper state. It does NOT upgrade that scope-local attestation into a globally canonical finality proof.
* Under `global-history-authority-v1`, key `181` MUST carry the same `FullVerificationReceipt` object and deterministic CBOR form as above.
* Under `global-history-authority-v1`, the signed receipt payload MUST bind exactly `(gid, author_leaf_id, barrier_update_reason, updater_leaf, updater_slot_generation, header[180], header[182], header[175])`.
* Under `global-history-authority-v1`, the receipt MUST be signed by the author's POP signing key that is currently and uniquely bound to `author_leaf_id` in the deployment-global authenticated membership view being used for acceptance.
* Under `global-history-authority-v1`, the server MUST verify that `author_leaf_id`, `barrier_update_reason`, `updater_leaf`, and `updater_slot_generation` in key `181` match the actual author/current update being accepted.
* Under `global-history-authority-v1`, key `181` MUST NOT appear without a matching key `182` for the same current `HistoryCommitment`; receipt validation fails closed if the attestation or commitment differs.
* Under `global-history-authority-v1`, any accepted `barrier_update` originated under that extension MUST carry both key `181` and key `182`; a bundle carrying key `182` without key `181`, or vice versa, is malformed for this extension.
* Under `global-history-authority-v1`, this receipt proves only that the author bound its `barrier_update` to one exact deployment-global attested helper state. It does NOT, by itself, prove federated consensus across multiple deployments.

Base-profile rule:
* In the base profile defined by this document, key `181` MUST carry the `global-history-authority-v1` receipt whenever key `175` is present, and servers MUST reject its absence or mismatch as malformed.

S11.11.4A Full-verification witness
Key `183` is the generic wire slot for an authority-issued `FullVerificationWitness` on `barrier_update` reasons `0` and `1`.
Generic requirements:
* The negotiated extension MUST define the exact witness object, signature suite, and negotiation/profile identifier.
* The witness MUST bind at minimum `(HistoryAuthorityScope, gid, current HistoryCommitment, current barrier_version, current kem_tree_hash_after, author_leaf_id, barrier_update_reason, updater_leaf, updater_slot_generation, digest(header[175]), digest(ResolveJoinsSince result), digest(ResolveRevokedLeaves result), digest(deployment_profile_manifest))`.
* The signer/authenticator for key `183` MUST be able to replay the exact `reason in {0,1}` authoring decision against the authenticated current tree and authenticated helper outputs for that same current state. A static blob or pure client self-assertion is insufficient.
* Under `global-history-authority-v1`, `FullVerificationWitness := { scope_id:bstr32, history_authority_extension:tstr, gid:bstr32, history_view_id:bstr32, history_commitment_id:bstr32, prev_history_commitment_id:bstr32, history_seq:uint, barrier_version:uint, kem_tree_hash_after:bstr32, author_leaf_id:bstr32, barrier_update_reason:uint, updater_leaf:uint, updater_slot_generation:uint64, barrier_update_digest:bstr32, joins_digest:bstr32, revoked_digest:bstr32, deployment_profile_manifest_digest:bstr32, signature:bstr }` encoded as deterministic CBOR.
* Under `global-history-authority-v1`, the server/history authority MUST issue key `183` only after replaying the exact S11.11.2-style chain-check for the candidate `barrier_update` against the authenticated current public tree, the authenticated A/B helper outputs, and the authenticated deployment-profile manifest for that same current committed state.
* Under `global-history-authority-v1`, accepted `barrier_update` bundles with reason `0` or `1` MUST carry key `183`; a missing, stale, or mismatched witness is malformed for this extension.
* Under `global-history-authority-v1`, key `183` proves server-verifiable authoring eligibility for that exact `reason in {0,1}` bundle within one deployment-global `HistoryAuthorityScope`. It still does NOT, by itself, prove federated consensus across multiple independent deployments.

S11.11.5 Global-history attestation
Key `182` is the generic wire slot for authenticated history attestations. Two cases exist:

1. `local-history-authority-v1` (defined by this document, not part of the base profile):
* Under `local-history-authority-v1`, key `182` MUST carry the scope-local `GlobalHistoryAttestation` object defined in S3.3.E.
* The client MUST verify key `182` under the negotiated `HistoryAuthorityDescriptor` and MUST require its `scope_id`, `history_view_id`, `HistoryCommitment`, `barrier_version`, and `kem_tree_hash_after` to match the helper/current-state decision it is about to make.
* The server MUST reject key `182` if it does not exactly match the current authenticated `HistoryCommitment`, `barrier_version`, and `kem_tree_hash_after` that the server is using for acceptance.
* When a client or server validates a `barrier_update` under `local-history-authority-v1`, key `182` MUST be accompanied by key `181`; a lone attestation is invalid.
* When `local-history-authority-v1` is negotiated, successful A)/B)/C)/D) responses and any join/merge/provisioning current-state helper bundles used for one decision MUST all validate to the same `HistoryAuthorityDescriptor` and the same scope-local attestation lineage.
* `local-history-authority-v1` uses `finality_kind = "local-append-only"` and therefore proves only scope-local append-only correlation. It MUST NOT be described as a globally canonical/final history proof.

2. Base profile `global-history-authority-v1` or another stronger globally canonical/final-history extension:
* The base profile requires `global-history-authority-v1`. A deployment that requires stronger globally canonical/final history than that deployment-global authority provides MUST negotiate an extension at least as strong.
* Under `global-history-authority-v1`, key `182` MUST carry the deployment-global `GlobalHistoryAttestation` object defined in S3.3.F.
* The client MUST verify key `182` under the negotiated `HistoryAuthorityDescriptor` and MUST require its `scope_id`, `history_view_id`, `HistoryCommitment`, `barrier_version`, and `kem_tree_hash_after` to match the helper/current-state decision it is about to make.
* The server MUST reject key `182` if it does not exactly match the current authenticated `HistoryCommitment`, `barrier_version`, and `kem_tree_hash_after` that the server is using for acceptance under that deployment-global authority.
* When a client or server validates a `barrier_update` under `global-history-authority-v1`, key `182` MUST be accompanied by key `181`; for reasons `0` and `1` in the base profile it MUST also be accompanied by key `183`. A lone attestation is invalid.
* When `global-history-authority-v1` is negotiated, successful A)/B)/C)/D) responses and any join/merge/provisioning current-state helper bundles used for one decision MUST all validate to the same `HistoryAuthorityDescriptor` and the same deployment-global attestation lineage.
* `global-history-authority-v1` uses `finality_kind = "global-append-only"` and therefore proves one deployment-global append-only lineage. It still does NOT, by itself, prove federated consensus across multiple independent deployments.
* A bare client self-assertion, or a restatement of one local `HistoryCommitment`, MUST NOT be documented as sufficient global-history attestation.

Base-profile rule:
* In the base profile defined by this document, key `182` MUST carry the `global-history-authority-v1` attestation whenever key `175` is present, and servers MUST reject its absence or mismatch as malformed.

S11.12 Server-side validation of barrier_update (normative; MUST)

S11.12.1 Validation procedure (MUST)
If header[175] present, the server MUST execute steps A through I in order:

A) Gating
* If header[178] is absent: reject 960.7.
* If header[178] is present and header[178] is not in {0,1,2}: reject 960.7.
* If header[178] == 2 and header[179] is absent or not exactly 32 bytes: reject 960.1.
* If header[178] != 2 and header[179] is present: reject 960.7.
* If header[180] is absent, not a bstr, or not valid CBOR_det(HistoryCommitment): reject 960.7.
* If header[175] is present and header[181] is absent in the base profile: reject 960.7.
* If header[175] is present and header[182] is absent in the base profile: reject 960.7.
* If header[178] is in {0,1} and header[183] is absent in the base profile: reject 960.7.
* If header[178] == 2 and header[183] is present: reject 960.7.
* Later steps MUST validate keys `181` / `182` / `183` exactly per the negotiated history-authority extension and MUST fail closed on any mismatch against `(header[175], header[178], header[180], gid, current authenticated state)`.
* If barrier_initialized == true and pending_revocations == false and header[178] == 0: reject 960.5 barrier_proactive_forbidden.
* If barrier_initialized == true and pending_revocations == true and header[178] != 0: reject 960.13.
* If header[178] == 1, later steps MUST enforce S10.4B.
* If header[178] == 2, later steps MUST enforce S10.4C.
* If merge_delegation_sig (key 135) is present: reject 960.4 barrier_merge_delegation_forbidden.

B) Parse + structure
* If length(header[175]) > max_barrier_update_bytes: reject 960.7.
* Parse BarrierUpdate and KemTreeCoverPayload from raw bytes; reject malformed CBOR with 960.7.
* Enforce CBOR_det determinism verification per S1.3 for both structures; non-determinism -> 960.7.
* Require BU.tree_size == N_max.
* Require BU.revocation_roots_hash == computed revocation_roots_hash (from S11.1).
* Require BU.barrier_version == header[176].
* If computed revocation_roots_hash != GroupState.barrier_roots_hash and GroupState.barrier_initialized == true:
  * Require header[178] == 0, else reject 960.13.
* Genesis: require BU.prev_barrier_version == 0.
* Non-genesis: require BU.prev_barrier_version == GroupState.barrier_version.

C) Canonicalization + duplicates MUST
* Enforce S11.5.1; failure -> 960.7.

D) Mandatory validation of path_nodes MUST
* Enforce S11.7; failure -> 960.7.

E) Contract for new_public_keys MUST
* Let CP := parsed KemTreeCoverPayload.
* Define pn := CP.path_nodes.
* Compute ExpectedNodeSet per S11.9 from pn.
* Require CP.new_public_keys contains exactly len(pn)-1 entries and exactly the nodes in ExpectedNodeSet; failure -> 960.7.

F) Updater identity binding + updater-not-revoked
* Define updater_leaf := CP.updater_leaf.
* Define `current_slot_lease(header[108]) := (slot_index, slot_generation)` as the unique currently active or pending slot lease for the acting `leaf_id`.
* Require `updater_leaf == current_slot_lease(header[108]).slot_index` and `CP.updater_slot_generation == current_slot_lease(header[108]).slot_generation`; else reject 960.1.
* Require the exact updater lease `(updater_leaf, CP.updater_slot_generation)` NOT appear in RevokedLeafSet for this update; else reject 960.1.
* Let JoinSet := ResolveJoinsSince(BU.prev_barrier_version).
* Let JoinLeafSet := the set of active `leaf_index` values carried by JoinSet.
* The server MUST evaluate `RevokedLeafSet`, `JoinSet`, and the `snapshot_base` used below against one common authenticated `HistoryCommitment`; inability to establish a single common commitment -> reject 960.9.
* The server MUST require `header[180]` to equal that same authenticated current-state `HistoryCommitment`; mismatch -> reject 960.9.
* These checks establish helper-state coherence only. They MUST NOT be documented or relied upon as proof that the client performed FULL verification, unless a deployment-defined extension adds such a proof.
* If header[178] == 1:
  * Require updater_leaf NOT IN JoinLeafSet, else reject 960.5.
  * Server MUST enforce S10.4B policy checks; on failure reject 960.12.
* If header[178] == 2:
  * Require updater_leaf IN JoinLeafSet, else reject 960.5.
  * Require `header[179]` to match one server-issued pending `join_finalize_auth` capability bound to the acting `(gid, leaf_id, updater_leaf, CP.updater_slot_generation)`; otherwise reject 960.1.
  * join_finalize MUST NOT execute S10.4B PCS rate-limit checks.

G) Hash-chain checks MUST
* Construct snapshot_base:
  * genesis: all-blank tree of size N_max
  * non-genesis: server's stored current pk_entries for kem_tree_hash_after
* Build snapshot_pre using S11.6 and compute expected_before.
* Require expected_before == BU.kem_tree_hash_before; else 960.8.
* Apply CP.new_public_keys to snapshot_pre to obtain snapshot_post.
* Compute expected_after := TreeHash(root_node) over snapshot_post.
* Require expected_after == BU.kem_tree_hash_after; else 960.8.

H) ExpectedPairs completeness/minimality MUST
* Using snapshot_pre and S11.8, compute ExpectedPairs:
  For each i = 0..len(pn)-2:
    child=pn[i], source=pn[i+1], targets = resolution(sibling(child))
    include (source, target) for each target in targets.
* Verify node_ciphertexts correspond exactly to ExpectedPairs (no missing pairs, no extra pairs).
* Verify each NodeCiphertext.target_pk_hash equals H_pk(pk_target)[0..15] for the pk_target in snapshot_pre.
* Failure -> reject 960.3.

I) State update on acceptance
Upon acceptance of this merge, server MUST set:
* barrier_initialized := true
* barrier_version := BU.barrier_version
* barrier_roots_hash := BU.revocation_roots_hash
* kem_tree_hash_after := BU.kem_tree_hash_after
and MUST persist the corresponding pk_entries snapshot_post as the current public tree.
If header[178] == 2, the matched pending `join_finalize_auth` capability for that leaf MUST be consumed/cleared on acceptance.
If any leaves are revoked by the accepted delta, any pending `join_finalize_auth` capability for those revoked leaves MUST be cleared.

NOTE (security model): server-side checks alone do not protect against an actively malicious server. Active-server injection protections are enforced by updater chain-check (S11.11.1), FULL client chain-check (S11.11.2), and FULL client ek_n verification (S11.13.6).

S11.13 Client recover (non-updater) (normative)
Definitions (normative)
* BU := the parsed BarrierUpdate from header[175]
* CP := the parsed KemTreeCoverPayload from BU.cover_payload
let self_slot_lease := the locally provisioned or persisted `(slot_index, slot_generation)` for `self_device_pk`
SelfPath := direct_path(leaf_node(self_slot_lease.slot_index))     /* node indices */
own_barrier_update := (header[108] == self_device_pk)
  AND (CP.updater_leaf == self_slot_lease.slot_index)
  AND (CP.updater_slot_generation == self_slot_lease.slot_generation)

Updater exclusion (normative, MUST):
If own_barrier_update == true, the client MUST NOT run Recover for that barrier_update. The updater activates via S11.14 (persisted pending state). Attempting Recover for one's own update would produce a spurious 960.6 (no NodeCiphertext targets the updater's own leaf by design).

S11.13.1 Unique match (fail-closed)
Client-local prerequisite (normative, MUST):
Allowing barrier recovery requires that, for each stored dk_t (for a node t on SelfPath), the client also has pkhash_t := H_pk(ek_t) (bstr32) where ek_t is the corresponding public key paired with dk_t.

A NodeCiphertext matches a client iff:
* client possesses dk_t for target_node=t on its SelfPath,
* client possesses pkhash_t for the same target_node=t,
* target_pk_hash == pkhash_t[0..15],
* Decaps(dk_t, kem_ct) yields ss and AEAD_Open succeeds with normative AAD/nonce (see S11.13.4), where the AAD uses pkhash_t.

Rules:
* |Matches| == 0 -> 960.6 barrier_recover_no_match (client-local; NOT a global reject)
* |Matches| > 1 -> 960.2 barrier_recover_multi_match (reject barrier_update; fail closed)
* |Matches| == 1 -> proceed

S11.13.2 On-path-only enforcement (normative)
For the unique match (s=source_node, t=target_node), client MUST verify:
* t IN SelfPath AND s IN SelfPath
Else reject barrier_update with 960.7.

S11.13.3 Mandatory validation (MUST)
Clients MUST enforce:
* S11.5.1 canonicalization rules (including CBOR_det determinism verification where applicable)
* S11.7 path_nodes validation
* Define barrier_update_bytes := raw bytes of header[175].
* length(barrier_update_bytes) <= max_barrier_update_bytes
* Require BU.tree_size == N_max.
* Require BU.barrier_version == header[176].
* Require BU.revocation_roots_hash == revocation_roots_hash (computed per S11.1).
* Local version adjacency:
  * allow genesis-local case only if `(local barrier_initialized == false AND BU.prev_barrier_version == 0 AND BU.barrier_version == 0)`,
  * otherwise require `local barrier_initialized == true`, `BU.prev_barrier_version == local barrier_version`, and `BU.barrier_version == local barrier_version + 1`.
* Local barrier_update_reason mirror:
  * if local `barrier_roots_hash != BU.revocation_roots_hash`, then `header[178] MUST equal 0`,
  * else let `JoinSet_local := ResolveJoinsSince(BU.prev_barrier_version)` and `JoinLeafSet_local := { leaf_index | record in JoinSet_local }`,
  * if local `barrier_roots_hash == BU.revocation_roots_hash` AND `CP.updater_leaf IN JoinLeafSet_local`, then `header[178] MUST equal 2`,
  * if local `barrier_roots_hash == BU.revocation_roots_hash` AND `CP.updater_leaf NOT IN JoinLeafSet_local`, then `header[178] MUST equal 1`,
  * except for the genesis-local case above, where `header[178] MUST equal 0`.
* Clients MUST reject stale, duplicate, or gap barrier updates that do not satisfy the local version-adjacency rules above.
* If a client is operating in a catch-up path outside this exact-adjacency recover rule because it has already learned that the current accepted head is newer than `local barrier_version + 1`, it MUST NOT best-effort apply or reseed `K_fs` across an unauthenticated `pcs_refresh` boundary. At minimum, if the currently observed accepted bundle itself carries `header[178] == 1`, the client MUST enter `recovery_required` or an equivalent non-active buffered state unless authenticated history proves the ordering and completeness of the intervening accepted lineage.
Failure -> reject barrier_update locally with 960.7.

S11.13.4 Recover derivation (normative)
Given the unique match (s, t) and the accepted BarrierUpdate with barrier_version=v_new:
ss := ML-KEM-768.Decaps(dk_t, kem_ct)
aad := CBOR_det([gid, v_new, BU.prev_barrier_version, BU.tree_size, revocation_roots_hash, BU.kem_tree_hash_before, BU.kem_tree_hash_after, CP.updater_leaf, s, t, pkhash_t])
nonce := H_L("barrier/wrap/nonce", [s, t])[0..11]
pt := AEAD_Open(key=ss, nonce=nonce, aad=aad, ct=wrapped_ps)
If AEAD_Open fails -> reject with 960.7.
If length(pt) != 32 -> reject with 960.7.
path_secret[s] := pt
Find s in CP.path_nodes at index j; if absent -> 960.7.
Derive upward along pn to root:
Let pn := CP.path_nodes.
For k = j+1 .. last:
  parent_node := pn[k]
  child_node  := pn[k-1]
  path_secret[parent_node] := HKDF-BLAKE3(
    ikm  = path_secret[child_node],
    salt = H_L("barrier/tree/path", [gid, parent_node]),
    info = "city-g|barrier/tree|v1",
    L=32
  )
Compute K_barrier_new:
K_barrier_new := HKDF-BLAKE3(
  ikm  = path_secret[root_node],
  salt = H_L("barrier/derive/salt", [gid, v_new, revocation_roots_hash]),
  info = "city-g|barrier/key|v1",
  L=32
)

S11.13.5 Deterministic dk_n storage rule (normative)
Let pn := CP.path_nodes and let s := source_node for the unique match.
Let j be the unique index such that pn[j] == s (must exist, else reject 960.7).
SuffixNodes := { pn[k] | k in [j..len(pn)-1] }
Client MUST:
* Maintain dk_leaf (join-generated) for n == leaf_node(self_slot_lease.slot_index); it is NOT derived from path_secret.
* Maintain pkhash_leaf := H_pk(ek_leaf) for the same leaf (bstr32).
* For each node n in (SuffixNodes INTERSECT SelfPath) such that n != leaf_node(self_slot_lease.slot_index):
  * derive (d_n, z_n) and (ek_n, dk_n) using S11.10 with path_secret[n]
  * store dk_n (overwriting any prior dk_n for that node)
  * store pkhash_n := H_pk(ek_n) alongside dk_n (overwriting any prior pkhash_n for that node)
* MUST NOT store derived keys for nodes outside SelfPath.

S11.13.6 Client verification of new_public_keys where derivable (normative; fail closed)
Let pn := CP.path_nodes.
Let ExpectedNodeSet := { pn[i] | i in [1..len(pn)-1] }
For each node n in (SuffixNodes INTERSECT ExpectedNodeSet):
* Client MUST locate the corresponding [n, ek_pub] entry in CP.new_public_keys (it exists by S11.9).
* Client MUST compute ek_n from S11.10 and MUST verify ek_pub == ek_n.
* If any mismatch occurs, client MUST reject barrier_update locally (fail closed) with 960.7.

S11.13.7 State update (normative)
Before committing the recovered post-state, the client MUST replay every server-side S10 invariant that is both client-visible and checkable from authenticated headers plus locally persisted state. At minimum:
* `header[143]` MUST equal the locally persisted `fs_epoch_base_ts` for the current session state.
* `header[153]` MUST equal `H_L("fs/dev/chain/v2", [header[108], header[141], header[152], header[176], barrier_update_digest])`.
* If `header[108]` equals the local author's device key, then `header[152]` MUST equal the locally persisted `fs_dev_prev_commit` and `header[141]` MUST be >= the locally persisted local-device `fs_ec`.
* If the client cannot perform these checks from authenticated headers plus locally persisted state, it MUST NOT commit the recovered post-state and MUST enter `barrier_recovery_pending` or `recovery_required`.
* This replay subset is intentionally limited to invariants derivable from authenticated headers plus locally persisted state. Remote membership/governance/rate-limit checks that are not client-visible remain server-side acceptance responsibilities in this base profile.
On successful processing:
* barrier_initialized := true
* barrier_version     := v_new
* barrier_roots_hash := BU.revocation_roots_hash
* K_barrier           := K_barrier_new
* kem_tree_hash_after := BU.kem_tree_hash_after
* pending_barrier_recovery := false
* `current_barrier_full_verified := false`, unless the same logical activation path already completed S11.11.2 FULL verification for this exact stored post-state as part of the same crash-safe decision.
* If header[178] == 1 (pcs_refresh), apply FS reseed per S6.6 using K_barrier_new at the same atomic activation point.
* If header[178] == 2 (join_finalize), `K_fs` MUST remain unchanged by this activation.
Atomicity requirement (normative, MUST):
* The entire successful activation above, together with all `dk_n/pkhash_n` updates from S11.13.5 and any PCS reseed of `K_fs`, MUST commit crash-safely as one logical transaction.
* After restart, the client MUST observe either the complete pre-activation state or the complete post-activation state, never a mixture.

S11.14 Updater local state management (normative; crash-safe; REQUIRED)
This section specifies how the updater activates its own barrier_update locally. The updater MUST NOT use the Recover path (S11.13) for its own updates.

S11.14.1 Persist-before-publish (MUST)
Before publishing/submitting any merge carrying header[175], the updater MUST persist durably (crash-safe):
* pending_barrier_version = v_new
* pending_we_epoch_id = the to-be-published `bundle.we_epoch_id`
* pending_fs_ec = header[141]
* pending_revocation_roots_hash = revocation_roots_hash
* pending_kem_tree_hash_after = kem_tree_hash_after /* BU.kem_tree_hash_after for the to-be-published barrier_update */
* pending_K_barrier_new = K_barrier_new
* pending_barrier_update_reason = header[178]
* pending_K_fs_after_pcs = (if header[178] == 1 then
    HKDF-BLAKE3(
      ikm  = (K_fs || K_barrier_new),
      salt = H_L("fs/pcs/salt", [weid, header[141], v_new]),
      info = "city-g|fs/pcs|v1",
      L=32
    )
  else null)
* pending_barrier_update_digest = H_L("barrier/update/digest", [raw header[175] bytes to publish])
* pending_activation_source = locally persisted pre-publish source state consisting at minimum of:
  * source_barrier_version
  * source_barrier_roots_hash
  * source_kem_tree_hash_after
  * source_current_history_commitment when the pre-publish source state was authenticated under a `HistoryAuthorityExtension`
  * source_current_history_authority_extension when the pre-publish source state was authenticated under a `HistoryAuthorityExtension`
  * source_current_global_history_attestation when the pre-publish source state was authenticated under a `HistoryAuthorityExtension`
  * source_fs_ec
  * source_fs_dev_prev_commit
* pending_on_path_key_material = { for each node n in ExpectedNodeSet:
    [ n:uint, dk_n:bstr(2400 bytes), pkhash_n:bstr32 ]
  }
Where:
* ExpectedNodeSet is computed from the to-be-published CP.path_nodes per S11.9.
* pkhash_n MUST equal H_pk(ek_n), where ek_n is derived from S11.10 for node n.
* Nodes in pending_on_path_key_material MUST be exactly ExpectedNodeSet, sorted strictly increasing by n, and contain no duplicates.
* Define `pending_merge_locator := [pending_barrier_version, pending_barrier_update_digest, pending_we_epoch_id]`.
Persistence ordering:
* MUST complete persistence BEFORE making the merge eligible for acceptance.
* If persistence fails, updater MUST abort emission of the barrier_update.

S11.14.2 Acceptance correlation + activation (MUST)
Upon observing acceptance of the merge carrying this barrier_update, or after `LookupMergeAcceptance(pending_merge_locator)` returns `status == accepted` under an authenticated `HistoryCommitment`:
* The observed acceptance / lookup result used for activation MUST come from the same `HistoryAuthorityScope` as the authenticated helper state used when the pending merge was constructed. If that cannot be established, the updater MUST enter `recovery_required/history_inconsistent` and MUST NOT activate.
* Compute accepted_digest := H_L("barrier/update/digest", [accepted raw header[175] bytes]).
* Require accepted_digest == pending_barrier_update_digest.
* Require the observed accepted `barrier_version` to equal `pending_barrier_version`.
* Require the observed accepted `header[141]` to equal `pending_fs_ec`.
* Require the observed accepted `header[178]` to equal `pending_barrier_update_reason`.
* Require the client's current locally persisted pre-activation source state to equal `pending_activation_source`; if not, the updater MUST enter `recovery_required/history_inconsistent` and MUST NOT activate.
* If the activating bundle is authored by the same local device, matches the locally persisted pending merge, and carries authority-bound headers (`header[181]` / `header[182]`), the client MUST validate those headers against the persisted `pending_activation_source` from the original pre-publish decision. The client MUST NOT silently reseed this validation from a later `merge_ticket_refresh` or other post-acceptance current-state artifact, because those artifacts may already describe the accepted post-state rather than the original pre-publish state bound into the bundle.
* Before local activation, clients MUST replay the client-visible subset of S10 using locally persisted state and the authenticated helper/provisioning values carried for that current state. At minimum this subset MUST reject:
  * unsupported/mismatched `fs_policy_version` (944.6),
  * mismatched `fs_epoch_base_ts` (945.0),
  * invalid `fs_dev_chain_bind` / local device continuity (947.2 / 947.0),
  * group forward jumps beyond the carried `last_accepted_ec + D_anchor_max` window (947.6),
  * new-device forward jumps beyond the carried `last_accepted_ec + D_first_device` window when `header[152] == ZERO32` (947.5),
  * local-device forward jumps beyond the persisted `stored_last_ec + D_device_max` window when the activating bundle is authored by the same local device (947.4).
* The helper/provisioning artifact used for these local checks MUST therefore carry the current FLG window parameters `(H, checkpoint_interval, S_anchor, S_first, S_device)` or an equivalent authenticated derivation of `(D_anchor_max, D_first_device, D_device_max)`, together with the current group `last_accepted_ec`.
* This client-side replay subset does not replace broader server-side S10 authorization, governance, or rate-limit checks that are not derivable from authenticated headers plus locally persisted state.
* If match: activate -- update local state:
  * barrier_initialized := true
  * barrier_version := pending_barrier_version
  * barrier_roots_hash := pending_revocation_roots_hash
  * K_barrier := pending_K_barrier_new
  * kem_tree_hash_after := pending_kem_tree_hash_after
  * pending_barrier_recovery := false
  * If pending_barrier_update_reason == 1: K_fs := pending_K_fs_after_pcs
  * If pending_barrier_update_reason IN {0,2}: `K_fs` MUST remain unchanged by this activation
  * for each entry [n, dk_n, pkhash_n] in pending_on_path_key_material:
    * if n IN SelfPath (updater's SelfPath), store (dk_n, pkhash_n) as the atomic pair for node n
    * if n NOT IN SelfPath, ignore (defense-in-depth)
* If mismatch: updater MUST NOT advance barrier_version locally and MUST surface 960.9 for diagnostics.
  Note: this mismatch diagnostic is conservative; it can indicate active-server tampering OR a race/loss scenario where a different update path won before local activation correlation succeeded.

S11.14.3 Pending state cleanup (MUST)
* After successful acceptance correlation and activation, updater MUST delete/clear all pending_* state.
* The updater MUST NOT infer "lost race" solely from `current barrier_version > pending_barrier_version`.
* The updater MUST determine non-acceptance status using `LookupMergeAcceptance(pending_merge_locator)`.
* The updater MUST discard pending_* state only when `LookupMergeAcceptance(pending_merge_locator)` authenticatedly returns either:
  * `status == superseded`, meaning the specific pending merge was not accepted and has been superseded by a different committed update, or
  * `status == final_rejected`, meaning authenticated finality guarantees the specific pending merge can no longer become accepted.
* If `LookupMergeAcceptance(pending_merge_locator)` returns `status == pending`, or authenticated history is otherwise insufficient to establish acceptance or non-acceptance, the updater MUST retain pending_* state or enter an explicit recovery-required state; it MUST NOT silently discard pending_* state and continue as though the pending merge had lost.

S11.14.4 Crash restart (normative)
On restart, the updater MUST check for pending_* state:
* The updater MUST determine acceptance status by consulting `LookupMergeAcceptance(pending_merge_locator)`, not merely by comparing against the current `GroupState.barrier_version`.
* If `LookupMergeAcceptance(pending_merge_locator)` returns `status == accepted`, the updater MUST obtain the accepted fields required by S11.14.2 and apply acceptance correlation, even if the current group `barrier_version` is already greater than `pending_barrier_version`.
* If `LookupMergeAcceptance(pending_merge_locator)` returns `status == superseded` or `status == final_rejected`, the updater MUST discard pending_* state.
* If `LookupMergeAcceptance(pending_merge_locator)` returns `status == pending`, or authenticated history is still insufficient to establish acceptance or non-acceptance under the rule above, the updater MUST retain pending_* state or transition to an explicit recovery-required state until authenticated history resolves acceptance or non-acceptance.

S12. JOIN PROVISIONING REQUIREMENTS (NORMATIVE)

S12.0 Genesis provisioning artifact (normative)
Before the first accepted MERGE when `barrier_initialized == false`, the deployment MUST establish the initial active leaf set as a genesis provisioning artifact. This artifact is the source consumed by `ResolveJoinsSince(0)` in S11.6.
Requirements:
* it MUST contain the complete initial active set,
* each entry MUST bind exactly one active device to exactly one `(leaf_index, slot_generation)` occupancy and one `ek_leaf`,
* entries MUST be strictly sorted by increasing `leaf_index`,
* `leaf_index` values MUST be unique and `< N_max`,
* `ek_leaf` MUST be exactly 1184 bytes for every entry,
* the artifact MUST be authenticated and persisted before genesis MERGE acceptance.
If the genesis provisioning artifact is absent, incomplete, or inconsistent, the server MUST reject genesis MERGE processing and MUST NOT claim this profile is fully implemented.

S12.1 Join anchor requirement
Joiner generates (ek_leaf, dk_leaf) := ML-KEM-768.KeyGen() and publishes ek_leaf in header[177].
Joiner MUST store dk_leaf locally and MUST also store pkhash_leaf := H_pk(ek_leaf) locally.
The initial JOIN anchor published by the joiner MUST carry `header[97]` in the S3.4 `author-local form`, not the `barrier-recovery form`; no knowledge of the current `K_barrier` is required or permitted for this initial JOIN publication.

S12.2 Provisioning to joiner
Join provisioning MUST deliver to the joiner as a signed and confidential provisioning artifact bound, at minimum, to `(gid, profile_version, current_history_view_id, current_history_commitment, current barrier_version, current kem_tree_hash_after, slot_index, slot_generation, N_max, max_barrier_update_bytes)`, and carrying a unique nonce, issuance time, and expiry. Joiners MUST reject artifacts that are stale, expired, replayed for the same join attempt, or not bound to the current `(gid, profile_version)`.
The provisioning artifact, the provisioned `current_history_commitment`, the provisioned accepted current `barrier_update`, and any subsequent authenticated S3.3 A/B/C lookups used to justify `join_finalize` bootstrap MUST all come from one common `HistoryAuthorityScope`; otherwise the joiner MUST fail closed and remain pending.
Base-profile wire/API requirement (normative):
* `JoinTicketResponse` MUST carry a non-empty `provisioning_artifact`.
* `provisioning_artifact` MUST be signed under the negotiated `history_authority_extension`.
* That signed artifact MUST bind exactly the client-visible provisioning fields consumed for bootstrap and local activation checks, including at minimum:
  * `history_authority_extension`
  * `history_authority_descriptor`
  * `current_global_history_attestation`
  * `current_join_records_completeness_attestation`
  * `current_revoked_records_completeness_attestation`
  * `current_history_view_id`
  * `current_history_commitment`
  * `current_barrier_update`
  * `current_predecessor_kem_tree_hash_after`
  * `current_join_records`
  * `current_revoked_records`
  * `join_finalize_auth`
  * `provisioning_nonce`
  * `provisioning_issued_at_ms`
  * `provisioning_expires_at_ms`
  * authenticated FLG window parameters and current `last_accepted_ec`
* Joiners MUST verify `provisioning_artifact` before consuming any provisioned current-state field.
Base-profile wire/API requirement for merge/current-state helper tickets (normative):
* Successful `MergeTicketResponse` and `expel_member_ticket` responses that carry authenticated current-state/helper objects MUST carry a non-empty `merge_ticket_artifact`.
* `merge_ticket_artifact` MUST be signed under the negotiated `history_authority_extension`.
* That signed artifact MUST bind exactly the client-visible current-state/helper fields consumed before originating reason 0/1 updates or local activation checks, including at minimum:
  * `history_authority_extension`
  * `history_authority_descriptor`
  * `current_global_history_attestation`
  * `current_history_view_id`
  * `current_history_commitment`
  * `barrier_version`
  * `slot_index`
  * `slot_generation`
  * `n_max`
  * `max_barrier_update_bytes`
  * `kem_tree_hash_after`
  * authenticated FLG window parameters and current `last_accepted_ec`
  * `we_epoch_id`
  * `pivot_parity_cbor`
  * `witness_cbor`
  * `srx_cbor`
  * the accepted current-state roots / suite identifiers consumed by local merge or expel authoring checks
* Clients MUST verify `merge_ticket_artifact` before consuming any delivered current-state/helper field from a merge/expel ticket.
Base-profile wire/API requirement for join/merge/helper/lookup profile/config delivery (normative):
* Successful `JoinTicketResponse`, `MergeTicketResponse`, `expel_member_ticket`, `ResolveRevokedLeaves`, `ResolveJoinsSince`, `FetchBarrierPublicTree`, and `LookupMergeAcceptance` responses that carry client-consumed profile/config fields MUST carry a non-empty `deployment_profile_manifest`.
* `deployment_profile_manifest` MUST be signed under the negotiated `history_authority_extension`.
* That signed manifest MUST bind at minimum:
  * `history_authority_extension`
  * `(gid, profile_version)`
  * `n_max`
  * `max_barrier_update_bytes`
  * authenticated FLG window parameters `(H, checkpoint_interval, S_anchor, S_first, S_device)`
* For paginated helper responses, every page for one logical helper result MUST carry the same authenticated `deployment_profile_manifest`; clients MUST fail closed on mismatch.
* Clients MUST verify `deployment_profile_manifest` before consuming those delivered profile/config fields.
Join provisioning MUST deliver to the joiner:
Barrier required fields:
* current barrier_initialized (bool) -- for joins into an already-existing group under this profile, this MUST be true
* slot_index (uint)
* slot_generation (uint64)
* current barrier_version (uint)
* current_history_view_id (bstr32)
* current_history_commitment (`HistoryCommitment`)
* provisioning_nonce (bstr32)
* provisioning_issued_at_ms (uint64)
* provisioning_expires_at_ms (uint64; MUST be >= provisioning_issued_at_ms)
* current predecessor committed `kem_tree_hash_after` (bstr32) for the accepted current `barrier_update` used by `join_finalize` bootstrap; this MAY be zero only when no accepted current `barrier_update` exists yet for the provisioned state
* authenticated current `JoinSet` / `ResolveJoinsSince(BU_current.prev_barrier_version)` records for the provisioned current committed state, or an equivalent authenticated artifact from which the same set can be deterministically recovered
* authenticated current `RevokedLeafSet` / `ResolveRevokedLeaves(BU_current.revocation_roots_hash)` records for the provisioned current committed state, or an equivalent authenticated artifact from which the same set can be deterministically recovered
* `join_finalize_auth` (bstr32), an opaque server-issued capability bound at minimum to `(gid, leaf_id, slot_index, slot_generation)` and required as `header[179]` when the joiner later originates reason 2
* current barrier_roots_hash (bstr32), OR authenticated current revocation-root material sufficient to deterministically compute the same barrier_roots_hash before any local S11.13.3 checks are applied
* current kem_tree_hash_after (bstr32)
* N_max (uint)
* max_barrier_update_bytes (uint)
* pcs_refresh_min_delta_device_ec (uint; >=1)
* pcs_refresh_min_delta_group_ec (uint; >=1)
* pcs_refresh_slot_width_ec (uint; >=1)
* authenticated accepted current `barrier_update` bytes for the current committed state, together with authenticated history material sufficient to authenticate the predecessor committed snapshot `H_prev_bootstrap` used by that update and to execute the S11.11.2 chain-checks for `join_finalize` bootstrap eligibility against that current `history_view_id`; this MUST include the authenticated current-state `JoinSet` and `RevokedLeafSet` needed for that check unless the deployment provides an equivalent authenticated lookup keyed to the provisioned `current_history_commitment`
* clients MUST reject a join provisioning artifact whose `provisioning_issued_at_ms` is implausibly far in the future, whose `provisioning_expires_at_ms` is in the authenticated past beyond bounded clock skew, or whose `provisioning_nonce` is absent or malformed
FS-hybrid required fields:
* initial K_fs (bstr32) and initial fs_ec (uint) -- or a derivation seed sufficient to deterministically compute the same initial `K_fs` and `fs_ec`
* Joiners MUST NOT locally sample an unrelated fresh `K_fs` for an already-existing group, because PCS reseed in S6.6 requires all honest clients to evolve from the same pre-refresh `K_fs`.
* group fs_epoch_base_ts (T_base; uint64)
* fs_policy_version (uint)
* authenticated FLG policy window parameters `(H, checkpoint_interval, S_anchor, S_first, S_device)` or equivalent authenticated derived caps `(D_anchor_max, D_first_device, D_device_max)`
* authenticated current group `last_accepted_ec`
* any suite identifiers required to verify proofs (Smallwood/VRF/SRX profiles)
Eligibility note (normative):
* A just-provisioned joiner into an already-existing group MUST be able to invoke S3.3.A/B and `FetchBarrierPublicTree(current kem_tree_hash_after)` for the provisioned current committed barrier state immediately after provisioning.
* The authenticated current-state A/B responses used for `join_finalize` bootstrap MUST validate to the provisioned `current_history_commitment`.
* `FetchBarrierPublicTree(current kem_tree_hash_after)` for that provisioned current state MUST at minimum return tree bytes that validate to the provisioned current `kem_tree_hash_after`; it MAY return a later same-scope `HistoryCommitment` if the current tree bytes are unchanged.
* The joiner MUST also be able to invoke `FetchBarrierPublicTree(H_prev_bootstrap)` for the provisioned accepted current `barrier_update`; that predecessor committed snapshot MAY carry an older retained `HistoryCommitment`, but MUST authenticate exactly to the provisioned predecessor committed `kem_tree_hash_after`.
* For reason 2 (`join_finalize`) eligibility only, a joiner that has the S12.2 current barrier metadata and successfully performs the FULL public-tree checks of S11.11.2 and the applicable `ek_n` verification of S11.13.6 against that provisioned current state is deemed FULL-verifying for current public state, even before it has derived the current `K_barrier`.
* This deeming rule is still a client-local predicate in the base profile. The server validates `join_finalize_auth` and helper-state coherence, not a cryptographic proof that the joiner performed those checks.

S12.3 Pending barrier recovery (normative)
Because the server is untrusted and blind to `K_barrier`, it CANNOT provision `K_barrier` directly to the joiner. Joiners MUST begin in a `pending_barrier_recovery` state.
While in `pending_barrier_recovery`:
* The joiner CANNOT encrypt outgoing payload messages (`SendParams` MUST be suspended or buffered).
* The joiner CANNOT decrypt incoming payload messages encoded with `K_barrier` (or subsequent epochs).
* The joiner MUST process any observed `barrier_update` messages (S11.13.4).
* The joiner MUST NOT assume its own initial JOIN-anchor `header[97]` is peer-recoverable from wire; peer-recoverable HP transport begins only once a `barrier-recovery form` envelope is published on an accepted MERGE.
* The joiner MUST NOT originate reason 0 (`revocation_or_bootstrap`) or reason 1 (`pcs_refresh`) while `pending_barrier_recovery == true`.
* Exception: the joiner MAY originate reason 2 (`join_finalize`), and no other barrier-update reason, while pending if, and only if:
  * it satisfies the S11.11.1 join_finalize bootstrap exception,
  * its own leaf is still present in the unresolved JoinSet for the current `barrier_version`,
  * and revocations are not pending for the update.
* A pending joiner that originates reason 2 MUST activate via S11.14, not via S11.13, for that self-authored update.
When the joiner successfully processes a `barrier_update` via S11.13 and derives `K_barrier_new` from the unique matching NodeCiphertext for its own path, it clears `pending_barrier_recovery` and may proceed with normal payload send/decrypt operation.
If the joiner successfully activates its own accepted reason 2 update via S11.14, it likewise clears `pending_barrier_recovery` and may proceed with normal payload send/decrypt operation.
If that current barrier state was learned only via recover-only processing (S11.11.3), the client MUST still NOT originate reason 0 or reason 1, MUST NOT act as updater generally, and MUST NOT originate pcs_refresh merges until it has obtained FULL verification of the current public tree at the current `barrier_version`.
Race/retry rule (normative):
* If a pending joiner's reason 2 attempt is not accepted, loses a race, or remains unresolved, the joiner MUST remain in `pending_barrier_recovery` and MUST continue processing observed `barrier_update` messages.
* Once authenticated history establishes that the specific reason 2 merge was not accepted, the joiner MAY originate a new reason 2 attempt against the then-current committed version only if it still satisfies the join_finalize eligibility predicate above; otherwise it MUST await and process another accepted `barrier_update`.

S13. ERROR CODES (NORMATIVE)

Encoding note (normative):
* Dotted forms (e.g., `960.10`) are the canonical documentation form.
* In machine fields that carry numeric freeze codes, implementations MUST encode the same code as decimal digits without a dot (e.g., `96010`).

Barrier codes
960.1  barrier_updater_invalid
Scope: Server + client
960.2  barrier_recover_multi_match
Scope: Client
960.3  barrier_expectedpairs_failure
Scope: Server
960.4  barrier_merge_delegation_forbidden
Scope: Server
960.5  barrier_proactive_forbidden
Scope: Server
960.6  barrier_recover_no_match
Scope: CLIENT-LOCAL only; not a global rejection reason
960.7  barrier_update_malformed
Scope: Server + client
960.8  barrier_tree_hash_chain_failure
Scope: Server + FULL client
960.9  barrier_tree_snapshot_auth_failure
Scope: CLIENT-LOCAL / UPDATER-LOCAL; MUST surface on snapshot/auth/correlation failures
960.10 barrier_genesis_required
Scope: Server
960.11 barrier_update_required_on_revocation_change
Scope: Server (acceptance gating)
960.12 pcs_refresh_rate_limited
Scope: Server (acceptance gating)
960.13 barrier_non_revocation_reason_forbidden_while_pending_revocations
Scope: Server (acceptance gating)

FS/acceptance codes
907.1  malformed CBOR / unknown key / duplicate key
945.0  fs_base_mismatch
947.0  fs_dev_chain_break
947.2  fs_dev_chain_bind_mismatch
947.4  fs_forward_jump_device
947.5  fs_forward_jump_first
947.6  fs_forward_jump_group
948.0  fs_policy_window_incompatible
944.6  fs_policy_version_unsupported

S14. KAT REQUIREMENTS (NORMATIVE)

S14.1 KAT: new_public_keys exact ExpectedNodeSet + ordering (MUST)
A reference test vector set MUST include at least one barrier_update where:
* pn has length >= 4,
* new_public_keys contains exactly len(pn)-1 entries,
* entries are strictly sorted by node_index and match ExpectedNodeSet exactly,
* server validation (S11.12.1) MUST accept,
* a FULL client chain-check (S11.11.2) MUST accept.
The KAT MUST also include a negative variant with:
* one missing ExpectedNodeSet node OR one extra node in new_public_keys,
and server validation MUST reject with 960.7.

S14.2 KAT: FULL client ek_n mismatch detection (MUST)
Threat model:
* malicious (or buggy) updater that can sign the anchor and produces a barrier_update whose public-tree hashes are internally consistent.
* Server does not have access to secrets and validates only structural + hash-chain + ExpectedPairs.
The KAT MUST include at least one barrier_update where:
* new_public_keys is modified by replacing exactly one ek_pub at some node n in ExpectedNodeSet with a different 1184-byte value,
* kem_tree_hash_after is recomputed accordingly so that server hash-chain checks (S11.12.1.G) still pass,
* all other MUST-checked server fields are updated as required for internal consistency,
* server validation (S11.12.1) MUST accept,
* a FULL-verifying client that derives path_secret[n] MUST compute ek_n via S11.10 and MUST reject locally per S11.13.6 (fail closed, 960.7).

S14.3 KAT: recover AAD binds full barrier metadata (MUST)
A reference test vector set MUST include at least one barrier_update where a client recovers using S11.13 and:
* the client stores pkhash_t for its matching target node t,
* the client constructs AAD using pkhash_t plus `BU.prev_barrier_version`, `BU.tree_size`, `BU.kem_tree_hash_before`, and `BU.kem_tree_hash_after` as specified in S11.13.4,
* decryption succeeds and yields a 32-byte path_secret[s].
A negative variant MUST modify pkhash_t (client-side) and MUST cause AEAD_Open failure (client rejects with 960.7).
Additional negative variants MUST modify exactly one of `BU.prev_barrier_version`, `BU.kem_tree_hash_before`, or `BU.kem_tree_hash_after` while leaving the candidate ciphertext and target selection otherwise unchanged; recovery MUST fail closed and MUST NOT yield an activated/persisted barrier state from that tampered bundle.

S14.4 KAT: updater activation stores pkhash_n (MUST)
A reference test vector set (or implementation conformance test) MUST include a scenario where:
* a client acts as updater, persists pending_* state per S11.14.1 including pkhash_n,
* the merge is accepted and the updater activates per S11.14.2,
* subsequently, the updater processes another barrier_update for which its unique match targets an internal node on its SelfPath (not necessarily the leaf),
* the updater is able to perform matching and AAD construction using the stored pkhash_t values, and recovery succeeds or fails only according to the normative match rules (no missing pkhash due to updater activation).

S14.5 KAT: proactive PCS refresh gating and rate-limit (MUST)
The test suite MUST include:
* Positive case:
  * RRH == GroupState.barrier_roots_hash,
  * MERGE with header[175], header[178]=1, header[176]=BV+1,
  * all S10.4B policy checks satisfied,
  * server accepts.
* Negative cases:
  * header[175] present with header[178]=0 while RRH unchanged -> reject 960.5,
  * RRH changed with header[178]=1 -> reject 960.13,
  * RRH unchanged but group/device/slot rate-limit violated -> reject 960.12.

S14.6 KAT: PCS reseed consistency and crash-safe activation (MUST)
The test suite MUST include a case where:
* header[178]=1 and barrier activation succeeds,
* updater and non-updater client derive identical K_fs after applying S6.6 at activation,
* after simulated crash/restart before activation completion, the implementation applies reseed at most once and converges to the same final K_fs.

S14.7 KAT: join_finalize gating, activation, and no-K_fs-reseed (MUST)
The test suite MUST include:
* Positive case:
  * RRH == GroupState.barrier_roots_hash,
  * MERGE with header[175], header[178]=2, header[176]=BV+1,
  * updater_leaf is in the unresolved JoinSet for BU.prev_barrier_version,
  * server accepts,
  * updater activation via S11.14.2 clears `pending_barrier_recovery`,
  * `K_barrier` advances,
  * `K_fs` remains unchanged across the activation.
* Negative cases:
  * header[175] present with header[178]=2 while updater_leaf is not in the unresolved JoinSet -> reject 960.5,
  * RRH changed with header[178]=2 -> reject 960.13,
  * RRH unchanged, updater_leaf in unresolved JoinSet, but header[178]=1 -> reject 960.5.

S14.8 KAT: join_finalize race / loss behavior (MUST)
The test suite MUST include a scenario where:
* a pending joiner publishes a reason 2 merge and persists pending_* state,
* a different accepted barrier_update is committed first at the competing next barrier version,
* updater acceptance correlation for the pending reason 2 merge does not falsely activate,
* the joiner remains `pending_barrier_recovery == true` until it either:
  * recovers from the accepted competing barrier_update, or
  * retries reason 2 after authenticated history establishes non-acceptance and the join_finalize eligibility predicate still holds,
* the implementation MUST NOT clear `pending_barrier_recovery` solely because a timer elapsed or because the current barrier version advanced.

S14.9 KAT: barrier-sealed-v1 transport validation and binding (MUST)
The test suite MUST include:
* Positive case:
  * a valid author-local JOIN envelope with mode `"barrier-sealed-v1"` and context `"author-local"` is accepted by S10.1/S12.1 shape validation without requiring `K_barrier`,
  * a valid `BarrierHpEnvelope` with mode `"barrier-sealed-v1"` and context `"barrier-recovery"`,
  * ciphertext length in `[AEAD_TAG_LEN, MAX_HP_ENVELOPE_BYTES]`,
  * AEAD suite `"chacha20-poly1305"`,
  * decryption using the authenticated `(gid, barrier_key, barrier_version, xk_hash, hp_commit)` tuple succeeds and recovers the original `BarrierHpPlaintext`.
* Negative cases:
  * any legacy/unknown transport mode in `header[97]` -> reject as malformed,
  * any unknown or wrong publication context in `element 1` -> reject as malformed,
  * empty ciphertext, ciphertext shorter than `AEAD_TAG_LEN`, or ciphertext longer than `MAX_HP_ENVELOPE_BYTES` -> reject as malformed,
  * successful AEAD open to an empty `BarrierHpPlaintext` -> reject as malformed,
  * successful AEAD open where recomputed `H_L("msphf/hp/commit", [BarrierHpPlaintext]) != header[99]` -> reject as malformed,
  * wrong AEAD suite or malformed UTF-8/text shape -> reject as malformed,
  * replay / cut-and-paste of a valid `hp_ciphertext` into a different `(gid, barrier_version, xk_hash, hp_commit)` context -> recovery MUST fail,
  * recovery attempted under the wrong barrier key -> recovery MUST fail.

END CITY-G UNIFIED SPEC (FS-HYBRID + PRS BARRIER) v0.1.4
