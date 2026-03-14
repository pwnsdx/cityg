CITY-G UNIFIED SPEC (FS-HYBRID + PRS BARRIER)

Version: v0.1.2 (repository errata through 2026-03-13)
Date: 2026-02-11
Status: Frozen wire/API profile with repository-tracked normative errata
Profile ID: tswe/msphf-we/fs-hybrid + prs-barrier (native; no legacy interop)

ERRATA STATUS
* The wire/API `profile_version` exposed by the current implementation remains `v0.1.2`.
* This repository copy of the specification includes post-freeze normative errata adopted after the original `v0.1.2 -- final` text.
* For commit-level traceability, see `docs/spec-conformance-changelog-v0.1.2.md`.

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

External subsystems assumed to exist with normative interfaces (not re-specified here):
* membership representation and verification (including cover_leaf_index mapping),
* MSPHF / ME-OR and its witness/NP language,
* Smallwood FS proof system and SRX/Smallwood-v1 proof system (verification APIs),
* ZK-VRF verification API,
* anchor authentication (signatures/suites per deployment), but MUST cover the canonical header map including fs_dev_commit and barrier fields.

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
A conforming method is:
1. Parse the received CBOR bytes using a parser that:
   * rejects floats,
   * rejects indefinite-length items,
   * rejects duplicate map keys,
   * rejects malformed CBOR.
2. Re-encode the parsed data model using CBOR_det rules.
3. Require the re-encoded bytes to be byte-for-byte identical to the original received bytes.

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
  okm32 := BLAKE3_keyed(key=prk32, message=(info_bytes || 0x01))[0..31]
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
* xk_hash : bstr32 transcript hash / handshake binding (opaque here)
* E_k : bstr    ME-OR derived value / binding (opaque here)

S3.2 Membership/SRX anchor roots (inputs)
* header[110], header[111], header[112], header[113] : bstr32 roots (membership and revocation)
* membership mapping: cover_leaf_index(device_pk) -> uint, committed by membership state
* membership state also defines the current per-group membership leaf identifier `leaf_id(device_pk) -> bstr32` for each active device. This 32-byte `leaf_id` is distinct from `cover_leaf_index(device_pk)` and is the canonical `sender_leaf_id` used in S8.

S3.3 Interfaces REQUIRED by this profile (implementability requirement)
The membership/SRX/barrier subsystems MUST provide to any authenticated group member:

A) ResolveRevokedLeaves(revocation_roots_hash) -> sorted unique list<uint>
Returns revoked cover leaf indices corresponding to revocation_roots_hash.
This enumeration MUST be integrity-protected by membership/SRX state referenced by header[112]/[113].

B) ResolveJoinsSince(prev_barrier_version) -> list of JoinLeafRecord
JoinLeafRecord = [device_pk:bstr, leaf_index:uint, ek_leaf:bstr]
Returns join leaf allocations and leaf public keys that became active since prev_barrier_version.
This enumeration MUST be integrity-protected by checkpoint history / membership state.
Output constraints (normative):
* entries MUST be strictly sorted by increasing `leaf_index`,
* `leaf_index` values MUST be unique,
* `leaf_index` MUST be `< N_max`,
* `ek_leaf` MUST be exactly 1184 bytes,
* if membership history is inconsistent (duplicate active allocation, out-of-range index, conflicting `ek_leaf` for the same activation), the implementation MUST fail closed and MUST NOT construct or accept a dependent `barrier_update`.

C) FetchBarrierPublicTree(kem_tree_hash_after) -> pk_entries
pk_entries is an array of length (2*N_max-1) of bstr, where each entry is either empty bstr (BOTTOM) or ML-KEM ek (1184 bytes).
The returned pk_entries MUST hash (per S11.4) to the requested kem_tree_hash_after.
Historical retention contract (normative):
* FetchBarrierPublicTree(kem_tree_hash_after) MUST work for any committed historical barrier public tree snapshot addressed by kem_tree_hash_after, not only the current one.
* The server MUST retain every committed pk_entries snapshot for as long as the corresponding group history/checkpoint history remains fetchable. Implementations MAY garbage-collect only together with retirement of the associated group history.

Snapshot-auth failure handling (normative; 960.9 wiring):
If FetchBarrierPublicTree(kem_tree_hash_after) returns pk_entries with TreeHash(root_node) != kem_tree_hash_after, the caller MUST treat the server as faulty/active, MUST NOT proceed with barrier_update creation/activation/verification that depends on that tree, and MUST surface local diagnostic code 960.9 barrier_tree_snapshot_auth_failure.

Verification levels (normative):
* A client that has A) and B) but not C) MUST NOT claim FULL barrier chain-check (it may still recover K_barrier via unique match).
* A client that has A), B), and C) and performs the MUST checks in S11.11.2 (FULL chain-check) and S11.13.6 (ek_n verification) is a FULL-verifying client.

S4. ANCHOR TYPES, HEADER-KEY REGISTRY, AND PRESENCE MATRIX (NORMATIVE)

S4.1 Anchor types (normative)
This profile defines three anchor types:
* JOIN anchor: introduces a new device leaf and MUST carry barrier_leaf_pk (key 177).
* MERGE anchor: carries merge/checkpoint state and MAY carry barrier_update (key 175) with barrier_update_reason (key 178); see predicates in S10.4, S10.4A, and S10.4B.
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
Key 175: barrier_update (bstr; optional; only when permitted by S10.4, S10.4A, and S11)
Key 178: barrier_update_reason (uint; required iff key 175 is present)

S4.2.4 Merge/checkpoint keys (merge-only set)
130, 131, 132, 133, 134, 135, 136, 138, 144, 145, 148
Restriction: key 136 kbroad_replay is FORBIDDEN (presence -> reject 907.1).

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
* MERGE: MUST include S4.2.1; MUST include merge/checkpoint keys as required by merge profile;
  MAY include S4.2.3 (subject to S10.4/S10.4A/S10.4B/S11) and MAY include S4.2.5 (subject to S9.3);
  MUST NOT include S4.2.2.
Additional presence rule (normative):
* key 178 MUST be present if and only if key 175 is present.

S4.4 Size limits (normative; deployments MAY tighten)
Max bytes per header field (unless otherwise specified by type):
* header[95]  max 8192
* header[146] max 16384
* header[161] max 16384
* header[122] max 1048576
* header[177] MUST be exactly 1184 bytes

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
* N_max : uint (power of two; fixed group lifetime)
* Server MUST store pk_entries matching kem_tree_hash_after and a historical map from each committed kem_tree_hash_after to its corresponding pk_entries, and MUST serve both current and historical committed snapshots via FetchBarrierPublicTree.

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
* dk_leaf for the client's barrier leaf (join-generated)
* pkhash_leaf := H_pk(ek_leaf) for the client's barrier leaf (bstr32)
* dk_n keys for internal nodes on the client's SelfPath (derived per S11.13.5)
* pkhash_n := H_pk(ek_n) for each stored dk_n (bstr32)
* pending_barrier_recovery : bool -- true for a newly joined client until it has successfully derived `K_barrier` via S11.13/S12.3

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
Define sender_leaf_id (normative):
* sender_leaf_id is the authenticated 32-byte current membership `leaf_id` of the sending device for this group, supplied by the outer message transport / authenticated sender context for this payload. It is NOT `cover_leaf_index(device_pk)`.
* The same sender_leaf_id MUST be supplied to both the encrypt and decrypt paths for S8.3/S8.4 derivations.
* If sender_leaf_id is missing, malformed, or not exactly 32 bytes, the implementation MUST fail closed and MUST NOT attempt payload decryption.
* If the surrounding transport/authenticated context also identifies the sender device (for example via `author_device_pk` or an equivalent membership record), implementations MUST verify that `sender_leaf_id` corresponds to that device's current membership `leaf_id`; mismatch -> drop payload.
Wire encoding requirement (normative, MUST):
* PayloadEnvelope MUST be encoded as CBOR_det array of length exactly 3.
* The first element MUST be the CBOR text string exactly equal to "fs-hybrid-msg-v2".
* msg_index MUST be cleartext (element 2).
* Receivers MUST verify CBOR_det determinism per S1.3 for PayloadEnvelope bytes; if invalid, receivers MUST discard the message as malformed.

S8.2 msg_index uniqueness rule (CRITICAL)
For any fixed sender-scoped tuple (gid, weid, t, xk_hash, E_k, barrier_version, sender_leaf_id), msg_index MUST be unique for every payload encrypted under that tuple.
Implementations MUST enforce either:
* strictly monotone msg_index starting at 0 per tuple, OR
* globally unique random 64-bit msg_index per tuple with collision resistance, plus anti-replay state.
Crash-safety requirement (normative, MUST):
Any state used to enforce uniqueness or anti-replay for msg_index MUST be persisted durably (crash-safe) before allowing encryption under the tuple to proceed. If crash-safe persistence is not available, this profile MUST NOT be used.
If uniqueness cannot be enforced, this profile MUST NOT be used.
Receiver duplicate-rejection rule (normative, MUST):
Define `tuple_tag` (normative):
* `tuple_tag := H_L("fs/msg/replay/tuple", [gid, weid, t, xk_hash, E_k, header[176], sender_leaf_id])`
Receivers MUST derive this exact `tuple_tag` and MUST reject a payload if the pair `(tuple_tag, msg_index)` has already been accepted locally. Duplicate detection MUST occur before the payload is released to the application.

S8.3 K_msg_epoch
K_msg_epoch := HKDF-BLAKE3(
  ikm  = E_k,
  salt = H_L("fs/msg/epoch_salt", [weid, t, xk_hash, E_k, header[176], K_barrier, sender_leaf_id]),
  info = "city-g|fs/msg/epoch|v2",
  L=32
)
Where `E_k` is the locally derived epoch key for the active `weid`.
`tau_e(t)` remains normative for FS chain/proof context per S6, while payload encryption in this profile binds to `E_k` in S8.

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
* If any of the above is violated, the server MUST reject with 960.11 barrier_update_required_on_revocation_change.

Clarification (normative):
* Since JOIN and REGULAR anchors MUST NOT carry header[175] by S4.3, any JOIN or REGULAR anchor for which RRH != GroupState.barrier_roots_hash MUST be rejected with 960.11.
* Clients MUST ensure that revocation roots have been barrier-covered (i.e., GroupState.barrier_roots_hash updated via an accepted MERGE with barrier_update) before emitting JOIN or REGULAR anchors.

If GroupState.barrier_initialized == true AND RRH == GroupState.barrier_roots_hash, then:
* JOIN and REGULAR anchors proceed under S10.4.
* MERGE anchors MAY omit header[175] and proceed under S10.4 and S11.12 gating.
* If MERGE carries header[175], proactive barrier behavior is controlled by S10.4B.

S10.4B Proactive PCS refresh gating (time-blind; normative)
This section applies only when:
* GroupState.barrier_initialized == true
* RRH == GroupState.barrier_roots_hash
* header[175] is present

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
KemTreeCoverPayload (CBOR bytes inside cover_payload):
KemTreeCoverPayload = [
  updater_leaf               : uint,
  path_nodes                 : [* uint],
  revoked_leaf_indices_hint  : null / [* uint],
  node_ciphertexts           : [* NodeCiphertext],
  new_public_keys            : [* [uint, bstr]]
]
NodeCiphertext:
NodeCiphertext = [
  source_node      : uint,
  target_node      : uint,
  target_pk_hash   : bstr16,
  kem_ct           : bstr,       1088 bytes
  wrapped_ps       : bstr        48 bytes (32 secret + 16 tag)
]
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
Genesis convention:
When barrier_initialized == false, prev_barrier_version MUST be treated as 0 for JoinSet enumeration, and ResolveJoinsSince(0) MUST return the complete active leaf set for genesis.
Leaf-allocation invariant (normative):
* cover leaf indices are single-assignment for the lifetime of `gid` and MUST NOT be reused after revocation.
snapshot_base:
* genesis: all-blank tree (every pk_i := empty bstr for all 2*N_max-1 nodes)
* non-genesis: current committed pk_entries
snapshot_pre construction (order is normative):
1. Apply JoinSet:
   For each JoinLeafRecord (device_pk, leaf_index=l, ek_leaf):
   * set pk at leaf_node(l) := ek_leaf
   * for each internal node on direct_path(leaf_node(l)) excluding the leaf: set pk := empty bstr
2. Apply RevokedLeafSet:
   For each revoked leaf r:
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
    salt = H_L("barrier/tree/path", [parent_node]),
    info = "city-g|barrier/tree|v1",
    L=32
  )
This derivation MUST be used so that client Recover (S11.13.4) computes identical path_secret values.
U3) Compute K_barrier_new:
* Set K_barrier_new := HKDF-BLAKE3(
    ikm  = path_secret[root_node],
    salt = H_L("barrier/derive/salt", [v_new, RRH]),
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
  * Define aad := CBOR_det([gid, v_new, RRH, u, source_node, t, H_pk(ek_t)]).
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
For node index n with context (barrier_version=v, revocation_roots_hash=RRH, tree_size=N_max):
d_n := HKDF-BLAKE3(
  ikm  = path_secret[n],
  salt = H_L("barrier/keygen/d_salt", [v, RRH, N_max, n]),
  info = "city-g|barrier/keygen-d|v1",
  L=32
)
z_n := HKDF-BLAKE3(
  ikm  = path_secret[n],
  salt = H_L("barrier/keygen/z_salt", [v, RRH, N_max, n]),
  info = "city-g|barrier/keygen-z|v1",
  L=32
)
(ek_n, dk_n) := ML-KEM-768.KeyGen_internal(d_n, z_n)
Constraints (MUST):
* new_public_keys entries MUST use ek_n produced by this derivation.
* Implementations MUST reject any ek in new_public_keys that is not 1184 bytes.

S11.11 Active-server resistance (normative; 960.9 wired)

S11.11.1 Updater MUST authenticate snapshot_base (CRITICAL)
Before constructing any barrier_update, the updater MUST:
* already hold FULL-verified current barrier state at its locally stored current `barrier_version`.
* A client whose current `kem_tree_hash_after` was learned only via recover-only processing MUST first re-establish FULL verification at the current version before originating any barrier_update or pcs_refresh merge.
* Let H_prev := updater's locally stored kem_tree_hash_after for current barrier_version.
* Genesis special case:
  * if barrier_initialized == false (genesis updater), H_prev is the TreeHash(root_node) of the all-blank tree of size N_max.
  * This value is deterministic and MUST be computed locally without fetching from the server.
* Non-genesis:
  * fetch pk_entries_prev := FetchBarrierPublicTree(H_prev).
  * Compute TreeHash(root_node) over pk_entries_prev per S11.4 and require it equals H_prev.
  * H_prev MAY refer to a historical committed tree snapshot; the server MUST support this per S3.3.C and S5.1.
If this check fails, the updater MUST abort barrier_update creation, MUST NOT sign/emit an anchor containing barrier_update, and MUST surface 960.9.

S11.11.2 FULL clients MUST chain-check (CRITICAL)
A FULL-verifying client processing a barrier_update MUST:
* Let H_prev := client's locally stored kem_tree_hash_after.
* Fetch pk_entries_prev := FetchBarrierPublicTree(H_prev) and verify it hashes to H_prev per S11.4; failure -> 960.9.
* H_prev MAY refer to a historical committed tree snapshot; the server MUST support this per S3.3.C and S5.1.
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

S11.12 Server-side validation of barrier_update (normative; MUST)

S11.12.1 Validation procedure (MUST)
If header[175] present, the server MUST execute steps A through I in order:

A) Gating
* If header[178] is absent: reject 960.7.
* If header[178] is present and header[178] is not in {0,1}: reject 960.7.
* If barrier_initialized == true and pending_revocations == false:
  * If header[178] != 1: reject 960.5 barrier_proactive_forbidden.
  * If header[178] == 1, server MUST enforce S10.4B policy checks; on failure reject 960.12.
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
* Require updater_leaf == cover_leaf_index(header[108]); else reject 960.1.
* Require updater_leaf NOT in RevokedLeafSet for this update; else reject 960.1.

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

NOTE (security model): server-side checks alone do not protect against an actively malicious server. Active-server injection protections are enforced by updater chain-check (S11.11.1), FULL client chain-check (S11.11.2), and FULL client ek_n verification (S11.13.6).

S11.13 Client recover (non-updater) (normative)
Definitions (normative)
* BU := the parsed BarrierUpdate from header[175]
* CP := the parsed KemTreeCoverPayload from BU.cover_payload
self_cover_leaf_index := cover_leaf_index(self_device_pk)
SelfPath := direct_path(leaf_node(self_cover_leaf_index))     /* node indices */
own_barrier_update := (header[108] == self_device_pk)
  AND (CP.updater_leaf == self_cover_leaf_index)

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
  * if local `barrier_roots_hash == BU.revocation_roots_hash`, then `header[178] MUST equal 1`,
  * if local `barrier_roots_hash != BU.revocation_roots_hash`, then `header[178] MUST equal 0`,
  * except for the genesis-local case above, where `header[178] MUST equal 0`.
* Clients MUST reject stale, duplicate, or gap barrier updates that do not satisfy the local version-adjacency rules above.
Failure -> reject barrier_update locally with 960.7.

S11.13.4 Recover derivation (normative)
Given the unique match (s, t) and the accepted BarrierUpdate with barrier_version=v_new:
ss := ML-KEM-768.Decaps(dk_t, kem_ct)
aad := CBOR_det([gid, v_new, revocation_roots_hash, CP.updater_leaf, s, t, pkhash_t])
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
    salt = H_L("barrier/tree/path", [parent_node]),
    info = "city-g|barrier/tree|v1",
    L=32
  )
Compute K_barrier_new:
K_barrier_new := HKDF-BLAKE3(
  ikm  = path_secret[root_node],
  salt = H_L("barrier/derive/salt", [v_new, revocation_roots_hash]),
  info = "city-g|barrier/key|v1",
  L=32
)

S11.13.5 Deterministic dk_n storage rule (normative)
Let pn := CP.path_nodes and let s := source_node for the unique match.
Let j be the unique index such that pn[j] == s (must exist, else reject 960.7).
SuffixNodes := { pn[k] | k in [j..len(pn)-1] }
Client MUST:
* Maintain dk_leaf (join-generated) for n == leaf_node(self_cover_leaf_index); it is NOT derived from path_secret.
* Maintain pkhash_leaf := H_pk(ek_leaf) for the same leaf (bstr32).
* For each node n in (SuffixNodes INTERSECT SelfPath) such that n != leaf_node(self_cover_leaf_index):
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
On successful processing:
* barrier_initialized := true
* barrier_version     := v_new
* barrier_roots_hash := BU.revocation_roots_hash
* K_barrier           := K_barrier_new
* kem_tree_hash_after := BU.kem_tree_hash_after
* pending_barrier_recovery := false
* If header[178] == 1 (pcs_refresh), apply FS reseed per S6.6 using K_barrier_new at the same atomic activation point.
Atomicity requirement (normative, MUST):
* The entire successful activation above, together with all `dk_n/pkhash_n` updates from S11.13.5 and any PCS reseed of `K_fs`, MUST commit crash-safely as one logical transaction.
* After restart, the client MUST observe either the complete pre-activation state or the complete post-activation state, never a mixture.

S11.14 Updater local state management (normative; crash-safe; REQUIRED)
This section specifies how the updater activates its own barrier_update locally. The updater MUST NOT use the Recover path (S11.13) for its own updates.

S11.14.1 Persist-before-publish (MUST)
Before publishing/submitting any merge carrying header[175], the updater MUST persist durably (crash-safe):
* pending_barrier_version = v_new
* pending_we_epoch_id = the to-be-published `bundle.we_epoch_id`, or an equivalent stable identifier sufficient for authenticated acceptance-history lookup of this specific merge
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
* pending_on_path_key_material = { for each node n in ExpectedNodeSet:
    [ n:uint, dk_n:bstr(2400 bytes), pkhash_n:bstr32 ]
  }
Where:
* ExpectedNodeSet is computed from the to-be-published CP.path_nodes per S11.9.
* pkhash_n MUST equal H_pk(ek_n), where ek_n is derived from S11.10 for node n.
* Nodes in pending_on_path_key_material MUST be exactly ExpectedNodeSet, sorted strictly increasing by n, and contain no duplicates.
Persistence ordering:
* MUST complete persistence BEFORE making the merge eligible for acceptance.
* If persistence fails, updater MUST abort emission of the barrier_update.

S11.14.2 Acceptance correlation + activation (MUST)
Upon observing acceptance of the merge carrying this barrier_update:
* Compute accepted_digest := H_L("barrier/update/digest", [accepted raw header[175] bytes]).
* Require accepted_digest == pending_barrier_update_digest.
* Require the observed accepted `barrier_version` to equal `pending_barrier_version`.
* Require the observed accepted `header[141]` to equal `pending_fs_ec`.
* Require the observed accepted `header[178]` to equal `pending_barrier_update_reason`.
* If match: activate -- update local state:
  * barrier_initialized := true
  * barrier_version := pending_barrier_version
  * barrier_roots_hash := pending_revocation_roots_hash
  * K_barrier := pending_K_barrier_new
  * kem_tree_hash_after := pending_kem_tree_hash_after
  * If pending_barrier_update_reason == 1: K_fs := pending_K_fs_after_pcs
  * for each entry [n, dk_n, pkhash_n] in pending_on_path_key_material:
    * if n IN SelfPath (updater's SelfPath), store (dk_n, pkhash_n) as the atomic pair for node n
    * if n NOT IN SelfPath, ignore (defense-in-depth)
* If mismatch: updater MUST NOT advance barrier_version locally and MUST surface 960.9 for diagnostics.
  Note: this mismatch diagnostic is conservative; it can indicate active-server tampering OR a race/loss scenario where a different update path won before local activation correlation succeeded.

S11.14.3 Pending state cleanup (MUST)
* After successful acceptance correlation and activation, updater MUST delete/clear all pending_* state.
* The updater MUST NOT infer "lost race" solely from `current barrier_version > pending_barrier_version`.
* The updater MUST discard pending_* state only when authenticated acceptance history is sufficient to determine that the specific pending merge identified by `(pending_barrier_version, pending_barrier_update_digest, pending_we_epoch_id or equivalent stable merge identifier)` was not accepted and a different committed update has superseded it.
* The updater MUST NOT discard pending_* state solely due to elapsed time unless the deployment provides an authenticated finality bound under which the specific pending merge can no longer become accepted after that bound.
* If acceptance status remains unknown and such authenticated finality is unavailable, the updater MUST retain pending_* state or enter an explicit recovery-required state; it MUST NOT silently discard pending_* state and continue as though the pending merge had lost.

S11.14.4 Crash restart (normative)
On restart, the updater MUST check for pending_* state:
* The updater MUST determine acceptance status by consulting authenticated anchor/checkpoint history sufficient to identify the specific pending merge, not merely by comparing against the current `GroupState.barrier_version`.
* If pending_barrier_update_digest is present and authenticated history shows that the corresponding merge has been accepted, the updater MUST obtain the accepted fields required by S11.14.2 and apply acceptance correlation, even if the current group `barrier_version` is already greater than `pending_barrier_version`.
* If pending_barrier_update_digest is present and authenticated history shows that the specific pending merge was not accepted and has been superseded by another committed update, the updater MUST discard pending_* state.
* If pending_barrier_update_digest is present but the merge status remains unknown, the updater MUST NOT discard pending_* state solely because a timeout elapsed, unless authenticated finality semantics guarantee that the merge can no longer be accepted.
* Otherwise, the updater MUST retain pending_* state or transition to an explicit recovery-required state until authenticated history resolves acceptance or non-acceptance.

S12. JOIN PROVISIONING REQUIREMENTS (NORMATIVE)

S12.0 Genesis provisioning artifact (normative)
Before the first accepted MERGE when `barrier_initialized == false`, the deployment MUST establish the initial active leaf set as a genesis provisioning artifact. This artifact is the source consumed by `ResolveJoinsSince(0)` in S11.6.
Requirements:
* it MUST contain the complete initial active set,
* each entry MUST bind exactly one active device to exactly one `leaf_index` and one `ek_leaf`,
* entries MUST be strictly sorted by increasing `leaf_index`,
* `leaf_index` values MUST be unique and `< N_max`,
* `ek_leaf` MUST be exactly 1184 bytes for every entry,
* the artifact MUST be authenticated and persisted before genesis MERGE acceptance.
If the genesis provisioning artifact is absent, incomplete, or inconsistent, the server MUST reject genesis MERGE processing and MUST NOT claim this profile is fully implemented.

S12.1 Join anchor requirement
Joiner generates (ek_leaf, dk_leaf) := ML-KEM-768.KeyGen() and publishes ek_leaf in header[177].
Joiner MUST store dk_leaf locally and MUST also store pkhash_leaf := H_pk(ek_leaf) locally.

S12.2 Provisioning to joiner
Join provisioning MUST deliver to the joiner (authenticated, confidential as per base provisioning rules):
Barrier required fields:
* current barrier_initialized (bool) -- for joins into an already-existing group under this profile, this MUST be true
* cover_leaf_index (uint)
* current barrier_version (uint)
* current barrier_roots_hash (bstr32), OR authenticated current revocation-root material sufficient to deterministically compute the same barrier_roots_hash before any local S11.13.3 checks are applied
* current kem_tree_hash_after (bstr32)
* N_max (uint)
* max_barrier_update_bytes (uint)
* pcs_refresh_min_delta_device_ec (uint; >=1)
* pcs_refresh_min_delta_group_ec (uint; >=1)
* pcs_refresh_slot_width_ec (uint; >=1)
FS-hybrid required fields:
* initial K_fs (bstr32) and initial fs_ec (uint) -- or a derivation seed sufficient to deterministically compute the same initial `K_fs` and `fs_ec`
* Joiners MUST NOT locally sample an unrelated fresh `K_fs` for an already-existing group, because PCS reseed in S6.6 requires all honest clients to evolve from the same pre-refresh `K_fs`.
* group fs_epoch_base_ts (T_base; uint64)
* fs_policy_version (uint)
* any suite identifiers required to verify proofs (Smallwood/VRF/SRX profiles)

S12.3 Pending barrier recovery (normative)
Because the server is untrusted and blind to `K_barrier`, it CANNOT provision `K_barrier` directly to the joiner. Joiners MUST begin in a `pending_barrier_recovery` state.
While in `pending_barrier_recovery`:
* The joiner CANNOT encrypt outgoing payload messages (`SendParams` MUST be suspended or buffered).
* The joiner CANNOT decrypt incoming payload messages encoded with `K_barrier` (or subsequent epochs).
* The joiner MUST process any observed `barrier_update` messages (S11.13.4).
* The joiner MUST NOT originate `barrier_update`, MUST NOT act as updater, and MUST NOT originate pcs_refresh merges while `pending_barrier_recovery == true`.
When the joiner successfully processes a `barrier_update` via S11.13 and derives `K_barrier_new` from the unique matching NodeCiphertext for its own path, it clears `pending_barrier_recovery` and may proceed with normal payload send/decrypt operation.
If that current barrier state was learned only via recover-only processing (S11.11.3), the client MUST still NOT originate `barrier_update`, MUST NOT act as updater, and MUST NOT originate pcs_refresh merges until it has obtained FULL verification of the current public tree at the current `barrier_version`.

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
960.13 pcs_refresh_forbidden_while_pending_revocations
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

S14.3 KAT: recover AAD uses pkhash_t (MUST)
A reference test vector set MUST include at least one barrier_update where a client recovers using S11.13 and:
* the client stores pkhash_t for its matching target node t,
* the client constructs AAD using pkhash_t as specified in S11.13.4,
* decryption succeeds and yields a 32-byte path_secret[s].
A negative variant MUST modify pkhash_t (client-side) and MUST cause AEAD_Open failure (client rejects with 960.7).

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

END CITY-G UNIFIED SPEC (FS-HYBRID + PRS BARRIER) v0.1.2 (repository errata through 2026-03-13)
