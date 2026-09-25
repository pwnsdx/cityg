#!/usr/bin/env python3
"""Independent verifier of the City-G v0.2 conformance vectors.

This script shares no code with the Rust implementation. It re-implements,
from the specification (docs/specs.md), the deterministic CBOR encoding, the
labelled hash H_L, Extract / ExpandLabel / DeriveSecret / MAC over BLAKE3,
ChaCha20-Poly1305 (RFC 8439, pure Python), the barrier tree hash, the roster
hash, the key schedule and message plane v3, and checks every value of
vectors.json. ML-KEM and ML-DSA are not re-implemented: their outputs appear
as data (public keys, ciphertexts, shared secrets, signatures).

Requires: python3 >= 3.9 and the `blake3` package (pip install blake3).
Usage: python3 kat/v0.2/verify_vectors.py [path/to/vectors.json]
"""

import json
import os
import struct
import sys

import blake3

PROFILE_TAG = "city-g/v0.2"
ZERO32 = bytes(32)
ML_DSA_87_SIGNATURE_BYTES = 4627


# --- Deterministic CBOR (RFC 8949 section 4.2.1) ---------------------------


class CMap:
    """A CBOR map as an ordered list of (key, value) pairs."""

    def __init__(self, pairs):
        self.pairs = list(pairs)

    def get(self, key):
        for k, v in self.pairs:
            if k == key:
                return v
        raise KeyError(key)

    def keys(self):
        return [k for k, _ in self.pairs]


def _head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 1 << 8:
        return bytes([(major << 5) | 24, value])
    if value < 1 << 16:
        return bytes([(major << 5) | 25]) + struct.pack(">H", value)
    if value < 1 << 32:
        return bytes([(major << 5) | 26]) + struct.pack(">I", value)
    return bytes([(major << 5) | 27]) + struct.pack(">Q", value)


def cbor(value):
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        data = value.encode("utf-8")
        return _head(3, len(data)) + data
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, CMap):
        entries = sorted((cbor(k), cbor(v)) for k, v in value.pairs)
        for (a, _), (b, _) in zip(entries, entries[1:]):
            if a == b:
                raise ValueError("duplicate map key")
        return _head(5, len(entries)) + b"".join(k + v for k, v in entries)
    raise TypeError(f"no CBOR encoding for {type(value)}")


def cbor_decode(data):
    """Decode one item and require the deterministic encoding."""

    def item(pos):
        initial = data[pos]
        major, info = initial >> 5, initial & 31
        pos += 1
        if major == 7:
            simple = {20: False, 21: True, 22: None}
            if info not in simple:
                raise ValueError("unsupported simple value or float")
            return simple[info], pos
        if info < 24:
            arg = info
        elif info in (24, 25, 26, 27):
            size = 1 << (info - 24)
            arg = int.from_bytes(data[pos : pos + size], "big")
            pos += size
        else:
            raise ValueError("indefinite length or reserved head")
        if major == 0:
            return arg, pos
        if major == 1:
            return -1 - arg, pos
        if major == 2:
            return bytes(data[pos : pos + arg]), pos + arg
        if major == 3:
            return data[pos : pos + arg].decode("utf-8"), pos + arg
        if major == 4:
            items = []
            for _ in range(arg):
                value, pos = item(pos)
                items.append(value)
            return items, pos
        if major == 5:
            pairs = []
            for _ in range(arg):
                key, pos = item(pos)
                value, pos = item(pos)
                pairs.append((key, value))
            return CMap(pairs), pos
        raise ValueError("tags are not allowed")

    value, end = item(0)
    if end != len(data):
        raise ValueError("trailing bytes")
    if cbor(value) != data:
        raise ValueError("not the deterministic encoding")
    return value


def typed(notation):
    """Python value of the typed JSON notation of the vector file."""
    (kind, inner), = notation.items()
    if kind in ("uint", "nint"):
        return int(inner)
    if kind == "bytes":
        return bytes.fromhex(inner)
    if kind == "text":
        return inner
    if kind == "bool":
        return bool(inner)
    if kind == "null":
        return None
    if kind == "array":
        return [typed(item) for item in inner]
    if kind == "map":
        return CMap((typed(k), typed(v)) for k, v in inner)
    raise ValueError(kind)


# --- Hashing and key derivation (docs/specs.md, section 4) -----------------


def H(data):
    return blake3.blake3(data).digest()


def H_L(label, args):
    return H(cbor([PROFILE_TAG, label, list(args)]))


def extract(salt, ikm):
    return blake3.blake3(ikm, key=salt).digest()


def expand_label(secret, label, context, length):
    info = cbor(["city-g/v0.2 expand", label, context, length])
    return blake3.blake3(info, key=secret).digest(length=length)


def derive_secret(secret, label):
    return expand_label(secret, label, b"", 32)


def mac(key, data):
    return blake3.blake3(cbor(["city-g/v0.2 mac", data]), key=key).digest()


# --- ChaCha20-Poly1305 (RFC 8439), pure Python -----------------------------


def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def _chacha_block(key, counter, nonce):
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    working = state[:]
    for _ in range(10):
        _quarter(working, 0, 4, 8, 12)
        _quarter(working, 1, 5, 9, 13)
        _quarter(working, 2, 6, 10, 14)
        _quarter(working, 3, 7, 11, 15)
        _quarter(working, 0, 5, 10, 15)
        _quarter(working, 1, 6, 11, 12)
        _quarter(working, 2, 7, 8, 13)
        _quarter(working, 3, 4, 9, 14)
    return struct.pack("<16I", *((w + s) & 0xFFFFFFFF for w, s in zip(working, state)))


def _chacha20(key, counter, nonce, data):
    out = bytearray()
    for offset in range(0, len(data), 64):
        block = _chacha_block(key, counter + offset // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[offset : offset + 64], block))
    return bytes(out)


def _poly1305(key, message):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset : offset + 16] + b"\x01"
        acc = (acc + int.from_bytes(chunk, "little")) * r % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def _pad16(data):
    return b"\x00" * (-len(data) % 16)


def aead_seal(key, nonce, plaintext, aad):
    otk = _chacha_block(key, 0, nonce)[:32]
    ciphertext = _chacha20(key, 1, nonce, plaintext)
    mac_data = aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
    mac_data += struct.pack("<QQ", len(aad), len(ciphertext))
    return ciphertext + _poly1305(otk, mac_data)


def aead_open(key, nonce, sealed, aad):
    ciphertext, tag = sealed[:-16], sealed[-16:]
    otk = _chacha_block(key, 0, nonce)[:32]
    mac_data = aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
    mac_data += struct.pack("<QQ", len(aad), len(ciphertext))
    if _poly1305(otk, mac_data) != tag:
        raise ValueError("AEAD tag mismatch")
    return _chacha20(key, 1, nonce, ciphertext)


def aead_self_test():
    # RFC 8439, section 2.8.2.
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only "
        b"one tip for the future, sunscreen would be it."
    )
    sealed = aead_seal(key, nonce, plaintext, aad)
    assert sealed[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691", "RFC 8439 tag"
    assert aead_open(key, nonce, sealed, aad) == plaintext
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except BaseException as error:  # a broken install can raise a pyo3 panic
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return "pure Python (RFC 8439 self-test)"
    assert ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad) == sealed
    return "pure Python, cross-checked with `cryptography`"


# --- Checks -----------------------------------------------------------------


class Report:
    def __init__(self):
        self.passed = 0
        self.failures = []

    def check(self, name, condition):
        if condition:
            self.passed += 1
        else:
            self.failures.append(name)


def unhex(value):
    return bytes.fromhex(value)


def check_cbor(report, vectors):
    for case in vectors["cbor_det"]:
        encoding = unhex(case["encoding"])
        report.check(case["id"], cbor(typed(case["value"])) == encoding)
        report.check(case["id"] + "/decode", cbor(cbor_decode(encoding)) == encoding)
    # Non-shortest head, indefinite length, duplicate keys, unsorted keys,
    # float, tag.
    for bad in ("1817", "5f4100ff", "a2010101 02", "a2020101 01", "f93c00", "c0 00"):
        bad = bad.replace(" ", "")
        try:
            cbor_decode(unhex(bad))
            report.check(f"cbor/reject/{bad}", False)
        except (ValueError, KeyError):
            report.check(f"cbor/reject/{bad}", True)


def check_hashes(report, vectors):
    for case in vectors["h_l"]:
        args = [typed(arg) for arg in case["args"]]
        report.check(case["id"], H_L(case["label"], args).hex() == case["digest"])
    kdf = vectors["kdf"]
    for case in kdf["h"]:
        report.check("h", H(unhex(case["input"])).hex() == case["digest"])
    for case in kdf["extract"]:
        report.check("extract", extract(unhex(case["salt"]), unhex(case["ikm"])).hex() == case["prk"])
    for case in kdf["expand_label"]:
        out = expand_label(unhex(case["secret"]), case["label"], unhex(case["context"]), case["length"])
        report.check(f"expand_label/{case['label']}", out.hex() == case["output"])
    for case in kdf["derive_secret"]:
        out = derive_secret(unhex(case["secret"]), case["label"])
        report.check(f"derive_secret/{case['label']}", out.hex() == case["output"])
    for case in kdf["mac"]:
        report.check("mac", mac(unhex(case["key"]), unhex(case["data"])).hex() == case["tag"])


def check_identifiers(report, ids):
    gid = unhex(ids["gid"])
    device_pk = unhex(ids["device_pk"])
    report.check("id/leaf_id", H_L("leaf-id", [gid, device_pk]).hex() == ids["leaf_id"])
    report.check(
        "id/group_id",
        H_L("group-id", [device_pk, unhex(ids["group_nonce"])]).hex() == ids["group_id"],
    )
    report.check("id/invite_id", H_L("invite-id", [unhex(ids["invite_pk"])]).hex() == ids["invite_id"])
    report.check(
        "id/epoch_ref", H_L("msg/epoch-ref", [gid, ids["epoch"]]).hex() == ids["epoch_ref"]
    )
    report.check("id/kem_pk_hash", H_L("kem-pk", [unhex(ids["kem_pk"])]).hex() == ids["kem_pk_hash"])
    report.check("id/ml-dsa-87 public key size", len(device_pk) == 2592)
    report.check("id/ml-kem-768 public key size", len(unhex(ids["kem_pk"])) == 1184)


def group_context(gid, epoch, tree_hash, roster_hash, cth):
    return cbor(["city-g/group-context/v2", gid, epoch, tree_hash, roster_hash, PROFILE_TAG, cth])


def epoch_secrets(prev_init, commit_secret, gc_encoding):
    epoch_secret = expand_label(extract(prev_init, commit_secret), "epoch", H(gc_encoding), 32)
    return {
        label: derive_secret(epoch_secret, label)
        for label in ("init", "msg", "confirm", "external")
    }


def check_key_schedule(report, ks):
    gc = ks["group_context"]
    encoding = group_context(
        unhex(gc["gid"]),
        gc["epoch"],
        unhex(gc["tree_hash"]),
        unhex(gc["roster_hash"]),
        unhex(gc["confirmed_transcript_hash"]),
    )
    report.check("ks/group_context", encoding.hex() == gc["encoding"])
    report.check("ks/group_context_hash", H(encoding).hex() == gc["hash"])
    commit_secret = derive_secret(unhex(ks["root_path_secret"]), "commit")
    report.check("ks/commit_secret", commit_secret.hex() == ks["commit_secret"])
    secrets = epoch_secrets(unhex(ks["prev_init_secret"]), commit_secret, encoding)
    report.check("ks/init_secret", secrets["init"].hex() == ks["init_secret"])
    report.check("ks/msg_secret", secrets["msg"].hex() == ks["msg_secret"])
    report.check("ks/external_secret", secrets["external"].hex() == ks["external_secret"])
    tag = mac(secrets["confirm"], unhex(gc["confirmed_transcript_hash"]))
    report.check("ks/confirmation_tag", tag.hex() == ks["confirmation_tag"])
    seed = expand_label(secrets["external"], "external kem", b"", 64)
    report.check("ks/external_kem_seed", seed.hex() == ks["external_kem_seed"])

    tr = ks["transcript"]
    confirmed = H_L(
        "confirmed-transcript",
        [unhex(tr["prev_interim"]), unhex(tr["anchor_tbs"]), unhex(tr["signature"])],
    )
    report.check("ks/confirmed_transcript", confirmed.hex() == tr["confirmed"])
    interim = H_L("interim-transcript", [confirmed, unhex(tr["confirmation_tag"])])
    report.check("ks/interim_transcript", interim.hex() == tr["interim"])

    ext = ks["external_init"]
    init = expand_label(
        extract(ZERO32, unhex(ext["shared_secret"])), "external init", H(unhex(ext["kem_output"])), 32
    )
    report.check("ks/external_init", init.hex() == ext["init_secret"])
    report.check("ks/ml-kem-768 ciphertext size", len(unhex(ext["kem_output"])) == 1088)


def roster_hash(members, admins, last_generation):
    records = [
        [m["leaf_id"], m["device_pk"], m["slot"], m["generation"], m["admission_hash"]]
        for m in sorted(members, key=lambda m: m["slot"])
    ]
    return H_L("roster", [records, sorted(admins), [list(pair) for pair in sorted(last_generation)]])


def check_roster(report, roster):
    gid = unhex(roster["gid"])
    members = []
    for m in roster["members"]:
        record = {
            "leaf_id": unhex(m["leaf_id"]),
            "device_pk": unhex(m["device_pk"]),
            "slot": m["slot"],
            "generation": m["generation"],
            "admission_hash": unhex(m["admission_hash"]),
        }
        report.check("roster/leaf_id", H_L("leaf-id", [gid, record["device_pk"]]) == record["leaf_id"])
        members.append(record)
    admins = [unhex(a) for a in roster["admins"]]
    report.check("roster/admins sorted bytewise", admins == sorted(admins))
    digest = roster_hash(members, admins, roster["last_generation"])
    report.check("roster/roster_hash", digest.hex() == roster["roster_hash"])


def wrap_keys(shared, context):
    return (
        expand_label(shared, "tree path wrap key", context, 32),
        expand_label(shared, "tree path wrap nonce", context, 12),
    )


def check_path_wrap(report, pw):
    context = cbor(
        [
            unhex(pw["gid"]),
            pw["epoch"],
            pw["author_slot"],
            pw["node"],
            pw["target"],
            H_L("kem-pk", [unhex(pw["target_public_key"])]),
        ]
    )
    key, nonce = wrap_keys(unhex(pw["shared_secret"]), context)
    try:
        secret = aead_open(key, nonce, unhex(pw["wrapped_secret"]), context)
    except ValueError:
        secret = None
    report.check("path_wrap/unwrap", secret is not None and secret.hex() == pw["root_path_secret"])
    # A two-slot tree has one parent (the root): its path secret is the first
    # of the chain.
    first = derive_secret(unhex(pw["author_leaf_secret"]), "tree path")
    report.check("path_wrap/path secret chain", first.hex() == pw["root_path_secret"])
    report.check("path_wrap/sizes", len(unhex(pw["wrapped_secret"])) == 48)


def tree_hash(n_max, leaves, parents):
    """leaves[slot] = [leaf_id, generation, public_key] or None;
    parents[node] = public key or None."""

    def node_hash(node):
        if node >= n_max - 1:
            slot = node - (n_max - 1)
            occupant = leaves[slot] if leaves[slot] is not None else []
            return H_L("tree/leaf", [n_max, slot, occupant])
        left, right = node_hash(2 * node + 1), node_hash(2 * node + 2)
        key = parents[node] if parents[node] is not None else b""
        return H_L("tree/parent", [node, key, left, right])

    return node_hash(0)


def direct_path(n_max, slot):
    node, path = n_max - 1 + slot, []
    while node > 0:
        node = (node - 1) // 2
        path.append(node)
    return path


def check_genesis(report, g):
    gid = unhex(g["gid"])
    creator_pk = unhex(g["creator_device_pk"])
    n_max = g["n_max"]
    report.check("genesis/gid", H_L("group-id", [creator_pk, unhex(g["group_nonce"])]) == gid)
    leaf_id = H_L("leaf-id", [gid, creator_pk])
    report.check("genesis/author_leaf_id", leaf_id.hex() == g["author_leaf_id"])

    commit = cbor_decode(unhex(g["commit"]))
    keys = sorted(commit.keys())
    report.check("genesis/registry", keys == [1, 2, 3, 4, 5, 6, 7, 8, 9, 14, 15, 108, 109, 110])
    report.check("genesis/profile", commit.get(1) == PROFILE_TAG)
    report.check("genesis/fields", commit.get(2) == gid and commit.get(3) == 0 and commit.get(4) == 0)
    report.check("genesis/prev interim", commit.get(5) == ZERO32)
    report.check("genesis/author", commit.get(6) == leaf_id and commit.get(108) == creator_pk)
    report.check("genesis/nonce and n_max", commit.get(14) == unhex(g["group_nonce"]) and commit.get(15) == n_max)
    tbs = cbor(CMap((k, v) for k, v in commit.pairs if k not in (109, 110)))
    report.check("genesis/anchor_tbs", tbs.hex() == g["anchor_tbs"])
    signature = commit.get(109)
    report.check("genesis/signature size", len(signature) == ML_DSA_87_SIGNATURE_BYTES)

    # Update path: the creator re-keys its leaf and its whole direct path;
    # nobody else is in the tree, so no path secret is encrypted.
    leaf_pk, nodes = commit.get(9)
    report.check("genesis/leaf key", leaf_pk.hex() == g["leaf_public_key"])
    report.check("genesis/path nodes", [n[0] for n in nodes] == direct_path(n_max, 0))
    report.check("genesis/no targets", all(n[2] == [] for n in nodes))
    parents = [None] * (n_max - 1)
    for node, public_key, _ in nodes:
        parents[node] = public_key
    for entry in g["tree_parents"]:
        expected = unhex(entry["public_key"]) if entry["public_key"] else None
        report.check(f"genesis/parent {entry['node']}", parents[entry["node"]] == expected)
    leaves = [None] * n_max
    leaves[0] = [leaf_id, 1, leaf_pk]
    digest = tree_hash(n_max, leaves, parents)
    report.check("genesis/tree_hash", digest.hex() == g["tree_hash"] and commit.get(8) == digest)
    roster = roster_hash(
        [{"leaf_id": leaf_id, "device_pk": creator_pk, "slot": 0, "generation": 1, "admission_hash": ZERO32}],
        [creator_pk],
        [(0, 1)],
    )
    report.check("genesis/roster_hash", roster.hex() == g["roster_hash"] and commit.get(7) == roster)

    # Key schedule: path secrets from the leaf secret up to the root.
    secret = derive_secret(unhex(g["leaf_secret"]), "tree path")
    for _ in direct_path(n_max, 0)[1:]:
        secret = derive_secret(secret, "tree path")
    commit_secret = derive_secret(secret, "commit")
    confirmed = H_L("confirmed-transcript", [ZERO32, tbs, signature])
    report.check("genesis/confirmed transcript", confirmed.hex() == g["confirmed_transcript_hash"])
    gc = group_context(gid, 0, digest, roster, confirmed)
    report.check("genesis/group_context", gc.hex() == g["group_context"])
    secrets = epoch_secrets(ZERO32, commit_secret, gc)
    tag = mac(secrets["confirm"], confirmed)
    report.check("genesis/confirmation_tag", tag == commit.get(110) and tag.hex() == g["confirmation_tag"])
    interim = H_L("interim-transcript", [confirmed, tag])
    report.check("genesis/interim transcript", interim.hex() == g["interim_transcript_hash"])
    report.check("genesis/init_secret", secrets["init"].hex() == g["init_secret"])
    report.check("genesis/msg_secret", secrets["msg"].hex() == g["msg_secret"])
    report.check("genesis/external_secret", secrets["external"].hex() == g["external_secret"])

    # Signed GroupInfo of epoch 0.
    info = cbor_decode(unhex(g["group_info"]))
    report.check("genesis/group info label", len(info) == 6 and info[0] == "city-g/group-info/v2")
    report.check("genesis/group info context", info[1] == gc and info[2] == tag and info[4] == leaf_id)
    report.check("genesis/group info external key", len(info[3]) == 1184)
    report.check("genesis/group info signature", len(info[5]) == ML_DSA_87_SIGNATURE_BYTES)

    # Message plane v3: the creator's chain in epoch 0.
    epoch_ref = H_L("msg/epoch-ref", [gid, 0])
    chain = expand_label(secrets["msg"], "msg sender", leaf_id, 32)
    generation = 0
    for message in g["messages"]:
        envelope = cbor_decode(unhex(message["envelope"]))
        label, ref, sender, gen, commitment, ciphertext = envelope
        report.check("message/label", label == "city-g-msg-v3")
        report.check("message/epoch_ref", ref == epoch_ref and sender == leaf_id)
        report.check("message/generation", gen == message["generation"])
        while generation < gen:
            chain = derive_secret(chain, "msg next")
            generation += 1
        key = expand_label(chain, "msg key", b"", 32)
        nonce = expand_label(chain, "msg nonce", b"", 12)
        report.check("message/key_commitment", H_L("msg/key-commitment", [key, nonce]) == commitment)
        aad = cbor(envelope[:5])
        try:
            plaintext = aead_open(key, nonce, ciphertext, aad)
        except ValueError:
            report.check("message/decrypt", False)
            continue
        framed_bytes, signature = cbor_decode(plaintext)
        report.check("message/signature size", len(signature) == ML_DSA_87_SIGNATURE_BYTES)
        framed = cbor_decode(framed_bytes)
        expected = [
            "city-g/msg/v3",
            gid,
            0,
            leaf_id,
            gen,
            message["content_type"],
            unhex(message["authenticated_data"]),
            message["signed_timestamp_ms"],
            unhex(message["plaintext"]),
        ]
        report.check("message/framed content", framed == expected)


SIGNED_LAYOUTS = {
    "remove-proposal": ["label", "gid", "leaf_id", "uint", "uint", "device_pk"],
    "invite": ["label", "gid", "device_pk", "uint", "device_pk"],
    "admission/invite": ["label", "gid", "leaf_id", "uint", "device_pk", "invite"],
    "admission/admin": ["label", "gid", "leaf_id", "uint", "device_pk", "null"],
    "alias": ["label", "gid", "device_pk", "text"],
    "session-auth": ["label", "gid", "device_pk", "uint"],
    "cover-failure": ["label", "gid", "uint", "leaf_id", "uint"],
}


def check_signed_objects(report, objects):
    by_id = {}
    for obj in objects:
        encoded = unhex(obj["encoded"])
        items = cbor_decode(encoded)
        by_id[obj["id"]] = items
        name = f"signed/{obj['id']}"
        report.check(name + "/shape", len(items) == obj["fields"] + 1 and items[0] == obj["label"])
        report.check(name + "/signature", len(items[-1]) == ML_DSA_87_SIGNATURE_BYTES)
        for field, kind in zip(items, SIGNED_LAYOUTS[obj["id"]]):
            ok = {
                "label": isinstance(field, str),
                "gid": isinstance(field, bytes) and len(field) == 32,
                "leaf_id": isinstance(field, bytes) and len(field) == 32,
                "device_pk": isinstance(field, bytes) and len(field) == 2592,
                "uint": isinstance(field, int) and field >= 0,
                "text": isinstance(field, str),
                "invite": isinstance(field, bytes),
                "null": field is None,
            }[kind]
            report.check(f"{name}/{kind}", ok)
    # The invite admission carries the signed invite and is signed by its key.
    invite = by_id["invite"]
    admission = by_id["admission/invite"]
    report.check("signed/admission kinds", admission[3] == 1 and by_id["admission/admin"][3] == 0)
    report.check("signed/admission embeds the invite", cbor_decode(admission[5]) == invite)
    report.check("signed/admission authorizer is the invite key", admission[4] == invite[2])


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "vectors.json")
    with open(path, encoding="utf-8") as handle:
        vectors = json.load(handle)
    aead = aead_self_test()
    report = Report()
    report.check("profile", vectors["profile"] == PROFILE_TAG)
    check_cbor(report, vectors)
    check_hashes(report, vectors)
    check_identifiers(report, vectors["identifiers"])
    check_key_schedule(report, vectors["key_schedule"])
    check_roster(report, vectors["roster"])
    check_path_wrap(report, vectors["path_wrap"])
    check_genesis(report, vectors["genesis"])
    check_signed_objects(report, vectors["signed_objects"])
    print(f"ChaCha20-Poly1305: {aead}")
    print(f"{report.passed} checks passed, {len(report.failures)} failed")
    for failure in report.failures:
        print(f"  FAILED {failure}")
    return 1 if report.failures else 0


if __name__ == "__main__":
    sys.exit(main())
