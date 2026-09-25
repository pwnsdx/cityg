#!/usr/bin/env python3
"""Independent verifier of the City-G v0.3 conformance vectors.

This script shares no code with the Rust implementation. It re-implements,
from the specification (docs/specs.md), the deterministic CBOR encoding, the
labelled hash H_L, Extract / ExpandLabel / DeriveSecret / MAC over BLAKE3,
ChaCha20-Poly1305 (RFC 8439) and X25519 (RFC 7748) in pure Python, X-Wing
(draft-connolly-cfrg-xwing-kem-06) on top of an independent ML-KEM-768, the
ratchet tree hash, resolutions and leaf proofs, the registry hash, the key
schedule with its joiner step, welcomes and message plane v4, and checks
every value of vectors.json. ML-DSA-65 signatures are verified with an
independent FIPS 204 implementation.

Requires: python3 >= 3.9 and the packages `blake3`, `kyber-py` (ML-KEM) and
`dilithium-py` (ML-DSA): pip install blake3 kyber-py dilithium-py.
Usage: python3 kat/v0.3/verify_vectors.py [path/to/vectors.json]
"""

import hashlib
import json
import os
import struct
import sys

import blake3
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

PROFILE_TAG = "city-g/v0.3"
ZERO32 = bytes(32)
ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SIGNATURE_BYTES = 3309
X_WING_PUBLIC_KEY_BYTES = 1216
X_WING_CIPHERTEXT_BYTES = 1120


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
    info = cbor([PROFILE_TAG + " expand", label, context, length])
    return blake3.blake3(info, key=secret).digest(length=length)


def derive_secret(secret, label):
    return expand_label(secret, label, b"", 32)


def mac(key, data):
    return blake3.blake3(cbor([PROFILE_TAG + " mac", data]), key=key).digest()


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


# --- X25519 (RFC 7748), pure Python ----------------------------------------

_P25519 = 2**255 - 19


def x25519(scalar, u_bytes):
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    p = _P25519
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * b % p
        x3, z3 = (da + cb) ** 2 % p, x1 * (da - cb) ** 2 % p
        x2, z2 = aa * bb % p, e * (aa + 121665 * e) % p
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def x25519_self_test():
    # RFC 7748, section 6.1.
    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob_pk = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    assert (
        x25519(alice, (9).to_bytes(32, "little")).hex()
        == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )
    assert (
        x25519(alice, bob_pk).hex()
        == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )


# --- X-Wing (draft-connolly-cfrg-xwing-kem-06) ------------------------------

X_WING_LABEL = bytes.fromhex("5c2e2f2f5e5c")


def _x_wing_expand(seed):
    expanded = hashlib.shake_256(seed).digest(96)
    ek_m, dk_m = ML_KEM_768._keygen_internal(expanded[0:32], expanded[32:64])
    sk_x = expanded[64:96]
    return ek_m, dk_m, sk_x, x25519(sk_x, (9).to_bytes(32, "little"))


def x_wing_public_key(seed):
    ek_m, _, _, pk_x = _x_wing_expand(seed)
    return ek_m + pk_x


def _x_wing_combiner(ss_m, ss_x, ct_x, pk_x):
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + X_WING_LABEL).digest()


def x_wing_encaps(public_key, eseed):
    pk_m, pk_x = public_key[:1184], public_key[1184:]
    ek_x = eseed[32:64]
    ct_x = x25519(ek_x, (9).to_bytes(32, "little"))
    ss_x = x25519(ek_x, pk_x)
    ss_m, ct_m = ML_KEM_768._encaps_internal(pk_m, eseed[0:32])
    return ct_m + ct_x, _x_wing_combiner(ss_m, ss_x, ct_x, pk_x)


def x_wing_decaps(seed, ciphertext):
    _, dk_m, sk_x, pk_x = _x_wing_expand(seed)
    ct_m, ct_x = ciphertext[:1088], ciphertext[1088:]
    ss_m = ML_KEM_768.decaps(dk_m, ct_m)
    return _x_wing_combiner(ss_m, x25519(sk_x, ct_x), ct_x, pk_x)


def keygen(secret, label):
    """KeyGen(secret, label) of section 4.3: (seed, public key)."""
    seed = expand_label(secret, label, b"", 32)
    return seed, x_wing_public_key(seed)


def ml_dsa_verify(public_key, message, signature, context):
    return ML_DSA_65.verify(public_key, message, signature, ctx=context.encode("ascii"))


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


def check_suite(report, suite):
    xw = suite["x_wing"]
    seed = unhex(xw["seed"])
    public_key = x_wing_public_key(seed)
    report.check("suite/x-wing public key", public_key.hex() == xw["public_key"])
    report.check("suite/x-wing sizes", len(public_key) == X_WING_PUBLIC_KEY_BYTES)
    ciphertext, shared = x_wing_encaps(public_key, unhex(xw["eseed"]))
    report.check("suite/x-wing ciphertext", ciphertext.hex() == xw["ciphertext"])
    report.check("suite/x-wing shared secret", shared.hex() == xw["shared_secret"])
    report.check("suite/x-wing decapsulation", x_wing_decaps(seed, ciphertext) == shared)
    report.check("suite/x-wing ciphertext size", len(ciphertext) == X_WING_CIPHERTEXT_BYTES)

    kg = suite["x_wing_keygen"]
    seed, public_key = keygen(unhex(kg["secret"]), kg["label"])
    report.check("suite/keygen seed", seed.hex() == kg["seed"])
    report.check("suite/keygen public key", public_key.hex() == kg["public_key"])

    ds = suite["ml_dsa_65"]
    public_key, _ = ML_DSA_65._keygen_internal(unhex(ds["seed"]))
    report.check("suite/ml-dsa-65 public key", public_key.hex() == ds["public_key"])
    signature = unhex(ds["signature"])
    report.check("suite/ml-dsa-65 signature size", len(signature) == ML_DSA_65_SIGNATURE_BYTES)
    report.check(
        "suite/ml-dsa-65 signature",
        ml_dsa_verify(public_key, unhex(ds["message"]), signature, ds["context"]),
    )
    report.check(
        "suite/ml-dsa-65 context separation",
        not ml_dsa_verify(public_key, unhex(ds["message"]), signature, "city-g/other/v1"),
    )


def check_identifiers(report, ids):
    gid = unhex(ids["gid"])
    device_pk = unhex(ids["device_pk"])
    derived_pk, _ = ML_DSA_65._keygen_internal(unhex(ids["device_seed"]))
    report.check("id/device key from seed", derived_pk == device_pk)
    report.check("id/device_id", H_L("device-id", [gid, device_pk]).hex() == ids["device_id"])
    report.check(
        "id/group_id",
        H_L("group-id", [device_pk, unhex(ids["group_nonce"])]).hex() == ids["group_id"],
    )
    report.check("id/invite_id", H_L("invite-id", [unhex(ids["invite_pk"])]).hex() == ids["invite_id"])
    report.check(
        "id/proposal_ref",
        H_L("proposal-ref", [unhex(ids["proposal"])]).hex() == ids["proposal_ref"],
    )
    report.check("id/epoch_ref", H_L("msg/epoch-ref", [gid, ids["epoch"]]).hex() == ids["epoch_ref"])
    kem_pk = unhex(ids["kem_pk"])
    report.check("id/kem key from seed", x_wing_public_key(unhex(ids["kem_seed"])) == kem_pk)
    report.check("id/kem_pk_hash", H_L("kem-pk", [kem_pk]).hex() == ids["kem_pk_hash"])
    member = ids["member_ref"]
    report.check("id/member_ref", cbor([member["leaf"], member["since"]]).hex() == member["encoding"])
    report.check("id/ml-dsa-65 public key size", len(device_pk) == ML_DSA_65_PUBLIC_KEY_BYTES)


def group_context(gid, epoch, tree_hash, registry_hash, cth):
    return cbor(["city-g/group-context/v3", gid, epoch, tree_hash, registry_hash, PROFILE_TAG, cth])


def epoch_secrets_from_joiner(joiner):
    epoch_secret = derive_secret(joiner, "epoch")
    return {
        label: derive_secret(epoch_secret, label)
        for label in ("init", "msg", "confirm", "external")
    }


def joiner_secret(prev_init, commit_secret, gc_encoding):
    return expand_label(extract(prev_init, commit_secret), "joiner", H(gc_encoding), 32)


def confirmed_transcript(prev_interim, anchor_tbs, signature, rotation_signature=b""):
    return H_L("confirmed-transcript", [prev_interim, anchor_tbs, signature, rotation_signature])


def check_key_schedule(report, ks):
    gc = ks["group_context"]
    encoding = group_context(
        unhex(gc["gid"]),
        gc["epoch"],
        unhex(gc["tree_hash"]),
        unhex(gc["registry_hash"]),
        unhex(gc["confirmed_transcript_hash"]),
    )
    report.check("ks/group_context", encoding.hex() == gc["encoding"])
    report.check("ks/group_context_hash", H(encoding).hex() == gc["hash"])
    joiner = joiner_secret(unhex(ks["prev_init_secret"]), unhex(ks["commit_secret"]), encoding)
    report.check("ks/joiner_secret", joiner.hex() == ks["joiner_secret"])
    secrets = epoch_secrets_from_joiner(joiner)
    report.check("ks/init_secret", secrets["init"].hex() == ks["init_secret"])
    report.check("ks/msg_secret", secrets["msg"].hex() == ks["msg_secret"])
    report.check("ks/external_secret", secrets["external"].hex() == ks["external_secret"])
    tag = mac(secrets["confirm"], unhex(gc["confirmed_transcript_hash"]))
    report.check("ks/confirmation_tag", tag.hex() == ks["confirmation_tag"])
    seed, external_pk = keygen(secrets["external"], "external kem")
    report.check("ks/external_kem_seed", seed.hex() == ks["external_kem_seed"])
    report.check("ks/external public key", external_pk.hex() == ks["external_public_key"])

    tr = ks["transcript"]
    confirmed = confirmed_transcript(unhex(tr["prev_interim"]), unhex(tr["anchor_tbs"]), unhex(tr["signature"]))
    report.check("ks/confirmed_transcript", confirmed.hex() == tr["confirmed"])
    rotated = confirmed_transcript(
        unhex(tr["prev_interim"]),
        unhex(tr["anchor_tbs"]),
        unhex(tr["signature"]),
        unhex(tr["rotation_signature"]),
    )
    report.check("ks/confirmed_transcript with rotation", rotated.hex() == tr["confirmed_with_rotation"])
    interim = H_L("interim-transcript", [confirmed, unhex(tr["confirmation_tag"])])
    report.check("ks/interim_transcript", interim.hex() == tr["interim"])

    ext = ks["external_init"]
    kem_output = unhex(ext["kem_output"])
    shared = x_wing_decaps(seed, kem_output)
    report.check("ks/external init decapsulation", shared.hex() == ext["shared_secret"])
    init = expand_label(extract(ZERO32, shared), "external init", H(kem_output), 32)
    report.check("ks/external_init", init.hex() == ext["init_secret"])


# --- Tree (section 6) ------------------------------------------------------


def level(node):
    count = 0
    while node & 1:
        node >>= 1
        count += 1
    return count


def left(node):
    return node ^ (1 << (level(node) - 1))


def right(node):
    return node ^ (3 << (level(node) - 1))


def parent(node):
    k = level(node)
    b = (node >> (k + 1)) & 1
    return (node | (1 << k)) ^ (b << (k + 1))


def sibling(node):
    p = parent(node)
    return right(p) if node < p else left(p)


def leaf_value(leaf):
    """[device_pk, since, encryption_key, admission_hash] or None."""
    return leaf


def node_digest(parent_node):
    key, unmerged = parent_node
    return H_L("tree/parent-node", [key, list(unmerged)])


def leaf_hash(index, leaf):
    return H_L("tree/leaf", [index, leaf_value(leaf)])


def parent_hash(digest, left_hash, right_hash):
    return H_L("tree/parent", [digest, left_hash, right_hash])


class Tree:
    def __init__(self, encoding):
        capacity, leaves, parents = cbor_decode(encoding)
        self.capacity = capacity
        self.leaves = leaves
        self.parents = parents
        self.width = len(leaves)

    def node(self, index):
        return self.leaves[index // 2] if index % 2 == 0 else self.parents[index // 2]

    def hash(self, index):
        if index % 2 == 0:
            return leaf_hash(index // 2, self.leaves[index // 2])
        node = self.parents[index // 2]
        digest = node_digest(node) if node is not None else None
        return parent_hash(digest, self.hash(left(index)), self.hash(right(index)))

    def tree_hash(self):
        return self.hash(self.width - 1)

    def resolution(self, index):
        if index % 2 == 0:
            return [index] if self.leaves[index // 2] is not None else []
        node = self.parents[index // 2]
        if node is not None:
            return sorted([index] + [2 * leaf for leaf in node[1]])
        return sorted(self.resolution(left(index)) + self.resolution(right(index)))


def verify_leaf_proof(encoding, tree_hash):
    """Recompute the root of a LeafProof; returns (leaf, node) if it matches."""
    leaf, width, node, path = cbor_decode(encoding)
    if width & (width - 1) or leaf >= width or len(path) != width.bit_length() - 1:
        return None
    index = 2 * leaf
    digest = leaf_hash(leaf, node)
    for parent_digest, sibling_hash in path:
        up = parent(index)
        if index < up:
            digest = parent_hash(parent_digest, digest, sibling_hash)
        else:
            digest = parent_hash(parent_digest, sibling_hash, digest)
        index = up
    return (leaf, node) if digest == tree_hash else None


def check_tree(report, t):
    tree = Tree(unhex(t["encoding"]))
    report.check("tree/width", tree.width == t["width"] and tree.width <= tree.capacity)
    occupied = [i for i, leaf in enumerate(tree.leaves) if leaf is not None]
    report.check(
        "tree/canonical width",
        tree.width == 1 << (max(occupied)).bit_length() if max(occupied) else tree.width == 1,
    )
    tree_hash = tree.tree_hash()
    report.check("tree/tree_hash", tree_hash.hex() == t["tree_hash"])
    for case in t["resolutions"]:
        report.check(f"tree/resolution {case['node']}", tree.resolution(case["node"]) == case["resolution"])
    for case in t["leaf_proofs"]:
        verified = verify_leaf_proof(unhex(case["encoding"]), tree_hash)
        report.check(
            f"tree/leaf proof {case['leaf']}",
            verified is not None and verified[1] == tree.leaves[case["leaf"]],
        )
    # A proof against another root, or with a tampered sibling, fails.
    first = unhex(t["leaf_proofs"][0]["encoding"])
    report.check("tree/leaf proof wrong root", verify_leaf_proof(first, bytes(32)) is None)
    leaf, width, node, path = cbor_decode(first)
    tampered = [list(step) for step in path]
    tampered[0][1] = bytes([tampered[0][1][0] ^ 1]) + tampered[0][1][1:]
    report.check(
        "tree/leaf proof tampered",
        verify_leaf_proof(cbor([leaf, width, node, tampered]), tree_hash) is None,
    )
    return tree_hash


def registry_hash(registry):
    return H_L("registry", list(registry))


def check_registry(report, r):
    registry = cbor_decode(unhex(r["encoding"]))
    capacity, admins, retired, floor = registry
    report.check("registry/capacity", capacity == r["capacity"])
    report.check("registry/retired floor", floor == r["retired_floor"] == 0)
    report.check("registry/admins increasing", admins == sorted(set(admins)) == r["admins"])
    report.check(
        "registry/retired",
        [[entry["admission_hash"], entry["expires_epoch"]] for entry in r["retired"]]
        == [[h.hex(), e] for h, e in retired],
    )
    report.check("registry/no creator admission", all(h != ZERO32 for h, _ in retired))
    report.check("registry/registry_hash", registry_hash(registry).hex() == r["registry_hash"])
    overflowed = cbor_decode(unhex(r["overflowed"]["encoding"]))
    report.check("registry/overflowed floor", overflowed[3] == r["overflowed"]["retired_floor"] > 0)
    report.check(
        "registry/overflowed registry_hash",
        registry_hash(overflowed).hex() == r["overflowed"]["registry_hash"],
    )


def wrap_keys(shared, context, prefix):
    return (
        expand_label(shared, prefix + " key", context, 32),
        expand_label(shared, prefix + " nonce", context, 12),
    )


def check_path_wrap(report, pw):
    target_seed = unhex(pw["target_seed"])
    target_pk = x_wing_public_key(target_seed)
    report.check("path_wrap/target key", target_pk.hex() == pw["target_public_key"])
    shared = x_wing_decaps(target_seed, unhex(pw["kem_ciphertext"]))
    report.check("path_wrap/decapsulation", shared.hex() == pw["shared_secret"])
    context = cbor([unhex(pw["gid"]), pw["epoch"], pw["author_leaf"], pw["node"], pw["target"], H_L("kem-pk", [target_pk])])
    key, nonce = wrap_keys(shared, context, "tree path wrap")
    try:
        secret = aead_open(key, nonce, unhex(pw["wrapped_secret"]), context)
    except ValueError:
        secret = None
    leaf_secret = unhex(pw["author_leaf_secret"])
    first = derive_secret(leaf_secret, "tree path")
    report.check("path_wrap/unwrap", secret == first)
    # A two-leaf tree has one parent (the root): commit_secret is one step
    # past it, and the node and leaf keys derive from the chain.
    report.check("path_wrap/commit secret", derive_secret(first, "tree path").hex() == pw["commit_secret"])
    report.check("path_wrap/node key", keygen(first, "tree node key")[1].hex() == pw["node_public_key"])
    report.check("path_wrap/leaf key", keygen(leaf_secret, "tree leaf key")[1].hex() == pw["leaf_public_key"])
    report.check("path_wrap/sizes", len(unhex(pw["wrapped_secret"])) == 48)


def open_signed(encoded, label, fields, context, signer_index):
    """Decode a signed array, check its label and size, and verify its
    signature under the key in field `signer_index` (or a given key)."""
    items = cbor_decode(encoded)
    if len(items) != fields + 1 or items[0] != label:
        return None, False
    signer = items[signer_index] if isinstance(signer_index, int) else signer_index
    ok = ml_dsa_verify(signer, cbor(items[:-1]), items[-1], context)
    return items, ok


def check_welcome(report, w):
    request, ok = open_signed(unhex(w["request"]), "city-g/join-request/v1", 6, "city-g/join-request/v1", 2)
    report.check("welcome/request signature", ok)
    request_ref = H_L("proposal-ref", [unhex(w["request"])])
    report.check("welcome/request_ref", request_ref.hex() == w["request_ref"])
    init_seed = unhex(w["init_seed"])
    report.check("welcome/init key", x_wing_public_key(init_seed) == request[4])
    welcome = cbor_decode(unhex(w["welcome"]))
    label, gid, epoch, ref, kem_ciphertext, wrapped = welcome
    report.check("welcome/fields", label == "city-g/welcome/v1" and gid == request[1] and epoch == w["epoch"] and ref == request_ref)
    shared = x_wing_decaps(init_seed, kem_ciphertext)
    context = cbor([gid, epoch, ref, H_L("kem-pk", [request[4]])])
    key, nonce = wrap_keys(shared, context, "welcome")
    try:
        joiner = aead_open(key, nonce, wrapped, context)
    except ValueError:
        joiner = None
    report.check("welcome/joiner secret", joiner is not None and joiner.hex() == w["joiner_secret"])
    admission = cbor_decode(request[5])
    report.check("welcome/admission names the device", admission[2] == H_L("device-id", [gid, request[2]]))


def check_genesis(report, g):
    gid = unhex(g["gid"])
    creator_pk = unhex(g["creator_device_pk"])
    report.check("genesis/creator key", ML_DSA_65._keygen_internal(unhex(g["creator_seed"]))[0] == creator_pk)
    report.check("genesis/gid", H_L("group-id", [creator_pk, unhex(g["group_nonce"])]) == gid)

    commit = cbor_decode(unhex(g["commit"]))
    keys = sorted(commit.keys())
    report.check("genesis/key registry", keys == [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 108, 109, 110])
    report.check("genesis/profile", commit.get(1) == PROFILE_TAG)
    report.check("genesis/fields", commit.get(2) == gid and commit.get(3) == 0 and commit.get(4) == 0)
    report.check("genesis/prev interim", commit.get(5) == ZERO32)
    report.check("genesis/author", commit.get(6) == 0 and commit.get(108) == creator_pk)
    report.check(
        "genesis/nonce and capacity",
        commit.get(15) == unhex(g["group_nonce"]) and commit.get(16) == g["capacity"],
    )
    tbs = cbor(CMap((k, v) for k, v in commit.pairs if k not in (109, 110, 111)))
    report.check("genesis/anchor_tbs", tbs.hex() == g["anchor_tbs"])
    signature = commit.get(109)
    report.check("genesis/signature", ml_dsa_verify(creator_pk, tbs, signature, "city-g/anchor/v3"))

    # A group of one member has a tree of width 1: the update path re-keys
    # the leaf only, and commit_secret = path_secret[0].
    leaf_pk, nodes = commit.get(9)
    leaf_secret = unhex(g["leaf_secret"])
    report.check("genesis/leaf key", leaf_pk.hex() == g["leaf_public_key"] and keygen(leaf_secret, "tree leaf key")[1] == leaf_pk)
    report.check("genesis/no path nodes", nodes == [])
    leaf = [creator_pk, 0, leaf_pk, ZERO32]
    tree_hash = leaf_hash(0, leaf)
    report.check("genesis/tree_hash", tree_hash.hex() == g["tree_hash"] and commit.get(7) == tree_hash)
    registry = registry_hash([g["capacity"], [0], [], 0])
    report.check("genesis/registry_hash", registry.hex() == g["registry_hash"] and commit.get(8) == registry)

    commit_secret = derive_secret(leaf_secret, "tree path")
    confirmed = confirmed_transcript(ZERO32, tbs, signature)
    report.check("genesis/confirmed transcript", confirmed.hex() == g["confirmed_transcript_hash"])
    gc = group_context(gid, 0, tree_hash, registry, confirmed)
    report.check("genesis/group_context", gc.hex() == g["group_context"])
    joiner = joiner_secret(ZERO32, commit_secret, gc)
    report.check("genesis/joiner_secret", joiner.hex() == g["joiner_secret"])
    secrets = epoch_secrets_from_joiner(joiner)
    tag = mac(secrets["confirm"], confirmed)
    report.check("genesis/confirmation_tag", tag == commit.get(110) and tag.hex() == g["confirmation_tag"])
    interim = H_L("interim-transcript", [confirmed, tag])
    report.check("genesis/interim transcript", interim.hex() == g["interim_transcript_hash"])
    report.check("genesis/init_secret", secrets["init"].hex() == g["init_secret"])
    report.check("genesis/msg_secret", secrets["msg"].hex() == g["msg_secret"])
    report.check("genesis/external_secret", secrets["external"].hex() == g["external_secret"])

    # Signed GroupInfo of epoch 0.
    info, ok = open_signed(unhex(g["group_info"]), "city-g/group-info/v3", 5, "city-g/group-info/v3", creator_pk)
    report.check("genesis/group info signature", ok)
    report.check("genesis/group info context", info[1] == gc and info[2] == tag and info[4] == 0)
    report.check("genesis/group info external key", info[3] == keygen(secrets["external"], "external kem")[1])

    # Message plane v4: the creator's chain in epoch 0.
    epoch_ref = H_L("msg/epoch-ref", [gid, 0])
    chain = expand_label(secrets["msg"], "msg sender", cbor([0, 0]), 32)
    generation = 0
    for message in g["messages"]:
        envelope = cbor_decode(unhex(message["envelope"]))
        label, ref, sender_leaf, sender_since, gen, commitment, ciphertext = envelope
        report.check("message/label", label == "city-g-msg-v4")
        report.check("message/header", ref == epoch_ref and sender_leaf == 0 and sender_since == 0)
        report.check("message/generation", gen == message["generation"])
        while generation < gen:
            chain = derive_secret(chain, "msg next")
            generation += 1
        key = expand_label(chain, "msg key", b"", 32)
        nonce = expand_label(chain, "msg nonce", b"", 12)
        report.check("message/key_commitment", H_L("msg/key-commitment", [key, nonce]) == commitment)
        aad = cbor(envelope[:6])
        try:
            plaintext = aead_open(key, nonce, ciphertext, aad)
        except ValueError:
            report.check("message/decrypt", False)
            continue
        framed_bytes, signature = cbor_decode(plaintext)
        report.check("message/signature", ml_dsa_verify(creator_pk, framed_bytes, signature, "city-g/msg/v4"))
        framed = cbor_decode(framed_bytes)
        expected = [
            "city-g/msg/v4",
            gid,
            0,
            0,
            0,
            gen,
            message["content_type"],
            unhex(message["authenticated_data"]),
            message["signed_timestamp_ms"],
            unhex(message["plaintext"]),
        ]
        report.check("message/framed content", framed == expected)


# Signer of each signed object: the index of the field holding the key.
SIGNERS = {
    "remove-proposal": 4,
    "invite": 5,
    "admission/invite": 5,
    "admission/admin": 5,
    "invite-revocation": 3,
    "join-request": 2,
    "alias": 2,
    "session-auth": 2,
    "cover-failure": 3,
}


def check_signed_objects(report, objects):
    by_id = {}
    for obj in objects:
        name = f"signed/{obj['id']}"
        items, ok = open_signed(unhex(obj["encoded"]), obj["label"], obj["fields"], obj["context"], SIGNERS[obj["id"]])
        report.check(name + "/shape", items is not None)
        report.check(name + "/signature", ok)
        report.check(name + "/context is the label", obj["context"] == obj["label"] or obj["id"] == "alias")
        by_id[obj["id"]] = items
    invite = by_id["invite"]
    admission = by_id["admission/invite"]
    report.check("signed/admission kinds", admission[4] == 1 and by_id["admission/admin"][4] == 0)
    report.check("signed/admission embeds the invite", cbor_decode(admission[6]) == invite)
    report.check("signed/admission authorizer is the invite key", admission[5] == invite[2])
    report.check("signed/invite uses", invite[4] == 16)
    report.check(
        "signed/revocation names the invite",
        by_id["invite-revocation"][2] == H_L("invite-id", [invite[2]]),
    )
    report.check("signed/join request carries the admission", cbor_decode(by_id["join-request"][5]) == admission)


def check_light(report, light, tree_hash):
    report.check("light/tree", light["tree_hash"] == tree_hash.hex())
    label, proofs = cbor_decode(unhex(light["light_commit"]))
    report.check("light/commit label", label == "city-g/light-commit/v1")
    leaves = [cbor_decode(cbor(proof))[0] for proof in proofs]
    report.check("light/commit proofs increasing", leaves == sorted(set(leaves)))
    for proof in proofs:
        report.check(f"light/commit proof {proof[0]}", verify_leaf_proof(cbor(proof), tree_hash) is not None)
    label, registry, members, joiner_proof = cbor_decode(unhex(light["light_join"]))
    report.check("light/join label", label == "city-g/light-join/v1")
    capacity, admins, _, floor = cbor_decode(registry)
    report.check("light/join registry", capacity == 8 and admins == [0, 1] and floor == 0)
    verified = verify_leaf_proof(cbor(joiner_proof), tree_hash)
    report.check("light/join proof", verified is not None)
    report.check(
        "light/join members",
        verified is not None and [verified[0], verified[1][1]] in members,
    )


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "vectors.json")
    with open(path, encoding="utf-8") as handle:
        vectors = json.load(handle)
    aead_self_test()
    x25519_self_test()
    report = Report()
    report.check("profile", vectors["profile"] == PROFILE_TAG)
    check_cbor(report, vectors)
    check_hashes(report, vectors)
    check_suite(report, vectors["suite"])
    check_identifiers(report, vectors["identifiers"])
    check_key_schedule(report, vectors["key_schedule"])
    tree_hash = check_tree(report, vectors["tree"])
    check_registry(report, vectors["registry"])
    check_path_wrap(report, vectors["path_wrap"])
    check_welcome(report, vectors["welcome"])
    check_genesis(report, vectors["genesis"])
    check_signed_objects(report, vectors["signed_objects"])
    check_light(report, vectors["light"], tree_hash)
    print("ChaCha20-Poly1305, X25519: pure Python (RFC 8439 and RFC 7748 self-tests)")
    print("X-Wing: ML-KEM-768 from kyber-py; ML-DSA-65: dilithium-py")
    print(f"{report.passed} checks passed, {len(report.failures)} failed")
    for failure in report.failures:
        print(f"  FAILED {failure}")
    return 1 if report.failures else 0


if __name__ == "__main__":
    sys.exit(main())
