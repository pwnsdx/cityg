#!/usr/bin/env python3
"""The shortcut a wrap dispute does not take: revealing ss_X, priced.

`x25519_ir.py` proves the X25519 half of a dispute inside the
zero-knowledge proof. The shortcut would have the member reveal
ss_X = X25519(sk_X, ct_X) to the verifier, with a Chaum-Pedersen proof that
the scalar of its public key pk_X also takes ct_X to ss_X, and give ss_X to
the circuit as a public input of the SHA3-256 combiner. This script prices
it: 97 bytes and a few scalar multiplications, where the proof in the field
of X25519 sends 23 MB.

The research notes reject it (preuves-et-mesures-2026-09-26.md, section
1.4, and litige-x25519-2026-09-26.md, section 3): the member becomes a
static Diffie-Hellman oracle for its node key. Whoever copies the ct_X of
an honest wrap to the same node into a bad wrap obtains, when the member
disputes the bad one, the X25519 half of the honest wrap's secret, which
then rests on ML-KEM alone. Refusing to reveal ss_X for a ct_X already seen
does not stop it: a server allied with the copier holds the honest wrap
back and delivers the copy first.

One piece of it holds, and the script tests it: ct_X must be the
u-coordinate of a point of order l, the prime order of the base point,
since an honest encapsulation, X25519(ek, 9), always gives one. A ct_X that
fails this public check convicts the committer without any proof. On that
subgroup, X25519(k, ct_X) depends only on k mod l, up to its sign, which
pk_X fixes.

The proof works on Edwards25519, birationally equivalent to Curve25519
(RFC 7748, section 4.1): u = (1 + y) / (1 - y). A point is sent as its
u-coordinate and the parity of its x-coordinate.

  proof := [signs, c, s]            1 + 32 + 32 bytes, with ss_X: 97 bytes
  A := a B, S := a C                a := clamp(sk_X) mod l, C := lift(ct_X)
  R1 := r B, R2 := r C
  c := SHA3-512(label, pk_X, ct_X, ss_X, signs, R1, R2, context) mod l
  s := r + c a mod l
  check: c = SHA3-512(..., s B - c A, s C - c S, context) mod l

Run: python3 x25519_dleq.py
"""

import hashlib
import os
import random
import sys
import time

from x25519_ir import BASE, P, x25519

L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
LABEL = b"city-g/dispute/x25519-dleq/v0"


def inv(x):
    return pow(x, P - 2, P)


# Edwards25519 in extended coordinates (X : Y : Z : T), RFC 8032 section
# 5.1.4; the formulas are complete, so the identity needs no special case.

IDENTITY = (0, 1, 1, 0)


def add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * D * t1 * t2 % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def neg(p):
    x, y, z, t = p
    return (-x % P, y, z, -t % P)


def mul(n, p):
    out = IDENTITY
    for bit in bin(n % (8 * L))[2:] if n else "":
        out = add(out, out)
        if bit == "1":
            out = add(out, p)
    return out


def affine(p):
    x, y, z, _ = p
    zi = inv(z)
    return x * zi % P, y * zi % P


def is_identity(p):
    x, y = affine(p)
    return x == 0 and y == 1


def u_and_sign(p):
    """The Montgomery u-coordinate of p and the parity of its x."""
    x, y = affine(p)
    return (1 + y) * inv(1 - y) % P, x & 1


def lift(u, sign):
    """The Edwards point with u-coordinate u and x of parity `sign`, or None
    if u is not canonical, maps to no point, or is on the twist."""
    if not 0 <= u < P or u == P - 1:
        return None
    y = (u - 1) * inv(u + 1) % P
    num, den = (y * y - 1) % P, (D * y * y + 1) % P
    x = num * pow(den, 3, P) * pow(num * pow(den, 7, P), (P - 5) // 8, P) % P
    if den * x * x % P == -num % P:
        x = x * SQRT_M1 % P
    if den * x * x % P != num:
        return None
    if x & 1 != sign:
        x = -x % P
    if x == 0 and sign:
        return None
    return (x, y, 1, x * y % P)


def in_subgroup(u):
    """The point of u-coordinate u, if it has order l; else None."""
    point = lift(u, 0)
    if point is None or is_identity(point) or not is_identity(mul(L, point)):
        return None
    return point


B = lift(9, 0)


def decode(u_bytes):
    """A canonical u-coordinate, or None: X25519 outputs are canonical."""
    u = int.from_bytes(u_bytes, "little")
    return u if len(u_bytes) == 32 and u < P else None


def challenge(pk, ct, ss, signs, r1, r2, context):
    h = hashlib.sha3_512(LABEL)
    for part in (pk, ct, ss, bytes([signs])):
        h.update(part)
    for point in (r1, r2):
        u, sign = u_and_sign(point)
        h.update(u.to_bytes(32, "little") + bytes([sign]))
    h.update(context)
    return int.from_bytes(h.digest(), "little") % L


def clamp(sk):
    k = bytearray(sk)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def prove(sk, ct, context, rng=os.urandom):
    """ss_X and the proof, or None when ct_X convicts the committer."""
    ct_u = decode(ct)
    c_point = in_subgroup(ct_u) if ct_u is not None else None
    if c_point is None:
        return None
    a = clamp(sk) % L
    big_a, big_s = mul(a, B), mul(a, c_point)
    pk, ss = x25519(sk, BASE), x25519(sk, ct)
    (u_a, sign_a), (u_s, sign_s) = u_and_sign(big_a), u_and_sign(big_s)
    assert u_a.to_bytes(32, "little") == pk and u_s.to_bytes(32, "little") == ss
    signs = sign_a | sign_s << 1
    r = int.from_bytes(rng(64), "little") % L
    c = challenge(pk, ct, ss, signs, mul(r, B), mul(r, c_point), context)
    s = (r + c * a) % L
    return ss, bytes([signs]) + c.to_bytes(32, "little") + s.to_bytes(32, "little")


def verify(pk, ct, ss, proof, context):
    """'ok', 'committer' when ct_X alone convicts the committer, or 'bad'."""
    ct_u = decode(ct)
    c_point = in_subgroup(ct_u) if ct_u is not None else None
    if c_point is None:
        return "committer"
    pk_u, ss_u = decode(pk), decode(ss)
    if pk_u is None or ss_u is None or len(proof) != 65 or proof[0] > 3:
        return "bad"
    signs = proof[0]
    c, s = int.from_bytes(proof[1:33], "little"), int.from_bytes(proof[33:], "little")
    big_a, big_s = lift(pk_u, signs & 1), lift(ss_u, signs >> 1)
    if big_a is None or big_s is None or c >= L or s >= L:
        return "bad"
    if any(is_identity(point) or not is_identity(mul(L, point)) for point in (big_a, big_s)):
        return "bad"
    r1 = add(mul(s, B), neg(mul(c, big_a)))
    r2 = add(mul(s, c_point), neg(mul(c, big_s)))
    return "ok" if challenge(pk, ct, ss, signs, r1, r2, context) == c else "bad"


def small_order_u():
    """The u-coordinates of Curve25519's points of order 1, 2, 4 and 8."""
    rng, out = random.Random(8), set()
    while len(out) < 4:
        torsion = mul(L, lift(rng.randrange(P), 0) or IDENTITY)
        for i in range(1, 8):
            if not is_identity(mul(i, torsion)):
                out.add(u_and_sign(mul(i, torsion))[0])
    return sorted(out)


def main():
    rng = random.Random(25519)
    assert is_identity(mul(L, B)) and not is_identity(B)
    # The Edwards arithmetic agrees with RFC 7748's ladder.
    for _ in range(5):
        k = rng.randbytes(32)
        assert u_and_sign(mul(clamp(k), B))[0].to_bytes(32, "little") == x25519(k, BASE)

    context = b"dispute of wrap 7 in window 42"
    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob_pk = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    alice_pk = x25519(alice, BASE)
    ss, proof = prove(alice, bob_pk, context)
    assert ss.hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert verify(alice_pk, bob_pk, ss, proof, context) == "ok"

    timings = {"prove": [], "verify": []}
    for _ in range(10):
        sk = rng.randbytes(32)
        ct = x25519(rng.randbytes(32), BASE)
        pk = x25519(sk, BASE)
        start = time.perf_counter()
        ss, proof = prove(sk, ct, context, rng.randbytes)
        timings["prove"].append(time.perf_counter() - start)
        start = time.perf_counter()
        assert verify(pk, ct, ss, proof, context) == "ok"
        timings["verify"].append(time.perf_counter() - start)
        # Another shared secret, another context, a tampered proof: all fail.
        other = x25519(rng.randbytes(32), ct)
        assert verify(pk, ct, other, proof, context) == "bad"
        assert verify(pk, ct, ss, proof, b"another dispute") == "bad"
        assert verify(x25519(rng.randbytes(32), BASE), ct, ss, proof, context) == "bad"
        for i in (0, 1, 40):
            tampered = bytearray(proof)
            tampered[i] ^= 1 if i else 2
            assert verify(pk, ct, ss, bytes(tampered), context) == "bad"

    # A ct_X that no honest encapsulation gives convicts the committer: a
    # point of small order, a point of mixed order, a point on the twist,
    # a non-canonical encoding.
    sk = rng.randbytes(32)
    pk = x25519(sk, BASE)
    small = small_order_u()
    honest = lift(int.from_bytes(x25519(rng.randbytes(32), BASE), "little"), 0)
    mixed = add(honest, lift(small[-1], 0))
    twist = next(u for u in range(2, 100) if lift(u, 0) is None)
    bad_cts = [u.to_bytes(32, "little") for u in small]
    bad_cts.append(u_and_sign(mixed)[0].to_bytes(32, "little"))
    bad_cts.append(twist.to_bytes(32, "little"))
    bad_cts.append((P + 9).to_bytes(32, "little"))
    for ct in bad_cts:
        assert prove(sk, ct, context) is None
        assert verify(pk, ct, x25519(sk, ct), bytes(65), context) == "committer"

    print(
        f"DLEQ: proof {len(proof)} bytes, with ss_X {len(proof) + 32};",
        f"{len(bad_cts)} dishonest ciphertexts convict the committer;",
        "pure Python: prove {:.0f} ms, verify {:.0f} ms".format(
            1000 * min(timings["prove"]), 1000 * min(timings["verify"])
        ),
    )


if __name__ == "__main__":
    sys.exit(main())
