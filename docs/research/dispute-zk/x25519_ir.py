#!/usr/bin/env python3
"""The X25519 half of a wrap dispute, as a SIEVE IR 2.0 relation.

The dispute proof of README.md shows that a member's X-Wing decapsulation
key, the one its public key commits to, does not open a wrap. Its X25519
half takes the 256 bits of `sk_X` that the Keccak circuit expands from the
seed and computes

  pk_X = X25519(sk_X, 9), checked against the member's public key, and
  ss_X = X25519(sk_X, ct_X), whose 255 bits go to the SHA3-256 combiner.

The two Montgomery ladders of RFC 7748 run in the field F_{2^255-19}
(type 1 of the relation), where one multiplication is one gate; the bits
live in F_2 (type 0), and cross between the two with the conversions of
Diet Mac'n'Cheese, one bit at a time:

* The ladder needs, at each step, the bit that says whether to swap:
  k_{t+1} xor k_t, a linear function of the scalar's bits in F_2. The
  circuit converts those 252 bits, not the scalar's, which saves the
  multiplication of the xor in the field; clamping fixes the others.
* The prover gives the bits of ss_X in F_2 and converts them; the circuit
  checks that they add up to the ladder's output, and, in F_2, that they
  encode a number below 2^255 - 19, so that they are canonical.
* The inverse at the end of the ladder is a hint w: z w = t, z (1 - t) = 0,
  w (1 - t) = 0, and ss_X = x w, which is 0 when z is 0, as in RFC 7748.

Operations on public values fold into constants, and a product with a
constant is linear: the relation has 5,048 multiplications in F_p, 2,522
per ladder and 4 for the inverse. The public values, pk_X and ct_X, are
constants of the relation, which the verifier builds from them.

A conversion check of Diet Mac'n'Cheese is sound, for 40 bits of
statistical security, when it checks at least 1024 conversions of one bit
width at once; the relation pads the 507 conversions it needs with
conversions of random bits up to `--pad` (1024 by default).

  x25519_ir.py check              the reference against RFC 7748 and
                                  OpenSSL, the relation's values against
                                  the reference
  x25519_ir.py dispute DIR        the relation and its witness, in DIR
      [--pad N] [--seed S]
  x25519_ir.py chain DIR N        N multiplications in F_{2^255-19}, to
                                  measure what one of them costs

Run the prover and the verifier of README.md on DIR/relation.txt, with
DIR/witness for the prover.
"""

import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile

P = 2**255 - 19
A24 = 121665
MODULI = (2, P)
F2, FP = 0, 1


# The reference: RFC 7748, sections 5 and 6.1.


def decode_scalar(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def decode_u(u):
    u = bytearray(u)
    u[31] &= 127
    return int.from_bytes(u, "little") % P


def cswap(swap, a, b):
    return (b, a) if swap else (a, b)


def x25519(k, u):
    k, x1 = decode_scalar(k), decode_u(u)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = k_t
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


BASE = (9).to_bytes(32, "little")

RFC7748_VECTORS = [
    # Section 5.2.
    (
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    ),
    (
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    ),
    # Section 6.1: Alice's and Bob's public keys, and their shared secret.
    (
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        BASE.hex(),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    ),
    (
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        BASE.hex(),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    ),
    (
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    ),
]

ITERATIONS = {
    1: "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
    1000: "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
}


# The relation: gates over F_2 and F_p, and the values they carry.


class Value:
    """A value of the relation: a wire, or a constant when `wire` is None."""

    def __init__(self, ty, wire, value):
        self.ty, self.wire, self.value = ty, wire, value % MODULI[ty]

    def is_constant(self, value=None):
        return self.wire is None and (value is None or self.value == value)


class Relation:
    """A SIEVE IR 2.0 relation over F_2 and F_p, evaluated as it is built.

    Operations on constants fold into constants, and a product with a
    constant is a linear gate: only products of two wires count as
    multiplications.
    """

    def __init__(self):
        self.gates = []
        self.next_wire = [0, 0]
        self.witness = ([], [])
        self.multiplications = [0, 0]
        self.conversions = 0

    def _wire(self, ty):
        wire = self.next_wire[ty]
        self.next_wire[ty] += 1
        return wire

    def constant(self, ty, value):
        return Value(ty, None, value)

    def private(self, ty, value):
        out = Value(ty, self._wire(ty), value)
        self.witness[ty].append(out.value)
        self.gates.append(f"${out.wire} <- @private({ty});")
        return out

    def add(self, a, b):
        ty = a.ty
        if a.is_constant():
            a, b = b, a
        if b.is_constant():
            if a.is_constant() or b.value == 0:
                return Value(ty, a.wire, a.value + b.value)
            out = Value(ty, self._wire(ty), a.value + b.value)
            self.gates.append(f"${out.wire} <- @addc({ty}: ${a.wire}, <{b.value:#x}>);")
            return out
        out = Value(ty, self._wire(ty), a.value + b.value)
        self.gates.append(f"${out.wire} <- @add({ty}: ${a.wire}, ${b.wire});")
        return out

    def scale(self, a, c):
        ty = a.ty
        c %= MODULI[ty]
        if a.is_constant() or c == 0:
            return Value(ty, None, a.value * c)
        if c == 1:
            return a
        out = Value(ty, self._wire(ty), a.value * c)
        self.gates.append(f"${out.wire} <- @mulc({ty}: ${a.wire}, <{c:#x}>);")
        return out

    def sub(self, a, b):
        return self.add(a, self.scale(b, -1))

    def mul(self, a, b):
        ty = a.ty
        if a.is_constant():
            return self.scale(b, a.value)
        if b.is_constant():
            return self.scale(a, b.value)
        out = Value(ty, self._wire(ty), a.value * b.value)
        self.gates.append(f"${out.wire} <- @mul({ty}: ${a.wire}, ${b.wire});")
        self.multiplications[ty] += 1
        return out

    def assert_zero(self, a):
        if a.is_constant():
            assert a.value == 0, "a constant assertion fails"
            return
        assert a.value == 0, "the witness does not satisfy the relation"
        self.gates.append(f"@assert_zero({a.ty}: ${a.wire});")

    def convert(self, bit):
        """A bit of F_2 as an element of F_p."""
        if bit.is_constant():
            return Value(FP, None, bit.value)
        out = Value(FP, self._wire(FP), bit.value)
        self.gates.append(f"{FP}: ${out.wire} <- @convert({F2}: ${bit.wire});")
        self.conversions += 1
        return out

    def text(self):
        header = [
            "version 2.0.0;",
            "circuit;",
            *(f"@type field {modulus};" for modulus in MODULI),
            f"@convert(@out: {FP}:1, @in: {F2}:1);",
            "@begin",
        ]
        return "\n".join(header + self.gates + ["@end", ""])

    def witness_text(self, ty):
        lines = ["version 2.0.0;", "private_input;", f"@type field {MODULI[ty]};", "@begin"]
        lines += [f"<{value:#x}>;" for value in self.witness[ty]]
        return "\n".join(lines + ["@end", ""])


def cswap_gates(r, swap, a, b):
    """Swap a and b when the bit `swap`, a value of F_p, is 1."""
    if swap.is_constant():
        return (b, a) if swap.value else (a, b)
    d = r.mul(swap, r.sub(b, a))
    return r.add(a, d), r.sub(b, d)


def ladder_gates(r, swaps, u):
    """RFC 7748's ladder, given the swap bit of each step, from t = 254."""
    one, zero = r.constant(FP, 1), r.constant(FP, 0)
    x1 = r.constant(FP, u)
    x2, z2, x3, z3 = one, zero, x1, one
    for t in range(254, -1, -1):
        x2, x3 = cswap_gates(r, swaps[t], x2, x3)
        z2, z3 = cswap_gates(r, swaps[t], z2, z3)
        a, b = r.add(x2, z2), r.sub(x2, z2)
        aa, bb = r.mul(a, a), r.mul(b, b)
        e = r.sub(aa, bb)
        # x_3 and z_3 matter only if a later step may swap them in.
        if any(not swaps[j].is_constant(0) for j in range(t)):
            c, d = r.add(x3, z3), r.sub(x3, z3)
            da, cb = r.mul(d, a), r.mul(c, b)
            total, diff = r.add(da, cb), r.sub(da, cb)
            x3 = r.mul(total, total)
            z3 = r.scale(r.mul(diff, diff), u)
        x2 = r.mul(aa, bb)
        z2 = r.mul(e, r.add(aa, r.scale(e, A24)))
    return x2, z2


def dispute(sk, ct_x, pad, rng):
    """The X25519 half for the key `sk` (32 bytes) and ciphertext `ct_x`."""
    r = Relation()
    # The 256 bits of sk_X, as the Keccak circuit gives them.
    bits = [r.private(F2, (sk[i // 8] >> (i % 8)) & 1) for i in range(256)]
    # Clamping: bits 0 to 2 and 255 are 0, bit 254 is 1.
    k = [r.constant(F2, 0)] * 3 + bits[3:254] + [r.constant(F2, 1), r.constant(F2, 0)]
    # The ladder swaps at step t when k_{t+1} xor k_t is 1, and at the end
    # when k_0 is, which clamping rules out.
    swaps = [r.convert(r.add(k[t + 1], k[t])) for t in range(255)]
    assert k[0].is_constant(0)

    pk_x = int.from_bytes(x25519(sk, BASE), "little")
    x2, z2 = ladder_gates(r, swaps, 9)
    r.assert_zero(r.sub(x2, r.scale(z2, pk_x)))

    x2, z2 = ladder_gates(r, swaps, decode_u(ct_x))
    w = r.private(FP, pow(z2.value, P - 2, P))
    t = r.mul(z2, w)
    one_minus_t = r.sub(r.constant(FP, 1), t)
    r.assert_zero(r.mul(z2, one_minus_t))
    r.assert_zero(r.mul(w, one_minus_t))
    ss_x = r.mul(x2, w)

    # The bits of ss_X, for SHA3-256: they add up to ss_X in F_p ...
    ss_bits = [r.private(F2, (ss_x.value >> i) & 1) for i in range(255)]
    total = r.constant(FP, 0)
    for i, bit in enumerate(ss_bits):
        total = r.add(total, r.scale(r.convert(bit), 1 << i))
    r.assert_zero(r.sub(total, ss_x))
    # ... and, in F_2, encode a number below p = 2^255 - 19: not both bits
    # 5 to 254 set and bits 0 to 4 at least 13.
    ones = ss_bits[5]
    for bit in ss_bits[6:]:
        ones = r.mul(ones, bit)
    b0, b1, b2, b3, b4 = ss_bits[:5]

    def either(a, b):
        return r.add(r.add(a, b), r.mul(a, b))

    at_least_13 = either(b4, r.mul(r.mul(b3, b2), either(b1, b0)))
    r.assert_zero(r.mul(ones, at_least_13))

    needed = r.conversions
    while r.conversions < pad:
        r.convert(r.private(F2, rng.getrandbits(1)))
    expected = x25519(sk, ct_x)
    assert ss_x.value.to_bytes(32, "little") == expected
    return r, needed


def chain(n, rng):
    """n multiplications in F_p: v := v^2 + a, from a private a."""
    r = Relation()
    a = r.private(FP, rng.randrange(P))
    v = a
    for _ in range(n):
        v = r.add(r.mul(v, v), a)
    r.assert_zero(r.sub(v, r.constant(FP, v.value)))
    return r


def write(r, out):
    os.makedirs(os.path.join(out, "witness"), exist_ok=True)
    with open(os.path.join(out, "relation.txt"), "w") as f:
        f.write(r.text())
    for ty, name in ((F2, "0_f2.txt"), (FP, "1_fp.txt")):
        with open(os.path.join(out, "witness", name), "w") as f:
            f.write(r.witness_text(ty))


def check():
    for k, u, out in RFC7748_VECTORS:
        assert x25519(bytes.fromhex(k), bytes.fromhex(u)).hex() == out, k
    # Section 5.2's iterations: k, u := X25519(k, u), k from k = u = 9.
    k = u = BASE
    for i in range(1, 1001):
        k, u = x25519(k, u), k
        if i in ITERATIONS:
            assert k.hex() == ITERATIONS[i], i
    rng = random.Random(7748)
    # An independent implementation, when OpenSSL is installed.
    agreed = 0
    if shutil.which("openssl"):
        with tempfile.TemporaryDirectory() as tmp:
            key, peer = os.path.join(tmp, "k.der"), os.path.join(tmp, "u.der")
            for _ in range(20):
                k, u = rng.randbytes(32), x25519(rng.randbytes(32), BASE)
                with open(key, "wb") as f:
                    f.write(bytes.fromhex("302e020100300506032b656e04220420") + k)
                with open(peer, "wb") as f:
                    f.write(bytes.fromhex("302a300506032b656e032100") + u)
                derived = subprocess.run(
                    ["openssl", "pkeyutl", "-derive", "-inkey", key, "-keyform", "DER",
                     "-peerkey", peer, "-peerform", "DER"],
                    capture_output=True, check=True,
                ).stdout
                assert derived == x25519(k, u)
                agreed += 1
    # The relation's values match the reference (dispute() asserts it),
    # also for a ciphertext of small order, where z is 0 and ss_X is 0.
    for ct_x in (x25519(rng.randbytes(32), BASE), bytes(32), (1).to_bytes(32, "little")):
        r, _ = dispute(rng.randbytes(32), ct_x, 0, rng)
    print(
        f"RFC 7748: {len(RFC7748_VECTORS)} vectors and 1,000 iterations pass;",
        f"OpenSSL agrees on {agreed} random keys;" if agreed else "OpenSSL not found;",
        "the relation's values match the reference",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    p = sub.add_parser("dispute")
    p.add_argument("out")
    p.add_argument("--pad", type=int, default=1024)
    p.add_argument("--seed", type=int, default=1)
    p = sub.add_parser("chain")
    p.add_argument("out")
    p.add_argument("n", type=int)
    p.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    if args.command == "check":
        check()
    elif args.command == "dispute":
        rng = random.Random(args.seed)
        sk, ephemeral = rng.randbytes(32), rng.randbytes(32)
        r, needed = dispute(sk, x25519(ephemeral, BASE), args.pad, rng)
        write(r, args.out)
        print(
            f"multiplications: {r.multiplications[FP]} in F_p, {r.multiplications[F2]} in F_2;",
            f"conversions: {needed}, padded to {r.conversions};",
            f"gates: {len(r.gates)}",
        )
    else:
        r = chain(args.n, random.Random(args.seed))
        write(r, args.out)
        print(f"multiplications: {r.multiplications[FP]} in F_p; gates: {len(r.gates)}")


if __name__ == "__main__":
    sys.exit(main())
