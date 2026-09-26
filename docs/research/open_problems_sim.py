#!/usr/bin/env python3
"""Cost model of the open problems of `problemes-ouverts-2026-09-26.md`.

It prints:

  1. the dispute of a wrap: the statement a member proves when it cannot
     open an X-Wing wrap (specification, section 7.2), counted in AND gates,
     multiplications in the fields of X25519 and Poly1305, and conversions
     between bits and field elements; and what a designated-verifier proof
     (QuickSilver) and a publicly verifiable one (VOLE-in-the-head) would
     send;
  2. checkpoints countersigned by witnesses, k of n, per day, by signature
     scheme;
  3. sender cards kept in a cache from one day to the next, when cards
     change once a week (UPDATE_INTERVAL) and a share of a reader's senders
     come back;
  4. what the known proofs of TreeKEM-like trees against adaptive
     corruptions lose, for a group of n members after Q operations: (Q n)^2
     with random oracles, Q^log2(n) in the standard model (Tainted TreeKEM,
     IEEE S&P 2021), and the bits of security a loss L leaves of the kappa a
     primitive offers, kappa - log2(L).

Keccak permutations are counted from the byte lengths of FIPS 203 and of
X-Wing; the matrix A of ML-KEM is sampled from the public seed rho of the
public key, so it stays outside the statement (its rejection sampling is
simulated with SHAKE128 to show what that saves). Gate counts are standard:
a Keccak-f[1600] permutation has 24 x 1600 AND gates, a 32-bit addition 31.
Proof sizes use the published per-gate costs: one field element per
non-linear gate for QuickSilver (1 bit per AND gate), and tau bits per AND
gate for VOLE-in-the-head (tau = 11 to 16 at 128-bit security).

Run: python3 docs/research/open_problems_sim.py
"""

import hashlib
import math
import os

KECCAK_AND = 24 * 1600
ADD32_AND = 31
BLAKE3_AND = 7 * 8 * 6 * ADD32_AND          # 7 rounds, 8 G functions, 6 additions each
CHACHA_AND = 10 * 8 * 4 * ADD32_AND + 16 * ADD32_AND

RATE = {"SHA3-256": 136, "SHA3-512": 72, "SHAKE128": 168, "SHAKE256": 136}


def human(n_bytes):
    for unit, size in (("MB", 1e6), ("KB", 1e3)):
        if n_bytes >= size:
            return f"{n_bytes / size:.1f} {unit}"
    return f"{n_bytes:.0f} B"


def perms(function, absorbed, squeezed=0):
    """Keccak-f permutations to absorb `absorbed` bytes (padding takes at
    least one byte) and squeeze `squeezed` bytes."""
    rate = RATE[function]
    return math.ceil((absorbed + 1) / rate) + max(0, math.ceil(squeezed / rate) - 1)


# ML-KEM-768 (FIPS 203): k = 3, eta1 = eta2 = 2, du = 10, dv = 4.
K, N = 3, 256
CT_M = 1088
CBD_BYTES = 64 * 2

KEYGEN = {
    # X-Wing expands its 32-byte seed with SHAKE256 into d, z and the X25519 key.
    "X-Wing seed expansion": perms("SHAKE256", 32, 96),
    "G(d || k)": perms("SHA3-512", 33, 64),
    "s, e (CBD)": 2 * K * perms("SHAKE256", 33, CBD_BYTES),
}
DECAPS = {
    "G(m' || h)": perms("SHA3-512", 64, 64),
    "y, e1, e2 (CBD)": (2 * K + 1) * perms("SHAKE256", 33, CBD_BYTES),
    "J(z || c)": perms("SHAKE256", 32 + CT_M, 32),
    "X-Wing combiner": perms("SHA3-256", 6 + 4 * 32, 32),
}


def sample_ntt_blocks(trials=2000):
    """Mean SHAKE128 blocks of SampleNTT (rejection sampling of 256
    coefficients below q = 3329), from random seeds."""
    total = 0
    for _ in range(trials):
        stream = hashlib.shake_128(os.urandom(34)).digest(168 * 8)
        count, blocks, pos = 0, 0, 0
        while count < N:
            if pos % 168 == 0:
                blocks += 1
            d1 = stream[pos] | ((stream[pos + 1] & 15) << 8)
            d2 = (stream[pos + 1] >> 4) | (stream[pos + 2] << 4)
            count += (d1 < 3329) + (d2 < 3329 and count + (d1 < 3329) < N)
            pos += 3
        total += blocks
    return total / trials


LADDER_MULTS = 255 * (9 + 2) + 254 + 11   # Montgomery ladder, cswaps, final inversion


def blake3_compressions(message_bytes):
    return math.ceil(message_bytes / 64)


# CBOR_det(["city-g/v0.4 expand", label, ctx, L]) with the wrap context
# [gid, epoch, v.level, v.index, t.level, t.index, kem_pk_hash(t_pk)].
WRAP_CONTEXT = 1 + 34 + 5 + 1 + 5 + 1 + 5 + 34
EXPAND_WRAP_KEY = 1 + 19 + 9 + 2 + WRAP_CONTEXT + 1
EXPAND_WRAP_NONCE = 1 + 19 + 11 + 2 + WRAP_CONTEXT + 1
EXPAND_NODE_KEY = 1 + 19 + 14 + 1 + 1
POLY1305_BLOCKS = math.ceil(WRAP_CONTEXT / 16) + 2 + 1


def dispute(branch):
    """The statement of a dispute. Branch 1: the wrap does not open (the tag
    fails). Branch 2: it opens, but to a secret whose key pair is not the
    node's published key."""
    keccak = sum(KEYGEN.values()) + sum(DECAPS.values())
    blake3 = blake3_compressions(EXPAND_WRAP_KEY) + blake3_compressions(EXPAND_WRAP_NONCE)
    chacha = 2
    ladders = 2                                   # the key's X25519 half, and decapsulation
    ands_misc = (K * N + N) * 12                  # rounding of compress and decompress
    ands_misc += CT_M * 8 + 256 + 127             # c' = c, the choice of K, the tag
    # Bits that become field elements: CBD bits and rounded coefficients mod
    # q; the X25519 scalar and shared secret; the Poly1305 key.
    to_q = (2 * K + 2 * K + 1) * N * 4 + (K * N + 2 * N) * 12
    to_25519 = ladders * 255 + 255
    if branch == 2:
        keccak += sum(KEYGEN.values())
        blake3 += blake3_compressions(EXPAND_NODE_KEY)
        ladders += 1
        to_q += 2 * K * N * 4
        to_25519 += 255
    ands = keccak * KECCAK_AND + blake3 * BLAKE3_AND + chacha * CHACHA_AND + ands_misc
    return {
        "keccak": keccak, "blake3": blake3, "chacha": chacha, "ands": ands,
        "p25519": ladders * LADDER_MULTS, "p1305": POLY1305_BLOCKS,
        "to_q": to_q, "to_25519": to_25519, "to_1305": 256,
    }


def report_dispute():
    print("1. The dispute of a wrap: what a member proves in zero knowledge")
    print(f"   Keccak-f[1600] permutations, key generation from the seed: {sum(KEYGEN.values())}"
          f" ({', '.join(f'{k} {v}' for k, v in KEYGEN.items())})")
    print(f"   decapsulation: {sum(DECAPS.values())}"
          f" ({', '.join(f'{k} {v}' for k, v in DECAPS.items())})")
    blocks = sample_ntt_blocks()
    print(f"   the matrix A (9 SampleNTT, {blocks:.2f} SHAKE128 blocks each on average) would add"
          f" {9 * blocks:.0f} permutations; it comes from the public seed rho, so it stays outside")
    print(f"   {'branch':>28} {'Keccak':>6} {'BLAKE3':>6} {'AND gates':>10} {'mult. mod 2^255-19':>18}"
          f" {'mult. mod 2^130-5':>17} {'bits to fields':>14}")
    for branch, name in ((1, "the wrap does not open"), (2, "it opens to a wrong secret")):
        d = dispute(branch)
        bits = d["to_q"] + d["to_25519"] + d["to_1305"]
        print(f"   {name:>28} {d['keccak']:>6} {d['blake3']:>6} {d['ands']:>10,} {d['p25519']:>18,}"
              f" {d['p1305']:>17} {bits:>14,}")
    print("   the lattice arithmetic is linear (public A, u and t), hence free in VOLE-based proofs")
    for branch in (1, 2):
        d = dispute(branch)
        dv = (d["ands"] / 8 + (d["p25519"] + d["to_25519"]) * 32 + (d["p1305"] + d["to_1305"]) * 17
              + d["to_q"] * 2)
        vith = [d["ands"] * tau / 8 for tau in (11, 16)]
        print(f"   branch {branch}: designated verifier (QuickSilver) about {human(dv)};"
              f" VOLE-in-the-head, boolean part, {human(vith[0])} to {human(vith[1])}")
    print("   (QuickSilver: 1 bit per AND gate, 1 field element per multiplication and per bit made a field")
    print("   element; VOLE-in-the-head: 11 to 16 bits per AND gate, its prime-field part not counted)")
    print()


SIGNATURES = {"ML-DSA-65": (3309, 1952), "FN-DSA-512": (666, 897), "UOV-Is-pkc": (96, 66_576)}


def report_witnesses():
    windows = 86_400 / 300
    print("2. Checkpoints countersigned by witnesses: k of n sign every window (5-minute windows)")
    print("   a fork needs two checkpoints of one epoch with k signatures each; f dishonest witnesses")
    print("   can make one if f >= 2k - n. With n = 3f + 1 and k = 2f + 1, f dishonest witnesses cannot,")
    print("   and f unavailable ones do not stop the group.")
    print(f"   {'witnesses':>9} {'k':>2} {'tolerates':>9} " + " ".join(f"{name:>11}" for name in SIGNATURES))
    for f in (0, 1, 2):
        n, k = 3 * f + 1, 2 * f + 1
        costs = " ".join(f"{human(windows * k * sig):>11}" for sig, _ in SIGNATURES.values())
        print(f"   {n:>9} {k:>2} {f:>9} {costs}")
    print(f"   (a day of signatures only; UOV adds its {human(SIGNATURES['UOV-Is-pkc'][1])} key once per witness;"
          f" hourly checkpoints cost 12 times less)")
    print()


CARD_PART = 1019          # device id, since, H(leaf key), card, admission, updated
LEAF_REST = CARD_PART - 897


def report_cards():
    import msg_sim
    senders = 10_000 // 5 + 1
    rotation = 7
    sessions = 10
    proofs = sessions * msg_sim.multiproof(10_000 // sessions // 5 + 1, 64)
    print(f"3. Sender cards in a cache, for a reader of 10,000 messages a day ({senders:,} senders a day,")
    print(f"   cards that change every {rotation} days, the split leaf of the note beyond v0.4)")
    print(f"   {'senders back from earlier days':>30} {'cache hits':>10} {'cards a day':>11}"
          f" {'with the proofs':>15}")
    for back in (0.0, 0.5, 0.8, 0.95):
        hits = back * (1 - 1 / rotation)
        day = senders * ((1 - hits) * CARD_PART + hits * LEAF_REST)
        print(f"   {back:>29.0%} {hits:>10.0%} {human(day):>11} {human(day + proofs):>15}")
    print(f"   (a hit still fetches the rest of the leaf, {LEAF_REST} bytes, to recompute its hash; the")
    print(f"   membership proofs of {sessions} sessions, {human(proofs)} a day, stay; the messages themselves"
          f" are 6.1 MB)")
    print()


def report_adaptive():
    print("4. Adaptive corruptions: what the known proofs of TreeKEM-like trees lose (Tainted TreeKEM)")
    print(f"   {'members':>9} {'operations':>10} {'loss, random oracles':>20} {'bits left, ML-KEM-768':>21}"
          f" {'bits left, X25519':>17} {'loss, standard model':>20}")
    for log_n in (10, 16, 20):
        for log_q in (20, 30):
            rom = 2 * (log_q + log_n)
            std = log_q * log_n
            x25519 = f"{128 - rom}" if rom < 128 else "none"
            print(f"   {'2^%d' % log_n:>9} {'2^%d' % log_q:>10} {'2^%d' % rom:>20} {192 - rom:>21}"
                  f" {x25519:>17} {'2^%d' % std:>20}")
    print("   (a loss L leaves kappa - log2(L) of the kappa bits a primitive offers: 192 for ML-KEM-768, NIST")
    print("   category 3, and 128 for X25519; X-Wing holds if either does. A million members with a change")
    print("   every 0.1 s make about 2^28 operations a year. In the standard model the loss exceeds 2^192, so")
    print("   the bound says nothing; no straight-line reduction is polynomial: each loses at least")
    print("   n^Omega(log log n), Kamath et al.)")
    print()


def main():
    print("Cost model of the open problems beyond v0.4.")
    print()
    report_dispute()
    report_witnesses()
    report_cards()
    report_adaptive()


if __name__ == "__main__":
    main()
