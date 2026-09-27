#!/usr/bin/env python3
"""The decryption failure rate of ML-KEM-768 for a key its owner chooses.

litige-entier-2026-09-26.md (section 1.2) keeps the member's seed out of
the statement of a wrap dispute: the circuit takes the ML-KEM key (s, e) as
a witness and bounds each coefficient to [-4, 3]. A member who picks a key
with larger coefficients than CBD_2 gives could make honest ciphertexts
fail to decrypt more often; a failure makes the re-encryption differ, and
the dispute's second statement would then convict an honest committer.
This script computes the failure rate that a bound on the key's norm
allows, and how often an honest key breaks it: one bound on the whole key,
|s|^2 + |e|^2, or one bound on each of s and e. The circuit of
longfellow/lattice_circuit.h bounds each of |s|^2 and |e|^2 by 1100;
litige-deux-branches-2026-09-27.md (section 2) reports the results.

The model is the one of the Kyber team's scripts
(https://github.com/pq-crystals/security-estimates): for a coefficient of
the message, the decryption error is

    e^T r + e2 + dv - s^T (e1 + du)

with r, e1, e2 drawn from CBD_2 and du, dv the rounding errors of
Compress_10 and Compress_4 of a uniform value, all independent. A
coefficient fails when the error exceeds q/4 in absolute value, and a
ciphertext when one of its 256 coefficients does (a union bound).

For a fixed key, coefficient l of e^T r sums e_j[k] r_j[l - k] over the 768
coefficients of e, each with its own r: its law depends only on how many
coefficients of e have each absolute value, and likewise for s. The script
convolves the exact laws in floating point, directly rather than by FFT so
that the tails keep their precision, over a window of [-3000, 3000]; the
mass that leaves the window is counted as failure, so each rate is an upper
bound. It checks itself against the published rate of ML-KEM-768 for honest
keys, then searches the key of bounded norm that fails most.

Needs numpy. Run: python3 decryption_failure.py [--joint B ...] [--apart B ...]
"""

import argparse
import math
from functools import lru_cache

import numpy as np

Q = 3329
N = 256          # coefficients of a polynomial, and of a message
K = 3            # module rank of ML-KEM-768
LEN = K * N      # coefficients of s, or of e
WINDOW = 3000    # the support kept: [-WINDOW, WINDOW]
MAGNITUDES = (1, 2, 3, 4)  # |coefficient| in [-4, 3]


class Law:
    """A law on the integers of [-WINDOW, WINDOW], and the mass that left."""

    def __init__(self, p, out=0.0):
        self.p = p
        self.out = out

    @staticmethod
    def of(values):
        p = np.zeros(2 * WINDOW + 1)
        for v, pr in values.items():
            p[v + WINDOW] += pr
        return Law(p)

    def __mul__(self, other):
        full = np.convolve(self.p, other.p)  # direct, not FFT
        mid = full[WINDOW:WINDOW + 2 * WINDOW + 1]
        lost = full[:WINDOW].sum() + full[3 * WINDOW + 1:].sum()
        return Law(mid.copy(), self.out + other.out + lost)

    def tail(self, t):
        """P(|X| > t), with the lost mass counted in."""
        i = math.floor(t)
        return self.p[:WINDOW - i].sum() + self.p[WINDOW + i + 1:].sum() + self.out


def delta():
    return Law.of({0: 1.0})


def power(law, n):
    result, base = delta(), law
    while n:
        if n & 1:
            result = result * base
        n >>= 1
        if n:
            base = base * base
    return result


def cbd2():
    return {-2: 1 / 16, -1: 4 / 16, 0: 6 / 16, 1: 4 / 16, 2: 1 / 16}


def compress(x, d):
    return (((x << d) + 1664) // Q) % (1 << d)


def decompress(y, d):
    return (Q * y + (1 << (d - 1))) >> d


def rounding(d):
    """The law of Decompress_d(Compress_d(x)) - x, centered, x uniform."""
    law = {}
    for x in range(Q):
        err = (decompress(compress(x, d), d) - x) % Q
        err = err - Q if err > Q // 2 else err
        law[err] = law.get(err, 0.0) + 1 / Q
    return law


def scaled(values, c):
    return {c * v: p for v, p in values.items()}


def plus(a, b):
    out = {}
    for va, pa in a.items():
        for vb, pb in b.items():
            out[va + vb] = out.get(va + vb, 0.0) + pa * pb
    return out


DU, DV = rounding(10), rounding(4)


@lru_cache(maxsize=None)
def doubled(kind, c, k):
    """2^k terms c r (kind 'e') or c (e1 + du) (kind 's')."""
    if k == 0:
        base = cbd2() if kind == "e" else plus(cbd2(), DU)
        return Law.of(scaled(base, c))
    half = doubled(kind, c, k - 1)
    return half * half


@lru_cache(maxsize=None)
def term(kind, c, n):
    """The sum of n terms c r (kind 'e') or c (e1 + du) (kind 's')."""
    result, k = delta(), 0
    while n:
        if n & 1:
            result = result * doubled(kind, c, k)
        n >>= 1
        k += 1
    return result


@lru_cache(maxsize=None)
def rest():
    """e2 + dv, the part of the error that the key does not scale."""
    return Law.of(plus(cbd2(), DV))


def fixed_key_rate(ns, ne):
    """log2 of the failure rate of a ciphertext for a key whose s (and e)
    has ns[c] (and ne[c]) coefficients of absolute value c."""
    law = rest()
    for c in MAGNITUDES:
        if ns.get(c):
            law = law * term("s", c, ns[c])
        if ne.get(c):
            law = law * term("e", c, ne[c])
    return math.log2(N * law.tail(Q / 4))


def honest_average_rate():
    """log2 of the failure rate averaged over honest keys, as Kyber's
    scripts compute it: products of independent CBD_2 coefficients."""
    def product(noise):
        out = {}
        for c, pc in cbd2().items():
            for v, pv in noise.items():
                out[c * v] = out.get(c * v, 0.0) + pc * pv
        return Law.of(out)

    law = power(product(cbd2()), LEN) * power(product(plus(cbd2(), DU)), LEN)
    return math.log2(N * (law * rest()).tail(Q / 4))


def norm(ns, ne):
    return sum(c * c * (ns.get(c, 0) + ne.get(c, 0)) for c in MAGNITUDES)


@lru_cache(maxsize=None)
def rate_of(k):
    """fixed_key_rate for a key given as two tuples of counts, s then e,
    by absolute value."""
    ns = dict(zip(MAGNITUDES, k[0]))
    ne = dict(zip(MAGNITUDES, k[1]))
    return fixed_key_rate(ns, ne)


def weight(counts):
    return sum(m * m * n for m, n in zip(MAGNITUDES, counts))


class Bound:
    """|s|^2 + |e|^2 <= joint, or |s|^2 <= s and |e|^2 <= e."""

    def __init__(self, joint=None, s=None, e=None):
        self.joint, self.s, self.e = joint, s, e

    def ok(self, k):
        if self.joint is not None:
            return weight(k[0]) + weight(k[1]) <= self.joint
        return weight(k[0]) <= self.s and weight(k[1]) <= self.e

    def room(self, k, part):
        """What part (0 for s, 1 for e) may still spend."""
        if self.joint is not None:
            return self.joint - weight(k[0]) - weight(k[1])
        return (self.s if part == 0 else self.e) - weight(k[part])

    def __str__(self):
        if self.joint is not None:
            return f"|s|^2 + |e|^2 <= {self.joint}"
        return f"|s|^2 <= {self.s}, |e|^2 <= {self.e}"


def spend(k, part, bound):
    """Spends what part may still spend on coefficients of absolute value
    1, where it has room."""
    counts = list(k[part])
    counts[0] += max(0, min(bound.room(k, part), LEN - sum(counts)))
    return (tuple(counts), k[1]) if part == 0 else (k[0], tuple(counts))


def neighbours(k, bound):
    """Keys one move away: turn `step` coefficients of one absolute value
    into another, in s or in e, then spend what the bound leaves."""
    for part in (0, 1):
        for step in (64, 16, 4, 1):
            for a in range(4):
                for b in range(4):
                    if a == b or k[part][a] < step:
                        continue
                    counts = list(k[part])
                    counts[a] -= step
                    counts[b] += step
                    trial = (tuple(counts), k[1]) if part == 0 else (k[0], tuple(counts))
                    while not bound.ok(trial) and counts[b] > 0:
                        counts[b] -= 1
                        trial = (tuple(counts), k[1]) if part == 0 else (k[0], tuple(counts))
                    if sum(counts) > LEN or not bound.ok(trial):
                        continue
                    yield spend(spend(trial, 0, bound), 1, bound)


def starts(bound):
    """Keys that spend the whole bound: one or two absolute values in s,
    and s or e first."""
    out = []
    for hi in range(4):
        for share in (0.0, 0.5, 1.0):
            for first in (0, 1):
                counts = [0, 0, 0, 0]
                empty = ((0,) * 4, (0,) * 4)
                c = MAGNITUDES[hi]
                room = bound.room(empty, first)
                counts[hi] = int(min(LEN, room // (c * c)) * share)
                k = (tuple(counts), (0,) * 4) if first == 0 else ((0,) * 4, tuple(counts))
                k = spend(spend(k, first, bound), 1 - first, bound)
                if bound.ok(k):
                    out.append(k)
    return out


def worst_key(bound):
    """The key within `bound` that fails most: the best of the starting
    keys, improved one move at a time while the rate grows."""
    best = max(starts(bound), key=rate_of)
    improved = True
    while improved:
        improved = False
        for k in neighbours(best, bound):
            if rate_of(k) > rate_of(best) + 1e-6:
                best, improved = k, True
                break
    return best, rate_of(best)


def honest_norm_tail(bound, coefficients=2 * LEN):
    """P(the sum of `coefficients` squares of CBD_2 exceeds `bound`): the
    chance that an honest key breaks the bound."""
    one = np.zeros(5)
    for v, p in cbd2().items():
        one[v * v] += p
    law, base, n = np.array([1.0]), one, coefficients
    while n:
        if n & 1:
            law = np.convolve(law, base)
        n >>= 1
        if n:
            base = np.convolve(base, base)
    return law[bound + 1:].sum()


def log2_or_zero(x):
    return f"2^{math.log2(x):.1f}" if x > 0 else "0"


def describe(ns, ne):
    part = lambda d: " + ".join(f"{n} of |{c}|" for c, n in sorted(d.items()) if n) or "0"
    return f"s: {part(ns)}; e: {part(ne)}"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--joint", type=int, nargs="*",
                        default=[1800, 1900, 2047, 2300])
    parser.add_argument("--apart", type=int, nargs="*",
                        default=[900, 960, 1024, 1100])
    args = parser.parse_args()

    print("ML-KEM-768, decryption failure rate of a ciphertext (log2):")
    print(f"  honest keys, on average (FIPS 203 gives -164.8): "
          f"{honest_average_rate():.1f}")
    typical = {1: 384, 2: 96}  # the expected shape of CBD_2
    print(f"  a typical honest key, {describe(typical, typical)}, "
          f"norm {norm(typical, typical)}: {fixed_key_rate(typical, typical):.1f}")

    def table(title, bounds, honest):
        print()
        print(title)
        print(f"  {'bound':>30}  {'honest key out':>15}  {'worst rate':>10}  worst key")
        for bound in bounds:
            k, rate = worst_key(bound)
            ns, ne = dict(zip(MAGNITUDES, k[0])), dict(zip(MAGNITUDES, k[1]))
            print(f"  {str(bound):>30}  {log2_or_zero(honest(bound)):>15}  "
                  f"{rate:>10.1f}  {describe(ns, ne)}")

    table("Coefficients in [-4, 3], one bound on the whole key:",
          [Bound(joint=b) for b in args.joint],
          lambda b: honest_norm_tail(b.joint))
    table("One bound on each of s and e (the circuit's is 1100):",
          [Bound(s=b, e=b) for b in args.apart],
          lambda b: 2 * honest_norm_tail(b.s, LEN))
    unbounded = {4: LEN}
    print()
    print(f"Without a bound, {describe(unbounded, unbounded)}: "
          f"{fixed_key_rate(unbounded, unbounded):.1f}")


if __name__ == "__main__":
    main()
