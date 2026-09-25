#!/usr/bin/env python3
"""Finding H-08: size of one barrier_update under the spec S11.6/S11.8 rules.

Best case for the tree: every node starts non-blank, then S11.6 step 2 blanks
the leaf and the full direct path (root included) of every revoked occupancy
returned by ResolveRevokedOccupancies (cumulative until the slot is reclaimed).
The updater then wraps its path secrets to resolution(sibling) at each level.
"""
import random

# NodeCiphertext = [source, target, target_pk_hash(16), kem_ct(1088), wrapped_ps(48)] + CBOR overhead
BYTES_PER_NODE_CIPHERTEXT = 1088 + 48 + 16 + 12


def cover_size(n_max: int, revoked_fraction: float, rnd: random.Random) -> int:
    leaf_base = n_max - 1
    non_blank = bytearray([1]) * (2 * n_max - 1)
    revoked = rnd.sample(range(n_max), int(revoked_fraction * n_max))
    for slot in revoked:
        node = leaf_base + slot
        while True:
            non_blank[node] = 0
            if node == 0:
                break
            node = (node - 1) // 2
    revoked_set = set(revoked)
    updater = rnd.choice([slot for slot in range(n_max) if slot not in revoked_set])

    def resolution(node: int) -> int:
        if non_blank[node]:
            return 1
        if node >= leaf_base:
            return 0
        return resolution(2 * node + 1) + resolution(2 * node + 2)

    node, count = leaf_base + updater, 0
    while node != 0:
        sibling = node + 1 if node % 2 == 1 else node - 1
        count += resolution(sibling)
        node = (node - 1) // 2
    return count


def main() -> None:
    rnd = random.Random(1)
    for n_max in (1024, 65536):
        trials = 50 if n_max <= 4096 else 10
        for fraction in (0.0, 0.01, 0.05, 0.10, 0.25):
            average = sum(cover_size(n_max, fraction, rnd) for _ in range(trials)) / trials
            megabytes = average * BYTES_PER_NODE_CIPHERTEXT / 1e6
            print(
                f"N_max={n_max:6d} revoked_unreclaimed={fraction:4.0%} "
                f"~{average:8.0f} NodeCiphertexts ~{megabytes:7.2f} MB/update"
            )
    for n_max in (1024, 65536):
        megabytes = (n_max - 1) * BYTES_PER_NODE_CIPHERTEXT / 1e6
        print(
            f"N_max={n_max:6d} fully occupied, internal nodes blank (e.g. bulk genesis): "
            f"{n_max - 1} NodeCiphertexts ~{megabytes:.1f} MB"
        )


if __name__ == "__main__":
    main()
