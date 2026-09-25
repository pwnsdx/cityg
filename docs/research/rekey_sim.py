#!/usr/bin/env python3
"""Cost model of windowed, partitioned batch re-keying for very large groups.

Companion of `grands-groupes-2026-09-25.md`. The group is one binary key
tree of 2**H leaves, all occupied. During a window, D random leaves change
(joins, removals, key updates). Every node above a changed leaf gets a new
secret and a new public key. The tree is split at level L: each district (a
subtree of 2**L leaves) is re-keyed by its own committer, in parallel with
the others, and the city (the levels above the districts) by one committer.

A committer knows the secrets it generates and nothing else. A re-keyed node
takes the new secret of one re-keyed child through a one-way step, and that
secret is wrapped to the other child (TreeKEM-style chaining). Where the
committer knows no child's new secret, it samples a fresh secret and wraps it
to both children: just above the leaves (the members' own keys) and just
above the district roots (the district committers' secrets). A removed leaf
receives nothing. The LKH count (one wrap per live child everywhere) is given
for comparison.

For each scenario the script reports:
  * the busiest district commit and the city commit (wraps, new public keys,
    bytes);
  * the total number of wraps, against the lower bound D*ln(N/D) of
    Anastos et al. (2024);
  * what one member downloads (the wraps of its own path);
  * the extra re-key needed when the busiest district's committer is removed
    right after its commit: every node it re-keyed is tainted by it (Tainted
    TreeKEM) and must be re-keyed again;
  * the number of successive commits profile v0.3 needs for the same load
    (at most 64 joins and 256 removals per commit).
It then gives the steady-state traffic of a member that follows every
window, for a few change rates and window lengths; 12 changes per second is
the load of the daily self-updates of a million members alone.

Sizes. Current suite: X-Wing ciphertext 1120 bytes, public key 1216 bytes,
ML-DSA-65 signature 3309 bytes. Compact suite: a multi-recipient KEM (mKEM)
shaped like ML-KEM-768 with a group-wide matrix (the construction of
Katsumata et al. used by Hashimoto et al.), which shares 992 bytes per commit
(the 960-byte vector u and an X25519 ephemeral key) and sends 128 bytes per
recipient, with 1184-byte public keys; and FN-DSA-1024 signatures of 1280
bytes. A wrap adds the AEAD-sealed 32-byte secret (48 bytes). A commit header
(epoch, hashes, tag) counts 200 bytes plus the signature; a member checks the
new tree hash with 32 bytes per level of its copath.

Run: python3 docs/research/rekey_sim.py
"""

import math
import random

SEAL = 48
HEADER = 200
HASH = 32
SAMPLE_MEMBERS = 20000
SUITES = {
    "current (X-Wing, ML-DSA-65)": {"wrap": 1120 + SEAL, "pk": 1216, "shared": 0, "sig": 3309},
    "compact (mKEM, FN-DSA-1024)": {"wrap": 128 + SEAL, "pk": 1184, "shared": 992, "sig": 1280},
}
CURRENT, COMPACT = SUITES.values()


def human(n_bytes):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n_bytes < 1000 or unit == "TB":
            return f"{n_bytes:.0f} B" if unit == "B" else f"{n_bytes:.1f} {unit}"
        n_bytes /= 1000
    return f"{n_bytes:.1f} TB"


def commit_bytes(suite, wraps, nodes):
    return wraps * suite["wrap"] + nodes * suite["pk"] + suite["shared"] + HEADER + suite["sig"]


def rekey_cost(h, l, levels, blank_leaves):
    """Wraps and new public keys of re-keying the nodes of `levels` (levels[k]
    is the set of re-keyed nodes of level k, k = 1..h; node i of level k is
    the ancestor leaf >> k), per district and for the city."""

    def boundary(k):
        # The committer knows no child's new secret: the children are members'
        # leaves (k = 1) or district roots re-keyed by another committer.
        return k == 1 or k == l + 1

    district = {}  # district -> [lkh wraps, chained wraps, nodes]
    city = [0, 0, 0]
    for k in range(1, h + 1):
        for node in levels[k]:
            children = [c for c in (2 * node, 2 * node + 1)
                        if not (k == 1 and c in blank_leaves)]
            lkh = len(children)
            fresh = not boundary(k) and any(c in levels[k - 1] for c in children)
            chained = lkh - 1 if fresh else lkh
            slot = district.setdefault(node >> (l - k), [0, 0, 0]) if k <= l else city
            slot[0] += lkh
            slot[1] += chained
            slot[2] += 1
    return district, city


def simulate(h, l, d, removal_share=0.5, seed=7):
    rng = random.Random(seed)
    n = 1 << h
    changed = rng.sample(range(n), d)
    removed = set(changed[: int(d * removal_share)])
    levels = [set(changed)] + [set() for _ in range(h)]
    for leaf in changed:
        for k in range(1, h + 1):
            node = leaf >> k
            if node in levels[k]:
                break  # its ancestors are already marked
            levels[k].add(node)
    district, city = rekey_cost(h, l, levels, removed)

    # What a member downloads: at a re-keyed ancestor, it derives the new
    # secret when the chain comes from its own side, and otherwise fetches
    # the wrap addressed to its child.
    def chain_source(k, node):
        if k in (1, l + 1):
            return None
        fresh = [c for c in (2 * node, 2 * node + 1) if c in levels[k - 1]]
        return fresh[0] if fresh else None

    members = [m for m in rng.sample(range(n), min(SAMPLE_MEMBERS, n)) if m not in removed]
    wraps, commits, district_changed = [], [], 0
    for m in members:
        fetched = [0, 0]  # from the district commit, from the city commit
        for k in range(1, h + 1):
            node = m >> k
            if node in levels[k] and chain_source(k, node) != (m >> (k - 1)):
                fetched[k > l] += 1
        wraps.append(sum(fetched))
        commits.append(sum(1 for f in fetched if f))
        district_changed += (m >> l) in levels[l]

    # Removing the busiest district's committer right after its commit: its
    # own path and every node it re-keyed in the district (tainted by it),
    # plus the city path above the district.
    busiest = max(district, key=lambda x: district[x][1])
    committer = rng.choice([m for m in range(busiest << l, (busiest + 1) << l) if m not in removed])
    taint = [set()] + [set() for _ in range(h)]
    for k in range(1, h + 1):
        if k <= l:
            taint[k] = {v for v in levels[k] if v >> (l - k) == busiest}
        taint[k].add(committer >> k)
    taint_district, taint_city = rekey_cost(h, l, taint, removed | {committer})

    return {
        "n": n,
        "d": d,
        "districts": 1 << (h - l),
        "changed_districts": len(district),
        "busiest": district[busiest],
        "city": city,
        "total_lkh": sum(v[0] for v in district.values()) + city[0],
        "total_wraps": sum(v[1] for v in district.values()) + city[1],
        "total_nodes": sum(v[2] for v in district.values()) + city[2],
        "bound": d * math.log(n / d) if d < n else 0.0,
        "member_mean": sum(wraps) / len(wraps),
        "member_max": max(wraps),
        "member_commits": sum(commits) / len(commits),
        "member_district_changed": district_changed / len(members),
        "taint_wraps": taint_district[busiest][1] + taint_city[1],
        "taint_nodes": taint_district[busiest][2] + taint_city[2],
    }


def member_window_bytes(suite, r, h):
    """Mean bytes a member downloads for one window it follows."""
    return (r["member_mean"] * suite["wrap"] + r["member_commits"] * suite["shared"]
            + h * HASH + (1 + r["member_district_changed"]) * (HEADER + suite["sig"]))


def v03_commits(d, removal_share):
    removals = int(d * removal_share)
    joins = d - removals
    return max(math.ceil(removals / 256), math.ceil(joins / 64))


def report(h, l, d, removal_share=0.5, seed=7):
    r = simulate(h, l, d, removal_share, seed)
    lkh_b, wraps_b, nodes_b = r["busiest"]
    lkh_c, wraps_c, nodes_c = r["city"]
    ratio = r["total_wraps"] / r["bound"] if r["bound"] else float("nan")
    print(f"N = 2^{h} = {r['n']:,} members, {r['districts']:,} districts of 2^{l}, "
          f"D = {d:,} changes ({int(removal_share * 100)} % removals)")
    print(f"  districts with a commit : {r['changed_districts']:,}")
    print(f"  busiest district commit : {wraps_b:,} wraps ({lkh_b:,} LKH), {nodes_b:,} new keys;"
          f" {human(commit_bytes(CURRENT, wraps_b, nodes_b))} current,"
          f" {human(commit_bytes(COMPACT, wraps_b, nodes_b))} compact")
    print(f"  city commit             : {wraps_c:,} wraps ({lkh_c:,} LKH), {nodes_c:,} new keys;"
          f" {human(commit_bytes(CURRENT, wraps_c, nodes_c))} current,"
          f" {human(commit_bytes(COMPACT, wraps_c, nodes_c))} compact")
    total_current, total_compact = (r["total_wraps"] * s["wrap"] + r["total_nodes"] * s["pk"]
                                    for s in (CURRENT, COMPACT))
    print(f"  all commits             : {r['total_wraps']:,} wraps ({r['total_lkh']:,} LKH),"
          f" {r['total_nodes']:,} new keys; {human(total_current)} current,"
          f" {human(total_compact)} compact;"
          f" lower bound D*ln(N/D) = {r['bound']:,.0f} wraps (x{ratio:.2f})")
    print(f"  one member downloads    : mean {r['member_mean']:.1f}, max {r['member_max']} wraps;"
          f" mean {human(member_window_bytes(CURRENT, r, h))} current,"
          f" {human(member_window_bytes(COMPACT, r, h))} compact (with headers)")
    print(f"  busiest committer removed: {r['taint_wraps']:,} wraps, {r['taint_nodes']:,} new keys"
          f" ({human(r['taint_wraps'] * CURRENT['wrap'] + r['taint_nodes'] * CURRENT['pk'])} current)")
    print(f"  profile v0.3            : {v03_commits(d, removal_share):,} successive commits")
    print()


def steady_state(h, l):
    print(f"Steady state, N = 2^{h}: a member that follows every window, per day")
    print(f"  {'changes/s':>9} {'window':>7} {'D':>5} {'PRS delay':>10} {'wraps':>6}"
          + "".join(f" {name:>28}" for name in SUITES))
    # 12 changes per second is what the daily self-update of every member of a
    # million-member group costs on its own (2**20 / 86400).
    for rate in (0.1, 1.0, 12.0):
        for window in (10, 60, 600):
            d = max(1, round(rate * window))
            r = simulate(h, l, d, seed=11)
            per_day = 86400 / window
            cells = "".join(f" {human(member_window_bytes(s, r, h) * per_day):>28}"
                            for s in SUITES.values())
            print(f"  {rate:>9} {window:>6}s {d:>5} {'<= ' + str(2 * window) + ' s':>10}"
                  f" {r['member_mean']:>6.1f}{cells}")
    print()


def main():
    print(__doc__.split("\n\n")[0])
    print()
    for d in (100, 1_000, 10_000, 100_000, 200_000, 500_000):
        report(20, 12, d)
    for d in (10_000, 100_000, 1_000_000):
        report(23, 12, d)
    steady_state(20, 12)


if __name__ == "__main__":
    main()
