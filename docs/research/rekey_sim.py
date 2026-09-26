#!/usr/bin/env python3
"""Cost model of windowed, partitioned batch re-keying for very large groups.

Companion of `grands-groupes-2026-09-25.md`. The group is one binary key
tree of 2**H leaves, all occupied. During a window, D leaves change (joins,
removals, key updates). Every node above a changed leaf gets a new secret
and a new public key. The tree is split at level L: each district (a
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

The script prints:
  1. waves of D random changes (half removals): the busiest district commit
     and the city commit, the total against the lower bound D*ln(N/D) of
     Anastos et al. (2024), what one member downloads, the extra re-key when
     the busiest district's committer is removed right after its commit
     (every node it re-keyed is tainted by it);
  2. placement of the joins of a wave: at random, into the leaves removed in
     the same window (paired), in whole free districts (contiguous), or
     paired first and the surplus in free districts (mixed);
  3. the district size;
  4. CPU time, from the costs measured by docs/research/bench;
  5. the steady-state traffic of a member that follows every window, with a
     signature to check in every window (no init chain) or only the
     confirmation tag (init chain);
  6. sampling audits of the entries of other districts.

Sizes: X-Wing ciphertext 1120 bytes, public key 1216 bytes; a wrap adds the
AEAD-sealed 32-byte secret (48 bytes). ML-DSA-65 signature 3309 bytes, public
key 1952 bytes. A commit header (epoch, hashes, tag) counts 200 bytes plus
its signature. A join record (device key, leaf key, one-time init key,
admission and request signatures) counts 11,200 bytes.

Run: python3 docs/research/rekey_sim.py
"""

import math
import random

SEAL = 48
WRAP = 1120 + SEAL
KEM_PK = 1216
SIG = 3309
HEADER = 200
HASH = 32
JOIN_RECORD = 11_200
LEAF_RECORD = 1952 + KEM_PK + 50     # device key, leaf key, since and admission hash
NODE_RECORD = KEM_PK + HASH + 16     # key, hash, taint
SAMPLE_MEMBERS = 20000

# Microseconds on one core of a 2.1 GHz Xeon (docs/research/bench, release).
CPU_US = {"keygen": 95, "wrap": 156, "unwrap": 320, "sign": 830, "verify": 210}


def human(n_bytes):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n_bytes < 1000 or unit == "TB":
            return f"{n_bytes:.0f} B" if unit == "B" else f"{n_bytes:.1f} {unit}"
        n_bytes /= 1000
    return f"{n_bytes:.1f} TB"


def seconds(us):
    return f"{us / 1e6:.2f} s" if us >= 1e5 else f"{us / 1e3:.1f} ms"


def commit_bytes(wraps, nodes):
    return wraps * WRAP + nodes * KEM_PK + HEADER + SIG


def commit_cpu_us(wraps, nodes):
    return wraps * CPU_US["wrap"] + nodes * CPU_US["keygen"] + CPU_US["sign"]


# ---------------------------------------------------------------- the model


def mark_levels(h, changed):
    """levels[k] = set of re-keyed nodes of level k (node i of level k is the
    ancestor leaf >> k)."""
    levels = [set(changed)] + [set() for _ in range(h)]
    for leaf in changed:
        for k in range(1, h + 1):
            node = leaf >> k
            if node in levels[k]:
                break  # its ancestors are already marked
            levels[k].add(node)
    return levels


def rekey_cost(h, l, levels, blank_leaves):
    """Wraps and new public keys of re-keying the nodes of `levels`, per
    district and for the city: {district: [lkh, chained, nodes]}, city."""

    def boundary(k):
        # The committer knows no child's new secret: the children are members'
        # leaves (k = 1) or district roots re-keyed by another committer.
        return k == 1 or k == l + 1

    district = {}
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


def changed_leaves(n, l, joins, removals, placement, rng):
    """Changed leaves and the leaves left blank, for one window."""
    if placement == "random":
        changed = rng.sample(range(n), joins + removals)
        return changed, set(changed[:removals])
    removed = rng.sample(range(n), removals)
    removed_set = set(removed)
    if placement == "paired":
        # Joiners take the leaves removed in the same window first.
        extra = []
        taken = set(removed)
        while len(extra) < max(0, joins - removals):
            leaf = rng.randrange(n)
            if leaf not in taken:
                taken.add(leaf)
                extra.append(leaf)
        return removed + extra, set(removed[joins:])
    if placement in ("contiguous", "mixed"):
        # Joiners fill whole free districts, from a random district boundary;
        # "mixed" first gives them the leaves removed in the same window.
        paired = min(joins, removals) if placement == "mixed" else 0
        surplus = joins - paired
        span = -(-surplus // (1 << l)) << l
        start = rng.randrange(0, n - span + 1, 1 << l)
        block = [leaf for leaf in range(start, start + surplus) if leaf not in removed_set]
        return removed + block, set(removed[paired:])
    raise ValueError(placement)


def simulate(h, l, joins, removals, placement="random", seed=7):
    rng = random.Random(seed)
    n = 1 << h
    changed, blank = changed_leaves(n, l, joins, removals, placement, rng)
    levels = mark_levels(h, changed)
    district, city = rekey_cost(h, l, levels, blank)

    # What a member downloads: at a re-keyed ancestor, it derives the new
    # secret when the chain comes from its own side, and otherwise fetches
    # the wrap addressed to its child.
    def chain_source(k, node):
        if k in (1, l + 1):
            return None
        fresh = [c for c in (2 * node, 2 * node + 1) if c in levels[k - 1]]
        return fresh[0] if fresh else None

    members = [m for m in rng.sample(range(n), min(SAMPLE_MEMBERS, n)) if m not in blank]
    wraps, district_changed = [], 0
    for m in members:
        fetched = 0
        for k in range(1, h + 1):
            node = m >> k
            if node in levels[k] and chain_source(k, node) != (m >> (k - 1)):
                fetched += 1
        wraps.append(fetched)
        district_changed += (m >> l) in levels[l]

    # Removing the busiest district's committer right after its commit: its
    # own path and every node it re-keyed in the district (tainted by it),
    # plus the city path above the district.
    busiest = max(district, key=lambda x: district[x][1])
    committer = rng.choice([m for m in range(busiest << l, (busiest + 1) << l) if m not in blank])
    taint = [set() for _ in range(h + 1)]
    for k in range(1, h + 1):
        if k <= l:
            taint[k] = {v for v in levels[k] if v >> (l - k) == busiest}
        taint[k].add(committer >> k)
    taint_district, taint_city = rekey_cost(h, l, taint, blank | {committer})

    d = joins + removals
    return {
        "n": n,
        "d": d,
        "joins": joins,
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
        "member_district_changed": district_changed / len(members),
        "taint_wraps": taint_district[busiest][1] + taint_city[1],
        "taint_nodes": taint_district[busiest][2] + taint_city[2],
    }


def member_window_bytes(r, h, signed):
    """Mean bytes a member downloads for one window it follows. `signed`: it
    checks the committers' signatures and the tree hash in every window (no
    init chain); otherwise it checks the confirmation tag only."""
    if signed:
        return (r["member_mean"] * WRAP + h * HASH
                + (1 + r["member_district_changed"]) * (HEADER + SIG))
    return r["member_mean"] * WRAP + HEADER


# ---------------------------------------------------------------- reports


def report_wave(h, l, d):
    joins, removals = d - d // 2, d // 2
    r = simulate(h, l, joins, removals)
    lkh_b, wraps_b, nodes_b = r["busiest"]
    lkh_c, wraps_c, nodes_c = r["city"]
    total = r["total_wraps"] * WRAP + r["total_nodes"] * KEM_PK
    ratio = r["total_wraps"] / r["bound"] if r["bound"] else float("nan")
    print(f"N = 2^{h} = {r['n']:,} members, {r['districts']:,} districts of 2^{l}, "
          f"D = {d:,} changes (50 % removals)")
    print(f"  districts with a commit : {r['changed_districts']:,}")
    print(f"  busiest district commit : {wraps_b:,} wraps ({lkh_b:,} LKH), {nodes_b:,} new keys,"
          f" {human(commit_bytes(wraps_b, nodes_b))}")
    print(f"  city commit             : {wraps_c:,} wraps ({lkh_c:,} LKH), {nodes_c:,} new keys,"
          f" {human(commit_bytes(wraps_c, nodes_c))}")
    print(f"  all commits             : {r['total_wraps']:,} wraps ({r['total_lkh']:,} LKH),"
          f" {r['total_nodes']:,} new keys, {human(total)};"
          f" lower bound D*ln(N/D) = {r['bound']:,.0f} wraps (x{ratio:.2f})")
    print(f"  one member downloads    : mean {r['member_mean']:.1f}, max {r['member_max']} wraps;"
          f" mean {human(member_window_bytes(r, h, True))} with signatures,"
          f" {human(member_window_bytes(r, h, False))} with the tag only")
    print(f"  busiest committer removed: {r['taint_wraps']:,} wraps, {r['taint_nodes']:,} new keys"
          f" ({human(r['taint_wraps'] * WRAP + r['taint_nodes'] * KEM_PK)})")
    print()


def report_placement(h, l, joins, removals):
    print(f"Placement, N = 2^{h}, {joins:,} joins and {removals:,} removals in one window")
    print(f"  {'placement':<11} {'wraps':>10} {'new keys':>10} {'all commits':>12}"
          f" {'busiest district':>17} {'member mean/max':>16}")
    for placement in ("random", "paired", "contiguous", "mixed"):
        r = simulate(h, l, joins, removals, placement)
        total = r["total_wraps"] * WRAP + r["total_nodes"] * KEM_PK
        busiest = commit_bytes(r["busiest"][1], r["busiest"][2])
        print(f"  {placement:<11} {r['total_wraps']:>10,} {r['total_nodes']:>10,} {human(total):>12}"
              f" {human(busiest):>17} {r['member_mean']:>11.1f} / {r['member_max']}")
    print()


def report_district_size(h, d):
    print(f"District size, N = 2^{h}, D = {d:,} random changes")
    print(f"  {'district':>9} {'districts':>9} {'busiest commit':>15} {'its CPU':>9}"
          f" {'city commit':>12} {'its CPU':>9} {'committer state':>16} {'member mean':>12}")
    for l in (10, 11, 12, 13, 14):
        r = simulate(h, l, d - d // 2, d // 2)
        _, wb, nb = r["busiest"]
        _, wc, nc = r["city"]
        state = (1 << l) * LEAF_RECORD + ((1 << l) - 1) * NODE_RECORD
        # The city committer also checks the signature of every district commit.
        city_cpu = commit_cpu_us(wc, nc) + r["changed_districts"] * CPU_US["verify"]
        print(f"  {'2^' + str(l):>9} {r['districts']:>9,} {human(commit_bytes(wb, nb)):>15}"
              f" {seconds(commit_cpu_us(wb, nb)):>9} {human(commit_bytes(wc, nc)):>12}"
              f" {seconds(city_cpu):>9} {human(state):>16} {r['member_mean']:>12.1f}")
    print()


def report_cpu():
    print("CPU, one core (costs measured by docs/research/bench)")
    worst = commit_cpu_us(4096 + 2047, 4095)
    print(f"  district commit, whole district of 2^12 renewed : {seconds(worst)}"
          f" ({4096 + 2047:,} wraps, 4,095 new keys)")
    for h, d in ((20, 200_000), (23, 1_000_000)):
        r = simulate(h, 12, d - d // 2, d // 2)
        _, wb, nb = r["busiest"]
        _, wc, nc = r["city"]
        joins = d - d // 2
        print(f"  N = 2^{h}, D = {d:,}:")
        print(f"    busiest district commit                        : {seconds(commit_cpu_us(wb, nb))}")
        print(f"    city commit, with the district signatures      :"
              f" {seconds(commit_cpu_us(wc, nc) + r['changed_districts'] * CPU_US['verify'])}")
        per_district = joins / r["districts"]
        print(f"    welcomes of one district ({per_district:,.0f} joiners)        :"
              f" {seconds(per_district * CPU_US['wrap'])}")
        print(f"    checking every join (2 signatures each)        :"
              f" {seconds(2 * joins * CPU_US['verify'])} for one core;"
              f" {seconds(2 * per_district * CPU_US['verify'])} per district committer")
    member = 20 * (CPU_US["unwrap"] + CPU_US["keygen"])
    print(f"  one member, 20 unwraps and 20 node keys          : {seconds(member)}"
          f" (+ {seconds(CPU_US['verify'])} per signature it checks)")
    print()


def report_steady_state(h, l):
    print(f"Steady state, N = 2^{h}: a member that follows every window, per day")
    print(f"  {'changes/s':>9} {'window':>7} {'D':>5} {'removal delay':>13} {'wraps':>6}"
          f" {'signed windows':>15} {'tag only':>10}")
    # 12 changes per second is what the daily self-update of every member of a
    # million-member group costs on its own (2**20 / 86400); 1.7 the weekly one.
    for rate in (0.1, 1.7, 12.0):
        for window in (10, 60, 600):
            d = max(1, round(rate * window))
            r = simulate(h, l, d - d // 2, d // 2, seed=11)
            per_day = 86400 / window
            signed = human(member_window_bytes(r, h, True) * per_day)
            tag_only = human(member_window_bytes(r, h, False) * per_day)
            print(f"  {rate:>9} {window:>6}s {d:>5} {'<= ' + str(2 * window) + ' s':>13}"
                  f" {r['member_mean']:>6.1f} {signed:>15} {tag_only:>10}")
    print()


def report_audits():
    print("Sampling audits: each entry of the window is checked by k members on average")
    print(f"  {'joins':>9} {'active members':>15} {'k':>4} {'P(missed)':>10}"
          f" {'records per member':>19} {'bytes per member':>17}")
    for joins in (100, 100_000):
        for active in (100_000, 1_000_000):
            for k in (5, 10, 20):
                records = k * joins / active
                print(f"  {joins:>9,} {active:>15,} {k:>4} {math.exp(-k):>10.1e}"
                      f" {records:>19.4f} {human(records * JOIN_RECORD):>17}")
    print()


def main():
    print(__doc__.split("\n\n")[0])
    print()
    for d in (100, 1_000, 10_000, 100_000, 200_000, 500_000):
        report_wave(20, 12, d)
    for d in (10_000, 100_000, 1_000_000):
        report_wave(23, 12, d)
    report_placement(20, 12, 100_000, 100_000)
    report_placement(20, 12, 150_000, 50_000)
    report_placement(23, 12, 500_000, 500_000)
    report_district_size(20, 200_000)
    report_district_size(23, 1_000_000)
    report_cpu()
    report_steady_state(20, 12)
    report_audits()


if __name__ == "__main__":
    main()
