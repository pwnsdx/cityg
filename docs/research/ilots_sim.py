#!/usr/bin/env python3
"""Cost model of îlots under a flat top.

Companion of `ilots-2026-09-26.md`. The group is a binary tree of 2**H
leaves cut into îlots of 2**C leaves. Inside an îlot, the changes of a
window are re-keyed as in the profile (rekey_sim's plans and chaining rule),
by one task per changed îlot. Above the îlots there is no tree: in every
window a fresh epoch secret goes to every îlot root, in one multi-recipient
ciphertext (a part shared by all îlots and a small part per îlot) or, for a
member whose îlot has a relay, in a 52-byte blob that a member of the îlot
seals under the îlot's secret. Joiners take the leaves that removals empty
(paired placement). The script prints, for a group of 2^20 members:

  1. why a flat top: how often a subtree of each size changes in a window,
     and how many wraps the binary city above the districts of the profile
     costs each member;
  2. what following the group costs a member per day, by îlot size, churn
     and window, against the profile of the parity note (districts of 2^12
     under a binary city);
  3. the top: what the task that sends the epoch secret to every îlot
     downloads, sends and computes;
  4. the îlot tasks and the welcomes of a window;
  5. a burst of 100,000 joins and 100,000 departures;
  6. repairing a cut îlot through its members' leaves, and a joiner's entry;
  7. larger groups, up to 2^24 members;
  8. nobody online: a joiner who enters alone and seals the window, with
     no removal waiting or with one;
  9. a city maintained above the îlots: every window re-keys a binary city
     along the paths of the îlots it changes; relays take the window secret
     from their city path, the flat top becomes a fallback for îlots with no
     relay in dense windows, and sparse windows need no flat top at all;
 10. a member's day at the candidate profile: following, messages and
     senders' cards, against the profile of the parity note; with a leaf
     whose hash keeps the leaf key apart, so that readers fetch the card
     part only; and the authorizer's checkpoints, checked by their
     signature alone.

Coming back after an absence costs what following costs over that time
(replay), with every missed epoch read. Sizes in bytes, CPU in microseconds
on one core (CPU_US of rekey_sim). It reuses rekey_sim.py.

Run: python3 docs/research/ilots_sim.py
"""

import math
import random

from rekey_sim import (CPU_US, HEADER, JOIN_RECORD, KEM_PK, SIG, WRAP, changed_leaves, commit_bytes, commit_cpu_us,
                       human, mark_levels, member_window_bytes, rekey_cost, simulate)

H = 20
N = 1 << H
DAY = 86_400
PROFILE_L = 12
SAMPLE = 20_000

MKEM_SHARED = 960 + 32          # ML-KEM-768 u part under a group-wide matrix, X25519 ephemeral key
MKEM_PART = 128 + 48            # ML-KEM-768 v part, and the epoch secret sealed under the part's key
ILOT_PK = 1152 + 32             # an îlot's key without its matrix seed
RELAY = 48 + 4                  # the sealed epoch secret and the îlot's index
SLIM_HEADER = 4 + 3 * 32        # epoch, seal hash, hash of the group context, confirmation tag
LABRADOR = 58_000               # a LaBRADOR proof for a relation of 2^20 constraints
LEAF = 32 + KEM_PK + 897 + 58   # device id, leaf key, FN-DSA-512 card, since, admission, updated
LEVEL = 64
WELCOME = 1120 + 48 + 100
CHECKPOINT = SIG + 300
EXT_INIT = 1120                 # the X-Wing ciphertext of the external init


def ilot_window(c, joins, removals, seed=11, h=H):
    """Re-key costs of one window with îlots of 2**c leaves, in a tree of 2**h."""
    rng = random.Random(seed)
    n = 1 << h
    changed, blank = changed_leaves(n, c, joins, removals, "paired", rng)
    levels = mark_levels(h, changed)
    for k in range(c + 1, h + 1):
        levels[k] = set()                         # no tree above the îlots
    ilots, _ = rekey_cost(h, c, levels, blank)

    def chain_source(k, node):
        if k == 1:
            return None
        fresh = [x for x in (2 * node, 2 * node + 1) if x in levels[k - 1]]
        return fresh[0] if fresh else None

    members = [m for m in rng.sample(range(n), SAMPLE) if m not in blank]
    wraps = []
    for m in members:
        fetched = 0
        for k in range(1, c + 1):
            node = m >> k
            if node in levels[k] and chain_source(k, node) != (m >> (k - 1)):
                fetched += 1
        wraps.append(fetched)
    busiest = max(ilots.values(), key=lambda v: v[1]) if ilots else [0, 0, 0]
    return {
        "ilots": 1 << (h - c),
        "changed": len(ilots),
        "wraps": sum(v[1] for v in ilots.values()),
        "nodes": sum(v[2] for v in ilots.values()),
        "busiest": busiest,
        "member_mean": sum(wraps) / len(wraps),
        "member_changed": sum(1 for w in wraps if w) / len(wraps),
    }


def top_item(mode):
    return {"relay": RELAY, "mkem": MKEM_SHARED + MKEM_PART, "xwing": WRAP}[mode]


def ilot_member_window(r, mode, header=HEADER):
    return r["member_mean"] * WRAP + top_item(mode) + header


def changes(rate, window):
    d = max(2, round(rate * window))
    return d - d // 2, d // 2


def profile_per_day(rate, window):
    joins, removals = changes(rate, window)
    r = simulate(H, PROFILE_L, joins, removals, placement="paired", seed=11)
    return member_window_bytes(r, H, False) * DAY / window


def report_saturation():
    print("1. Why a flat top (1.7 changes/s; joiners take the removed leaves)")
    for window in (60, 300):
        joins, removals = changes(1.7, window)
        changed = max(joins, removals)
        cells = []
        for k in (6, 8, 10, 12, 14, 16):
            expected = changed * (1 << k) / N
            cells.append(f"2^{k}: {1 - math.exp(-expected):.0%}")
        print(f"   windows of {window:>3} s, chance that a subtree changes: " + ", ".join(cells))
        profile = simulate(H, PROFILE_L, joins, removals, placement="paired", seed=11)
        districts = ilot_window(PROFILE_L, joins, removals)
        city = profile["member_mean"] - districts["member_mean"]
        print(f"     profile: {profile['member_mean']:.1f} wraps per member and window, {city:.1f} of them in the city"
              f" ({city / profile['member_mean']:.0%})")
    print()


def report_following():
    print(f"2. Following the group, per member and per day (N = 2^{H}; joiners take the removed leaves)")
    print(f"   {'changes/s':>9} {'window':>7} {'îlots':>7} {'îlot changed':>12} {'with relays':>11}"
          f" {'multi-recipient':>15} {'profile':>9}")
    for rate in (0.1, 1.7, 12.0):
        for window in (60, 300):
            joins, removals = changes(rate, window)
            profile = profile_per_day(rate, window)
            for c in (6, 8, 10, 12):
                r = ilot_window(c, joins, removals)
                per_day = DAY / window
                relays = ilot_member_window(r, "relay") * per_day
                mkem = ilot_member_window(r, "mkem") * per_day
                shown = human(profile) if c == 6 else ""
                print(f"   {rate:>9} {window:>6}s {'2^' + str(c):>7} {r['member_changed']:>11.0%}"
                      f" {human(relays):>11} {human(mkem):>15} {shown:>9}")
    print("   (profile: districts of 2^12 under a binary city, paired placement; coming back after an absence")
    print("   costs the same per day away, with every missed epoch read)")
    for window in (60, 300):
        joins, removals = changes(1.7, window)
        r = ilot_window(8, joins, removals)
        slim = ilot_member_window(r, "relay", SLIM_HEADER) * DAY / window
        print(f"   with relays and a {SLIM_HEADER}-byte header (seal hash, group context hash, tag), îlots of 2^8,"
              f" 1.7 changes/s, windows of {window} s: {human(slim)} a day")
    print()


def report_top():
    print("3. The top, per window: the epoch secret to every îlot root")
    print(f"   {'îlots':>7} {'keys fetched':>12} {'multi-recipient':>15} {'X-Wing wraps':>12} {'CPU at most':>11}"
          f" {'16 helpers, each':>16}")
    for c in (6, 8, 10, 12):
        ilots = 1 << (H - c)
        fetched = ilots * ILOT_PK
        mkem = MKEM_SHARED + ilots * MKEM_PART
        xwing = ilots * WRAP
        cpu = ilots * CPU_US["wrap"]
        helpers = 16 if ilots >= 256 else 1
        each = f"{human(fetched / helpers)} + {human(mkem / helpers)}"
        print(f"   {ilots:>7,} {human(fetched):>12} {human(mkem):>15} {human(xwing):>12} {cpu / 1e6:>10.2f}s"
              f" {each:>16}")
    print(f"   a proof that the multi-recipient ciphertext holds one secret for every îlot (4,096 parts of 256"
          f" coefficients, 2^20 equations): about {human(LABRADOR)} with LaBRADOR")
    print()


def report_tasks():
    print("4. Îlot tasks and welcomes per window (1.7 changes/s, îlots of 2^8)")
    for window in (60, 300):
        joins, removals = changes(1.7, window)
        r = ilot_window(8, joins, removals)
        mean_wraps = r["wraps"] / max(1, r["changed"])
        mean_cpu = commit_cpu_us(r["wraps"], r["nodes"]) / max(1, r["changed"])
        mean_bytes = commit_bytes(r["wraps"] / max(1, r["changed"]), r["nodes"] / max(1, r["changed"]))
        print(f"   windows of {window:>3} s: {r['changed']} of {r['ilots']:,} îlots change; a task has"
              f" {mean_wraps:.1f} wraps on average ({mean_cpu / 1e3:.1f} ms, {human(mean_bytes)} sent),"
              f" the busiest {r['busiest'][1]}; {removals} removals, each in a leaf a joiner takes")
        print(f"     {joins} welcomes to one-time init keys: {human(joins * WELCOME)} as X-Wing welcomes,"
              f" {human(MKEM_SHARED + joins * MKEM_PART)} as one multi-recipient ciphertext")
    print()


def report_burst():
    joins = removals = 100_000
    print(f"5. A burst of {joins:,} joins and {removals:,} departures in one window")
    profile = simulate(H, PROFILE_L, joins, removals, placement="paired")
    print(f"   profile: {profile['total_wraps']:,} wraps, {human(member_window_bytes(profile, H, False))}"
          f" per member")
    for c in (8, 10):
        r = ilot_window(c, joins, removals, seed=7)
        busiest_cpu = commit_cpu_us(r["busiest"][1], r["busiest"][2])
        print(f"   îlots of 2^{c}: {r['wraps']:,} wraps in {r['changed']:,} îlot tasks, the busiest"
              f" {r['busiest'][1]} ({busiest_cpu / 1e3:.0f} ms); per member"
              f" {human(ilot_member_window(r, 'relay'))} with a relay,"
              f" {human(ilot_member_window(r, 'mkem'))} without")
    print(f"   welcomes: {human(joins * WELCOME)} as X-Wing welcomes, {human(MKEM_SHARED + joins * MKEM_PART)} as one"
          f" multi-recipient ciphertext, to share among members of the previous epoch")
    print()


def report_repair_and_entry():
    print("6. Repair and entry")
    for c in (6, 8, 10):
        size = 1 << c
        print(f"   îlots of 2^{c}: repairing a cut îlot through its leaves takes at most {size} wraps,"
              f" {human(size * WRAP)}; a joiner downloads"
              f" {human(WELCOME + LEAF + c * LEVEL + c * (KEM_PK + 32) + c * WRAP + WRAP + CHECKPOINT)}")
    profile_entry = WELCOME + LEAF + H * LEVEL + H * (KEM_PK + 32) + H * WRAP + CHECKPOINT
    print(f"   profile: a joiner downloads {human(profile_entry)}")
    print()


def report_larger():
    print("7. Larger groups, 5-minute windows, 1.7 changes per second per 2^20 members")
    for h in (22, 24):
        rate = 1.7 * (1 << (h - H))
        joins, removals = changes(rate, 300)
        profile = simulate(h, PROFILE_L, joins, removals, placement="paired", seed=11)
        per_day = DAY / 300
        print(f"   2^{h} members, {rate:.1f} changes/s: profile {human(member_window_bytes(profile, h, False) * per_day)}"
              f" a day")
        for c in (8, 10, 12):
            r = ilot_window(c, joins, removals, h=h)
            keys = r["ilots"] * ILOT_PK
            print(f"     îlots of 2^{c}: {r['member_changed']:.0%} of members see their îlot change;"
                  f" {human(ilot_member_window(r, 'relay') * per_day)} a day with relays,"
                  f" {human(ilot_member_window(r, 'mkem') * per_day)} without; the top fetches {human(keys)}"
                  f" of keys and sends {human(MKEM_SHARED + r['ilots'] * MKEM_PART)}")
    print()


def lone_entrant(h, c, removal, mode):
    """What a joiner that seals a window alone sends and fetches. `c` is
    the îlot height (or the tree height for the profile, with no top);
    `mode` is the top's encryption, or None for no top."""
    seal = HEADER + SIG + EXT_INIT
    send = c * (WRAP + KEM_PK) + seal               # its own path
    fetch = c * KEM_PK + CHECKPOINT + KEM_PK         # its copath keys, its anchor, the external key
    if removal:
        send += c * (WRAP + KEM_PK)                  # the path of the removed member
        fetch += c * KEM_PK
        if mode is not None:
            ilots = 1 << (h - c)
            send += ilots * WRAP if mode == "xwing" else MKEM_SHARED + ilots * MKEM_PART
            fetch += ilots * (KEM_PK if mode == "xwing" else ILOT_PK)
    return send, fetch


def report_lone_entrant():
    print("8. Nobody online: a joiner enters alone and seals the window (external init)")
    print(f"   {'members':>8} {'structure':>20} {'no removal: sends':>18} {'fetches':>9}"
          f" {'a removal waits: sends':>23} {'fetches':>9}")
    for h in (8, 14, 20, 24):
        c = min(8, h)
        rows = [("profile", h, None), ("îlots, X-Wing top", c, "xwing"), ("îlots, multi-recipient", c, "mkem")]
        for name, height, mode in rows:
            send0, fetch0 = lone_entrant(h, height, False, None)
            send1, fetch1 = lone_entrant(h, height, True, mode)
            print(f"   {'2^' + str(h):>8} {name:>20} {human(send0):>18} {human(fetch0):>9}"
                  f" {human(send1):>23} {human(fetch1):>9}")
    evidence = EXT_INIT + JOIN_RECORD + 2 * H * 32 + HEADER
    print(f"   each member, when it comes back, downloads about {human(evidence)} for that window: the external init,")
    print("   the entrant's request and admission, two registry proofs; with no removal, the top is not renewed")
    print()


def city_window(city_h, changed_ilots, seed=11):
    """Re-key of a binary city of height `city_h` over the îlot roots along
    the paths of the changed îlots (whose new roots the top does not know):
    the top's wraps and new keys, the mean wraps a member of a random îlot
    downloads to follow its city path, and the keys the top fetches (the
    children of re-keyed nodes that it does not re-key itself)."""
    rng = random.Random(seed)
    levels = mark_levels(city_h, list(changed_ilots))
    cost, _ = rekey_cost(city_h, city_h, levels, set())
    wraps = sum(v[1] for v in cost.values())
    nodes = sum(v[2] for v in cost.values())
    fetched = sum(1 for k in range(1, city_h + 1) for node in levels[k]
                  for child in (2 * node, 2 * node + 1) if k == 1 or child not in levels[k - 1])

    def chain_source(k, node):
        if k == 1:
            return None
        fresh = [x for x in (2 * node, 2 * node + 1) if x in levels[k - 1]]
        return fresh[0] if fresh else None

    total = 0
    for _ in range(SAMPLE):
        i = rng.randrange(1 << city_h)
        for k in range(1, city_h + 1):
            node = i >> k
            if node in levels[k] and chain_source(k, node) != (i >> (k - 1)):
                total += 1
    return wraps, nodes, total / SAMPLE, fetched


def changed_ilots(c, joins, removals, seed=11, h=H):
    rng = random.Random(seed)
    changed, _ = changed_leaves(1 << h, c, joins, removals, "paired", rng)
    return {leaf >> c for leaf in changed}


def city_top(c, city_h, rate, window, flat_share):
    """The top of one window with a maintained city: îlots changed, city
    wraps, city path, the upkeep, the upkeep with flat items to a share of
    the îlots when the window is dense, and the keys that costs to fetch."""
    joins, removals = changes(rate, window)
    changed = changed_ilots(c, joins, removals)
    wraps, nodes, path, fetched = city_window(city_h, changed)
    upkeep = wraps * WRAP + nodes * KEM_PK
    flat = round(flat_share * (1 << city_h)) if path > 1.5 else 0
    return len(changed), wraps, path, upkeep, upkeep + flat * WRAP, (fetched + flat) * KEM_PK


def report_city():
    c = 8
    city_h = H - c
    ilots = 1 << city_h
    print(f"9. A city maintained above the îlots (îlots of 2^{c}, a binary city of height {city_h})")
    print(f"   {'changes/s':>9} {'window':>7} {'îlots changed':>13} {'city wraps':>10} {'city path':>9}"
          f" {'upkeep':>9} {'+ flat, 10%':>11} {'keys read':>9} {'+ flat, all':>11} {'flat only':>9}")
    for rate in (0.1, 1.7, 12.0):
        for window in (60, 300):
            changed, wraps, path, upkeep, fallback, read = city_top(c, city_h, rate, window, 0.1)
            flat_all = city_top(c, city_h, rate, window, 1.0)[4]
            print(f"   {rate:>9} {window:>6}s {changed:>13} {wraps:>10} {path:>8.2f}w"
                  f" {human(upkeep):>9} {human(fallback):>11} {human(read):>9} {human(flat_all):>11}"
                  f" {human(ilots * WRAP):>9}")
    print("   (city path: wraps a relay, or a member with neither relay nor flat item, downloads per window;")
    print("   in dense windows, a path above 1.5 wraps, flat items go to the îlots with no relay, 10% of them")
    print("   here, or to all îlots, and then a relay reads one item; keys read: what the top fetches with")
    print(f"   flat items for 10%. A flat top only fetches {human(ilots * ILOT_PK)} of îlot keys in every window,")
    print(f"   sparse or dense, and sends {human(ilots * WRAP)} with X-Wing or"
          f" {human(MKEM_SHARED + ilots * MKEM_PART)} with the multi-recipient KEM, as in report 3)")
    rate = 1.0
    while city_top(c, city_h, rate + 0.5, 300, 0.1)[4] < ilots * WRAP:
        rate += 0.5
    print(f"   with windows of 5 minutes, the city with flat items for 10% costs less than a flat top up to"
          f" about {rate:g} changes/s; with windows of 60 s, at every rate above")
    wraps, nodes, _, _ = city_window(city_h, range(ilots))
    print(f"   switching from a flat top only to a maintained city rebuilds it whole: {wraps} wraps and {nodes} keys,"
          f" {human(wraps * WRAP + nodes * KEM_PK)}")
    path = city_top(c, city_h, 1.7, 300, 0.1)[2]
    duties = DAY / 300 * ilots / (1 << H)
    print(f"   at 1.7 changes/s and 5 minutes, a relay reads {human(path * WRAP)} a window; relaying spread"
          f" over the members is {duties:.1f} duty per member a day")
    for k in (1, 2):
        wraps, nodes, path, _ = city_window(city_h, random.Random(3).sample(range(ilots), k))
        print(f"   a sparse window changing {k} îlot{'s' if k > 1 else ''}: {wraps} city wraps"
              f" ({human(wraps * WRAP + nodes * KEM_PK)}), {path:.2f} wraps per member, no flat top")
    wraps, nodes, path, _ = city_window(city_h, random.Random(5).sample(range(ilots), 2))
    own = 2 * c * (WRAP + KEM_PK)
    send = own + wraps * WRAP + nodes * KEM_PK + HEADER + SIG + EXT_INIT
    fetch = 2 * c * KEM_PK + 2 * city_h * KEM_PK + CHECKPOINT + KEM_PK
    print(f"   nobody online, a joiner applies a waiting removal: sends {human(send)} and fetches {human(fetch)},"
          f" instead of 4.8 MB and 5.0 MB with a flat top only")
    print()


def report_day():
    import msg_sim
    import parity_sim
    rate, window = 1.7, 300
    joins, removals = changes(rate, window)
    r = ilot_window(8, joins, removals)
    windows = DAY / window
    relays = ilot_member_window(r, "relay") * windows
    flat = ilot_member_window(r, "mkem") * windows
    print(f"10. A member's day at the candidate profile (îlots of 2^8, windows of 5 minutes, {rate} changes/s,")
    print("    FN-DSA-512 cards, bursts of 2, encrypted sender data)")
    # A leaf whose hash keeps the leaf key apart, H(leaf key) in place of
    # the key: a reader fetches the card part of a sender's leaf only.
    card_part = parity_sim.LEAF - KEM_PK + 32
    print(f"   {'messages read':>13} {'messages':>9} {'senders':>9} {'with relays':>12} {'without':>9}"
          f" {'parity profile':>15} {'split leaf, relays':>18}")
    for read in (100, 1_000, 10_000):
        parity_following, messages, senders = parity_sim.member_day(read, rate, window)
        senders_day = min(read // 5 + 1, 20_000)  # as in parity_sim.member_day
        split = senders - senders_day * (parity_sim.LEAF - card_part)
        print(f"   {read:>13,} {human(messages):>9} {human(senders):>9} {human(relays + messages + senders):>12}"
              f" {human(flat + messages + senders):>9} {human(parity_following + messages + senders):>15}"
              f" {human(relays + messages + split):>18}")
    print(f"   (split leaf: a reader fetches {card_part:,} bytes of a sender's leaf instead of {parity_sim.LEAF:,})")
    card = msg_sim.SCHEMES["FN-DSA-512"][0]
    checkpoint = CHECKPOINT - SIG + card
    print(f"   checking the authorizer's checkpoint of every window adds {human(windows * checkpoint)} a day;"
          f" of every hour, {human(24 * checkpoint)}")
    # The member already has what the checkpoint signs: the header's hashes
    # and the tag it computes. It fetches the signature alone.
    uov_sig, uov_pk = msg_sim.SCHEMES["UOV-Is-pkc"][:2]
    print(f"   the signature alone, over what the member already has: FN-DSA-512 {human(windows * card)} a day,"
          f" UOV-Is-pkc {human(windows * uov_sig)} a day and its {human(uov_pk)} key once")
    print()


def main():
    print("Cost model of îlots under a flat top.")
    print()
    report_saturation()
    report_following()
    report_top()
    report_tasks()
    report_burst()
    report_repair_and_entry()
    report_larger()
    report_lone_entrant()
    report_city()
    report_day()


if __name__ == "__main__":
    main()
