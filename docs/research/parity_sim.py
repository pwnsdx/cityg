#!/usr/bin/env python3
"""Cost model of City-G at parity with MLS.

Companion of `parite-mls-2026-09-26.md`. At parity with MLS every member
holds a leaf in the tree and follows the group, as in profile city-g/v0.4;
the note adds a message plane framed as MLS PrivateMessages, joins
authorized by the service in batches, checkpoints signed by the authorizer
for every window, which members may check, and removals split into urgent
and ordinary ones. The
script prints, for a group of 2^20 members:

  1. what following the group costs a member per day, by churn and by the
     cadence of windows (the delay of an ordinary removal);
  2. a member's day: following, messages and senders' keys;
  3. a burst of 100,000 joins and 100,000 departures: commits, what each
     member downloads, what each joiner downloads, and the authorizations;
  4. coming back after an absence: replaying every window, or jumping;
  5. seeing every change of the membership (the membership log);
  6. who re-keys the tree: members, as in the profile, or servers that draw
     the secrets themselves, one or k of them each drawing a share
     (`rekey-serveur-2026-09-26.md`): what a member downloads, what the
     servers compute, and the tasks members do when they re-key.

Sizes in bytes, CPU in microseconds on one core (MSG_US and CPU_US of
docs/research/bench). It reuses rekey_sim.py (re-key of a window) and
msg_sim.py (messages and senders' keys).

Run: python3 docs/research/parity_sim.py
"""

import math

import msg_sim
from rekey_sim import (HEADER, KEM_PK, SIG, WRAP, commit_bytes, commit_cpu_us, human,
                       member_window_bytes, simulate)

H = 20
L = 12
DAY = 86_400
N = 1 << H

DEVICE_ID = 32
CARD_PK = msg_sim.SCHEMES["FN-DSA-512"][1]
LEAF = DEVICE_ID + KEM_PK + CARD_PK + 58    # device id, leaf key, card, since, admission, updated
LEVEL = 64                                  # a level of a leaf proof: content and sibling
SENDER_DATA = 4 + 16                        # reuse guard and AEAD tag of the encrypted sender data
CHECKPOINT = SIG + 300                      # epoch, interim hash, tree and registry hashes, tag
SEAL_LINK = 9_000                           # a seal proof, the sealer's leaf proof, the registry roots
WELCOME = 1120 + 48 + 100
CHANGE_RECORD = 48                          # kind, leaf, device id, card hash prefix
PROOF_STEP = 32
LEVEL_ONE_WRAP = 768 + 32 + 48             # ML-KEM-512 and X25519 ciphertexts, sealed secret

MLDSA_VERIFY_US = 259.7


def following_per_day(rate, window, seed=11):
    """Bytes a member downloads per day to follow every window."""
    d = max(1, round(rate * window))
    r = simulate(H, L, d - d // 2, d // 2, seed=seed)
    return member_window_bytes(r, H, False) * DAY / window, r["member_mean"]


def report_following():
    print(f"1. Following the group at parity, per member and per day (N = 2^{H})")
    print(f"   {'changes/s':>9} {'window':>7} {'ordinary removal delay':>22} {'wraps per window':>17} {'per day':>9}")
    for rate in (0.1, 1.7, 12.0):
        for window in (60, 300, 600):
            per_day, wraps = following_per_day(rate, window)
            print(f"   {rate:>9} {window:>6}s {'<= ' + str(window) + ' s':>22} {wraps:>17.1f} {human(per_day):>9}")
    urgent = 50
    extra, _ = following_per_day(0.001, 5)
    print(f"   an urgent removal adds one window of a few changes: {human(extra * 5 / DAY)};"
          f" {urgent} a day add {human(extra * 5 / DAY * urgent)}")
    for window in (5, 10):
        per_day, _ = following_per_day(1.7, window)
        print(f"   windows of {window} s, as when every removal closes one (v0.4: 5 s), 1.7 changes/s:"
              f" {human(per_day)} a day")
    for window in (60, 300):
        mldsa = DAY / window * CHECKPOINT
        fndsa = DAY / window * (CHECKPOINT - SIG + msg_sim.SCHEMES["FN-DSA-512"][0])
        print(f"   checking the authorizer's checkpoint of every {window:>3} s window: {human(mldsa)} a day"
              f" (ML-DSA-65), {human(fndsa)} (FN-DSA-512)")
    per_day, wraps = following_per_day(1.7, 300)
    level_one = per_day * (wraps * LEVEL_ONE_WRAP + HEADER) / (wraps * WRAP + HEADER)
    print(f"   level-I suite (ML-KEM-512 with X25519, {LEVEL_ONE_WRAP}-byte wraps), 1.7 changes/s,"
          f" 300 s: {human(level_one)} a day instead of {human(per_day)}")
    print()


def member_day(read, rate, window, sessions=10):
    following, _ = following_per_day(rate, window)
    senders_day = min(read // 5 + 1, 20_000)
    senders_session = read // sessions // 5 + 1
    messages = read * (msg_sim.per_message("FN-DSA-512", 2) + SENDER_DATA)
    senders = senders_day * LEAF + sessions * msg_sim.multiproof(senders_session, LEVEL)
    return following, messages, senders


def report_days():
    print(f"2. A member's day at parity ({1.7} changes/s; FN-DSA-512 cards, bursts of 2, encrypted sender data)")
    print(f"   {'messages read':>13} {'window':>7} {'following':>10} {'messages':>9} {'senders':>9} {'total':>9}"
          f" {'v0.4 port, 60 s':>16}")
    for read in (100, 1_000, 10_000):
        for window in (60, 300):
            following, messages, senders = member_day(read, 1.7, window)
            port = following_per_day(1.7, 60)[0] + read * msg_sim.baseline_message() + (
                min(read // 5 + 1, 20_000) * msg_sim.TREE_LEAF
                + 10 * msg_sim.multiproof(read // 10 // 5 + 1, LEVEL))
            print(f"   {read:>13,} {window:>6}s {human(following):>10} {human(messages):>9} {human(senders):>9}"
                  f" {human(following + messages + senders):>9} {human(port):>16}")
    print("   (v0.4 port: the same member with every message signed by its ML-DSA-65 device key)")
    print()


def joiner_entry(anchor):
    """Bytes a joiner downloads: welcome, entry (leaf proof, path parents,
    last steps), and its anchor."""
    entry = LEAF + H * LEVEL + H * (KEM_PK + 32) + H * WRAP
    return WELCOME + entry + anchor


def report_burst():
    joins = removals = 100_000
    print(f"3. A burst of {joins:,} joins and {removals:,} departures in one window, N = 2^{H}")
    r = simulate(H, L, joins, removals)
    total = r["total_wraps"] * WRAP + r["total_nodes"] * KEM_PK
    _, _, busiest_nodes = r["busiest"]
    print(f"   commits: {r['total_wraps']:,} wraps, {human(total)} in all; busiest district"
          f" {human(commit_bytes(r['busiest'][1], busiest_nodes))}")
    print(f"   each member: {r['member_mean']:.1f} wraps on average,"
          f" {human(member_window_bytes(r, H, False))} for this window")
    with_checkpoint = joiner_entry(CHECKPOINT)
    with_chain = joiner_entry(CHECKPOINT + 30 * SEAL_LINK)
    print(f"   each joiner: {human(with_checkpoint)} anchored on the authorizer's checkpoint of its window;"
          f" {human(with_chain)} with an hourly checkpoint and 30 seal links on average")
    print(f"   all joiners: {human(joins * with_checkpoint)} instead of {human(joins * with_chain)}")
    proof = math.ceil(math.log2(joins)) * PROOF_STEP
    print(f"   authorizations: one signature per join, {human(joins * SIG)} and"
          f" {joins * MLDSA_VERIFY_US / 1e6:.0f} s of verification for each checker;"
          f" batched, one signature and {proof} bytes of proof per join, {human(joins * proof + SIG)}")
    print()


def report_return():
    print("4. Coming back after an absence (1.7 changes/s)")
    jump = WELCOME + H * WRAP + LEAF + H * LEVEL + CHECKPOINT
    for window in (60, 300):
        per_day, _ = following_per_day(1.7, window)
        print(f"   windows of {window:>3} s: replaying costs {human(per_day)} per day away,"
              f" {human(7 * per_day)} for a week; it reads everything it missed")
    print(f"   jumping: {human(jump)}, whatever the absence; the epochs it missed stay unreadable")
    print()


def report_log():
    print("5. Seeing every change of the membership, per day (the membership log)")
    for rate in (0.1, 1.7, 12.0):
        print(f"   {rate:>4} changes/s: {human(rate * DAY * CHANGE_RECORD)}")
    print(f"   one member's roster proof: {H * PROOF_STEP} bytes")
    print()


def server_window_bytes(r, servers, sig):
    """Bytes a member downloads for one window when `servers` servers each
    re-key a tree of shares: from each, its wraps, a header, the server's
    signature of its commit and the proof that its wraps are in it."""
    return servers * (r["member_mean"] * WRAP + HEADER + sig + H * PROOF_STEP)


def report_who_rekeys():
    rate = 1.7
    fndsa = msg_sim.SCHEMES["FN-DSA-512"][0]
    print(f"6. Who re-keys the tree ({rate} changes/s, N = 2^{H})")
    print("   per member and per day; the servers sign with ML-DSA-65 (with FN-DSA-512)")
    print(f"   {'window':>7} {'members (profile)':>18} {'1 server':>18} {'2 servers':>18} {'3 servers':>18}")
    for window in (60, 300):
        d = max(1, round(rate * window))
        r = simulate(H, L, d - d // 2, d // 2, seed=11)
        windows = DAY / window
        members = member_window_bytes(r, H, False) * windows
        cells = []
        for k in (1, 2, 3):
            ml = server_window_bytes(r, k, SIG) * windows
            fn = server_window_bytes(r, k, fndsa) * windows
            cells.append(f"{human(ml) + ' (' + human(fn) + ')':>18}")
        print(f"   {window:>6}s {human(members):>18} " + " ".join(cells))
    tagged = []
    for window in (60, 300):
        d = max(1, round(rate * window))
        r = simulate(H, L, d - d // 2, d // 2, seed=11)
        per_day = member_window_bytes(r, H, False) * DAY / window
        tagged.append(f"{window} s: " + ", ".join(f"{human(k * per_day)} for k = {k}" for k in (1, 2, 3)))
    print("   when a member still computes the tag and seals the welcomes (A1, B1), members check the tag,")
    print("   not the servers' signatures: " + "; ".join(tagged))
    for window in (60, 300):
        d = max(1, round(rate * window))
        r = simulate(H, L, d - d // 2, d // 2, seed=11)
        cpu = commit_cpu_us(r["total_wraps"], r["total_nodes"])
        print(f"   server CPU, windows of {window:>3} s: {r['total_wraps']:,} wraps, {cpu / 1e6:.2f} s of one core"
              f" per window, {cpu * DAY / window / 1e6 / 3600:.2f} core-hours a day, per server")
    joins = removals = 100_000
    r = simulate(H, L, joins, removals)
    cpu = commit_cpu_us(r["total_wraps"], r["total_nodes"])
    print(f"   server CPU, a burst of {joins:,} joins and {removals:,} departures: {r['total_wraps']:,} wraps,"
          f" {cpu / 1e6:.0f} s of one core, {cpu / 1e6 / 32:.1f} s on 32 cores, per server")
    one_tree = joiner_entry(CHECKPOINT)
    two_trees = one_tree + (H * (KEM_PK + 32) + H * WRAP + WELCOME)
    print(f"   each joiner: {human(one_tree)} with one tree, {human(two_trees)} with two trees of shares")
    print("   tasks of the members when they re-key (the profile), per window:")
    for window in (60, 300):
        d = max(1, round(rate * window))
        r = simulate(H, L, d - d // 2, d // 2, seed=11)
        district_wraps = r["total_wraps"] - r["city"][1]
        district_nodes = r["total_nodes"] - r["city"][2]
        tasks = r["changed_districts"]
        mean_wraps = district_wraps / tasks
        mean_cpu = commit_cpu_us(district_wraps, district_nodes) / tasks
        mean_bytes = commit_bytes(district_wraps / tasks, district_nodes / tasks)
        city_cpu = commit_cpu_us(r["city"][1], r["city"][2])
        city_bytes = commit_bytes(r["city"][1], r["city"][2])
        print(f"     windows of {window:>3} s: {tasks} district tasks of {mean_wraps:.0f} wraps"
              f" ({mean_cpu / 1e3:.0f} ms, {human(mean_bytes)} sent), busiest {r['busiest'][1]} wraps;"
              f" the city's task, {r['city'][1]} wraps ({city_cpu / 1e3:.0f} ms, {human(city_bytes)});"
              f" {d // 2} welcomes")
    r = simulate(H, L, joins, removals)
    busiest_cpu = commit_cpu_us(r["busiest"][1], r["busiest"][2])
    print(f"     the burst: {r['changed_districts']} district tasks, the busiest {r['busiest'][1]:,} wraps"
          f" ({busiest_cpu / 1e6:.1f} s, {human(commit_bytes(r['busiest'][1], r['busiest'][2]))});"
          f" the city's task, {r['city'][1]} wraps")
    print()


def main():
    print("Cost model of City-G at parity with MLS.")
    print()
    report_following()
    report_days()
    report_burst()
    report_return()
    report_log()
    report_who_rekeys()


if __name__ == "__main__":
    main()
