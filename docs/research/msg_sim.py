#!/usr/bin/env python3
"""Cost model of the message plane of very large groups.

Companion of `plan-de-messages-2026-09-26.md`. It compares, for a reader of
a group of N members, a direct port of a classic message plane onto City-G
v0.4 (every member follows every window; every message is signed with the
sender's ML-DSA-65 device key, checked against its leaf) with the
techniques of the note:

  * sender cards: a compact message key per member, in a roster leaf, so
    that messages carry a compact signature (FN-DSA today; round-3
    candidates of NIST's additional signatures for reference);
  * burst chains: one signature covers every envelope a sender sent since
    its previous signature;
  * keepers and readers: only keepers hold the tree's keys; a reader gets
    the reader secrets of the epochs it missed in one key bundle from a
    keeper, checked against chained reader tags, instead of following every
    window;
  * the public chain of reader secrets: each seal carries the reader secret
    of its epoch encrypted under that of the previous epoch, so that a
    reader needs no member online, except after a break of the chain (a
    ban), when any online member serves it a bundle;
  * the sealed message log and admin checkpoints (their cost only).

The script prints:
  1. the bytes a reader downloads per message read, by signature scheme and
     burst size, and the CPU to check it;
  2. what a sender's key costs a reader: once, then at every session;
  3. what staying able to read costs per day: every window's packet, key
     bundles, or the public chain with its breaks;
  4. a reader's day, and the delivery service's egress;
  5. the re-key of a burst with every member in the tree, and with keepers
     only (through rekey_sim.py);
  6. the load of the members that serve bundles;
  7. history: coming back after a day or a week, aggregated signatures.

Sizes in bytes. CPU in microseconds on one core: MSG_US and CPU_US of a run
of docs/research/bench on the machine that wrote the note, and, for the
candidates the bench does not cover, the figures of their submitters
(PQShield's signature zoo, sqisign.org at 3 GHz).

Run: python3 docs/research/msg_sim.py
"""

import math

import rekey_sim
from rekey_sim import KEM_PK, SIG, WRAP, human, simulate

H = 20                      # 2^20 members
L = 12                      # districts of 2^12 leaves
DAY = 86_400
WINDOW = 60                 # seconds, a window per minute in a busy group
EPOCHS_PER_DAY = DAY // WINDOW
CHANGES_PER_S = 1.7         # every member updates once a week (research note, 4.5)
SESSIONS = 10               # a reader opens the app ten times a day

TEXT = 150                  # a typical text message
ENVELOPE = 48               # epoch, occupancy, generation, AEAD tag, framing
COMMITMENT = 32             # key commitment, for reports
LINK = 4                    # first generation a signature covers
HASH = 32

DEVICE_PK = 1952            # ML-DSA-65
TREE_LEAF = DEVICE_PK + KEM_PK + 58     # LeafNode: device key, leaf key, since, admission, updated
TREE_LEVEL = 64             # a level of a leaf proof: content of the ancestor and sibling hash
ROSTER_REST = 58            # since, card epoch, role, admission hash, framing
ROSTER_LEVEL = 32           # a level of a roster proof: the sibling hash

# name: (signature, public key, verification µs, status)
SCHEMES = {
    "ML-DSA-65": (SIG, DEVICE_PK, 259.7, "FIPS 204"),
    "FN-DSA-512": (666, 897, 23.0, "FIPS 206 draft"),
    "FN-DSA-1024": (1280, 1793, 42.1, "FIPS 206 draft"),
    "MAYO-2": (239, 2928, 11.3, "round-3 candidate"),
    "SQIsign-I": (200, 83, 4_000.0, "round-3 candidate"),
    "SQIsign-III": (306, 129, 10_500.0, "round-3 candidate"),
    "UOV-Is-pkc": (96, 66_576, 47.6, "round-3 candidate"),
}
CARD = "FN-DSA-512"         # the card of the reader's day (section 4)
BURST = 2                   # envelopes per signature in the reader's day

# Measured by docs/research/bench (MSG_US, CPU_US).
AEAD_US = 1.87
CHAIN_US = 8.14             # a sender's chain in a secret tree of 2^24 leaves
DERIVE_US = 0.36
ENCAPS_US = 213.5
DECAPS_US = 387.7
MLDSA_VERIFY_US = 259.7

XWING_CT = 1120
BUNDLE_FRAMING = 16 + 64    # AEAD tag, request reference, range
EPOCH_PUBLIC = 3 * HASH     # seal hash, confirmation tag, reader tag
EPOCH_SECRET = 32           # the epoch's reader secret
CHECKPOINT = SIG + 200      # an admin checkpoint: epoch, interim hash, registry roots
EPOCH_LINK = 32 + 16        # the epoch's reader secret under the previous one, AEAD tag
LINK_EPOCH = 2 * HASH + EPOCH_LINK      # seal hash, confirmation tag, link
KEEPER_HEIGHT = 14
KEEPER_PROOF = TREE_LEAF + KEEPER_HEIGHT * TREE_LEVEL
SIGNED_BUNDLE = SIG + KEEPER_PROOF      # option: the keeper signs, with its leaf proof
CHANGE_RECORD = 40          # a reader's join or departure in a seal: kind, leaf, digest


# ---------------------------------------------------------------- messages


def per_message(scheme, burst, text=TEXT):
    """Bytes per message read. Burst 1: every envelope is signed. Burst
    b >= 2: b - 1 envelopes go unsigned and a closing envelope carries the
    signature over the chain."""
    sig = SCHEMES[scheme][0]
    if burst == 1:
        return ENVELOPE + COMMITMENT + text + LINK + sig
    return ENVELOPE + COMMITMENT + text + (ENVELOPE + LINK + sig) / burst


def baseline_message(text=TEXT):
    return ENVELOPE + text + SIG


def verify_us(scheme, burst):
    return SCHEMES[scheme][2] / burst + AEAD_US


def seconds_us(us):
    if us >= 1e6:
        return f"{us / 1e6:.2f} s"
    return f"{us / 1000:.2f} ms" if us >= 1000 else f"{us:.0f} us"


# ---------------------------------------------------------------- senders


def multiproof(k, level):
    """Bytes of a proof of k random leaves among 2^H: the paths meet in the
    top log2(k) levels, and each path needs a sibling below."""
    if k <= 0:
        return 0
    return k * (H - int(math.log2(k))) * level


def baseline_sender_first():
    return TREE_LEAF + H * TREE_LEVEL


def card_leaf(scheme):
    return HASH + SCHEMES[scheme][1] + ROSTER_REST


def card_sender_first(scheme):
    return card_leaf(scheme) + H * ROSTER_LEVEL


# ---------------------------------------------------------------- following


def packets_per_day(rate=CHANGES_PER_S):
    d = max(1, round(rate * WINDOW))
    r = simulate(H, L, d - d // 2, d // 2, seed=11)
    return rekey_sim.member_window_bytes(r, H, False) * EPOCHS_PER_DAY


def bundle_bytes(epochs):
    return XWING_CT + BUNDLE_FRAMING + epochs * (EPOCH_PUBLIC + EPOCH_SECRET)


def bundles_per_day(sessions, checkpoints=True):
    per_session = XWING_CT + BUNDLE_FRAMING + (CHECKPOINT if checkpoints else 0)
    return sessions * per_session + EPOCHS_PER_DAY * (EPOCH_PUBLIC + EPOCH_SECRET)


def links_per_day(sessions, breaks, checkpoints=True):
    """The public chain: a link per epoch, except the epochs that break the
    chain, whose reader secrets come in bundles, at most one per session."""
    bundles = min(sessions, breaks)
    return ((EPOCHS_PER_DAY - breaks) * LINK_EPOCH + breaks * (EPOCH_PUBLIC + EPOCH_SECRET)
            + bundles * (XWING_CT + BUNDLE_FRAMING) + (sessions * CHECKPOINT if checkpoints else 0))


# ---------------------------------------------------------------- reports


def report_messages():
    print(f"1. Bytes a reader downloads per message read ({TEXT}-byte text)")
    print(f"   {'scheme':<12} {'status':<18} {'sig':>6} {'burst 1':>8} {'burst 2':>8}"
          f" {'burst 4':>8} {'vs today':>9} {'verify, burst 2':>16}")
    base = baseline_message()
    print(f"   {'today':<12} {'ML-DSA-65 each':<18} {SIG:>6} {base:>8.0f} {'':>8} {'':>8}"
          f" {'x1.0':>9} {seconds_us(verify_us('ML-DSA-65', 1)):>16}")
    for name, (sig, _, _, status) in SCHEMES.items():
        sizes = [per_message(name, b) for b in (1, 2, 4)]
        print(f"   {name:<12} {status:<18} {sig:>6} {sizes[0]:>8.0f} {sizes[1]:>8.0f}"
              f" {sizes[2]:>8.0f} {'x' + format(base / sizes[1], '.1f'):>9}"
              f" {seconds_us(verify_us(name, 2)):>16}")
    print(f"   (burst b: one signature per b envelopes, in a closing envelope; each envelope"
          f" carries a {COMMITMENT}-byte key commitment)")
    print()


def report_senders():
    print(f"2. What a sender's key costs a reader (N = 2^{H})")
    print(f"   {'':<44} {'first time':>10} {'each session: 1 sender':>23} {'20':>9} {'200':>9}")
    rows = [("today: device key and leaf key in the tree", baseline_sender_first(), TREE_LEVEL,
             TREE_LEAF)]
    for name in ("FN-DSA-512", "FN-DSA-1024", "SQIsign-III", "UOV-Is-pkc"):
        rows.append((f"sender card {name} in the roster", card_sender_first(name), ROSTER_LEVEL,
                     card_leaf(name)))
    for label, first, level, _ in rows:
        print(f"   {label:<44} {human(first):>10} {human(multiproof(1, level)):>23}"
              f" {human(multiproof(20, level)):>9} {human(multiproof(200, level)):>9}")
    print("   (each session the reader checks the senders it reads against the latest root:"
          " a cached leaf, a path per sender)")
    print()


def report_following():
    print(f"3. Staying able to read, per reader and per day (N = 2^{H}, a window per minute)")
    for rate in (0.1, 1.7, 12.0):
        print(f"   following every window, {rate:>4} changes/s            : {human(packets_per_day(rate))}")
    for sessions in (1, 10, 48):
        print(f"   key bundles and checkpoints, {sessions:>2} sessions a day  : {human(bundles_per_day(sessions))}")
    for label, breaks in (("a break a day,", 1), ("a break an hour,", 24)):
        bundles = min(SESSIONS, breaks)
        print(f"   public chain, {label:<16} {SESSIONS} sessions : {human(links_per_day(SESSIONS, breaks))}"
              f" ({bundles} bundle{'s' if bundles > 1 else ''} a day)")
    print(f"   one bundle: {human(XWING_CT + BUNDLE_FRAMING)} and {EPOCH_PUBLIC + EPOCH_SECRET} bytes per epoch"
          f" ({EPOCH_PUBLIC} public, {EPOCH_SECRET} secret); a checkpoint {human(CHECKPOINT)};"
          f" a bundle signed by its keeper, {human(SIGNED_BUNDLE)} more;"
          f" the public chain, {LINK_EPOCH} bytes per epoch")
    print()


def reader_day(read, sessions=SESSIONS):
    senders_day = min(read // 5 + 1, 20_000)
    senders_session = read // sessions // 5 + 1
    today = (packets_per_day() + read * baseline_message()
             + senders_day * TREE_LEAF + sessions * multiproof(senders_session, TREE_LEVEL))
    cards = (bundles_per_day(sessions) + read * per_message(CARD, BURST)
             + senders_day * card_leaf(CARD) + sessions * multiproof(senders_session, ROSTER_LEVEL))
    cpu_today = read * verify_us("ML-DSA-65", 1)
    cpu_cards = read * verify_us(CARD, BURST) + sessions * DECAPS_US
    return senders_day, today, cards, cpu_today, cpu_cards


def report_days():
    print(f"4. A reader's day ({SESSIONS} sessions), and the delivery service's egress for 2^{H} readers")
    print(f"   {'messages read':>13} {'senders':>8} {'today':>9} {'readers':>9} {'gain':>6}"
          f" {'CPU today':>10} {'CPU readers':>12} {'egress today':>13} {'egress readers':>15}")
    n = 1 << H
    for read in (100, 1_000, 10_000, 86_400):
        senders, today, cards, cpu_today, cpu_cards = reader_day(read)
        print(f"   {read:>13,} {senders:>8,} {human(today):>9} {human(cards):>9}"
              f" {'x' + format(today / cards, '.0f'):>6} {seconds_us(cpu_today):>10}"
              f" {seconds_us(cpu_cards):>12} {human(today * n):>13} {human(cards * n):>15}")
    print(f"   (readers: {CARD} cards, bursts of {BURST}, a bundle and a checkpoint per session;"
          f" senders: one for every five messages read, all new each day)")
    print()


def report_rekey():
    print(f"5. Re-key of a burst of 100,000 joins and 100,000 departures, N = 2^{H}")
    everyone = simulate(H, L, 100_000, 100_000)
    all_bytes = everyone["total_wraps"] * WRAP + everyone["total_nodes"] * KEM_PK
    print(f"   every member in the tree : {everyone['total_wraps']:,} wraps, {human(all_bytes)} of commits")
    for keepers_log in (14, 16):
        keepers = 1 << keepers_log
        share = keepers / (1 << H)
        churn = max(1, round(100_000 * share))
        r = simulate(keepers_log, min(L, keepers_log - 2), churn, churn)
        wraps = r["total_wraps"] * WRAP + r["total_nodes"] * KEM_PK
        records = (200_000 - 2 * churn) * CHANGE_RECORD
        print(f"   {keepers:,} keepers ({share:.1%}), the same share of the burst: {r['total_wraps']:,} wraps,"
              f" {human(wraps)}; reader changes {human(records)} of records, no wrap"
              f" (x{everyone['total_wraps'] / r['total_wraps']:.0f} fewer wraps)")
    print()


def report_keepers():
    print(f"6. Keepers' load: each reader asks for a bundle at each session (2^{H} readers)")
    per_request_us = MLDSA_VERIFY_US + H * DERIVE_US + ENCAPS_US + AEAD_US
    for keepers in (1 << 12, 1 << 14, 1 << 16):
        for sessions in (10, 48):
            requests = (1 << H) * sessions / keepers
            epochs = EPOCHS_PER_DAY / sessions
            served = requests * (XWING_CT + BUNDLE_FRAMING + epochs * EPOCH_SECRET)
            print(f"   {keepers:>6,} keepers, {sessions:>2} sessions a day: {requests:>9,.0f} requests a day each,"
                  f" {requests * per_request_us / 1e6:>5.1f} s of CPU, {human(served)} sent")
    print("   (a request: the reader's signature, its roster leaf, an encapsulation;"
          " the public part of a bundle comes from the delivery service)")
    online = (1 << H) // 10
    for breaks in (1, 24):
        requests = (1 << H) * min(SESSIONS, breaks)
        print(f"   public chain, {breaks:>2} break{'s' if breaks > 1 else ''} a day, any of the {online:,} members online"
              f" (10 %) serves: {requests / online:,.0f} requests a day each")
    print()


def report_history():
    print("7. History")
    for days in (1, 7):
        replay = packets_per_day() * days
        bundle = bundle_bytes(EPOCHS_PER_DAY * days) + CHECKPOINT
        print(f"   back after {days} day{'s' if days > 1 else ''}: replaying every window {human(replay)};"
              f" one bundle and a checkpoint {human(bundle)} (x{replay / bundle:.0f})")
    falcon = 10_000 * SCHEMES["FN-DSA-512"][0]
    print(f"   10,000 FN-DSA-512 signatures of a history: {human(falcon)} one by one;"
          f" about 74 KB aggregated with LaBRADOR (CRYPTO 2024)")
    per_seal = 8 + HASH
    print(f"   sealed message log: {per_seal} bytes per seal (count and root); inclusion of an envelope"
          f" among 10,000: {math.ceil(math.log2(10_000)) * HASH} bytes")
    print()


def main():
    print("Cost model of the message plane of very large groups.")
    print()
    report_messages()
    report_senders()
    report_following()
    report_days()
    report_rekey()
    report_keepers()
    report_history()


if __name__ == "__main__":
    main()
