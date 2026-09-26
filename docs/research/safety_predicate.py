#!/usr/bin/env python3
"""The safety predicate of the proof sketch of `preuve-arbre-2026-09-26.md`.

The security game of that note asks the adversary to tell the message
secret of an epoch from random, for an epoch that is *safe*: no leak of
the game reaches the epoch in the graph of secrets. This script computes
that graph on traces: secrets are names, each mechanism of City-G adds a
rule saying what the adversary learns from what, and a leak gives it
secrets outright. The epoch is safe when its message secret stays out of
the closure.

  derive(y, x)         y := ExpandLabel(x, ...), DeriveSecret, a node key
                       pair, a relay key: x gives y
  extract(y, a, b)     y := Extract(a, b), a dual PRF: y needs a and b
  wrap(s, k)           s wrapped (X-Wing and AEAD) to the key pair derived
                       from k: k gives s
  welcome(j, i, l)     the joiner secret j sealed to the init key i, and for
                       a catch-up to the leaf key l too: j needs them all

Each trace mirrors a formal model, symbolic (ProVerif) or computational
(CryptoVerif), and the script checks that the predicate calls the epoch
safe exactly when the model proves its secret. It exits with status 1 if
one of them disagrees.

Run: python3 docs/research/safety_predicate.py
"""

import sys


class Trace:
    """What the adversary sees and holds: rules and leaks."""

    def __init__(self):
        self.rules = []
        self.leaked = set()

    def derive(self, out, source):
        self.rules.append((out, (source,)))

    def extract(self, out, salt, ikm):
        self.rules.append((out, (salt, ikm)))

    def wrap(self, secret, key_source):
        self.rules.append((secret, (key_source,)))

    def welcome(self, joiner, init_key, leaf_key=None):
        inputs = (init_key,) if leaf_key is None else (init_key, leaf_key)
        self.rules.append((joiner, inputs))

    def leak(self, *secrets):
        self.leaked.update(secrets)

    def epoch_secrets(self, n):
        """The secrets derived from the epoch secret of epoch n (section 9)."""
        for label in ("init", "msg", "confirm", "external"):
            self.derive(f"{label}{n}", f"epoch{n}")

    def window(self, n, init_prev, root):
        """The key schedule of the window that creates epoch n."""
        self.derive(f"commit{n}", root)
        self.extract(f"joiner{n}", init_prev, f"commit{n}")
        self.derive(f"epoch{n}", f"joiner{n}")
        self.epoch_secrets(n)

    def window_without_init(self, n, root):
        """A key schedule without the init chain (the rejected design)."""
        self.derive(f"commit{n}", root)
        self.derive(f"epoch{n}", f"commit{n}")
        self.epoch_secrets(n)

    def entrant_window(self, n, root):
        """A window an entrant seals: an external init, encapsulated to the
        external key of epoch n - 1, replaces init_{n-1}."""
        self.derive(f"external_init{n}", f"external{n - 1}")
        self.window(n, f"external_init{n}", root)

    def known(self):
        known = set(self.leaked)
        changed = True
        while changed:
            changed = False
            for out, inputs in self.rules:
                if out not in known and all(source in known for source in inputs):
                    known.add(out)
                    changed = True
        return known

    def safe(self, secret):
        return secret not in self.known()


# ---------- the profile (docs/formal/, and its computational counterparts) ----------

def taint(rule):
    """M, a malicious member of district 2, drew and kept the secret s1 of
    d1 when it committed district 1 in window 1; it knows everything of
    epoch 1. Window 2 removes it."""
    t = Trace()
    t.leak("leaf_M", "s1", "s2", "root1", "init1")
    t.wrap("t2", "leaf_C")
    if rule:
        t.wrap("t1", "leaf_A")
        t.wrap("t1", "leaf_B")
        d1 = "t1"
    else:
        d1 = "s1"
    t.wrap("root2", d1)
    t.wrap("root2", "t2")
    t.window(2, "init1", "root2")
    return t, "msg2"


def post_compromise(update):
    """The tree of taint(), M honest but leaked while it committed d1; in
    window 2 it updates to a leaf key the adversary does not get."""
    t = Trace()
    t.leak("leaf_M", "s1", "s2", "root1", "init1")
    t.wrap("t2", "leaf_C")
    t.wrap("t2", "leaf_M2" if update else "leaf_M")
    t.wrap("t1", "leaf_A")
    t.wrap("t1", "leaf_B")
    t.wrap("root2", "t1")
    t.wrap("root2", "t2")
    t.window(2, "init1", "root2")
    return t, "msg2"


def forward_secrecy(init_chain):
    """Windows 1 and 2 wrap their roots to A's leaf key, which A keeps; A's
    device then leaks its state of epoch 2, having erased epoch 1."""
    t = Trace()
    t.wrap("root1", "leaf_A")
    t.wrap("root2", "leaf_A")
    if init_chain:
        t.window(1, "init0", "root1")
        t.window(2, "init1", "root2")
    else:
        t.window_without_init(1, "root1")
        t.window_without_init(2, "root2")
    t.leak("leaf_A", "epoch2")
    return t, "msg1"


def join(secret):
    """J enters epoch 2 with a welcome to its one-time init key, then its
    whole state leaks: its leaf key, the joiner secret and epoch 2."""
    t = Trace()
    t.epoch_secrets(1)
    t.wrap("root2", "leaf_J")
    t.window(2, "init1", "root2")
    t.welcome("joiner2", "init_key_J")
    t.leak("leaf_J", "joiner2", "epoch2")
    return t, secret


def entrant_removal():
    """Nobody is online; M's removal waits and M knows epoch 1, the external
    key included. J seals window 2 as an entrant, re-keying M's path and its
    taints: the root goes to keys M does not know."""
    t = Trace()
    t.leak("epoch1", "leaf_M", "s1")
    t.epoch_secrets(1)
    t.wrap("t1", "leaf_A")
    t.wrap("root2", "t1")
    t.wrap("root2", "leaf_J")
    t.entrant_window(2, "root2")
    return t, "msg2"


def open_group():
    """An open group: the delivery service joins with a device of its own."""
    t = Trace()
    t.wrap("root2", "leaf_A")
    t.window(2, "init1", "root2")
    t.leak("init_key_DS")
    t.welcome("joiner2", "init_key_DS")
    return t, "msg2"


def catch_up(bound):
    """A thief holds M's device key, not its state, and has a catch-up of M
    welcomed with an init key of its own. Since this change, the welcome is
    sealed to M's leaf key too."""
    t = Trace()
    t.wrap("root2", "leaf_A")
    t.window(2, "init1", "root2")
    t.leak("init_key_thief")
    t.welcome("joiner2", "init_key_thief", "leaf_M" if bound else None)
    return t, "msg2"


def catch_up_after_stolen_update():
    """The same thief first signs an update of M to a leaf key of its own,
    then a catch-up: it reads the epoch, but M's leaf changed, so M can no
    longer follow and notices."""
    t = Trace()
    t.wrap("root2", "leaf_A")
    t.window(2, "init1", "root2")
    t.leak("init_key_thief", "leaf_thief")
    t.welcome("joiner2", "init_key_thief", "leaf_thief")
    return t, "msg2"


# ---------- the research models (formal-parity/, formal-computational/) ----------

def sticky_removal(collude):
    """M, removed by window 2, knows epoch 1 and a node that window 3 still
    wraps its root to. A second removed member may give the init secret of
    epoch 2, which it had as a member."""
    t = Trace()
    t.leak("epoch1", "node_N")
    t.epoch_secrets(1)
    t.wrap("root2", "leaf_A")
    t.window(2, "init1", "root2")
    t.wrap("root3", "node_N")
    t.window(3, "init2", "root3")
    if collude:
        t.leak("init2")
    return t, "msg3"


def lone_entrant(removal_waiting):
    """An entrant seals window 2 alone, with a commit secret that is a public
    constant; a member whose removal waits knows epoch 1."""
    t = Trace()
    t.leak("public_root")
    t.epoch_secrets(1)
    if removal_waiting:
        t.leak("epoch1")
    t.entrant_window(2, "public_root")
    return t, "msg2"


def weak_rng(hedged):
    """The committer's generator is broken: the adversary knows its output."""
    t = Trace()
    t.leak("r")
    if hedged:
        t.extract("fresh", "init_committer", "r")
    else:
        t.derive("fresh", "r")
    return t, "fresh"


def relay(root_known):
    """A relay item and a flat item carry the window secret of an îlot, under
    the relay key and to the X-Wing key of the îlot's root."""
    t = Trace()
    t.derive("relay_key", "root_i")
    t.wrap("r", "relay_key")
    t.wrap("r", "root_i")
    if root_known:
        t.leak("root_i")
    return t, "r"


def city(maintained, second_colludes):
    """The city above the îlots: node P above îlots k and j, node Q above
    îlot l. Window 2 removes M1 (îlot k), window 3 removes M2 (îlot l); the
    window secret goes flat to every îlot root, then through the city."""
    t = Trace()
    t.leak("root_k1", "P1", "epoch1")
    t.epoch_secrets(1)
    if second_colludes:
        t.leak("root_l1", "Q1")
    if maintained:
        t.wrap("P2", "root_k2")
        t.wrap("P2", "root_j")
    for root in ("root_k2", "root_j", "root_l1"):
        t.wrap("r2", root)
    t.window(2, "init1", "r2")
    if second_colludes:
        t.leak("epoch2")
    t.wrap("Q3", "root_l3")
    t.wrap("r3", "Q3")
    t.wrap("r3", "P2" if maintained else "P1")
    t.window(3, "init2", "r3")
    return t, "msg3"


def history_link_rejoin():
    """M, removed by window 2, joins again in window 3, whose history link
    carries the commit secret of epoch 2 under a key derived from epoch 3."""
    t = Trace()
    t.leak("epoch1")
    t.epoch_secrets(1)
    t.wrap("root2", "leaf_A")
    t.window(2, "init1", "root2")
    t.wrap("root3", "leaf_M_new")
    t.window(3, "init2", "root3")
    t.derive("history_key3", "commit3")
    t.wrap("commit2", "history_key3")
    t.leak("leaf_M_new")
    return t, "msg2"


# (name, trace builder, the models it mirrors, True if they prove the secret)
TRACES = [
    ("taint", lambda: taint(True), "docs/formal/taint.pv, taint.ocv", True),
    ("taint, without the rule", lambda: taint(False),
     "taint_without_rule.pv, taint_without_rule.ocv", False),
    ("post-compromise", lambda: post_compromise(True),
     "post_compromise.pv, post_compromise.ocv", True),
    ("post-compromise, no update", lambda: post_compromise(False),
     "post_compromise_without_update.ocv", False),
    ("forward secrecy", lambda: forward_secrecy(True),
     "forward_secrecy.pv, fs_stable_keys.ocv", True),
    ("forward secrecy, no init chain", lambda: forward_secrecy(False),
     "forward_secrecy_without_init.pv, fs_stable_keys_without_init.ocv", False),
    ("join, the epoch before", lambda: join("msg1"), "join.pv (first query)", True),
    ("join, the epoch entered", lambda: join("msg2"), "join.pv (sanity check)", False),
    ("entrant with a removal", entrant_removal, "entrant_removal.pv", True),
    ("open group", open_group, "open_group.pv (the service joins)", False),
    ("catch-up bound to the leaf", lambda: catch_up(True),
     "catch_up_stolen_key.pv, catch_up_leaf_bound.pv, catch_up_leaf_bound.ocv", True),
    ("catch-up, init key alone", lambda: catch_up(False),
     "catch_up_init_only.pv, catch_up_device_key.pv, catch_up_init_only.ocv", False),
    ("catch-up after a stolen update", catch_up_after_stolen_update,
     "preuves-et-mesures, table 3.4", False),
    ("sticky removal", lambda: sticky_removal(False), "sticky_removal.ocv", True),
    ("sticky removal, collusion", lambda: sticky_removal(True),
     "sticky_removal_collude.ocv", False),
    ("lone entrant", lambda: lone_entrant(False),
     "ilot_entrant_join.pv, entrant_window.ocv", True),
    ("lone entrant, removal waiting", lambda: lone_entrant(True),
     "ilot_entrant_removal_without_top.pv, entrant_window_removal_waiting.ocv", False),
    ("weak generator, hedged", lambda: weak_rng(True), "weak_rng.ocv", True),
    ("weak generator, unhedged", lambda: weak_rng(False), "weak_rng_unhedged.ocv", False),
    ("relay", lambda: relay(False), "ilot_relay.pv, relay.ocv", True),
    ("relay, root known", lambda: relay(True), "relay_known_root.ocv", False),
    ("city maintained", lambda: city(True, True),
     "ilot_city_maintained.pv, city_maintained.ocv", True),
    ("city stale", lambda: city(False, True), "ilot_city_stale.pv, city_stale.ocv", False),
    ("city stale, one removed", lambda: city(False, False),
     "ilot_city_sticky.pv, city_sticky.ocv", True),
    ("history link, rejoin", history_link_rejoin, "history_link_rejoin.pv", False),
]


def main():
    print("The safety predicate of the proof sketch, against the formal models")
    print(f"  {'trace':<32} {'secret':<7} {'predicate':<9} {'models':<9} agree")
    disagree = 0
    for name, build, models, proved in TRACES:
        trace, secret = build()
        safe = trace.safe(secret)
        agree = safe == proved
        disagree += not agree
        print(f"  {name:<32} {secret:<7} {'safe' if safe else 'exposed':<9}"
              f" {'proved' if proved else 'attack':<9} {'yes' if agree else 'NO'}   {models}")
    print(f"  {len(TRACES)} traces, {len(TRACES) - disagree} agree with their models")
    return 1 if disagree else 0


if __name__ == "__main__":
    sys.exit(main())
