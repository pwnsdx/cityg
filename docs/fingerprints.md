# Fingerprints

Members can check out of band that they see the same group. The GUI shows
three 32-byte values in its inspector:

| Name | Value | Changes |
| --- | --- | --- |
| **Security code (transcript)** | `interim_transcript_hash_n` of the current epoch (`GroupSession::transcript_fingerprint`) | With every commit. |
| **Tree hash** | `tree_hash_n` (specs.md, section 6.3) | With every commit, since each one re-keys its author's path. |
| **Registry hash** | `registry_hash_n` (specs.md, section 7) | When admins change or a member is removed. |

## What they prove

The interim transcript hash of epoch `n` chains every commit of the group
since its genesis, with its signatures and confirmation tag (specs.md,
section 8). Two members of the same epoch with the same security code have
accepted the same sequence of commits, hence they agree on:

* the members, their device keys and occupancies, and the admins;
* the tree, the registry and the epoch secrets (the GroupContext binds the
  transcript);
* the history: no commit was shown to one of them and hidden from the other.

The delivery service cannot make two members accept different histories
with equal codes without a collision of BLAKE3. It can still show members
different histories (a fork) and let each branch go on: comparing security
codes out of band is what detects it. A member on one branch of a fork also
rejects the commits of the other branch.

It is also how a new member makes sure it joined the real group. A joiner
checks the epoch it enters but cannot check the history before it, so a
delivery service could make it enter a fabricated view of the group, with a
member the service controls (specs.md, section 2.3). After joining, compare
the security code with the member who invited you, or another member you
know: equal codes mean you share their history.

This covers light members too. A light member cannot recompute the tree hash
of a commit (specs.md, section 14.6); if a delivery service colluding with a
member showed it a commit that full members reject, its security code would
differ from theirs from that epoch on.

The tree and registry hashes alone prove agreement on the state of the
current epoch, not on the history. The registry hash is useful to confirm
that an admin change or a removal reached everyone.

## Comparing

Compare codes of the **same epoch** (the inspector shows the epoch next to
them): after a commit, both sides must have processed it. The GUI groups the
hexadecimal value for reading; comparing the first 16 hexadecimal digits
(64 bits) catches an accidental difference, and 32 digits (128 bits) is the
level to use against an adversary who can try many histories. **Copy**
copies the full value.

## What they do not prove

* Who a member is: aliases are self-asserted. Compare a member's device key
  (**Copy my identity** on their side) with what you see in the member list.
* That a member is not an adversary: an admin that admits the adversary gives
  it membership.
* Anything about messages: message authenticity comes from the sender's
  signature (specs.md, section 11).
