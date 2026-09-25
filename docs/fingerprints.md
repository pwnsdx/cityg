# Fingerprints

Members can check out of band that they see the same group. The GUI shows
two 32-byte values in its inspector:

| Name | Value | Changes |
| --- | --- | --- |
| **Security code (transcript)** | `interim_transcript_hash_n` of the current epoch (`GroupSession::transcript_fingerprint`) | With every commit. |
| **Roster hash** | `roster_hash_n` (specs.md, section 7) | When a member joins, leaves, is removed, resyncs, or when admins change. |

## What they prove

The interim transcript hash of epoch `n` chains every commit of the group
since its genesis, with its signature and confirmation tag (specs.md,
section 8). Two members of the same epoch with the same security code have
accepted the same sequence of commits, hence they agree on:

* the members, their device keys, slots and generations, and the admins;
* the tree, and the epoch secrets (the GroupContext binds the transcript);
* the history: no commit was shown to one of them and hidden from the other.

The delivery service cannot make two members accept different histories
with equal codes without a collision of BLAKE3. It can still show members
different histories (a fork) and let each branch go on: comparing security
codes out of band is what detects it. A member on one branch of a fork also
rejects the commits of the other branch.

The roster hash alone proves agreement on the membership of the current
epoch, not on the history. It is useful to confirm that a join or a removal
reached everyone.

## Comparing

Compare codes of the **same epoch** (the inspector shows the epoch next to
them): after a commit, both sides must have processed it. The GUI groups the
hexadecimal value for reading; comparing the first 16 hexadecimal digits
(64 bits) catches an accidental difference, and 32 digits (128 bits) is the
level to use against an adversary who can try many histories. **Copy**
copies the full value.

## What they do not prove

* Who a member is: aliases are self-asserted. Compare a member's device key
  (**Copy my identity** on their side) with what you see in the roster.
* That a member is not an adversary: an admin that admits the adversary gives
  it membership.
* Anything about messages: message authenticity comes from the sender's
  signature (specs.md, section 11).
