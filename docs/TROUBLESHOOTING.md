# Troubleshooting

Problems you may meet with the v0.2 delivery service, the GUI and the
command-line tools, with their causes. API error codes are listed in
[api-reference.md](api-reference.md#errors).

## Server

**`configuration validation failed: ...` at startup.** A value is out of
range: every numeric `[server]` value must be positive and
`max_group_size` at most 1024. See [configuration.md](configuration.md).

**Rooms disappear after a restart.** No `state_path` is set: the log says
`no state path configured: rooms live in memory only`. Set
`CITYG_SERVER_STATE_PATH` to a durable directory.

**Two instances serve the same state path.** A room has a single writer;
two processes appending to the same journals diverge. Run one process per
state path, and shard by `gid` to scale out (see [deployment.md](deployment.md)).

**`500 internal` on writes.** The journal could not be written (disk full,
permissions). The request fails and the room is reloaded from storage on
its next request; fix the storage, then retry. Nothing that was answered
with a success is lost.

**`410 gone` from a Worker.** A v0.1.4 client called the removed `/v1` API.
v0.1.4 and v0.2 do not interoperate: update the client.

## Joining

**`Invalid invite link`.** Links of profile v0.2 start with `cityg-invite:`
and carry `"version":4`. Older links (v0.1.4) cannot be used; ask an admin
for a new one.

**`404 not_found` when joining.** The invite expired (7 days by default in
the GUI) or the server URL in the link is not the room's server. Ask for a
new link.

**`403` "a removed device cannot join again".** The joining device key
held an occupancy of this group that ended: device keys are good for one
membership. Join with a new device key (the GUI and the CLI create one for
every join).

**`403` or `422` when publishing the join commit.** The invite's admin is no
longer an admin, or the invite was revoked with its admin: every admission
must chain to a current admin (specs.md, section 10.2). Ask a current admin
for a new link.

**`413 payload_too_large` when joining.** The group is full (`n_max`
members) or the commit exceeds a limit.

**The join keeps failing with `409`.** Other members commit at the same
time; the client retries on the new epoch a few times. If it persists, the
group changes faster than the join can follow (for example a loop of
self-updates): retry later.

## Messaging

**`403 forbidden` on send.** This device has a recorded removal (it asked
to leave, or an admin proposed its removal), or it is no longer a member.

**`409 conflict` on send.** The envelope's generation was already used,
usually after restoring an old copy of the session: a restored device must
not resend with spent generations. Resync (rejoin its slot) to get fresh
keys.

**`422` on send.** The envelope belongs to an epoch that is no longer
active: the device missed commits. Sync first; the client does it and
retries.

**Messages from a member are rejected.** Receivers drop messages whose
signature does not verify with the sender's key in the roster, whose sender
is no longer a member, or that are replays. The GUI counts them under
*Rejected messages*; a steady count points at a buggy or malicious member.

**Older messages are missing after a long absence.** The server keeps
messages for `message_retention_secs` (7 days by default); messages that
expired before the device read them are gone. Commits last longer; if one
the device needs expired, it resyncs automatically.

## Membership and keys

**"This device could not follow a commit and re-entered its slot."** The
device could not process a commit: it lost state, restored an old backup, or
the commit's author did not cover it (a faulty or malicious member). It
signed a cover-failure report, which every member can see, and rejoined its
own slot with a Resync commit. A report naming the same author repeatedly
points at that author.

**A member does not leave.** A leave is a recorded proposal that another
member commits. If no other member is online, the proposal waits: the
leaving device can no longer send, and the next member to come online (or
the next joiner, if everyone left) commits it.

**"Room admin rights required".** Removing others, inviting, admitting and
changing admins need an admin. The last admin cannot be revoked.

**Two members see different security codes in the same epoch.** They do not
share the same history: the server showed them different commits (a fork),
or one of them processed a different commit. Do not trust the room until
you understand why; see [fingerprints.md](fingerprints.md).

## GUI

**The GUI does not start on Linux.** Install `libxcb1-dev`,
`libxkbcommon-dev` and `libxkbcommon-x11-dev`, and build with
`--features native-app`.

**Two GUI windows share a session.** Give each instance its own
`CITYG_GUI_CONFIG_DIR`.

**"failed to decrypt session payload" at startup.** The session file does
not decrypt with the local key file or passphrase (for example
`CITYG_GUI_SESSION_PASSPHRASE` changed, or the key file was lost). The GUI
refuses it rather than load it; restore the right key, or use **Reset
session** and join again with a new invite.

## Collecting information for a report

* The `x-request-id` response header of the failing request, and the server
  log lines of that request.
* The API error code and message (the GUI's **Copy Details**).
* The epoch and security code shown by the GUI inspector.
* Never include session files, key files or invite links: they hold secrets.
