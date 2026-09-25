# GUI user guide

`cityg-gui` is the desktop client of City-G (profile v0.3), built with GPUI.
It keeps one room per window session, follows the room's log, and runs the
member's protocol duties (committing leaves and joins, re-keying, erasing old
keys) in the background.

## Starting

```bash
cargo run -p cityg-api                            # a local delivery service
cargo run -p cityg-gui --features native-app      # the client
```

Linux needs the XCB and xkbcommon development packages
(`libxcb1-dev libxkbcommon-dev libxkbcommon-x11-dev`). To run two clients on
one machine, give each its own directory:

```bash
CITYG_GUI_CONFIG_DIR=/tmp/cityg-alice cargo run -p cityg-gui --features native-app
CITYG_GUI_CONFIG_DIR=/tmp/cityg-bob   cargo run -p cityg-gui --features native-app
```

## Creating a room

1. In **Join a City-G Room**, enter the **Server URL** (for example
   `http://127.0.0.1:8080`) and your alias.
2. Select **New room**, then **Create room**.

The client generates a device key, builds the genesis commit of a group
of up to 64 members whose identifier binds that key, and publishes it. You
are the room's first admin. The status line then says *Room created. Copy an invite link to bring
others in.*

## Inviting

Use **Copy Invite** (menu, or the invite action of the session view). The
link looks like

```text
cityg-invite:{"version":5,"server_url":"http://127.0.0.1:8080","room_id":"…","invite_seed":"…"}
```

It carries the server URL, the room identifier and an invite seed. You, as
an admin, have signed the matching invite, which the server honours for 7
days and 64 joins. **Anyone holding the link can join until then:** send it
over a channel you trust, to the people you mean to invite.

## Joining

1. Paste the whole link in **Invite link**; the form fills the server URL
   (*Invite imported. Choose your alias and join.*).
2. Choose an alias and select **Join room**.

The client signs its own admission with the invite key and records a join
request with the server. If a member is online, its next commit brings you
in together with everyone else waiting, and your client enters with the
welcome that commit left for it. If nobody commits within a second or two,
your client commits its own entry (and brings the others along): no other
member needs to be online.

## Chatting

Type in the composer and press Enter (or **Send Message**). A message is
encrypted with a key of your own chain in the current epoch and signed with
your device key. Received messages show the sender's alias and the
timestamp the sender signed; the sender's identity comes from the room's
tree, so a member cannot write in another member's name. **Toggle Ciphertext** shows
the envelopes as the server sees them.

## Members and admins

The **Members** panel lists the members of the current epoch, with a search
field. Admins see **Expel** next to other members: it signs a removal
proposal and commits it at once, re-keying the tree so the removed member
learns nothing of later epochs.

The **Room admins** panel lists admin identities (device public keys).
**Copy my identity** copies your device key; to grant admin rights to a
member, an admin pastes that member's key in the target field and selects
**Grant**. **Revoke** asks for confirmation (**Confirm revoke** /
**Cancel revoke**). If a commit leaves the room without admins, its author
becomes admin automatically. Admin rights stay with a member through a
resync or a key rotation, and end when it leaves.

## Leaving

**Leave room** signs a removal proposal for your own place in the room and
submits it (*Leave requested. The remaining members commit your removal.*).
The next member to run its maintenance commits it; your device never
authors the commit that removes it, which is what guarantees that it cannot
learn keys of later epochs. If you were the last member, the next device to
join commits your removal.

When another member removes you, the client says *This device is no longer
a member of the room. Join it again with a new invite.* and clears the
session.

## Keeping keys fresh

* **PCS refresh** re-keys your leaf and path in a new epoch right away
  (*Keys refreshed*). If the device's state was copied, the attacker loses
  access to the epochs that follow. If its device key may have been stolen,
  a refresh is not enough: leave the room (or have an admin remove the
  device) and join again from a new device key.
* The maintenance task (every 30 seconds by default) commits pending leave
  requests and join requests of other members, re-keys your leaf at least
  every 24 hours, and erases the message keys of earlier epochs 10 minutes
  after the next epoch starts.
* If the client cannot process a commit (for example after restoring an old
  backup), it reports a cover failure and re-enters its leaf: *This device
  could not follow a commit and re-entered the room with a new occupancy
  (resync).*

## Checking you see the same room

The inspector (**Toggle Inspector**) shows the **Security code
(transcript)**, the **Tree hash** and the **Registry hash**. Two members with
the same security code have the same history of commits, hence the same
members and keys.
Compare the first characters over another channel (voice, in person) when
you need assurance that nobody is interposed, and in particular right after
joining, with the member who invited you: a new member cannot check the
room's history by itself; see [fingerprints.md](fingerprints.md).

## Local files

The client keeps, in its configuration directory
(`CITYG_GUI_CONFIG_DIR`, or `<user config directory>/cityg`; **Show Config
Folder** opens it):

* the session file: the complete member state, including secrets, encrypted
  with a key file next to it or with a key derived from
  `CITYG_GUI_SESSION_PASSPHRASE` (use a long random passphrase: the
  derivation is not a password hash);
* the chat history of sent messages, encrypted the same way;
* alias bindings and the security log.

The session file is rewritten before a message leaves the device, so a
restart never reuses a message key. A damaged or foreign session file is
refused rather than loaded. **Reset session** deletes the local state
without leaving the room: other members still see this device until it is
removed.

## Messages you may see

| Message | Meaning | What to do |
| --- | --- | --- |
| *The room moved on* | Your commit lost the race for its epoch. | Nothing: the client syncs and retries. |
| *Room admin rights required* | The action needs an admin. | Ask an admin. |
| *Verification failed* | The server or a member rejected a signature or a transition. | Retry once; report it if it persists. |
| *Incompatible server* | The server does not serve the v0.3 API (it runs an earlier profile, or answers 410). | Use a City-G v0.3 server. |
| *Invalid invite link* | Not a version 5 `cityg-invite:` link. | Ask for a new link. |
| *Room not found* | Wrong server URL or room identifier. | Check the link. |
| *Rate limited* | A proxy in front of the server rate-limits. | Wait and retry. |

More in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
