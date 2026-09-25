# GUI user guide

`cityg-gui` is the desktop client of City-G (profile v0.2), built with GPUI.
It keeps one room per window session, follows the room's log, and runs the
member's protocol duties (committing leaves, re-keying, erasing old keys) in
the background.

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
whose identifier binds that key, and publishes it. You are the room's first
admin. The status line then says *Room created. Copy an invite link to bring
others in.*

## Inviting

Use **Copy Invite** (menu, or the invite action of the session view). The
link looks like

```text
cityg-invite:{"version":4,"server_url":"http://127.0.0.1:8080","room_id":"…","invite_seed":"…"}
```

It carries the server URL, the room identifier and an invite seed. You, as
an admin, have signed the matching invite, which the server stores until it
expires (7 days by default). **Anyone holding the link can join until then:**
send it over a channel you trust, to the people you mean to invite.

## Joining

1. Paste the whole link in **Invite link**; the form fills the server URL
   (*Invite imported. Choose your alias and join.*).
2. Choose an alias and select **Join room**.

The client signs its own admission with the invite key, checks the room's
GroupInfo against the public tree and roster, and publishes a join commit.
No other member needs to be online.

## Chatting

Type in the composer and press Enter (or **Send Message**). A message is
encrypted with a key of your own chain in the current epoch and signed with
your device key. Received messages show the sender's alias and the
timestamp the sender signed; the sender's identity comes from the roster, so
a member cannot write in another member's name. **Toggle Ciphertext** shows
the envelopes as the server sees them.

## Members and admins

The **Members** panel lists the roster of the current epoch, with a search
field. Admins see **Expel** next to other members: it signs a removal
proposal and commits it at once, re-keying the tree so the removed member
learns nothing of later epochs.

The **Room admins** panel lists admin identities (device public keys).
**Copy my identity** copies your device key; to grant admin rights to a
member, an admin pastes that member's key in the target field and selects
**Grant**. **Revoke** asks for confirmation (**Confirm revoke** /
**Cancel revoke**). The last admin cannot be revoked; if no admin remains,
the member in the lowest slot becomes admin automatically.

## Leaving

**Leave room** signs a removal proposal for your own slot and submits it
(*Leave requested. The remaining members commit your removal.*). The next
member to run its maintenance commits it; your device never authors the
commit that removes it, which is what guarantees that it cannot learn keys
of later epochs. If you were the last member, the room becomes vacant.

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
  requests of other members, re-keys your leaf at least every 24 hours, and
  erases the previous epoch's message keys 10 minutes after a new epoch
  starts.
* If the client cannot process a commit (for example after restoring an old
  backup), it reports a cover failure and re-enters its slot: *This device
  could not follow a commit and re-entered its slot (resync).*

## Checking you see the same room

The inspector (**Toggle Inspector**) shows the **Security code
(transcript)** and the **Roster hash**. Two members with the same security
code have the same history of commits, hence the same members and keys.
Compare the first characters over another channel (voice, in person) when
you need assurance that nobody is interposed; see
[fingerprints.md](fingerprints.md).

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
| *Outdated server* | The server runs the removed v0.1.4 API. | Use a City-G v0.2 server. |
| *Invalid invite link* | Not a version 4 `cityg-invite:` link. | Ask for a new link. |
| *Room not found* | Wrong server URL or room identifier. | Check the link. |
| *Rate limited* | A proxy in front of the server rate-limits. | Wait and retry. |

More in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
