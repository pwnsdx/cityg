#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cityg_core::admission::SignedAdmission;
use cityg_core::binding::AliasBinding;
use cityg_core::cover::CoverFailureReason;
use cityg_core::hash::Digest;
use cityg_core::identity::DeviceIdentity;
use cityg_core::ledger::ProposalStatus;
use cityg_core::session::{GroupSession, PublishedCommit};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use super::*;

struct Member {
    identity: DeviceIdentity,
    session: GroupSession,
}

struct Fixture {
    rng: ChaCha20Rng,
    room: Room,
    journal: Vec<RoomRecord>,
    alice: Member,
    bob: Member,
    now: u64,
}

fn gid_of(member: &Member) -> Digest {
    *member.session.gid()
}

fn fixture(config: RoomConfig) -> Fixture {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let alice_identity = DeviceIdentity::from_seed(&[1; 32]);
    let (pending, genesis) = GroupSession::create(&alice_identity, 8, &mut rng).unwrap();
    let (mut room, record) =
        Room::create(&genesis.commit, &genesis.group_info, 1_000, config).unwrap();
    let mut journal = vec![record];
    let alice = Member {
        identity: alice_identity,
        session: pending.into_session().unwrap(),
    };

    let bob_identity = DeviceIdentity::from_seed(&[2; 32]);
    let invite_seed = [9; 32];
    let invite = alice
        .session
        .create_invite(&alice.identity, &invite_seed, 100_000, &mut rng)
        .unwrap();
    let (_, record) = room.publish_invite(invite.encoded(), 1_000).unwrap();
    journal.push(record);
    let admission = SignedAdmission::with_invite(
        &bob_identity.leaf_id(&gid_of(&alice)).unwrap(),
        &invite,
        &invite_seed,
        &mut rng,
    )
    .unwrap();
    let info = room.info().unwrap();
    let (pending, join) =
        GroupSession::join(&bob_identity, &info.snapshot, &[], admission, &mut rng).unwrap();
    let (_, record) = room
        .publish_commit(&join.commit, &join.group_info, 1_000)
        .unwrap();
    journal.push(record);
    let bob = Member {
        identity: bob_identity,
        session: pending.into_session().unwrap(),
    };
    let mut fixture = Fixture {
        rng,
        room,
        journal,
        alice,
        bob,
        now: 1_000,
    };
    sync(&fixture.room, &mut fixture.alice);
    fixture
}

fn sync(room: &Room, member: &mut Member) {
    let page = room.log_after(0, usize::MAX);
    for entry in page.entries {
        if let LogBody::Commit { commit, group_info } = entry.body
            && entry.epoch == member.session.epoch() + 1
        {
            member
                .session
                .process_commit(&commit, Some(&group_info))
                .unwrap();
        }
    }
}

impl Fixture {
    fn send(&mut self, from_alice: bool, text: &[u8]) -> LogEntry {
        let member = if from_alice {
            &mut self.alice
        } else {
            &mut self.bob
        };
        let envelope = member
            .session
            .encrypt(&member.identity, 1, b"", text, self.now, &mut self.rng)
            .unwrap();
        let leaf = *member.session.my_leaf_id();
        let (entry, record) = self.room.send(&envelope, &leaf, self.now).unwrap();
        self.journal.push(record);
        entry
    }

    fn commit(&mut self, from_alice: bool) -> PublishedCommit {
        let member = if from_alice {
            &mut self.alice
        } else {
            &mut self.bob
        };
        let pending_removals: Vec<_> = self.room.ledger().pending_removals().cloned().collect();
        let (pending, published) = member
            .session
            .commit(&member.identity, &pending_removals, &[], &mut self.rng)
            .unwrap();
        let (_, record) = self
            .room
            .publish_commit(&published.commit, &published.group_info, self.now)
            .unwrap();
        self.journal.push(record);
        member.session.apply_own_commit(pending).unwrap();
        published
    }
}

#[test]
fn rooms_order_commits_and_messages() {
    let mut f = fixture(RoomConfig::default());
    assert_eq!(f.room.head_seq(), 2);
    let entry = f.send(true, b"hello");
    assert_eq!(entry.seq, 3);
    assert_eq!(entry.epoch, 1);
    let LogBody::Message { envelope, .. } = &entry.body else {
        panic!("message entry")
    };
    assert_eq!(f.bob.session.decrypt(envelope).unwrap().plaintext, b"hello");

    // A member cannot relay an envelope as another member.
    let forged = f
        .alice
        .session
        .encrypt(&f.alice.identity, 1, b"", b"x", f.now, &mut f.rng)
        .unwrap();
    let bob_leaf = *f.bob.session.my_leaf_id();
    assert!(matches!(
        f.room.send(&forged, &bob_leaf, f.now),
        Err(RoomError::Forbidden(_))
    ));

    f.commit(false);
    sync(&f.room, &mut f.alice);
    let page = f.room.log_after(3, 10);
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.head_seq, 4);
    assert_eq!(page.first_seq, 1);
    assert!(matches!(page.entries[0].body, LogBody::Commit { .. }));
    assert_eq!(f.room.log_after(0, 2).entries.len(), 2);
    assert_eq!(f.room.info().unwrap().epoch, 2);
    assert!(f.room.is_member(&bob_leaf));
    assert_eq!(f.room.gid(), f.alice.session.gid());
}

#[test]
fn journal_replay_and_snapshots_rebuild_the_same_room() {
    let mut f = fixture(RoomConfig::default());
    f.send(true, b"one");
    f.send(false, b"two");
    let binding = AliasBinding::sign(
        f.alice.session.gid(),
        "alice",
        &f.alice.identity,
        &mut f.rng,
    )
    .unwrap();
    f.journal
        .push(f.room.bind_alias(binding.encoded()).unwrap());
    let report = f
        .bob
        .session
        .report_cover_failure(
            &f.bob.identity,
            1,
            CoverFailureReason::StateLost,
            &mut f.rng,
        )
        .unwrap();
    f.journal
        .push(f.room.submit_cover_failure(report.encoded()).unwrap());
    f.commit(true);
    sync(&f.room, &mut f.bob);
    let leave = f
        .bob
        .session
        .propose_leave(&f.bob.identity, &mut f.rng)
        .unwrap();
    let (status, vacant, record) = f
        .room
        .submit_remove_proposal(leave.encoded(), f.now)
        .unwrap();
    assert_eq!(status, ProposalStatus::Recorded);
    assert!(!vacant);
    f.journal.push(record.unwrap());
    let (status, _, record) = f
        .room
        .submit_remove_proposal(leave.encoded(), f.now)
        .unwrap();
    assert_eq!(status, ProposalStatus::AlreadyRecorded);
    assert!(record.is_none());

    let replayed = Room::replay(&f.journal, RoomConfig::default()).unwrap();
    assert_eq!(
        replayed.to_snapshot().unwrap(),
        f.room.to_snapshot().unwrap()
    );
    let restored =
        Room::from_snapshot(&f.room.to_snapshot().unwrap(), RoomConfig::default()).unwrap();
    assert_eq!(
        restored.to_snapshot().unwrap(),
        f.room.to_snapshot().unwrap()
    );
    assert_eq!(restored.aliases(), vec![binding.encoded().to_vec()]);
    assert_eq!(restored.cover_failures().len(), 1);
    assert_eq!(restored.info().unwrap().pending_removals.len(), 1);

    // Records survive their encoding.
    let encoded: Vec<Vec<u8>> = f.journal.iter().map(|r| r.encode().unwrap()).collect();
    let stored = StoredRoom {
        snapshot: None,
        journal: encoded.clone(),
    };
    let from_store = restore_room(&stored, RoomConfig::default()).unwrap();
    assert_eq!(
        from_store.to_snapshot().unwrap(),
        f.room.to_snapshot().unwrap()
    );
    // Snapshot plus tail replay.
    let split = 3;
    let head = Room::replay(&f.journal[..split], RoomConfig::default()).unwrap();
    let stored = StoredRoom {
        snapshot: Some(head.to_snapshot().unwrap()),
        journal: encoded[split..].to_vec(),
    };
    let from_store = restore_room(&stored, RoomConfig::default()).unwrap();
    assert_eq!(
        from_store.to_snapshot().unwrap(),
        f.room.to_snapshot().unwrap()
    );

    assert!(Room::replay(&[], RoomConfig::default()).is_err());
    assert!(Room::replay(&f.journal[1..], RoomConfig::default()).is_err());
    let mut double_genesis = f.room.clone();
    assert!(double_genesis.apply_record(&f.journal[0]).is_err());
    assert!(Room::from_snapshot(&[0x80], RoomConfig::default()).is_err());
}

#[test]
fn aliases_invites_and_limits() {
    let mut f = fixture(RoomConfig::default());
    let gid = gid_of(&f.alice);
    let stranger = DeviceIdentity::from_seed(&[3; 32]);
    let binding = AliasBinding::sign(&gid, "stranger", &stranger, &mut f.rng).unwrap();
    assert!(matches!(
        f.room.bind_alias(binding.encoded()),
        Err(RoomError::Forbidden(_))
    ));
    let other_group = AliasBinding::sign(&[0; 32], "alice", &f.alice.identity, &mut f.rng).unwrap();
    assert!(f.room.bind_alias(other_group.encoded()).is_err());
    let bob_alias = AliasBinding::sign(&gid, "bob", &f.bob.identity, &mut f.rng).unwrap();
    f.room.bind_alias(bob_alias.encoded()).unwrap();
    assert_eq!(f.room.aliases().len(), 1);

    let invite = f
        .alice
        .session
        .create_invite(&f.alice.identity, &[4; 32], 5_000, &mut f.rng)
        .unwrap();
    let (id, _) = f.room.publish_invite(invite.encoded(), f.now).unwrap();
    assert_eq!(f.room.invite(&id, f.now), Some(invite.encoded().to_vec()));
    assert_eq!(f.room.invite(&id, 6_000), None);
    assert_eq!(f.room.invite(&[0; 32], f.now), None);

    // Removed members lose their alias.
    let removal = f
        .alice
        .session
        .propose_removal(&f.alice.identity, 1, &mut f.rng)
        .unwrap();
    let (pending, published) = f
        .alice
        .session
        .commit(&f.alice.identity, &[removal], &[], &mut f.rng)
        .unwrap();
    f.room
        .publish_commit(&published.commit, &published.group_info, f.now)
        .unwrap();
    f.alice.session.apply_own_commit(pending).unwrap();
    assert!(f.room.aliases().is_empty());

    // Groups larger than the deployment allows are refused.
    let small = RoomConfig {
        max_n_max: 4,
        ..RoomConfig::default()
    };
    let (_, genesis) = GroupSession::create(&stranger, 8, &mut f.rng).unwrap();
    assert!(matches!(
        Room::create(&genesis.commit, &genesis.group_info, 0, small),
        Err(RoomError::Limit(_))
    ));
}

#[test]
fn retention_keeps_the_latest_commit() {
    let config = RoomConfig {
        message_retention_ms: 100,
        commit_retention_ms: 1_000,
        max_log_entries: 6,
        ..RoomConfig::default()
    };
    let mut f = fixture(config);
    for index in 0..5u8 {
        f.send(true, &[index]);
    }
    // The cap drops the oldest messages first.
    let page = f.room.log_after(0, usize::MAX);
    assert_eq!(page.entries.len(), 6);
    assert_eq!(
        page.entries
            .iter()
            .filter(|e| matches!(e.body, LogBody::Commit { .. }))
            .count(),
        2
    );
    f.now += 200;
    assert_eq!(f.room.prune(f.now), 4);
    f.now += 5_000;
    assert_eq!(f.room.prune(f.now), 1);
    let page = f.room.log_after(0, usize::MAX);
    assert_eq!(page.entries.len(), 1, "the latest commit stays");
    assert_eq!(page.first_seq, 2);
    assert_eq!(page.head_seq, 7);
}

fn store_round_trip<S: RoomStore>(store: &mut S, f: &Fixture) {
    let gid = gid_of(&f.alice);
    assert!(store.load(&gid).unwrap().is_none());
    for (index, record) in f.journal.iter().enumerate() {
        assert_eq!(
            store.append(&gid, &record.encode().unwrap()).unwrap(),
            index + 1
        );
    }
    let loaded = store.load(&gid).unwrap().unwrap();
    let room = restore_room(&loaded, RoomConfig::default()).unwrap();
    assert_eq!(room.to_snapshot().unwrap(), f.room.to_snapshot().unwrap());

    store.compact(&gid, &room.to_snapshot().unwrap()).unwrap();
    let loaded = store.load(&gid).unwrap().unwrap();
    assert!(loaded.journal.is_empty());
    let mut room = restore_room(&loaded, RoomConfig::default()).unwrap();
    assert_eq!(room.to_snapshot().unwrap(), f.room.to_snapshot().unwrap());

    // Records after a compaction start a new journal.
    let record = room
        .bind_alias(
            AliasBinding::sign(
                &gid,
                "alice",
                &f.alice.identity,
                &mut ChaCha20Rng::seed_from_u64(1),
            )
            .unwrap()
            .encoded(),
        )
        .unwrap();
    assert_eq!(store.append(&gid, &record.encode().unwrap()).unwrap(), 1);
    let restored =
        restore_room(&store.load(&gid).unwrap().unwrap(), RoomConfig::default()).unwrap();
    assert_eq!(restored.to_snapshot().unwrap(), room.to_snapshot().unwrap());
    assert_eq!(store.list().unwrap(), vec![gid]);
}

#[test]
fn memory_store_round_trips() {
    let f = fixture(RoomConfig::default());
    store_round_trip(&mut MemoryRoomStore::new(), &f);
}

#[test]
fn file_store_round_trips_and_survives_torn_writes() {
    let f = fixture(RoomConfig::default());
    let dir = tempfile::tempdir().unwrap();
    let mut store = FileRoomStore::new(dir.path()).unwrap();
    store_round_trip(&mut store, &f);

    // A second store instance reads the same state.
    let gid = gid_of(&f.alice);
    let reopened = FileRoomStore::new(dir.path()).unwrap();
    assert!(reopened.load(&gid).unwrap().is_some());

    // A torn final frame (crash during append) is ignored.
    let room_dir = dir.path().join("rooms-v2").join(
        gid.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let journal = std::fs::read_dir(&room_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("journal-"))
        })
        .unwrap();
    let before = std::fs::read(&journal).unwrap();
    let mut torn = before.clone();
    torn.extend_from_slice(&[0, 0, 1, 0, 42]);
    std::fs::write(&journal, torn).unwrap();
    let loaded = reopened.load(&gid).unwrap().unwrap();
    assert_eq!(loaded.journal.len(), 1);
    assert!(
        FileRoomStore::new(dir.path())
            .unwrap()
            .load(&[0; 32])
            .unwrap()
            .is_none()
    );
}
