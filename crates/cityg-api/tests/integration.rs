#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! End-to-end tests of the delivery service over HTTP, driven by the member
//! driver of `cityg-api-client`.

use std::net::SocketAddr;
use std::path::Path;

use cityg_api::routes::{ServiceState, router};
use cityg_api_client::cityg_core::identity::DeviceIdentity;
use cityg_api_client::{DsClient, InviteLink, LightMember, Member};
use cityg_runtime::{NativeRoomStore, ServiceConfig};
use cityg_server::RoomConfig;
use futures::StreamExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

struct Server {
    url: String,
    handle: JoinHandle<()>,
}

async fn start(store: NativeRoomStore) -> Server {
    start_with(ServiceConfig::default(), store).await
}

async fn start_with(config: ServiceConfig, store: NativeRoomStore) -> Server {
    let state = ServiceState::new(config, store, 64);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    Server {
        url: format!("http://{addr}"),
        handle,
    }
}

fn identity(seed: u8) -> DeviceIdentity {
    DeviceIdentity::from_seed(&[seed; 32])
}

async fn join(server: &Server, link: &InviteLink, seed: u8) -> Member {
    Member::join_with_invite(DsClient::new(&server.url).unwrap(), identity(seed), link)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_create_join_talk_leave_and_get_removed() {
    let server = start(NativeRoomStore::for_state_path(None).unwrap()).await;
    let mut alice = Member::create(DsClient::new(&server.url).unwrap(), identity(1), 8)
        .await
        .unwrap();
    alice.bind_alias("alice").await.unwrap();
    let link = alice
        .create_invite_link(&server.url, 60_000, 4)
        .await
        .unwrap();
    let parsed = InviteLink::parse(&link.encode()).unwrap().unwrap();
    // Bob and Carol join at the same time: one of them commits both
    // entries, in a single epoch.
    let (mut bob, mut carol) = tokio::join!(join(&server, &parsed, 2), join(&server, &parsed, 3));
    bob.bind_alias("bob").await.unwrap();

    let report = alice.sync().await.unwrap();
    assert_eq!(report.commits.len(), 1, "one commit for two joins");
    assert_eq!(report.join_requests.len(), 2);
    bob.sync().await.unwrap();
    carol.sync().await.unwrap();
    assert_eq!(alice.session().epoch(), 1);
    assert_eq!(bob.session().epoch(), 1);
    assert_eq!(carol.session().epoch(), 1);
    assert_eq!(
        alice.session().transcript_fingerprint(),
        carol.session().transcript_fingerprint()
    );

    let aliases = carol.aliases().await.unwrap();
    assert_eq!(
        aliases.get(&alice.session().me()).map(String::as_str),
        Some("alice")
    );
    assert_eq!(
        aliases.get(&bob.session().me()).map(String::as_str),
        Some("bob")
    );

    let sent = alice.send_text("hello everyone").await.unwrap();
    assert_eq!(sent.epoch, 1);
    let bob_report = bob.sync().await.unwrap();
    assert_eq!(bob_report.messages.len(), 1);
    assert_eq!(bob_report.messages[0].plaintext, b"hello everyone");
    assert_eq!(
        bob_report.messages[0].signed_timestamp_ms,
        sent.signed_timestamp_ms
    );
    let carol_report = carol.sync().await.unwrap();
    assert_eq!(carol_report.messages[0].plaintext, b"hello everyone");
    // Own messages are not reported back.
    assert!(alice.sync().await.unwrap().messages.is_empty());

    // Carol leaves; Bob commits the recorded proposal.
    carol.leave().await.unwrap();
    let report = bob.sync().await.unwrap();
    assert_eq!(report.proposals.len(), 1);
    // Carol can no longer commit: her own removal is recorded.
    assert!(!carol.commit_pending().await.unwrap());
    assert!(bob.commit_pending().await.unwrap());
    assert!(!bob.commit_pending().await.unwrap());
    let report = carol.sync().await.unwrap();
    assert!(report.removed);
    alice.sync().await.unwrap();
    assert_eq!(alice.session().tree().member_count(), 2);

    // Alice (admin) removes Bob in one commit.
    let bob_leaf = bob.session().my_leaf();
    alice.remove_member(bob_leaf).await.unwrap();
    assert!(bob.sync().await.unwrap().removed);
    assert_eq!(alice.session().tree().member_count(), 1);
    assert!(bob.send_text("still here?").await.is_err());
    server.handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn online_members_commit_join_requests_in_batches() {
    let server = start(NativeRoomStore::for_state_path(None).unwrap()).await;
    let mut alice = Member::create(DsClient::new(&server.url).unwrap(), identity(51), 16)
        .await
        .unwrap();
    let link = alice
        .create_invite_link(&server.url, 60_000, 8)
        .await
        .unwrap();
    // Three devices ask to join; Alice commits the recorded requests while
    // they wait for their welcomes.
    let joiners = async {
        tokio::join!(
            join(&server, &link, 52),
            join(&server, &link, 53),
            join(&server, &link, 54)
        )
    };
    let committer = async {
        let mut committed = 0;
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if alice.commit_pending().await.unwrap() {
                committed += 1;
            }
            if alice.session().tree().member_count() == 4 {
                break;
            }
        }
        committed
    };
    let ((mut bob, mut carol, mut dave), commits) = tokio::join!(joiners, committer);
    assert!(commits >= 1);
    assert!(
        alice.session().epoch() <= 3,
        "at most one commit per joiner"
    );
    for member in [&mut bob, &mut carol, &mut dave] {
        member.sync().await.unwrap();
        assert_eq!(member.session().epoch(), alice.session().epoch());
    }
    dave.send_text("from dave").await.unwrap();
    assert_eq!(
        alice.sync().await.unwrap().messages[0].plaintext,
        b"from dave"
    );
    assert_eq!(bob.sync().await.unwrap().messages.len(), 1);
    assert_eq!(carol.sync().await.unwrap().messages.len(), 1);

    // A revoked link admits nobody.
    assert_eq!(alice.revoke_invite(&link).await.unwrap(), 0);
    let refused =
        Member::join_with_invite(DsClient::new(&server.url).unwrap(), identity(55), &link).await;
    assert!(refused.is_err());
    server.handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_rotate_their_device_key() {
    let server = start(NativeRoomStore::for_state_path(None).unwrap()).await;
    let mut alice = Member::create(DsClient::new(&server.url).unwrap(), identity(61), 4)
        .await
        .unwrap();
    let link = alice
        .create_invite_link(&server.url, 60_000, 1)
        .await
        .unwrap();
    let mut bob = join(&server, &link, 62).await;
    alice.sync().await.unwrap();
    let before = bob.send_text("old key").await.unwrap();
    let occupancy = bob.session().me();
    let report = bob.rotate_device_key(identity(63)).await.unwrap();
    assert!(!report.removed);
    assert_eq!(bob.identity().public_key(), identity(63).public_key());
    assert_eq!(bob.session().me(), occupancy);
    let report = alice.sync().await.unwrap();
    assert_eq!(report.messages[0].plaintext, b"old key");
    assert_eq!(report.messages[0].epoch, before.epoch);
    assert_eq!(
        report.commits[0].rotated_device_pk.as_deref(),
        Some(identity(63).public_key())
    );
    bob.send_text("new key").await.unwrap();
    let report = alice.sync().await.unwrap();
    assert_eq!(
        report.messages[0].sender_device_pk,
        identity(63).public_key()
    );
    // The old key no longer opens a session.
    let exported = bob.export().unwrap();
    assert!(Member::restore(DsClient::new(&server.url).unwrap(), identity(62), &exported).is_err());
    server.handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_commits_retry_and_lost_state_resyncs() {
    let server = start(NativeRoomStore::for_state_path(None).unwrap()).await;
    let mut alice = Member::create(DsClient::new(&server.url).unwrap(), identity(11), 8)
        .await
        .unwrap();
    let link = alice
        .create_invite_link(&server.url, 60_000, 1)
        .await
        .unwrap();
    let mut bob = join(&server, &link, 12).await;
    alice.sync().await.unwrap();

    // Both commit from the same epoch: one wins, the other rebuilds.
    let (first, second) = tokio::join!(alice.self_update(), bob.self_update());
    first.unwrap();
    second.unwrap();
    alice.sync().await.unwrap();
    bob.sync().await.unwrap();
    assert_eq!(alice.session().epoch(), 3);
    assert_eq!(
        alice.session().transcript_fingerprint(),
        bob.session().transcript_fingerprint()
    );

    // Bob loses his local state and re-enters his slot.
    let bob_identity = bob.identity().clone();
    drop(bob);
    let mut bob = Member::resync_from_scratch(
        DsClient::new(&server.url).unwrap(),
        bob_identity,
        &alice.gid(),
    )
    .await
    .unwrap();
    alice.sync().await.unwrap();
    assert_eq!(alice.session().epoch(), bob.session().epoch());
    bob.send_text("back again").await.unwrap();
    let report = alice.sync().await.unwrap();
    assert_eq!(report.messages[0].plaintext, b"back again");

    // Admin rights move by signed commits.
    alice
        .set_admin(bob.session().my_leaf(), true)
        .await
        .unwrap();
    bob.sync().await.unwrap();
    assert!(bob.session().is_admin());
    bob.set_admin(alice.session().my_leaf(), false)
        .await
        .unwrap();
    alice.sync().await.unwrap();
    assert!(!alice.session().is_admin());
    assert!(
        alice
            .create_invite_link(&server.url, 1_000, 1)
            .await
            .is_err()
    );
    assert!(alice.set_admin(9, true).await.is_err());
    server.handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_that_missed_pruned_commits_resyncs() {
    // A log of three entries: commits a member has not read are dropped.
    let config = ServiceConfig {
        room: RoomConfig {
            max_log_entries: 3,
            ..RoomConfig::default()
        },
        ..ServiceConfig::default()
    };
    let server = start_with(config, NativeRoomStore::for_state_path(None).unwrap()).await;
    let mut alice = Member::create(DsClient::new(&server.url).unwrap(), identity(21), 8)
        .await
        .unwrap();
    let link = alice
        .create_invite_link(&server.url, 60_000, 1)
        .await
        .unwrap();
    let mut bob = join(&server, &link, 22).await;
    alice.sync().await.unwrap();
    for _ in 0..4 {
        alice.self_update().await.unwrap();
    }
    assert_eq!(alice.session().epoch(), 5);
    assert_eq!(bob.session().epoch(), 1);

    // The oldest retained commit is not the next one Bob needs: he resyncs.
    let report = bob.sync().await.unwrap();
    assert!(report.resynced);
    assert!(!report.removed);
    assert_eq!(bob.session().epoch(), 6);
    alice.sync().await.unwrap();
    assert_eq!(
        alice.session().transcript_fingerprint(),
        bob.session().transcript_fingerprint()
    );
    bob.send_text("caught up").await.unwrap();
    let report = alice.sync().await.unwrap();
    assert_eq!(report.messages[0].plaintext, b"caught up");
    server.handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn light_members_follow_the_group_over_http() {
    let server = start(NativeRoomStore::for_state_path(None).unwrap()).await;
    let mut alice = Member::create(DsClient::new(&server.url).unwrap(), identity(61), 16)
        .await
        .unwrap();
    let link = alice
        .create_invite_link(&server.url, 60_000, 8)
        .await
        .unwrap();
    // Carol joins as a light member while Alice commits the recorded
    // requests: she enters with her welcome, without the public tree.
    let joiner =
        LightMember::join_with_invite(DsClient::new(&server.url).unwrap(), identity(62), &link);
    let committer = async {
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            alice.commit_pending().await.unwrap();
            if alice.session().tree().member_count() == 2 {
                break;
            }
        }
    };
    let (carol, ()) = tokio::join!(joiner, committer);
    let mut carol = carol.unwrap();
    assert_eq!(carol.session().member_count(), 2);
    assert_eq!(carol.session().epoch(), alice.session().epoch());
    assert!(format!("{carol:?}").contains("LightMember"));

    // Bob joins as a full member; Carol follows the commit with its proofs.
    let mut bob = join(&server, &link, 63).await;
    let report = carol.sync().await.unwrap();
    assert_eq!(report.commits.len(), 1);
    alice.sync().await.unwrap();
    assert_eq!(
        carol.session().transcript_fingerprint(),
        bob.session().transcript_fingerprint()
    );

    // Bob's key is proven when his first message arrives.
    bob.send_text("hello from bob").await.unwrap();
    let report = carol.sync().await.unwrap();
    assert_eq!(report.messages[0].plaintext, b"hello from bob");
    assert_eq!(carol.deferred_messages(), 0);
    carol.send_text("light hello").await.unwrap();
    let received = alice.sync().await.unwrap().messages;
    assert_eq!(received.len(), 2);
    assert_eq!(received[1].plaintext, b"light hello");
    bob.bind_alias("bob").await.unwrap();
    carol.bind_alias("carol").await.unwrap();
    let aliases = carol.aliases().await.unwrap();
    assert!(aliases.values().any(|alias| alias == "bob"));
    assert!(aliases.values().any(|alias| alias == "carol"));

    // To commit, Carol becomes full for a moment, then light again.
    let mut full = carol.upgrade().await.unwrap();
    full.self_update().await.unwrap();
    let mut carol = full.into_light().unwrap();
    assert_eq!(carol.session().epochs_since_own_update(), 0);
    alice.sync().await.unwrap();
    bob.sync().await.unwrap();
    assert_eq!(
        carol.session().transcript_fingerprint(),
        alice.session().transcript_fingerprint()
    );

    // The light state persists and resumes.
    let exported = carol.export().unwrap();
    let restored =
        LightMember::restore(DsClient::new(&server.url).unwrap(), identity(62), &exported).unwrap();
    assert_eq!(restored.session().epoch(), carol.session().epoch());
    assert_eq!(restored.log_seq(), carol.log_seq());
    assert!(
        LightMember::restore(DsClient::new(&server.url).unwrap(), identity(99), &exported).is_err()
    );
    carol.expire_previous_epochs().unwrap();

    // Alice removes Carol, who learns it from the next commit.
    alice
        .remove_member(carol.session().me().leaf)
        .await
        .unwrap();
    let report = carol.sync().await.unwrap();
    assert!(report.removed);
    let report = carol.sync().await.unwrap();
    assert!(report.removed, "a removed light member's token is refused");
    server.handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_light_member_that_missed_pruned_commits_resyncs() {
    let config = ServiceConfig {
        room: RoomConfig {
            max_log_entries: 3,
            ..RoomConfig::default()
        },
        ..ServiceConfig::default()
    };
    let server = start_with(config, NativeRoomStore::for_state_path(None).unwrap()).await;
    let mut alice = Member::create(DsClient::new(&server.url).unwrap(), identity(71), 8)
        .await
        .unwrap();
    let link = alice
        .create_invite_link(&server.url, 60_000, 1)
        .await
        .unwrap();
    let mut bob = join(&server, &link, 72).await.into_light().unwrap();
    alice.sync().await.unwrap();
    for _ in 0..4 {
        alice.self_update().await.unwrap();
    }
    let report = bob.sync().await.unwrap();
    assert!(report.resynced);
    assert!(!report.removed);
    alice.sync().await.unwrap();
    assert_eq!(
        alice.session().transcript_fingerprint(),
        bob.session().transcript_fingerprint()
    );
    bob.send_text("caught up").await.unwrap();
    assert_eq!(
        alice.sync().await.unwrap().messages[0].plaintext,
        b"caught up"
    );
    server.handle.abort();
}

async fn restart_round(dir: &Path) {
    let server = start(NativeRoomStore::for_state_path(Some(&dir.join("rooms"))).unwrap()).await;
    let mut alice = Member::create(DsClient::new(&server.url).unwrap(), identity(21), 4)
        .await
        .unwrap();
    let link = alice
        .create_invite_link(&server.url, 60_000, 1)
        .await
        .unwrap();
    let bob = join(&server, &link, 22).await;
    alice.sync().await.unwrap();
    for index in 0..300 {
        alice.send_text(&format!("message {index}")).await.unwrap();
    }
    let exported_alice = alice.export().unwrap();
    let exported_bob = bob.export().unwrap();
    server.handle.abort();
    drop(alice);
    drop(bob);

    // A new server process reads the rooms back from disk; the members
    // restore their exported state and carry on.
    let server = start(NativeRoomStore::for_state_path(Some(&dir.join("rooms"))).unwrap()).await;
    let mut bob = Member::restore(
        DsClient::new(&server.url).unwrap(),
        identity(22),
        &exported_bob,
    )
    .unwrap();
    let report = bob.sync().await.unwrap();
    assert_eq!(report.messages.len(), 300);
    assert_eq!(report.messages[299].plaintext, b"message 299");
    let mut alice = Member::restore(
        DsClient::new(&server.url).unwrap(),
        identity(21),
        &exported_alice,
    )
    .unwrap();
    alice.self_update().await.unwrap();
    bob.sync().await.unwrap();
    assert_eq!(bob.session().epoch(), alice.session().epoch());
    assert!(
        Member::restore(
            DsClient::new(&server.url).unwrap(),
            identity(23),
            &exported_bob
        )
        .is_err()
    );
    server.handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rooms_survive_a_server_restart() {
    let dir = tempfile::tempdir().unwrap();
    restart_round(dir.path()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_notifies_log_heads() {
    let server = start(NativeRoomStore::for_state_path(None).unwrap()).await;
    let mut alice = Member::create(DsClient::new(&server.url).unwrap(), identity(31), 4)
        .await
        .unwrap();
    let url = alice.websocket_url().await.unwrap();
    let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let mut next_text = async || loop {
        let frame = socket.next().await.unwrap().unwrap();
        if frame.is_text() {
            return frame.into_text().unwrap().to_string();
        }
    };
    let first = next_text().await;
    assert!(first.contains("\"head_seq\":1"), "{first}");
    let sent = alice.send_text("ping").await.unwrap();
    let notice = next_text().await;
    assert!(
        notice.contains(&format!("\"head_seq\":{}", sent.seq)),
        "{notice}"
    );

    // Bad subscriptions are refused.
    let bad = format!(
        "{}/v3/ws?gid={}&token={}",
        server.url.replace("http://", "ws://"),
        hex::encode(alice.gid()),
        "00".repeat(32)
    );
    assert!(tokio_tungstenite::connect_async(bad).await.is_err());
    server.handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_state_sink_makes_spent_generations_durable() {
    use std::sync::{Arc, Mutex};
    let server = start(NativeRoomStore::for_state_path(None).unwrap()).await;
    let mut alice = Member::create(DsClient::new(&server.url).unwrap(), identity(41), 4)
        .await
        .unwrap();
    let link = alice
        .create_invite_link(&server.url, 60_000, 1)
        .await
        .unwrap();
    let mut bob = join(&server, &link, 42).await;
    alice.sync().await.unwrap();

    let saved: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let sink_target = saved.clone();
    alice.set_state_sink(Arc::new(move |state: &[u8]| {
        *sink_target.lock().map_err(|_| "poisoned".to_string())? = state.to_vec();
        Ok(())
    }));
    alice.send_text("one").await.unwrap();
    // The device crashes right after sending: it restarts from what the sink
    // persisted, which already accounts for the spent generation.
    let state = saved.lock().unwrap().clone();
    drop(alice);
    let mut alice =
        Member::restore(DsClient::new(&server.url).unwrap(), identity(41), &state).unwrap();
    assert_eq!(alice.session().next_own_generation(), 1);
    alice.send_text("two").await.unwrap();
    let report = bob.sync().await.unwrap();
    let texts: Vec<_> = report
        .messages
        .iter()
        .map(|m| m.plaintext.clone())
        .collect();
    assert_eq!(texts, vec![b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(report.rejected, 0);

    // A failing sink stops the send before anything leaves the device.
    alice.set_state_sink(Arc::new(|_: &[u8]| Err("disk full".to_string())));
    assert!(alice.send_text("three").await.is_err());
    assert!(bob.sync().await.unwrap().messages.is_empty());
    server.handle.abort();
}

#[test]
fn members_wrap_only_their_own_sessions() {
    use cityg_api_client::cityg_core::session::GroupSession;
    let owner = identity(9);
    let (pending, _published) = GroupSession::create(&owner, 4, &mut rand_core::OsRng).unwrap();
    let session = pending.into_session().unwrap();
    let exported = session.export().unwrap();
    let client = DsClient::new("http://127.0.0.1:9").unwrap();

    let stranger = GroupSession::import(&exported).unwrap();
    assert!(Member::from_session(client.clone(), identity(10), stranger, 1).is_err());

    let member = Member::from_session(client.clone(), identity(9), session, 7).unwrap();
    assert_eq!(member.log_seq(), 7);
    let restored = Member::restore(client, identity(9), &member.export().unwrap()).unwrap();
    assert_eq!(restored.gid(), member.gid());
    assert_eq!(restored.log_seq(), 7);
}
