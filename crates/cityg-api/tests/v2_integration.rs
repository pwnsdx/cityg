#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! End-to-end tests of the `/v2` delivery service over HTTP, driven by the
//! v2 member driver of `cityg-api-client`.

use std::net::SocketAddr;
use std::path::Path;

use cityg_api::v2_routes::{V2State, router};
use cityg_api_client::v2::cityg_core::identity::DeviceIdentity;
use cityg_api_client::v2::{DsClient, InviteLink, Member};
use cityg_runtime::v2::{NativeRoomStore, ServiceConfig};
use futures::StreamExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

struct Server {
    url: String,
    handle: JoinHandle<()>,
}

async fn start(store: NativeRoomStore) -> Server {
    let state = V2State::new(ServiceConfig::default(), store, 64);
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
    let link = alice.create_invite_link(&server.url, 60_000).await.unwrap();
    let parsed = InviteLink::parse(&link.encode()).unwrap().unwrap();
    let mut bob = join(&server, &parsed, 2).await;
    let mut carol = join(&server, &parsed, 3).await;
    bob.bind_alias("bob").await.unwrap();

    let report = alice.sync().await.unwrap();
    assert_eq!(report.commits.len(), 2);
    bob.sync().await.unwrap();
    assert_eq!(alice.session().epoch(), 2);
    assert_eq!(bob.session().epoch(), 2);
    assert_eq!(carol.session().epoch(), 2);

    let aliases = carol.aliases().await.unwrap();
    assert_eq!(
        aliases
            .get(alice.session().my_leaf_id())
            .map(String::as_str),
        Some("alice")
    );
    assert_eq!(
        aliases.get(bob.session().my_leaf_id()).map(String::as_str),
        Some("bob")
    );

    let sent = alice.send_text("hello everyone").await.unwrap();
    assert_eq!(sent.epoch, 2);
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
    assert!(!carol.leave().await.unwrap());
    let report = bob.sync().await.unwrap();
    assert_eq!(report.proposals.len(), 1);
    assert!(bob.commit_pending_removals().await.unwrap());
    assert!(!bob.commit_pending_removals().await.unwrap());
    let report = carol.sync().await.unwrap();
    assert!(report.removed);
    alice.sync().await.unwrap();
    assert_eq!(alice.session().roster().len(), 2);

    // Alice (admin) removes Bob in one commit.
    alice.remove_member(1).await.unwrap();
    assert!(bob.sync().await.unwrap().removed);
    assert_eq!(alice.session().roster().len(), 1);
    assert!(bob.send_text("still here?").await.is_err());
    server.handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_commits_retry_and_lost_state_resyncs() {
    let server = start(NativeRoomStore::for_state_path(None).unwrap()).await;
    let mut alice = Member::create(DsClient::new(&server.url).unwrap(), identity(11), 8)
        .await
        .unwrap();
    let link = alice.create_invite_link(&server.url, 60_000).await.unwrap();
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
    let bob_pk = bob.identity().public_key().to_vec();
    alice.set_admin(&bob_pk, true).await.unwrap();
    bob.sync().await.unwrap();
    assert!(bob.session().roster().is_admin(&bob_pk));
    let alice_pk = alice.identity().public_key().to_vec();
    bob.set_admin(&alice_pk, false).await.unwrap();
    alice.sync().await.unwrap();
    assert!(!alice.session().roster().is_admin(&alice_pk));
    assert!(alice.create_invite_link(&server.url, 1_000).await.is_err());
    server.handle.abort();
}

async fn restart_round(dir: &Path) {
    let server =
        start(NativeRoomStore::for_state_path(Some(&dir.join("state.journal"))).unwrap()).await;
    let mut alice = Member::create(DsClient::new(&server.url).unwrap(), identity(21), 4)
        .await
        .unwrap();
    let link = alice.create_invite_link(&server.url, 60_000).await.unwrap();
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
    let server =
        start(NativeRoomStore::for_state_path(Some(&dir.join("state.journal"))).unwrap()).await;
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
        "{}/v2/ws?gid={}&token={}",
        server.url.replace("http://", "ws://"),
        hex::encode(alice.gid()),
        "00".repeat(32)
    );
    assert!(tokio_tungstenite::connect_async(bad).await.is_err());
    server.handle.abort();
}
