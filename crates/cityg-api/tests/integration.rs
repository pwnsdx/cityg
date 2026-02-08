use std::time::Duration;

use anyhow::{Result, anyhow};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use cityg_api_client::{CitygApiClient, Error};
use cityg_client::{
    ClientEpochBundle,
    demo::{DEMO_GID, bootstrap_public, demo_bundle, kbroad_public, kbroad_secret},
};
use cityg_config::CityGConfig;
use reqwest::StatusCode;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::sleep;

async fn spawn_server_on(port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut config = CityGConfig::default();
        config.server.seed_demo_room = true;
        if let Err(err) = cityg_api::run_with_config(addr, config).await {
            eprintln!("server exited with error: {err}");
        }
    })
}

async fn spawn_server_with_seed_demo_room(port: u16, seed_demo_room: bool) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut config = CityGConfig::default();
        config.server.seed_demo_room = seed_demo_room;
        if let Err(err) = cityg_api::run_with_config(addr, config).await {
            eprintln!("server exited with error: {err}");
        }
    })
}

fn encode_field1_bytes(payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(payload.len() + 8);
    body.push(0x0A); // field #1, length-delimited bytes
    let mut n = payload.len() as u64;
    loop {
        let mut byte = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        body.push(byte);
        if n == 0 {
            break;
        }
    }
    body.extend_from_slice(payload);
    body
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn accept_epoch_rejects_oversized_body() {
    let port = 8122;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let body = vec![0u8; (2 * 1024 * 1024) + 1];
    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/v1/accept_epoch"))
        .body(body)
        .send()
        .await
        .expect("send oversized body");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    handle.abort();
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn end_to_end_demo_flow() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("error"))
        .try_init();

    let port = 8088;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));
    for _ in 0..10 {
        if client.health().await.is_ok() {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    let alice_bundle = demo_bundle("alice").expect("alice bundle");
    client
        .accept_epoch_bundle(&alice_bundle)
        .await
        .expect("accept alice");

    let bob_bundle = demo_bundle("bob").expect("bob bundle");
    let bob_accept = client
        .accept_epoch_bundle(&bob_bundle)
        .await
        .expect("accept bob");

    let members = client
        .members(DEMO_GID.as_ref(), None)
        .await
        .expect("members after bob");
    assert_eq!(members.members.len(), 2);

    let bundle_response = client
        .get_bundle(&bob_bundle.we_epoch_id)
        .await
        .expect("get bundle");
    let fetched_bundle =
        ClientEpochBundle::from_cbor(&bundle_response.bundle_cbor).expect("decode bundle");
    assert_eq!(
        fetched_bundle.hp_aead_key, [0u8; 32],
        "server bundle must not expose local hp key"
    );
    assert_eq!(
        fetched_bundle.epoch_key, [0u8; 32],
        "server bundle must not expose derived epoch key"
    );
    let (bob_epoch_key, _) = fetched_bundle
        .derive_epoch_secrets_with_kbroad_secret(kbroad_secret())
        .expect("epoch key");
    let cipher = ChaCha20Poly1305::new((&bob_epoch_key).into());
    let nonce = (&bob_bundle.we_epoch_id[..12]).into();
    let plaintext = b"secret hello";
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");

    client
        .send_message(&bob_bundle.we_epoch_id, &ciphertext, Some(b"alice"))
        .await
        .expect("send msg");

    let messages = client
        .fetch_messages(&bob_bundle.we_epoch_id)
        .await
        .expect("fetch");
    assert_eq!(messages.messages.len(), 1);

    let decrypted = cipher
        .decrypt(nonce, messages.messages[0].ciphertext.as_slice())
        .expect("decrypt");
    assert_eq!(decrypted.as_slice(), plaintext);

    let window = client.window().await.expect("window");
    assert!(
        window
            .entries
            .iter()
            .any(|entry| entry.wid == bob_accept.wid && !entry.heads.is_empty()),
        "window contains bob head"
    );

    drop(client);
    handle.abort();
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn window_limits_can_be_tuned() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("error"))
        .try_init();

    let port = 8089;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));
    client
        .configure_window(Some(3), Some(200))
        .await
        .expect("configure window");

    let effective = client
        .configure_window(None, None)
        .await
        .expect("read window config");
    assert_eq!(effective.h_max, 3);
    assert_eq!(effective.ttl_ms, 200);

    let alice_bundle = demo_bundle("alice").expect("alice bundle");
    let alice_accept = client
        .accept_epoch_bundle(&alice_bundle)
        .await
        .expect("accept alice");

    sleep(Duration::from_millis(250)).await;

    client
        .configure_window(None, Some(200))
        .await
        .expect("refresh window ttl");

    let bob_bundle = demo_bundle("bob").expect("bob bundle");
    client
        .accept_epoch_bundle(&bob_bundle)
        .await
        .expect("accept bob");

    let window = client.window().await.expect("window snapshot");
    let mut seen_alice = false;
    let mut total_heads = 0usize;
    for entry in &window.entries {
        total_heads += entry.heads.len();
        if entry
            .heads
            .iter()
            .any(|head| head.we_epoch_id == alice_accept.we_epoch_id)
        {
            seen_alice = true;
        }
    }
    assert!(total_heads >= 1, "expected at least one active head");
    assert!(
        !seen_alice,
        "alice head should have expired under custom ttl"
    );

    drop(client);
    handle.abort();
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn configure_window_rejects_invalid() -> Result<()> {
    let port = 8091;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));
    assert_bad_request(client.configure_window(Some(0), Some(10)).await)?;
    assert_bad_request(client.configure_window(None, Some(0)).await)?;
    assert_bad_request(client.configure_window(Some(2000), None).await)?;

    drop(client);
    handle.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn debug_seed_window_endpoint_handles_validation_paths() {
    let port = 8110;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let http = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");

    let response = http
        .post(format!("{base}/v1/debug/window/seed"))
        .body(encode_field1_bytes(&[]))
        .send()
        .await
        .expect("seed endpoint request");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = http
        .post(format!("{base}/v1/debug/window/seed"))
        .body(encode_field1_bytes(&[0x01, 0x02]))
        .send()
        .await
        .expect("seed endpoint invalid bundle request");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let valid_bundle = demo_bundle("alice").expect("demo bundle");
    let response = http
        .post(format!("{base}/v1/debug/window/seed"))
        .body(encode_field1_bytes(
            &valid_bundle.to_cbor().expect("bundle cbor"),
        ))
        .send()
        .await
        .expect("seed endpoint valid bundle request");
    assert_eq!(response.status(), StatusCode::OK);

    handle.abort();
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn refresh_pivot_endpoint_rejects_empty_and_invalid_payloads() {
    let port = 8111;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let http = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");

    let response = http
        .post(format!("{base}/v1/pivot/refresh"))
        .body(encode_field1_bytes(&[]))
        .send()
        .await
        .expect("refresh endpoint empty payload");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = http
        .post(format!("{base}/v1/pivot/refresh"))
        .body(encode_field1_bytes(&[0xFF]))
        .send()
        .await
        .expect("refresh endpoint malformed payload");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    handle.abort();
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn window_snapshot_reflects_heads() {
    let port = 8092;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));
    client
        .configure_window(None, Some(5_000))
        .await
        .expect("configure window");

    let alice = demo_bundle("alice").expect("alice bundle");
    client
        .accept_epoch_bundle(&alice)
        .await
        .expect("accept alice");
    let bob = demo_bundle("bob").expect("bob bundle");
    client.accept_epoch_bundle(&bob).await.expect("accept bob");

    let snapshot = client.window().await.expect("window snapshot");
    let total_heads: usize = snapshot.entries.iter().map(|entry| entry.heads.len()).sum();
    assert_eq!(total_heads, 2, "window should track two active heads");

    let telemetry = client.telemetry().await.expect("telemetry");
    assert!(
        !telemetry.entries.is_empty(),
        "telemetry should return at least one entry"
    );

    drop(client);
    handle.abort();
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn window_full_rest_api_freeze() -> Result<()> {
    let port = 8093;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));
    let alice = demo_bundle("alice").expect("alice bundle");
    client
        .accept_epoch_bundle(&alice)
        .await
        .expect("accept alice");

    client
        .configure_window(Some(1), Some(5_000))
        .await
        .expect("configure window");

    let bob = demo_bundle("bob").expect("bob bundle");
    client
        .debug_seed_window_head(&bob)
        .await
        .expect("seed window head");

    let (status, freeze_reason) = match client.accept_epoch_bundle(&bob).await {
        Err(Error::HttpStatus {
            status,
            freeze_reason,
            ..
        }) => (status, freeze_reason),
        other => return Err(anyhow!("expected window full error, got {:?}", other)),
    };
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(freeze_reason.as_deref(), Some("mh_window_full"));

    let telemetry = client.telemetry().await.expect("telemetry");
    assert!(
        telemetry
            .entries
            .iter()
            .any(|entry| entry.freeze_window_full >= 1),
        "telemetry should record window full freeze"
    );

    drop(client);
    handle.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn window_full_concurrent_freeze() -> Result<()> {
    let port = 8094;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let base_url = format!("http://127.0.0.1:{port}");
    let client = CitygApiClient::new(base_url.clone());

    let alice = demo_bundle("alice").expect("alice bundle");
    client
        .accept_epoch_bundle(&alice)
        .await
        .expect("accept alice");

    client
        .configure_window(Some(1), Some(5_000))
        .await
        .expect("configure window");

    let bob = demo_bundle("bob").expect("bob bundle");
    client
        .debug_seed_window_head(&bob)
        .await
        .expect("seed window head");

    let attempts = 3;
    let mut set = JoinSet::new();
    for _ in 0..attempts {
        let bundle = bob.clone();
        let url = base_url.clone();
        set.spawn(async move {
            let worker = CitygApiClient::new(url);
            worker.accept_epoch_bundle(&bundle).await
        });
    }

    let mut successes = 0usize;
    let mut window_full = 0usize;
    let mut parity_freeze = 0usize;
    while let Some(result) = set.join_next().await {
        match result {
            Ok(Ok(_)) => successes += 1,
            Ok(Err(Error::HttpStatus {
                status,
                freeze_reason,
                ..
            })) => {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                match freeze_reason.as_deref() {
                    Some("mh_window_full") => {
                        window_full += 1;
                    }
                    Some("msphf_rho_parity") => {
                        parity_freeze += 1;
                    }
                    other => {
                        return Err(anyhow!("unexpected freeze reason: {:?}", other));
                    }
                }
            }
            Ok(Err(other)) => return Err(anyhow!("unexpected error: {other:?}")),
            Err(join_err) => return Err(anyhow!("task panicked: {join_err}")),
        }
    }

    let freezes = window_full + parity_freeze;
    assert_eq!(successes + freezes, attempts);
    assert_eq!(successes, 0, "all requests should freeze with window full");
    assert_eq!(
        freezes, attempts,
        "expected every concurrent request to freeze"
    );
    assert!(
        window_full >= 1,
        "at least one response should surface the mh_window_full freeze"
    );

    let telemetry = client.telemetry().await.expect("telemetry");
    let recorded_freezes: u64 = telemetry
        .entries
        .iter()
        .map(|entry| entry.freeze_window_full + entry.freeze_rho_replay)
        .sum();
    assert!(
        recorded_freezes >= freezes as u64,
        "telemetry should record at least {freezes} freezes"
    );

    drop(client);
    handle.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn members_pagination() -> Result<()> {
    let port = 8095;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));
    let alice = demo_bundle("alice").expect("alice bundle");
    client
        .accept_epoch_bundle(&alice)
        .await
        .expect("accept alice");
    let bob = demo_bundle("bob").expect("bob bundle");
    client.accept_epoch_bundle(&bob).await.expect("accept bob");
    let carol = demo_bundle("carol").expect("carol bundle");
    client
        .accept_epoch_bundle(&carol)
        .await
        .expect("accept carol");

    let first_page = client
        .members_with_range(DEMO_GID.as_ref(), None, Some(0), Some(1))
        .await?;
    assert_eq!(first_page.members.len(), 1);
    assert_eq!(first_page.total_count, 3);
    assert_eq!(first_page.next_offset, 1);

    let second_page = client
        .members_with_range(
            DEMO_GID.as_ref(),
            None,
            Some(first_page.next_offset),
            Some(1),
        )
        .await?;
    assert_eq!(second_page.members.len(), 1);
    assert_eq!(second_page.total_count, 3);
    assert_eq!(second_page.next_offset, 2);

    let final_page = client
        .members_with_range(
            DEMO_GID.as_ref(),
            None,
            Some(second_page.next_offset),
            Some(2),
        )
        .await?;
    assert_eq!(final_page.members.len(), 1);
    assert_eq!(final_page.total_count, 3);
    assert_eq!(final_page.next_offset, 3);

    drop(client);
    handle.abort();
    Ok(())
}

fn assert_bad_request<T: std::fmt::Debug>(result: Result<T, Error>) -> Result<()> {
    match result {
        Err(Error::HttpStatus { status, .. }) if status == StatusCode::BAD_REQUEST => Ok(()),
        Err(other) => Err(anyhow!("expected bad request error, got {:?}", other)),
        Ok(_) => Err(anyhow!(
            "expected bad request error, got successful response"
        )),
    }
}

// ========== Error Handling Tests ==========

#[tokio::test]
#[allow(clippy::expect_used)]
async fn error_invalid_room_id_format() -> Result<()> {
    let port = 8096;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));

    // Test with invalid hex characters
    let result = client.join_ticket("invalid-room-id", "alice", None).await;
    assert_bad_request(result)?;

    // Test with wrong length (too short)
    let result = client.join_ticket("deadbeef", "alice", None).await;
    assert_bad_request(result)?;

    // Test with wrong length (too long)
    let too_long = "a".repeat(65);
    let result = client.join_ticket(&too_long, "alice", None).await;
    assert_bad_request(result)?;

    drop(client);
    handle.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn error_server_unavailable() -> Result<()> {
    // Create client pointing to non-existent server
    let client = CitygApiClient::new("http://127.0.0.1:9999");

    // Should fail with connection error
    let result = client.health().await;
    assert!(result.is_err(), "expected error when server unavailable");

    match result {
        Err(Error::Http(e)) if e.is_connect() || e.is_timeout() => Ok(()),
        Err(other) => Err(anyhow!("expected connection error, got {:?}", other)),
        Ok(_) => Err(anyhow!("expected error but got success")),
    }
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn error_invalid_bundle_data() -> Result<()> {
    let port = 8097;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));

    // Try to decode an invalid bundle response
    let alice = demo_bundle("alice").expect("alice bundle");
    client
        .accept_epoch_bundle(&alice)
        .await
        .expect("accept alice");

    // Fetch with wrong epoch ID (all zeros)
    let zero_epoch = [0u8; 32];
    let result = client.get_bundle(&zero_epoch).await;

    // Should get a not found or decode error
    assert!(
        result.is_err(),
        "expected error when fetching non-existent bundle"
    );

    drop(client);
    handle.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn join_ticket_omits_bootstrap_key_when_policy_disabled() -> Result<()> {
    let port = 8101;
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));
    let room_id = hex::encode([0x33u8; 32]);
    client.bootstrap_room(&room_id, kbroad_public()).await?;
    let ticket = client.join_ticket(&room_id, "alice", None).await?;
    assert!(
        ticket.bootstrap_public.is_empty(),
        "bootstrap key should be omitted when policy is disabled"
    );

    drop(client);
    handle.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn join_ticket_includes_bootstrap_key_when_policy_enabled() -> Result<()> {
    let port = 8102;
    let handle = spawn_server_with_seed_demo_room(port, true).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));
    let room_id = hex::encode([0x34u8; 32]);
    client.bootstrap_room(&room_id, kbroad_public()).await?;
    let ticket = client.join_ticket(&room_id, "alice", None).await?;
    assert_eq!(ticket.bootstrap_public, bootstrap_public());

    drop(client);
    handle.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn error_message_with_invalid_epoch() -> Result<()> {
    let port = 8098;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));

    // Send a message to non-existent epoch (should succeed - messages can be queued)
    let fake_epoch = [0xffu8; 32];
    let result = client
        .send_message(&fake_epoch, b"test message", Some(b"sender"))
        .await;

    // Should succeed - the API accepts messages for any epoch (offline queue support)
    assert!(
        result.is_ok(),
        "messages should be accepted even for non-existent epochs (offline queue)"
    );

    // Verify the message was stored
    let messages = client.fetch_messages(&fake_epoch).await?;
    assert_eq!(messages.messages.len(), 1, "message should be queued");

    drop(client);
    handle.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn error_members_with_invalid_gid() -> Result<()> {
    let port = 8099;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));

    // Query members with non-existent GID
    let fake_gid = [0xffu8; 32];
    let result = client.members(&fake_gid, None).await;

    // Should succeed but return empty list or error
    match result {
        Ok(response) => {
            assert_eq!(
                response.members.len(),
                0,
                "expected no members for non-existent GID"
            );
            Ok(())
        }
        Err(Error::HttpStatus { status, .. }) if status == StatusCode::NOT_FOUND => Ok(()),
        Err(other) => Err(anyhow!("unexpected error type: {:?}", other)),
    }?;

    drop(client);
    handle.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn error_recovery_graceful_degradation() -> Result<()> {
    let port = 8100;
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));

    // Accept a valid bundle
    let alice = demo_bundle("alice").expect("alice bundle");
    client
        .accept_epoch_bundle(&alice)
        .await
        .expect("accept alice");

    // Send a valid message
    let bundle_response = client
        .get_bundle(&alice.we_epoch_id)
        .await
        .expect("get bundle");
    let fetched_bundle =
        ClientEpochBundle::from_cbor(&bundle_response.bundle_cbor).expect("decode bundle");
    assert_eq!(
        fetched_bundle.hp_aead_key, [0u8; 32],
        "server bundle must not expose local hp key"
    );
    assert_eq!(
        fetched_bundle.epoch_key, [0u8; 32],
        "server bundle must not expose derived epoch key"
    );
    let (epoch_key, _) = fetched_bundle
        .derive_epoch_secrets_with_kbroad_secret(kbroad_secret())
        .expect("epoch key");

    let key_array: &[u8; 32] = epoch_key
        .as_slice()
        .try_into()
        .expect("epoch key is 32 bytes");
    let cipher = ChaCha20Poly1305::new(key_array.into());
    let nonce_array: &[u8; 12] = alice.we_epoch_id[..12]
        .try_into()
        .expect("nonce is 12 bytes");
    let nonce = nonce_array.into();
    let plaintext = b"test message";
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");

    client
        .send_message(&alice.we_epoch_id, &ciphertext, Some(b"alice"))
        .await
        .expect("send message");

    // Now kill the server
    handle.abort();
    // Wait longer for server to fully shutdown and connections to close
    sleep(Duration::from_millis(500)).await;

    // Create a new client to avoid connection pooling issues
    let new_client = CitygApiClient::new(format!("http://127.0.0.1:{port}"));

    // Subsequent operations should fail gracefully with proper errors
    let result = new_client.health().await;
    assert!(result.is_err(), "should fail after server shutdown");

    match result {
        Err(Error::Http(_)) => Ok(()),
        Err(other) => Err(anyhow!("expected HTTP error, got {:?}", other)),
        Ok(_) => Err(anyhow!("expected error after server shutdown")),
    }
}
