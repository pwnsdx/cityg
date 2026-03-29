use std::time::Duration;

use anyhow::{Result, anyhow};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use ciborium::value::Value;
use cityg_api_client::{
    CitygApiClient, Error, IdentityBinding, RoomAdminOperation, RoomAdminProof,
    build_room_admin_leaf_pair_proof, build_room_admin_listing_proof, build_room_admin_proof,
    build_room_admin_target_proof, generate_room_admin_keypair,
};
use cityg_client::{
    CityGClient, ClientEpochBundle,
    demo::{DEMO_GID, bootstrap_public, demo_bundle, demo_member_leaf, kbroad_public},
    witness::SrxInputsOwned,
};
use cityg_config::CityGConfig;
use msphf_orchestrator::{
    AnchorInstanceParts, DEFAULT_POLICY_VERSION, DEFAULT_PROOF_MODE, DEFAULT_VRF_ID,
    ForwardSecrecyState, FsJoinInputs, FsMergeInputs, LeafIdMode, OrchestrationParams, PopKeypair,
    compute_leaf_id, hdr,
};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use prost::Message as _;
use reqwest::StatusCode;
use serde_bytes::ByteBuf;
use std::sync::Once;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::sleep;

const TEST_ADMIN_TOKEN: &str = "integration-admin-token";
const TEST_MESSAGE_TOKEN: &str = "integration-message-token";

fn ensure_admin_auth_env() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        std::env::set_var("CITYG_SERVER_WINDOW_ADMIN_TOKEN", TEST_ADMIN_TOKEN);
        std::env::set_var("CITYG_SERVER_ROOMS_ADMIN_TOKEN", TEST_ADMIN_TOKEN);
        std::env::set_var("CITYG_SERVER_MESSAGE_AUTH_TOKEN", TEST_MESSAGE_TOKEN);
        std::env::remove_var("CITYG_SERVER_ALLOW_INSECURE_ADMIN");
    });
}

fn test_client(base_url: impl Into<String>) -> CitygApiClient {
    CitygApiClient::new(base_url)
        .with_admin_token(TEST_ADMIN_TOKEN)
        .with_message_auth_token(TEST_MESSAGE_TOKEN)
}

async fn bootstrap_room(
    client: &CitygApiClient,
    room_id: &str,
    kbroad_public: &[u8],
) -> Result<()> {
    let (pop_public_key, pop_secret_key) = generate_room_admin_keypair();
    let admin_proof = build_room_admin_proof(
        RoomAdminOperation::Bootstrap,
        room_id,
        kbroad_public,
        &pop_public_key,
        &pop_secret_key,
    )?;
    client
        .bootstrap_room_as_admin(room_id, kbroad_public, admin_proof)
        .await?;
    Ok(())
}

fn with_window_admin(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    builder.header("x-cityg-admin-token", TEST_ADMIN_TOKEN)
}

fn with_message_auth(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    builder.header("x-cityg-message-token", TEST_MESSAGE_TOKEN)
}

#[allow(clippy::expect_used)]
fn next_free_local_port() -> u16 {
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral test port")
        .local_addr()
        .expect("read ephemeral test port")
        .port()
}

async fn spawn_server_on(port: u16) -> JoinHandle<()> {
    ensure_admin_auth_env();
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
    ensure_admin_auth_env();
    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut config = CityGConfig::default();
        config.server.seed_demo_room = seed_demo_room;
        if let Err(err) = cityg_api::run_with_config(addr, config).await {
            eprintln!("server exited with error: {err}");
        }
    })
}

async fn spawn_server_on_with_state_path(
    port: u16,
    state_path: std::path::PathBuf,
) -> JoinHandle<()> {
    ensure_admin_auth_env();
    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut config = CityGConfig::default();
        config.server.seed_demo_room = true;
        config.server.state_path = Some(state_path);
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

#[derive(Clone, PartialEq, prost::Message)]
struct RawExpelMemberTicketRequest {
    #[prost(string, tag = "1")]
    room_id: String,
    #[prost(bytes = "vec", tag = "2")]
    author_leaf_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    target_leaf_id: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    admin_proof: Option<RoomAdminProof>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct RawRoomAdminMutationRequest {
    #[prost(string, tag = "1")]
    room_id: String,
    #[prost(bytes = "vec", tag = "2")]
    target_pop_public_key: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    admin_proof: Option<RoomAdminProof>,
}

struct JoinedMember {
    bundle: ClientEpochBundle,
}

fn array32(name: &str, bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("{name} must be 32 bytes"))
}

fn barrier_leaf_public_key() -> Vec<u8> {
    vec![0x42; 1_184]
}

fn demo_vrf_keys_for_seed(seed: u8) -> Result<(Vec<u8>, Vec<u8>)> {
    let params = msphf_orchestrator::lb::generate_parameters([seed; 32])?;
    let (sk, pk) = msphf_orchestrator::lb::generate_keypair(&params, [seed.wrapping_add(1); 32])?;
    Ok((sk, pk))
}

fn build_identity_binding(
    alias: &str,
    pop_public_key: &[u8],
    pop_secret_key: &dilithium5::SecretKey,
) -> Result<IdentityBinding> {
    let message_data = (
        ByteBuf::from(alias.as_bytes().to_vec()),
        ByteBuf::from(pop_public_key.to_vec()),
    );
    let mut message = Vec::new();
    ciborium::ser::into_writer(&message_data, &mut message)?;
    let signature = dilithium5::detached_sign(message.as_slice(), pop_secret_key);
    Ok(IdentityBinding {
        alias: alias.to_string(),
        pop_public_key: pop_public_key.to_vec(),
        signature: signature.as_bytes().to_vec(),
    })
}

async fn bootstrap_room_with_admin_identity(
    client: &CitygApiClient,
    room_id: &str,
    admin_pop_public_key: &[u8],
    admin_pop_secret_key: &dilithium5::SecretKey,
) -> Result<()> {
    let admin_proof = build_room_admin_proof(
        RoomAdminOperation::Bootstrap,
        room_id,
        kbroad_public(),
        admin_pop_public_key,
        admin_pop_secret_key.as_bytes(),
    )?;
    client
        .bootstrap_room_as_admin(room_id, kbroad_public(), admin_proof)
        .await?;
    Ok(())
}

async fn join_room_member(
    client: &CitygApiClient,
    room_id: &str,
    alias: &str,
    seed: u8,
) -> Result<JoinedMember> {
    let (pop_pk, pop_sk) = dilithium5::keypair();
    join_room_member_with_identity(
        client,
        room_id,
        alias,
        seed,
        pop_pk.as_bytes().to_vec(),
        pop_sk,
    )
    .await
}

async fn join_room_member_with_identity(
    client: &CitygApiClient,
    room_id: &str,
    alias: &str,
    seed: u8,
    pop_public_key: Vec<u8>,
    pop_sk: dilithium5::SecretKey,
) -> Result<JoinedMember> {
    let identity_binding = build_identity_binding(alias, &pop_public_key, &pop_sk)?;
    let ticket = client
        .join_ticket(room_id, alias, Some(identity_binding))
        .await?;
    let gid = array32("gid", &ticket.gid)?;
    let leaf_id = array32("leaf_id", &ticket.leaf_id)?;
    let expected_leaf_id = compute_leaf_id(
        LeafIdMode::PerGroup,
        &gid,
        "ML-DSA-65",
        pop_public_key.as_slice(),
    )?;
    assert_eq!(
        leaf_id, expected_leaf_id,
        "join ticket leaf_id must match identity binding"
    );

    let srx_inputs = SrxInputsOwned::from_cbor(&ticket.srx_cbor)?.into_srx_inputs();
    let (vrf_secret_key, vrf_public_key) = demo_vrf_keys_for_seed(seed)?;
    let mut fs_state = ForwardSecrecyState::new([seed.wrapping_add(1); 32]);
    let mut header = std::collections::BTreeMap::new();
    header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header.insert(
        hdr::HDR_KBROAD_PUB,
        Value::Bytes(ticket.kbroad_public.clone()),
    );
    header.insert(
        hdr::HDR_BARRIER_VERSION,
        Value::Integer(ciborium::value::Integer::from(ticket.barrier_version)),
    );
    header.insert(
        hdr::HDR_BARRIER_LEAF_PK,
        Value::Bytes(barrier_leaf_public_key()),
    );

    let parts = AnchorInstanceParts {
        gid: &gid,
        cat: &array32("cat", &ticket.cat)?,
        tswe_salt_hash: &array32("tswe_salt_hash", &ticket.tswe_salt_hash)?,
        parent_root: &array32("parent_root", &ticket.parent_root)?,
        join_delta_root: &array32("join_delta_root", &ticket.join_delta_root)?,
        revoked_since_prev_root: &array32("revoked_since_root", &ticket.revoked_since_root)?,
        revoked_root: &array32("revoked_root", &ticket.revoked_root)?,
        pox_r_commit: Some(&array32("pox_r_commit", &ticket.pox_r_commit)?),
    };

    let params = OrchestrationParams {
        msphf_crs_id: if ticket.msphf_crs_id.is_empty() {
            msphf_core::params::RLWE_CRS_ID_DEFAULT
        } else {
            ticket.msphf_crs_id.as_str()
        },
        params_id: if ticket.msphf_params_id.is_empty() {
            msphf_core::params::RLWE_PARAMS_ID_MOCK
        } else {
            ticket.msphf_params_id.as_str()
        },
        srx: Some(srx_inputs),
        srx_mode: msphf_orchestrator::SrxMode::Complete,
        pop_keys: Some(PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: pop_public_key.as_slice(),
            secret_key: &pop_sk,
        }),
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode: if ticket.proof_mode.is_empty() {
            DEFAULT_PROOF_MODE
        } else {
            ticket.proof_mode.as_str()
        },
        vrf_id: if ticket.vrf_id.is_empty() {
            DEFAULT_VRF_ID
        } else {
            ticket.vrf_id.as_str()
        },
        policy_version: if ticket.policy_version.is_empty() {
            DEFAULT_POLICY_VERSION
        } else {
            ticket.policy_version.as_str()
        },
        vrf_secret_key: Some(vrf_secret_key.as_slice()),
        vrf_public_key: Some(vrf_public_key.as_slice()),
        fs_policy_version: ticket.fs_policy_version.as_str(),
        fs_epoch_base_ts: ticket.fs_epoch_base_ts,
        barrier_version: ticket.barrier_version,
        fs_join: FsJoinInputs::default(),
        fs_merge: FsMergeInputs::default(),
    };

    let witness_bytes = if ticket.witness_cbor.is_empty() {
        None
    } else {
        Some(ticket.witness_cbor.as_slice())
    };

    let mut bundle =
        CityGClient::generate_epoch(header, parts, params, &mut fs_state, witness_bytes)?;
    if !ticket.bootstrap_public.is_empty() {
        assert_eq!(
            ticket.bootstrap_public,
            bootstrap_public(),
            "join ticket bootstrap key should match the demo bootstrap authority in tests"
        );
        cityg_client::demo::attach_bootstrap(&mut bundle)?;
    }

    Ok(JoinedMember { bundle })
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn accept_epoch_rejects_oversized_body() {
    let port = next_free_local_port();
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

    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    for _ in 0..10 {
        if client.health().await.is_ok() {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    let alice_bundle = demo_bundle("alice").expect("alice bundle");
    let alice_leaf = demo_member_leaf("alice");
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
    let bob_epoch_key = bob_bundle.epoch_key;
    let cipher = ChaCha20Poly1305::new((&bob_epoch_key).into());
    let nonce = (&bob_bundle.we_epoch_id[..12]).into();
    let plaintext = b"secret hello";
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");

    client
        .send_message(&bob_bundle.we_epoch_id, &ciphertext, Some(&alice_leaf))
        .await
        .expect("send msg");

    let messages = client
        .fetch_messages(&bob_bundle.we_epoch_id, &alice_leaf)
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
async fn restart_rehydrates_bundle_store_for_post_restart_bundle_fetch() {
    let temp_root = std::env::temp_dir().join(format!(
        "cityg-api-restart-bundles-{}-{}",
        std::process::id(),
        next_free_local_port()
    ));
    std::fs::create_dir_all(&temp_root).expect("create temp root");
    let journal_path = temp_root.join("bundle-restart.journal");
    let port = next_free_local_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let alice = demo_bundle("alice").expect("alice bundle");
    client
        .accept_epoch_bundle(&alice)
        .await
        .expect("accept alice");
    let bob = demo_bundle("bob").expect("bob bundle");
    client.accept_epoch_bundle(&bob).await.expect("accept bob");
    client
        .get_bundle(&bob.we_epoch_id)
        .await
        .expect("get bob bundle");

    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path).await;
    sleep(Duration::from_millis(250)).await;

    let after_restart = client
        .get_bundle(&bob.we_epoch_id)
        .await
        .expect("replayed bundle should remain fetchable after restart");
    let replayed_bundle =
        ClientEpochBundle::from_cbor(&after_restart.bundle_cbor).expect("decode replayed bundle");
    assert_eq!(replayed_bundle.we_epoch_id, bob.we_epoch_id);
    assert!(
        replayed_bundle
            .header_map
            .contains_key(&msphf_orchestrator::hdr::HDR_HP_BYTES),
        "replayed stored merge bundle should retain barrier hp envelope"
    );

    handle.abort();
    let _ = handle.await;
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn malformed_join_rejection_does_not_poison_restart_or_future_honest_joins() -> Result<()> {
    let temp_root = std::env::temp_dir().join(format!(
        "cityg-api-malformed-join-{}-{}",
        std::process::id(),
        next_free_local_port()
    ));
    std::fs::create_dir_all(&temp_root).expect("create temp root");
    let journal_path = temp_root.join("malformed-join.journal");
    let port = next_free_local_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let alice = demo_bundle("alice").expect("alice bundle");
    client
        .accept_epoch_bundle(&alice)
        .await
        .expect("accept alice");

    let mut malformed_bob = demo_bundle("bob").expect("bob bundle");
    malformed_bob
        .header_map
        .remove(&msphf_orchestrator::hdr::HDR_BARRIER_LEAF_PK);
    let malformed_err = client
        .accept_epoch_bundle(&malformed_bob)
        .await
        .expect_err("malformed join must fail");
    assert!(
        matches!(malformed_err, Error::HttpStatus { .. }),
        "malformed join should surface as an HTTP rejection"
    );

    let members_before_restart = client
        .members(DEMO_GID.as_ref(), None)
        .await
        .expect("members after malformed reject");
    assert_eq!(
        members_before_restart.members.len(),
        1,
        "rejected malformed join must not poison the live roster"
    );

    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path).await;
    sleep(Duration::from_millis(250)).await;

    let members_after_restart = client
        .members(DEMO_GID.as_ref(), None)
        .await
        .expect("members after restart");
    assert_eq!(
        members_after_restart.members.len(),
        1,
        "restart after malformed join must preserve the healthy roster"
    );

    let bob = demo_bundle("bob").expect("bob bundle");
    client
        .accept_epoch_bundle(&bob)
        .await
        .expect("honest bob join after malformed reject");

    let members_after_honest_join = client
        .members(DEMO_GID.as_ref(), None)
        .await
        .expect("members after honest bob");
    assert_eq!(
        members_after_honest_join.members.len(),
        2,
        "a later honest join must still succeed after restart"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn malformed_admin_expel_request_does_not_poison_restart_or_future_honest_joins() -> Result<()>
{
    let temp_root = std::env::temp_dir().join(format!(
        "cityg-api-malformed-admin-expel-{}-{}",
        std::process::id(),
        next_free_local_port()
    ));
    std::fs::create_dir_all(&temp_root).expect("create temp root");
    let journal_path = temp_root.join("malformed-admin-expel.journal");
    let room_id = hex::encode([0x35u8; 32]);
    let gid = hex::decode(&room_id)?;
    let port = next_free_local_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let (alice_pk, alice_sk) = dilithium5::keypair();
    bootstrap_room_with_admin_identity(&client, &room_id, alice_pk.as_bytes(), &alice_sk).await?;

    let author_leaf_id = [0xA1; 32];
    let target_leaf_id = [0xB2; 32];
    let admin_proof = build_room_admin_leaf_pair_proof(
        RoomAdminOperation::ExpelMember,
        &room_id,
        &author_leaf_id,
        &target_leaf_id,
        alice_pk.as_bytes(),
        alice_sk.as_bytes(),
    )?;
    let malformed_request = RawExpelMemberTicketRequest {
        room_id: room_id.clone(),
        author_leaf_id: author_leaf_id.to_vec(),
        target_leaf_id: target_leaf_id[..31].to_vec(),
        admin_proof: Some(admin_proof),
    };
    let response = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{port}/v1/rooms/expel_member_ticket"
        ))
        .header("content-type", "application/protobuf")
        .body(malformed_request.encode_to_vec())
        .send()
        .await
        .expect("send malformed expel request");
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "malformed admin expel request must fail closed"
    );

    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path).await;
    sleep(Duration::from_millis(250)).await;

    let charlie = join_room_member(&client, &room_id, "charlie", 0x93).await?;
    client
        .accept_epoch_bundle(&charlie.bundle)
        .await
        .expect("accept charlie after malformed admin expel restart");
    let members_after_honest_join = client.members(gid.as_slice(), None).await?;
    assert_eq!(
        members_after_honest_join.members.len(),
        1,
        "the room must remain joinable after malformed admin expel rejection and restart"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn malformed_admin_expel_request_concurrent_with_honest_join_survives_restart() -> Result<()>
{
    let temp_root = std::env::temp_dir().join(format!(
        "cityg-api-malformed-admin-expel-race-{}-{}",
        std::process::id(),
        next_free_local_port()
    ));
    std::fs::create_dir_all(&temp_root).expect("create temp root");
    let journal_path = temp_root.join("malformed-admin-expel-race.journal");
    let room_id = hex::encode([0x38u8; 32]);
    let gid = hex::decode(&room_id)?;
    let port = next_free_local_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let (alice_pk, alice_sk) = dilithium5::keypair();
    bootstrap_room_with_admin_identity(&client, &room_id, alice_pk.as_bytes(), &alice_sk).await?;

    let malformed_request = RawExpelMemberTicketRequest {
        room_id: room_id.clone(),
        author_leaf_id: [0xC1; 32].to_vec(),
        target_leaf_id: [0xD2; 31].to_vec(),
        admin_proof: Some(build_room_admin_leaf_pair_proof(
            RoomAdminOperation::ExpelMember,
            &room_id,
            &[0xC1; 32],
            &[0xD2; 32],
            alice_pk.as_bytes(),
            alice_sk.as_bytes(),
        )?),
    };
    let response = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{port}/v1/rooms/expel_member_ticket"
        ))
        .header("content-type", "application/protobuf")
        .body(malformed_request.encode_to_vec())
        .send()
        .await
        .expect("send malformed expel request");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let charlie = join_room_member(&client, &room_id, "charlie", 0x95).await?;
    client
        .accept_epoch_bundle(&charlie.bundle)
        .await
        .expect("accept charlie after malformed expel race");
    let members_before_restart = client.members(gid.as_slice(), None).await?;
    assert_eq!(
        members_before_restart.members.len(),
        1,
        "honest join must still succeed before restart after malformed expel race"
    );

    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path).await;
    sleep(Duration::from_millis(250)).await;

    let members_after_restart = client.members(gid.as_slice(), None).await?;
    assert_eq!(
        members_after_restart.members.len(),
        1,
        "restart must preserve the honest joined member after malformed expel race rejection"
    );
    let listed_admins = client
        .list_room_admins(
            &room_id,
            build_room_admin_listing_proof(&room_id, alice_pk.as_bytes(), alice_sk.as_bytes())?,
        )
        .await?;
    assert_eq!(
        listed_admins.admin_pop_public_keys,
        vec![alice_pk.as_bytes().to_vec()],
        "room-admin ACL must remain healthy after malformed expel race and restart"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn malformed_room_admin_mutation_requests_do_not_poison_acl_or_restart() -> Result<()> {
    let temp_root = std::env::temp_dir().join(format!(
        "cityg-api-malformed-admin-mutation-{}-{}",
        std::process::id(),
        next_free_local_port()
    ));
    std::fs::create_dir_all(&temp_root).expect("create temp root");
    let journal_path = temp_root.join("malformed-admin-mutation.journal");
    let room_id = hex::encode([0x36u8; 32]);
    let port = next_free_local_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let (creator_pk, creator_sk) = dilithium5::keypair();
    let (delegate_pk, _delegate_sk) = dilithium5::keypair();
    bootstrap_room_with_admin_identity(&client, &room_id, creator_pk.as_bytes(), &creator_sk)
        .await?;

    let malformed_grant = RawRoomAdminMutationRequest {
        room_id: room_id.clone(),
        target_pop_public_key: delegate_pk.as_bytes()[..47].to_vec(),
        admin_proof: Some(build_room_admin_target_proof(
            RoomAdminOperation::GrantAdmin,
            &room_id,
            &delegate_pk.as_bytes()[..47],
            creator_pk.as_bytes(),
            creator_sk.as_bytes(),
        )?),
    };
    let malformed_grant_response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/v1/rooms/grant_admin"))
        .header("content-type", "application/protobuf")
        .body(malformed_grant.encode_to_vec())
        .send()
        .await
        .expect("send malformed grant_admin request");
    assert_eq!(malformed_grant_response.status(), StatusCode::BAD_REQUEST);

    let listed_before_restart = client
        .list_room_admins(
            &room_id,
            build_room_admin_listing_proof(&room_id, creator_pk.as_bytes(), creator_sk.as_bytes())?,
        )
        .await?;
    assert_eq!(listed_before_restart.admin_pop_public_keys.len(), 1);

    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let granted = client
        .grant_room_admin(
            &room_id,
            delegate_pk.as_bytes(),
            build_room_admin_target_proof(
                RoomAdminOperation::GrantAdmin,
                &room_id,
                delegate_pk.as_bytes(),
                creator_pk.as_bytes(),
                creator_sk.as_bytes(),
            )?,
        )
        .await?;
    assert_eq!(granted.status, "granted");
    assert_eq!(granted.admin_count, 2);

    let malformed_revoke = RawRoomAdminMutationRequest {
        room_id: room_id.clone(),
        target_pop_public_key: delegate_pk.as_bytes()[..47].to_vec(),
        admin_proof: Some(build_room_admin_target_proof(
            RoomAdminOperation::RevokeAdmin,
            &room_id,
            &delegate_pk.as_bytes()[..47],
            creator_pk.as_bytes(),
            creator_sk.as_bytes(),
        )?),
    };
    let malformed_revoke_response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/v1/rooms/revoke_admin"))
        .header("content-type", "application/protobuf")
        .body(malformed_revoke.encode_to_vec())
        .send()
        .await
        .expect("send malformed revoke_admin request");
    assert_eq!(malformed_revoke_response.status(), StatusCode::BAD_REQUEST);

    let listed_after_bad_revoke = client
        .list_room_admins(
            &room_id,
            build_room_admin_listing_proof(&room_id, creator_pk.as_bytes(), creator_sk.as_bytes())?,
        )
        .await?;
    assert_eq!(listed_after_bad_revoke.admin_pop_public_keys.len(), 2);

    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path).await;
    sleep(Duration::from_millis(250)).await;

    let revoked = client
        .revoke_room_admin(
            &room_id,
            delegate_pk.as_bytes(),
            build_room_admin_target_proof(
                RoomAdminOperation::RevokeAdmin,
                &room_id,
                delegate_pk.as_bytes(),
                creator_pk.as_bytes(),
                creator_sk.as_bytes(),
            )?,
        )
        .await?;
    assert_eq!(revoked.status, "revoked");
    assert_eq!(revoked.admin_count, 1);

    let listed_final = client
        .list_room_admins(
            &room_id,
            build_room_admin_listing_proof(&room_id, creator_pk.as_bytes(), creator_sk.as_bytes())?,
        )
        .await?;
    assert_eq!(listed_final.admin_pop_public_keys.len(), 1);

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn replayed_room_admin_grant_proof_rejected_after_restart_without_poisoning_acl() -> Result<()>
{
    let temp_root = std::env::temp_dir().join(format!(
        "cityg-api-replayed-admin-grant-{}-{}",
        std::process::id(),
        next_free_local_port()
    ));
    std::fs::create_dir_all(&temp_root).expect("create temp root");
    let journal_path = temp_root.join("replayed-admin-grant.journal");
    let room_id = hex::encode([0x37u8; 32]);
    let port = next_free_local_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let (creator_pk, creator_sk) = dilithium5::keypair();
    let (delegate_pk, _delegate_sk) = dilithium5::keypair();
    bootstrap_room_with_admin_identity(&client, &room_id, creator_pk.as_bytes(), &creator_sk)
        .await?;

    let grant_proof = build_room_admin_target_proof(
        RoomAdminOperation::GrantAdmin,
        &room_id,
        delegate_pk.as_bytes(),
        creator_pk.as_bytes(),
        creator_sk.as_bytes(),
    )?;
    let granted = client
        .grant_room_admin(&room_id, delegate_pk.as_bytes(), grant_proof.clone())
        .await?;
    assert_eq!(granted.status, "granted");
    assert_eq!(granted.admin_count, 2);

    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path).await;
    sleep(Duration::from_millis(250)).await;

    let replay_err = client
        .grant_room_admin(&room_id, delegate_pk.as_bytes(), grant_proof)
        .await
        .expect_err("replayed room-admin proof must fail after restart");
    assert!(
        matches!(replay_err, Error::HttpStatus { .. }),
        "replayed room-admin proof should surface as an HTTP rejection: {replay_err:?}"
    );

    let listed_after_replay = client
        .list_room_admins(
            &room_id,
            build_room_admin_listing_proof(&room_id, creator_pk.as_bytes(), creator_sk.as_bytes())?,
        )
        .await?;
    assert_eq!(
        listed_after_replay.admin_pop_public_keys.len(),
        2,
        "replayed grant proof must not poison ACL state after restart"
    );

    let revoked = client
        .revoke_room_admin(
            &room_id,
            delegate_pk.as_bytes(),
            build_room_admin_target_proof(
                RoomAdminOperation::RevokeAdmin,
                &room_id,
                delegate_pk.as_bytes(),
                creator_pk.as_bytes(),
                creator_sk.as_bytes(),
            )?,
        )
        .await?;
    assert_eq!(revoked.status, "revoked");
    assert_eq!(revoked.admin_count, 1);

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn window_limits_can_be_tuned() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("error"))
        .try_init();

    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
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
    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
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
    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let http = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");

    let response = with_window_admin(http.post(format!("{base}/v1/debug/window/seed")))
        .body(encode_field1_bytes(&[]))
        .send()
        .await
        .expect("seed endpoint request");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = with_window_admin(http.post(format!("{base}/v1/debug/window/seed")))
        .body(encode_field1_bytes(&[0x01, 0x02]))
        .send()
        .await
        .expect("seed endpoint invalid bundle request");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let valid_bundle = demo_bundle("alice").expect("demo bundle");
    let response = with_window_admin(http.post(format!("{base}/v1/debug/window/seed")))
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
    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let http = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");

    let response = with_message_auth(http.post(format!("{base}/v1/pivot/refresh")))
        .body(encode_field1_bytes(&[]))
        .send()
        .await
        .expect("refresh endpoint empty payload");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = with_message_auth(http.post(format!("{base}/v1/pivot/refresh")))
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
    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
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
    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
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
    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let base_url = format!("http://127.0.0.1:{port}");
    let client = test_client(base_url.clone());

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
            let worker = test_client(url);
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
    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
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
    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));

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
    let client = test_client("http://127.0.0.1:9999");

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
    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));

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
    let port = next_free_local_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let room_id = hex::encode([0x33u8; 32]);
    bootstrap_room(&client, &room_id, kbroad_public()).await?;
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
    let port = next_free_local_port();
    let handle = spawn_server_with_seed_demo_room(port, true).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let room_id = hex::encode([0x34u8; 32]);
    bootstrap_room(&client, &room_id, kbroad_public()).await?;
    let ticket = client.join_ticket(&room_id, "alice", None).await?;
    assert_eq!(ticket.bootstrap_public, bootstrap_public());

    drop(client);
    handle.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn error_message_with_invalid_epoch() -> Result<()> {
    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let sender_leaf = demo_member_leaf("alice");

    // Send/fetch against non-existent epoch should be rejected.
    let fake_epoch = [0xffu8; 32];
    let result = client
        .send_message(&fake_epoch, b"test message", Some(&sender_leaf))
        .await;
    assert!(
        matches!(
            result,
            Err(Error::HttpStatus {
                status: StatusCode::NOT_FOUND,
                ..
            })
        ),
        "unknown epochs should not accept message writes"
    );

    let fetch = client.fetch_messages(&fake_epoch, &sender_leaf).await;
    assert!(
        matches!(
            fetch,
            Err(Error::HttpStatus {
                status: StatusCode::NOT_FOUND,
                ..
            })
        ),
        "unknown epochs should not allow message reads"
    );

    drop(client);
    handle.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn error_members_with_invalid_gid() -> Result<()> {
    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));

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
    let port = next_free_local_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(200)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));

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
    let epoch_key = alice.epoch_key;

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
    let sender_leaf = demo_member_leaf("alice");

    client
        .send_message(&alice.we_epoch_id, &ciphertext, Some(&sender_leaf))
        .await
        .expect("send message");

    // Now kill the server
    handle.abort();
    // Wait longer for server to fully shutdown and connections to close
    sleep(Duration::from_millis(500)).await;

    // Create a new client to avoid connection pooling issues
    let new_client = test_client(format!("http://127.0.0.1:{port}"));

    // Subsequent operations should fail gracefully with proper errors
    let result = new_client.health().await;
    assert!(result.is_err(), "should fail after server shutdown");

    match result {
        Err(Error::Http(_)) => Ok(()),
        Err(other) => Err(anyhow!("expected HTTP error, got {:?}", other)),
        Ok(_) => Err(anyhow!("expected error after server shutdown")),
    }
}
