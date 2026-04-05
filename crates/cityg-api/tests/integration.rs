use std::time::Duration;

use anyhow::{Result, anyhow};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use ciborium::value::Value;
use cityg_api_client::{
    CitygApiClient, Error, IdentityBinding, MergeAcceptanceStatus, RoomAdminOperation,
    RoomAdminProof, SlotLease,
    build_room_admin_leaf_pair_proof, build_room_admin_listing_proof, build_room_admin_proof,
    build_room_admin_target_proof, generate_room_admin_keypair,
};
use cityg_client::{
    CityGClient, ClientEpochBundle,
    barrier::compute_revocation_roots_hash,
    barrier_merge_bundle::{
        BarrierMergeBundleInputs, PreparedBarrierMergeBundle, build_barrier_merge_bundle,
    },
    barrier_update::compute_barrier_update_digest,
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
use tokio::time::{sleep, timeout};

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
    leaf_id: [u8; 32],
    slot_lease: SlotLease,
    join_finalize_auth_token: [u8; 32],
    current_revoked_occupancies: Vec<SlotLease>,
    pop_public_key: Vec<u8>,
    pop_secret_key: dilithium5::SecretKey,
    vrf_secret_key: Vec<u8>,
    vrf_public_key: Vec<u8>,
    forward_state: ForwardSecrecyState,
}

fn array32(name: &str, bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("{name} must be 32 bytes"))
}

fn barrier_leaf_public_key() -> Vec<u8> {
    vec![0x42; 1_184]
}

fn header_u64_field(bundle: &ClientEpochBundle, key: u64, name: &str) -> Result<u64> {
    match bundle.header_map.get(&key) {
        Some(Value::Integer(value)) => value
            .clone()
            .try_into()
            .map_err(|_| anyhow!("{name} must be a uint")),
        _ => Err(anyhow!("{name} missing")),
    }
}

fn header_bytes32_field(bundle: &ClientEpochBundle, key: u64, name: &str) -> Result<[u8; 32]> {
    match bundle.header_map.get(&key) {
        Some(Value::Bytes(bytes)) => array32(name, bytes),
        _ => Err(anyhow!("{name} missing")),
    }
}

fn header_bytes_field(bundle: &ClientEpochBundle, key: u64, name: &str) -> Result<Vec<u8>> {
    match bundle.header_map.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        _ => Err(anyhow!("{name} missing")),
    }
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

    Ok(JoinedMember {
        bundle,
        leaf_id,
        slot_lease: SlotLease {
            slot_index: ticket.slot_index,
            slot_generation: ticket.slot_generation,
        },
        join_finalize_auth_token: array32(
            "join_finalize_auth_token",
            &ticket.join_finalize_auth_token,
        )?,
        current_revoked_occupancies: ticket
            .current_revoked_occupancies
            .iter()
            .map(|record| SlotLease {
                slot_index: u64::from(record.slot_index),
                slot_generation: record.slot_generation,
            })
            .collect(),
        pop_public_key,
        pop_secret_key: pop_sk,
        vrf_secret_key,
        vrf_public_key,
        forward_state: fs_state,
    })
}

async fn build_join_finalize_bundle(
    client: &CitygApiClient,
    room_id: &str,
    member: &JoinedMember,
    join_finalize_auth_token: [u8; 32],
    barrier_update_reason: u64,
) -> Result<PreparedBarrierMergeBundle> {
    let gid = array32("gid", &hex::decode(room_id)?)?;
    let ticket = client.merge_ticket_refresh(room_id, &member.leaf_id).await?;
    let fs_ec = header_u64_field(&member.bundle, hdr::HDR_FS_EC, "fs_ec")?;
    let fs_epoch_commit = header_bytes32_field(
        &member.bundle,
        hdr::HDR_FS_EPOCH_COMMIT,
        "fs_epoch_commit",
    )?;
    let fs_dev_prev_commit = header_bytes32_field(
        &member.bundle,
        hdr::HDR_FS_DEV_COMMIT,
        "fs_dev_prev_commit",
    )?;

    let prepared_runtime = ticket.prepare_origin_runtime(
        cityg_api_client::PrepareOriginMergeTicketInput {
            operation_label: "join_finalize",
            local_barrier_version: ticket.barrier_version,
            local_kem_tree_hash_after: ticket.kem_tree_hash_after,
            local_current_history_commitment: Some(&ticket.current_history_commitment),
            local_current_history_authority_extension: ticket.history_authority_extension.clone(),
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
            stored_max_barrier_update_bytes: 0,
            join_finalize_auth_token: Some(join_finalize_auth_token),
        },
    )?;
    let prepared_snapshot = client
        .barrier_prepare_snapshot(prepared_runtime.snapshot_preparation_request(
            room_id,
            &gid,
            &member.leaf_id,
            member.pop_secret_key.as_bytes(),
            barrier_update_reason,
            "join_finalize",
        ))
        .await?;

    let next_barrier_version = prepared_runtime.barrier_version.saturating_add(1);
    let prepared_orchestration = prepared_runtime.prepare_barrier_orchestration(
        &gid,
        member.pop_public_key.as_slice(),
        &member.pop_secret_key,
        member.vrf_secret_key.as_slice(),
        member.vrf_public_key.as_slice(),
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        next_barrier_version,
    );
    build_barrier_merge_bundle(BarrierMergeBundleInputs {
        header: prepared_snapshot.header,
        parts: prepared_orchestration.parts,
        params: prepared_orchestration.params,
        forward_state: member.forward_state.clone(),
        parities: prepared_runtime.parities.as_slice(),
        witness_bytes: prepared_runtime.witness_bytes.as_deref(),
        pivot: &prepared_snapshot.pivot,
        gid: &gid,
        cat: &prepared_snapshot.cat,
        parent_root: &prepared_snapshot.parent_root,
        current_k_fs: None,
        next_barrier_version,
        barrier_key: &prepared_snapshot.barrier_update.k_barrier_new,
        barrier_update_reason,
        disable_autonomic_evolve: false,
    })
}

async fn build_leave_bundle(
    client: &CitygApiClient,
    room_id: &str,
    member: &JoinedMember,
) -> Result<ClientEpochBundle> {
    let gid = array32("gid", &hex::decode(room_id)?)?;
    let ticket = client.merge_ticket(room_id, &member.leaf_id).await?;
    let fs_ec = header_u64_field(&member.bundle, hdr::HDR_FS_EC, "fs_ec")?;
    let fs_epoch_commit = header_bytes32_field(
        &member.bundle,
        hdr::HDR_FS_EPOCH_COMMIT,
        "fs_epoch_commit",
    )?;
    let fs_dev_prev_commit = header_bytes32_field(
        &member.bundle,
        hdr::HDR_FS_DEV_COMMIT,
        "fs_dev_prev_commit",
    )?;

    let prepared_runtime = ticket.prepare_revocation_runtime(
        cityg_api_client::PrepareRevocationMergeTicketInput {
            operation_label: "leave",
            local_barrier_version: ticket.barrier_version,
            local_kem_tree_hash_after: ticket.kem_tree_hash_after,
            local_current_history_commitment: Some(&ticket.current_history_commitment),
            local_current_history_authority_extension: ticket.history_authority_extension.clone(),
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
            stored_max_barrier_update_bytes: 0,
        },
    )?;
    let prepared_snapshot = client
        .barrier_prepare_snapshot(prepared_runtime.snapshot_preparation_request(
            room_id,
            &gid,
            &member.leaf_id,
            member.pop_secret_key.as_bytes(),
            Some(member.leaf_id),
            0,
            "leave",
        ))
        .await?;

    let next_barrier_version = prepared_runtime.barrier_version.saturating_add(1);
    let prepared_orchestration = prepared_runtime.prepare_barrier_orchestration(
        &gid,
        member.pop_public_key.as_slice(),
        &member.pop_secret_key,
        member.vrf_secret_key.as_slice(),
        member.vrf_public_key.as_slice(),
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        next_barrier_version,
    );
    let built = build_barrier_merge_bundle(BarrierMergeBundleInputs {
        header: prepared_snapshot.header,
        parts: prepared_orchestration.parts,
        params: prepared_orchestration.params,
        forward_state: member.forward_state.clone(),
        parities: prepared_runtime.parities.as_slice(),
        witness_bytes: prepared_runtime.witness_bytes.as_deref(),
        pivot: &prepared_snapshot.pivot,
        gid: &gid,
        cat: &prepared_snapshot.cat,
        parent_root: &prepared_snapshot.parent_root,
        current_k_fs: None,
        next_barrier_version,
        barrier_key: &prepared_snapshot.barrier_update.k_barrier_new,
        barrier_update_reason: 0,
        disable_autonomic_evolve: false,
    })?;

    Ok(built.bundle)
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn bootstrapped_room_join_keeps_merge_ticket_refresh_available() -> Result<()> {
    let port = next_free_local_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let room_id = hex::encode([0x91u8; 32]);
    bootstrap_room(&client, &room_id, kbroad_public()).await?;

    let alice = join_room_member(&client, &room_id, "alice", 0x91).await?;
    client
        .accept_epoch_bundle(&alice.bundle)
        .await
        .expect("accept alice into bootstrapped room");

    let refresh = client
        .merge_ticket_refresh(&room_id, &alice.leaf_id)
        .await
        .expect("bootstrapped room must keep merge refresh ticket available after first join");
    assert_eq!(
        refresh.kbroad_public,
        kbroad_public(),
        "merge refresh ticket must still carry the registered room kbroad key"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn public_barrier_helpers_preserve_slot_generations_across_slot_reuse() -> Result<()> {
    let port = next_free_local_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let room_id = hex::encode([0xA6u8; 32]);
    bootstrap_room(&client, &room_id, kbroad_public()).await?;

    let mut alice = join_room_member(&client, &room_id, "alice", 0xA6).await?;
    assert_eq!(
        alice.slot_lease.slot_index, 0,
        "first join should consume the first free slot"
    );
    client
        .accept_epoch_bundle(&alice.bundle)
        .await
        .expect("accept alice");
    let alice_finalize = build_join_finalize_bundle(
        &client,
        &room_id,
        &alice,
        alice.join_finalize_auth_token,
        2,
    )
    .await?;
    client
        .accept_epoch_bundle(&alice_finalize.bundle)
        .await
        .expect("accept alice finalize");
    alice.bundle = alice_finalize.bundle.clone();
    alice.forward_state = alice_finalize.forward_state_after;

    let leave_bundle = build_leave_bundle(&client, &room_id, &alice).await?;
    client
        .accept_epoch_bundle(&leave_bundle)
        .await
        .expect("accept alice leave");

    let mut bob = join_room_member(&client, &room_id, "bob", 0xA7).await?;
    assert_eq!(
        bob.current_revoked_occupancies,
        vec![alice.slot_lease],
        "join provisioning should expose the revoked occupancy that the new join supersedes"
    );
    client
        .accept_epoch_bundle(&bob.bundle)
        .await
        .expect("accept bob");
    let bob_reclaim = timeout(
        Duration::from_secs(10),
        build_join_finalize_bundle(&client, &room_id, &bob, bob.join_finalize_auth_token, 0),
    )
    .await
    .map_err(|_| anyhow!("build bob reclaim finalize timed out"))??;
    assert_eq!(
        header_u64_field(
            &bob_reclaim.bundle,
            hdr::HDR_BARRIER_UPDATE_REASON,
            "barrier_update_reason",
        )?,
        0,
        "reused-slot joiner finalize should publish reason=0",
    );
    client
        .accept_epoch_bundle(&bob_reclaim.bundle)
        .await
        .expect("accept bob reclaim finalize");
    bob.bundle = bob_reclaim.bundle.clone();
    bob.forward_state = bob_reclaim.forward_state_after;

    let joins = client
        .barrier_resolve_join_occupancies_since(&room_id, 0)
        .await?;
    assert_eq!(
        joins.records.len(),
        1,
        "historical join helper should prune the superseded occupancy"
    );
    assert_eq!(u64::from(joins.records[0].slot_index), alice.slot_lease.slot_index);
    assert_eq!(u64::from(joins.records[0].slot_index), bob.slot_lease.slot_index);
    assert_eq!(
        joins.records[0].slot_generation,
        bob.slot_lease.slot_generation
    );
    assert!(
        joins.records[0].slot_generation > alice.slot_lease.slot_generation,
        "slot reuse must advance slot_generation on the public helper surface"
    );

    let refresh = client
        .merge_ticket_refresh(&room_id, &bob.leaf_id)
        .await
        .expect("refresh ticket should be available for bob");
    let current_revocation_roots_hash =
        compute_revocation_roots_hash(&refresh.revoked_since_root, &refresh.revoked_root)?;
    let revoked = client
        .barrier_resolve_revoked_occupancies(&room_id, &current_revocation_roots_hash)
        .await?;
    assert!(
        revoked.records.is_empty(),
        "reclaim join must clear the superseded revoked occupancy from the current helper view"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn public_stale_join_finalize_auth_rejected_after_slot_reuse() -> Result<()> {
    let port = next_free_local_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let room_id = hex::encode([0xA7u8; 32]);
    bootstrap_room(&client, &room_id, kbroad_public()).await?;

    let mut alice = join_room_member(&client, &room_id, "alice", 0xB1).await?;
    client
        .accept_epoch_bundle(&alice.bundle)
        .await
        .expect("accept alice");
    let alice_finalize = build_join_finalize_bundle(
        &client,
        &room_id,
        &alice,
        alice.join_finalize_auth_token,
        2,
    )
    .await?;
    client
        .accept_epoch_bundle(&alice_finalize.bundle)
        .await
        .expect("accept alice finalize");
    alice.bundle = alice_finalize.bundle.clone();
    alice.forward_state = alice_finalize.forward_state_after;

    let mut bob = join_room_member(&client, &room_id, "bob", 0xB2).await?;
    client
        .accept_epoch_bundle(&bob.bundle)
        .await
        .expect("accept bob");

    let bob_finalize = build_join_finalize_bundle(
        &client,
        &room_id,
        &bob,
        bob.join_finalize_auth_token,
        2,
    )
    .await?;
    assert_eq!(
        header_u64_field(
            &bob_finalize.bundle,
            hdr::HDR_BARRIER_UPDATE_REASON,
            "barrier_update_reason",
        )?,
        2,
        "fresh joiner finalize should publish reason=2",
    );
    client
        .accept_epoch_bundle(&bob_finalize.bundle)
        .await
        .expect("accept bob finalize");
    bob.bundle = bob_finalize.bundle.clone();
    bob.forward_state = bob_finalize.forward_state_after;

    let bob_leave = build_leave_bundle(&client, &room_id, &bob).await?;
    client
        .accept_epoch_bundle(&bob_leave)
        .await
        .expect("accept bob leave");

    let charlie = join_room_member(&client, &room_id, "charlie", 0xB3).await?;
    assert_eq!(
        charlie.current_revoked_occupancies,
        vec![bob.slot_lease],
        "reused-slot join should surface the revoked occupancy it supersedes"
    );
    client
        .accept_epoch_bundle(&charlie.bundle)
        .await
        .expect("accept charlie");

    let reclaim_bundle = build_join_finalize_bundle(
        &client,
        &room_id,
        &charlie,
        charlie.join_finalize_auth_token,
        0,
    )
    .await?;
    assert_eq!(
        header_u64_field(
            &reclaim_bundle.bundle,
            hdr::HDR_BARRIER_UPDATE_REASON,
            "barrier_update_reason",
        )?,
        0,
        "reused-slot joiner finalize should publish reason=0",
    );
    let mut stale_reclaim_bundle = reclaim_bundle.bundle.clone();
    stale_reclaim_bundle.header_map.insert(
        hdr::HDR_JOIN_FINALIZE_AUTH,
        Value::Bytes(bob.join_finalize_auth_token.to_vec()),
    );

    let (status, freeze_reason) = match client.accept_epoch_bundle(&stale_reclaim_bundle).await {
        Err(Error::HttpStatus {
            status,
            freeze_reason,
            ..
        }) => (status, freeze_reason),
        other => {
            return Err(anyhow!(
                "expected stale join_finalize_auth rejection, got {:?}",
                other
            ));
        }
    };
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(freeze_reason.as_deref(), Some("barrier_updater_invalid"));

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn public_lookup_merge_acceptance_tracks_reclaim_join_finalize() -> Result<()> {
    let port = next_free_local_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let client = test_client(format!("http://127.0.0.1:{port}"));
    let mut ready = false;
    for _ in 0..20 {
        if timeout(Duration::from_secs(1), client.health()).await.is_ok_and(|result| result.is_ok())
        {
            ready = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    if !ready {
        return Err(anyhow!("server readiness timed out before slot-lease lookup test"));
    }
    let room_id = hex::encode([0xA8u8; 32]);
    timeout(
        Duration::from_secs(10),
        bootstrap_room(&client, &room_id, kbroad_public()),
    )
    .await
    .map_err(|_| anyhow!("bootstrap room timed out for slot-lease lookup test"))??;

    let mut alice = join_room_member(&client, &room_id, "alice", 0xC1).await?;
    client
        .accept_epoch_bundle(&alice.bundle)
        .await
        .expect("accept alice");
    let alice_finalize = build_join_finalize_bundle(
        &client,
        &room_id,
        &alice,
        alice.join_finalize_auth_token,
        2,
    )
    .await?;
    client
        .accept_epoch_bundle(&alice_finalize.bundle)
        .await
        .expect("accept alice finalize");
    alice.bundle = alice_finalize.bundle.clone();
    alice.forward_state = alice_finalize.forward_state_after;

    let alice_leave = build_leave_bundle(&client, &room_id, &alice).await?;
    client
        .accept_epoch_bundle(&alice_leave)
        .await
        .expect("accept alice leave");

    let mut bob = join_room_member(&client, &room_id, "bob", 0xC2).await?;
    client
        .accept_epoch_bundle(&bob.bundle)
        .await
        .expect("accept bob");

    let bob_reclaim = timeout(
        Duration::from_secs(10),
        build_join_finalize_bundle(&client, &room_id, &bob, bob.join_finalize_auth_token, 0),
    )
    .await
    .map_err(|_| anyhow!("build bob reclaim finalize timed out"))??;
    let pending_barrier_version = header_u64_field(
        &bob_reclaim.bundle,
        hdr::HDR_BARRIER_VERSION,
        "barrier_version",
    )?;
    let pending_barrier_update = header_bytes_field(
        &bob_reclaim.bundle,
        hdr::HDR_BARRIER_UPDATE,
        "barrier_update",
    )?;
    let pending_barrier_update_digest = compute_barrier_update_digest(&pending_barrier_update)?;
    let pending_lookup = timeout(
        Duration::from_secs(10),
        client.barrier_lookup_merge_acceptance(
            &room_id,
            pending_barrier_version,
            &pending_barrier_update_digest,
            &bob_reclaim.bundle.we_epoch_id,
        ),
    )
    .await
    .map_err(|_| anyhow!("lookup pending reclaim acceptance timed out"))??;
    assert_eq!(pending_lookup.status, MergeAcceptanceStatus::Pending);
    assert_eq!(pending_lookup.accepted_barrier_version, None);
    assert_eq!(pending_lookup.accepted_reason, None);

    timeout(
        Duration::from_secs(10),
        client.accept_epoch_bundle(&bob_reclaim.bundle),
    )
    .await
    .map_err(|_| anyhow!("accept bob reclaim finalize timed out"))??;
    bob.bundle = bob_reclaim.bundle.clone();
    bob.forward_state = bob_reclaim.forward_state_after;

    let accepted_lookup = timeout(
        Duration::from_secs(10),
        client.barrier_lookup_merge_acceptance(
            &room_id,
            pending_barrier_version,
            &pending_barrier_update_digest,
            &bob.bundle.we_epoch_id,
        ),
    )
    .await
    .map_err(|_| anyhow!("lookup accepted reclaim acceptance timed out"))??;
    assert_eq!(accepted_lookup.status, MergeAcceptanceStatus::Accepted);
    assert_eq!(
        accepted_lookup.accepted_barrier_version,
        Some(pending_barrier_version)
    );
    assert_eq!(accepted_lookup.accepted_reason, Some(0));
    assert_eq!(
        accepted_lookup.accepted_digest,
        Some(pending_barrier_update_digest)
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
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
async fn concurrent_malformed_join_and_honest_join_preserve_room_across_restart() -> Result<()> {
    let temp_root = std::env::temp_dir().join(format!(
        "cityg-api-concurrent-malformed-join-race-{}-{}",
        std::process::id(),
        next_free_local_port()
    ));
    std::fs::create_dir_all(&temp_root).expect("create temp root");
    let journal_path = temp_root.join("concurrent-malformed-join-race.journal");
    let port = next_free_local_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let base_url = format!("http://127.0.0.1:{port}");
    let client = test_client(base_url.clone());
    let honest_client = test_client(base_url);
    let alice = demo_bundle("alice").expect("alice bundle");
    client
        .accept_epoch_bundle(&alice)
        .await
        .expect("accept alice");

    let honest_bob = demo_bundle("bob").expect("bob bundle");
    let mut malformed_bob = honest_bob.clone();
    malformed_bob
        .header_map
        .remove(&msphf_orchestrator::hdr::HDR_BARRIER_LEAF_PK);

    let malformed_task = tokio::spawn(async move {
        let err = client
            .accept_epoch_bundle(&malformed_bob)
            .await
            .expect_err("malformed join must fail");
        assert!(
            matches!(err, Error::HttpStatus { .. }),
            "malformed join should surface as an HTTP rejection: {err:?}"
        );
        Ok::<(), anyhow::Error>(())
    });
    let honest_task = tokio::spawn(async move {
        honest_client
            .accept_epoch_bundle(&honest_bob)
            .await
            .expect("honest join must succeed during malformed join race");
        Ok::<(), anyhow::Error>(())
    });

    malformed_task.await.expect("malformed task panicked")?;
    honest_task.await.expect("honest task panicked")?;

    let members_before_restart = test_client(format!("http://127.0.0.1:{port}"))
        .members(DEMO_GID.as_ref(), None)
        .await?;
    assert_eq!(
        members_before_restart.members.len(),
        2,
        "concurrent malformed join must not block the honest joined member"
    );

    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path).await;
    sleep(Duration::from_millis(250)).await;

    let members_after_restart = test_client(format!("http://127.0.0.1:{port}"))
        .members(DEMO_GID.as_ref(), None)
        .await?;
    assert_eq!(
        members_after_restart.members.len(),
        2,
        "restart must preserve the honest joined member after the concurrent malformed join race"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn restart_during_concurrent_malformed_join_and_honest_join_recovers_cleanly() -> Result<()> {
    let temp_root = std::env::temp_dir().join(format!(
        "cityg-api-restart-concurrent-malformed-join-race-{}-{}",
        std::process::id(),
        next_free_local_port()
    ));
    std::fs::create_dir_all(&temp_root).expect("create temp root");
    let journal_path = temp_root.join("restart-concurrent-malformed-join-race.journal");
    let port = next_free_local_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let base_url = format!("http://127.0.0.1:{port}");
    let client = test_client(base_url.clone());
    let honest_client = test_client(base_url.clone());
    let observe_client = test_client(base_url);
    let alice = demo_bundle("alice").expect("alice bundle");
    client
        .accept_epoch_bundle(&alice)
        .await
        .expect("accept alice");

    let honest_bob = demo_bundle("bob").expect("bob bundle");
    let mut malformed_bob = honest_bob.clone();
    malformed_bob
        .header_map
        .remove(&msphf_orchestrator::hdr::HDR_BARRIER_LEAF_PK);

    let malformed_task = tokio::spawn(async move {
        match client.accept_epoch_bundle(&malformed_bob).await {
            Err(Error::HttpStatus { .. }) => Ok::<(), anyhow::Error>(()),
            Err(Error::Http(err)) if err.is_connect() || err.is_request() || err.is_timeout() => {
                Ok(())
            }
            other => Err(anyhow!("unexpected malformed join outcome: {other:?}")),
        }
    });
    let honest_task =
        tokio::spawn(async move { honest_client.accept_epoch_bundle(&honest_bob).await });

    sleep(Duration::from_millis(25)).await;
    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path).await;
    sleep(Duration::from_millis(250)).await;

    malformed_task.await.expect("malformed task panicked")?;
    match honest_task.await.expect("honest task panicked") {
        Ok(_) => {}
        Err(Error::Http(_)) => {}
        Err(Error::HttpStatus { status, .. })
            if status == StatusCode::INTERNAL_SERVER_ERROR
                || status == StatusCode::SERVICE_UNAVAILABLE
                || status == StatusCode::BAD_GATEWAY => {}
        Err(other) => return Err(anyhow!("unexpected honest join outcome: {other:?}")),
    }

    let members_after_restart = observe_client.members(DEMO_GID.as_ref(), None).await?;
    if members_after_restart.members.len() < 2 {
        let honest_retry = demo_bundle("bob").expect("bob retry bundle");
        observe_client
            .accept_epoch_bundle(&honest_retry)
            .await
            .expect("retry honest join after restart");
    }

    let members_final = observe_client.members(DEMO_GID.as_ref(), None).await?;
    assert_eq!(
        members_final.members.len(),
        2,
        "room must converge to the honest joined member after concurrent malformed join race and restart"
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
async fn concurrent_malformed_admin_expel_request_and_honest_join_preserve_room_across_restart()
-> Result<()> {
    let temp_root = std::env::temp_dir().join(format!(
        "cityg-api-concurrent-malformed-admin-expel-race-{}-{}",
        std::process::id(),
        next_free_local_port()
    ));
    std::fs::create_dir_all(&temp_root).expect("create temp root");
    let journal_path = temp_root.join("concurrent-malformed-admin-expel-race.journal");
    let room_id = hex::encode([0x39u8; 32]);
    let gid = hex::decode(&room_id)?;
    let port = next_free_local_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let base_url = format!("http://127.0.0.1:{port}");
    let client = test_client(base_url.clone());
    let honest_client = test_client(base_url.clone());
    let (alice_pk, alice_sk) = dilithium5::keypair();
    bootstrap_room_with_admin_identity(&client, &room_id, alice_pk.as_bytes(), &alice_sk).await?;

    let malformed_request = RawExpelMemberTicketRequest {
        room_id: room_id.clone(),
        author_leaf_id: [0xC3; 32].to_vec(),
        target_leaf_id: [0xD4; 31].to_vec(),
        admin_proof: Some(build_room_admin_leaf_pair_proof(
            RoomAdminOperation::ExpelMember,
            &room_id,
            &[0xC3; 32],
            &[0xD4; 32],
            alice_pk.as_bytes(),
            alice_sk.as_bytes(),
        )?),
    };
    let honest_room_id = room_id.clone();

    let malformed_future = async move {
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
            "concurrent malformed admin expel must fail closed"
        );
        Ok::<(), anyhow::Error>(())
    };
    let honest_join_future = async move {
        let charlie = join_room_member(&honest_client, &honest_room_id, "charlie", 0x97).await?;
        honest_client
            .accept_epoch_bundle(&charlie.bundle)
            .await
            .expect("accept charlie during concurrent malformed expel race");
        Ok::<(), anyhow::Error>(())
    };

    let (malformed_result, honest_result) = tokio::join!(malformed_future, honest_join_future);
    malformed_result?;
    honest_result?;

    let members_before_restart = client.members(gid.as_slice(), None).await?;
    assert_eq!(
        members_before_restart.members.len(),
        1,
        "concurrent malformed expel request must not block the honest joined member"
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
        "restart must preserve the honest joined member after the concurrent malformed expel race"
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
        "room-admin ACL must remain healthy after the concurrent malformed expel race and restart"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
#[allow(clippy::expect_used)]
async fn restart_during_concurrent_malformed_admin_race_and_honest_join_recovers_cleanly()
-> Result<()> {
    let temp_root = std::env::temp_dir().join(format!(
        "cityg-api-restart-concurrent-malformed-admin-race-{}-{}",
        std::process::id(),
        next_free_local_port()
    ));
    std::fs::create_dir_all(&temp_root).expect("create temp root");
    let journal_path = temp_root.join("restart-concurrent-malformed-admin-race.journal");
    let room_id = hex::encode([0x3Au8; 32]);
    let gid = hex::decode(&room_id)?;
    let port = next_free_local_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let base_url = format!("http://127.0.0.1:{port}");
    let control_client = test_client(base_url.clone());
    let honest_client = test_client(base_url.clone());
    let observe_client = test_client(base_url.clone());
    let (alice_pk, alice_sk) = dilithium5::keypair();
    bootstrap_room_with_admin_identity(&control_client, &room_id, alice_pk.as_bytes(), &alice_sk)
        .await?;

    let charlie = join_room_member(&control_client, &room_id, "charlie", 0x98).await?;
    let honest_bundle = charlie.bundle.clone();
    let malformed_request = RawExpelMemberTicketRequest {
        room_id: room_id.clone(),
        author_leaf_id: [0xC5; 32].to_vec(),
        target_leaf_id: [0xD6; 31].to_vec(),
        admin_proof: Some(build_room_admin_leaf_pair_proof(
            RoomAdminOperation::ExpelMember,
            &room_id,
            &[0xC5; 32],
            &[0xD6; 32],
            alice_pk.as_bytes(),
            alice_sk.as_bytes(),
        )?),
    };

    let malformed_port = port;
    let malformed_task = tokio::spawn(async move {
        match reqwest::Client::new()
            .post(format!(
                "http://127.0.0.1:{malformed_port}/v1/rooms/expel_member_ticket"
            ))
            .header("content-type", "application/protobuf")
            .body(malformed_request.encode_to_vec())
            .send()
            .await
        {
            Ok(response) => {
                assert_eq!(
                    response.status(),
                    StatusCode::BAD_REQUEST,
                    "concurrent malformed admin expel must fail closed when it reaches the server"
                );
                Ok::<(), anyhow::Error>(())
            }
            Err(err) if err.is_connect() || err.is_request() || err.is_timeout() => Ok(()),
            Err(err) => Err(anyhow!(
                "unexpected malformed request transport error: {err}"
            )),
        }
    });
    let honest_task =
        tokio::spawn(async move { honest_client.accept_epoch_bundle(&honest_bundle).await });

    sleep(Duration::from_millis(25)).await;
    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path).await;
    sleep(Duration::from_millis(250)).await;

    malformed_task.await??;
    match honest_task.await.expect("honest join task panicked") {
        Ok(_) => {}
        Err(Error::Http(_)) => {}
        Err(Error::HttpStatus { status, .. })
            if status == StatusCode::INTERNAL_SERVER_ERROR
                || status == StatusCode::SERVICE_UNAVAILABLE
                || status == StatusCode::BAD_GATEWAY => {}
        Err(other) => return Err(anyhow!("unexpected honest join outcome: {other:?}")),
    }

    let members_after_restart = observe_client.members(gid.as_slice(), None).await?;
    if members_after_restart.members.is_empty() {
        observe_client
            .accept_epoch_bundle(&charlie.bundle)
            .await
            .expect("retry honest join after restart");
    }

    let members_final = observe_client.members(gid.as_slice(), None).await?;
    assert_eq!(
        members_final.members.len(),
        1,
        "room must converge to the honest joined member after concurrent malformed race and restart"
    );
    let listed_admins = observe_client
        .list_room_admins(
            &room_id,
            build_room_admin_listing_proof(&room_id, alice_pk.as_bytes(), alice_sk.as_bytes())?,
        )
        .await?;
    assert_eq!(
        listed_admins.admin_pop_public_keys,
        vec![alice_pk.as_bytes().to_vec()],
        "room-admin ACL must remain healthy after concurrent malformed race and restart"
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
