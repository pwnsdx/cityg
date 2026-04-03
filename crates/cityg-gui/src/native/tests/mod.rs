use super::*;
use futures::SinkExt;
use gpui::{EmptyView, Modifiers, TestAppContext};
use msphf_rlwe::CapssBranchWitness;
use prost::Message;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::sync::{Arc, Once, atomic::AtomicU16};
use tempfile::TempDir;
use tokio::{task::JoinHandle, time::sleep};

use crate::barrier_shared::{encode_full_verification_receipt, encode_history_commitment_header};
use crate::native::app_actions::{
    CopyRoomIdAction, ShowSessionOverviewAction, TextSelectAllAction, ToggleSidebarAction,
};
use cityg_api_client::HistoryAuthorityDescriptor;
use msphf_orchestrator::{LeafIdMode, compute_leaf_id};

#[path = "admin_expel.rs"]
mod admin_expel;
#[path = "client_state_props.rs"]
mod client_state_props;
#[path = "gpui_handlers.rs"]
mod gpui_handlers;
#[path = "gpui_window_actions.rs"]
mod gpui_window_actions;
#[path = "join_bootstrap.rs"]
mod join_bootstrap;
#[path = "message_crypto.rs"]
mod message_crypto;
#[path = "pending_recovery_guards.rs"]
mod pending_recovery_guards;
#[path = "replay_fetch.rs"]
mod replay_fetch;
#[path = "restart_recovery.rs"]
mod restart_recovery;
#[path = "session_persistence.rs"]
mod session_persistence;
#[path = "watch_backlog.rs"]
mod watch_backlog;
#[path = "websocket_worker.rs"]
mod websocket_worker;

static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(18400);
struct TestEnvLock(std::sync::Mutex<()>);

impl TestEnvLock {
    const fn new() -> Self {
        Self(std::sync::Mutex::new(()))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ()>, std::convert::Infallible> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()))
    }
}

static ENV_VAR_LOCK: TestEnvLock = TestEnvLock::new();
const TEST_ADMIN_TOKEN: &str = "cityg-test-admin-token";
const TEST_MESSAGE_TOKEN: &str = "cityg-test-message-token";
static TEST_AUTH_ENV_INIT: Once = Once::new();
const TEST_PROFILE_VERSION: &str = "v0.1.4";
const TEST_HISTORY_AUTHORITY_EXTENSION_ID: &str = "global-history-authority-v1";
const TEST_GLOBAL_HISTORY_FINALITY_KIND: &str = "global-append-only";

fn init_test_auth_env() {
    TEST_AUTH_ENV_INIT.call_once(|| {
        // SAFETY: test auth env is initialized once with process-stable values.
        unsafe {
            std::env::set_var("CITYG_SERVER_WINDOW_ADMIN_TOKEN", TEST_ADMIN_TOKEN);
            std::env::set_var("CITYG_SERVER_ROOMS_ADMIN_TOKEN", TEST_ADMIN_TOKEN);
            std::env::set_var("CITYG_SERVER_MESSAGE_AUTH_TOKEN", TEST_MESSAGE_TOKEN);
            std::env::set_var(CLIENT_ADMIN_TOKEN_ENV, TEST_ADMIN_TOKEN);
            std::env::set_var(CLIENT_MESSAGE_TOKEN_ENV, TEST_MESSAGE_TOKEN);
            std::env::remove_var("CITYG_SERVER_ALLOW_INSECURE_ADMIN");
        }
    });
}

fn next_test_port() -> u16 {
    for _ in 0..256 {
        let candidate = NEXT_TEST_PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", candidate)) {
            drop(listener);
            return candidate;
        }
    }

    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral test port")
        .local_addr()
        .expect("read ephemeral test port")
        .port()
}

#[derive(Clone, PartialEq, prost::Message)]
struct MockPbFsForwardLeapPolicy {
    #[prost(uint64, tag = "1")]
    h: u64,
    #[prost(uint64, tag = "2")]
    checkpoint_interval: u64,
    #[prost(uint64, tag = "3")]
    slack_anchor: u64,
    #[prost(uint64, tag = "4")]
    slack_first_device: u64,
    #[prost(uint64, tag = "5")]
    slack_device: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct MockPbHistoryCommitment {
    #[prost(bytes = "vec", tag = "1")]
    history_view_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    history_commitment_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    prev_history_commitment_id: Vec<u8>,
    #[prost(uint64, tag = "4")]
    history_seq: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct MockBarrierLookupMergeAcceptanceResponse {
    #[prost(int32, tag = "1")]
    status: i32,
    #[prost(bytes = "vec", tag = "2")]
    history_view_id: Vec<u8>,
    #[prost(uint64, optional, tag = "3")]
    accepted_barrier_version: Option<u64>,
    #[prost(uint64, optional, tag = "4")]
    accepted_fs_ec: Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    accepted_reason: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "6")]
    accepted_digest: Option<Vec<u8>>,
    #[prost(message, optional, tag = "7")]
    history_commitment: Option<MockPbHistoryCommitment>,
    #[prost(bytes = "vec", tag = "8")]
    history_authority_descriptor: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    global_history_attestation: Vec<u8>,
    #[prost(string, tag = "10")]
    history_authority_extension: String,
    #[prost(string, tag = "11")]
    profile_version: String,
    #[prost(uint64, tag = "12")]
    n_max: u64,
    #[prost(uint64, tag = "13")]
    max_barrier_update_bytes: u64,
    #[prost(message, optional, tag = "14")]
    fs_forward_leap_policy: Option<MockPbFsForwardLeapPolicy>,
    #[prost(bytes = "vec", tag = "15")]
    deployment_profile_manifest: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct TestHistoryAuthorityDescriptorWire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Serialize, Deserialize)]
struct TestGlobalHistoryAttestationWire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    u64,
    u64,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    String,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Serialize)]
struct TestGlobalHistoryAttestationSignedPayload<'a>(
    &'static str,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u64,
    u64,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    &'a str,
);

#[derive(Serialize, Deserialize)]
struct TestDeploymentProfileManifestWire {
    #[serde(with = "serde_bytes")]
    scope_id: Vec<u8>,
    history_authority_extension: String,
    #[serde(with = "serde_bytes")]
    gid: Vec<u8>,
    profile_version: String,
    n_max: u64,
    max_barrier_update_bytes: u64,
    fs_forward_leap_h: u64,
    fs_forward_leap_checkpoint_interval: u64,
    fs_forward_leap_slack_anchor: u64,
    fs_forward_leap_slack_first_device: u64,
    fs_forward_leap_slack_device: u64,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct TestDeploymentProfileManifestSignedPayload<'a> {
    label: &'static str,
    #[serde(with = "serde_bytes")]
    scope_id: &'a [u8; 32],
    history_authority_extension: &'a str,
    #[serde(with = "serde_bytes")]
    gid: &'a [u8; 32],
    profile_version: &'a str,
    n_max: u64,
    max_barrier_update_bytes: u64,
    fs_forward_leap_h: u64,
    fs_forward_leap_checkpoint_interval: u64,
    fs_forward_leap_slack_anchor: u64,
    fs_forward_leap_slack_first_device: u64,
    fs_forward_leap_slack_device: u64,
}

struct TestHistoryAuthority {
    descriptor: HistoryAuthorityDescriptor,
    descriptor_bytes: Vec<u8>,
    secret_key: Vec<u8>,
    attestation_bytes: Vec<u8>,
}

fn encode_test_cbor_det<T: Serialize>(value: &T) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_cbor_vec(value)?)
}

fn session_gid_from_room_id(session: &AppSession) -> [u8; 32] {
    hex_decode(&session.room_id)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .unwrap_or(session.gid)
}

fn install_test_barrier_leaf_keypair(
    session: &mut AppSession,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (public_key, secret_key, pkhash) =
        cityg_client::barrier_crypto::generate_barrier_leaf_keypair()?;
    session.barrier_state.dk_leaf = Zeroizing::new(secret_key);
    session.barrier_state.pkhash_leaf = pkhash;
    Ok(public_key)
}

fn test_new_public_key_wire(node: u64) -> Result<NewPublicKeyWire, Box<dyn std::error::Error>> {
    let (public_key, _, _) = cityg_client::barrier_crypto::generate_barrier_leaf_keypair()?;
    Ok(NewPublicKeyWire(node, public_key))
}

fn install_valid_message_identities(
    session: &mut AppSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = cityg_api_client::generate_room_admin_identity();
    session.leaf_id = compute_leaf_id(
        LeafIdMode::PerGroup,
        &session.gid,
        "ML-DSA-65",
        identity.pop_public_key.as_slice(),
    )?;
    session.pop_public_key = identity.pop_public_key;
    session.pop_secret_key = identity.pop_secret_key;

    let (msg_sign_pk, msg_sign_sk) = cityg_client::message_auth::generate_message_signing_keypair();
    session.msg_sign_public_key = msg_sign_pk;
    session.msg_sign_secret_key = msg_sign_sk;
    Ok(())
}

fn mock_pb_fs_forward_leap_policy(policy: &FsForwardLeapPolicy) -> MockPbFsForwardLeapPolicy {
    MockPbFsForwardLeapPolicy {
        h: policy.h,
        checkpoint_interval: policy.checkpoint_interval,
        slack_anchor: policy.slack_anchor,
        slack_first_device: policy.slack_first_device,
        slack_device: policy.slack_device,
    }
}

fn mock_pb_history_commitment(commitment: &HistoryCommitment) -> MockPbHistoryCommitment {
    MockPbHistoryCommitment {
        history_view_id: commitment.history_view_id.to_vec(),
        history_commitment_id: commitment.history_commitment_id.to_vec(),
        prev_history_commitment_id: commitment.prev_history_commitment_id.to_vec(),
        history_seq: commitment.history_seq,
    }
}

fn build_test_history_authority(
    history_commitment: HistoryCommitment,
    gid: [u8; 32],
    barrier_version: u64,
    kem_tree_hash_after: [u8; 32],
) -> Result<TestHistoryAuthority, Box<dyn std::error::Error>> {
    let (public_key_bytes, secret_key_bytes) =
        cityg_client::message_auth::generate_message_signing_keypair();
    let descriptor = HistoryAuthorityDescriptor {
        scope_id: [0xA1; 32],
        public_key: public_key_bytes,
    };
    let descriptor_bytes = encode_test_cbor_det(&TestHistoryAuthorityDescriptorWire(
        descriptor.scope_id.to_vec(),
        descriptor.public_key.clone(),
    ))?;
    let parent_attestation_id = [0u8; 32];
    let payload = encode_test_cbor_det(&TestGlobalHistoryAttestationSignedPayload(
        "cityg/global-history-attestation-v1",
        &descriptor.scope_id,
        &gid,
        &history_commitment.history_view_id,
        &history_commitment.history_commitment_id,
        &history_commitment.prev_history_commitment_id,
        history_commitment.history_seq,
        barrier_version,
        &kem_tree_hash_after,
        &parent_attestation_id,
        TEST_GLOBAL_HISTORY_FINALITY_KIND,
    ))?;
    let signature = cityg_client::message_auth::detached_sign_payload(
        payload.as_slice(),
        secret_key_bytes.as_slice(),
    )?;
    let attestation_bytes = encode_test_cbor_det(&TestGlobalHistoryAttestationWire(
        descriptor.scope_id.to_vec(),
        gid.to_vec(),
        history_commitment.history_view_id.to_vec(),
        history_commitment.history_commitment_id.to_vec(),
        history_commitment.prev_history_commitment_id.to_vec(),
        history_commitment.history_seq,
        barrier_version,
        kem_tree_hash_after.to_vec(),
        parent_attestation_id.to_vec(),
        TEST_GLOBAL_HISTORY_FINALITY_KIND.to_string(),
        signature,
    ))?;
    Ok(TestHistoryAuthority {
        descriptor,
        descriptor_bytes,
        secret_key: secret_key_bytes,
        attestation_bytes,
    })
}

fn build_test_deployment_profile_manifest(
    authority: &TestHistoryAuthority,
    gid: &[u8; 32],
    n_max: u64,
    max_barrier_update_bytes: u64,
    fs_policy: &FsForwardLeapPolicy,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let payload = encode_test_cbor_det(&TestDeploymentProfileManifestSignedPayload {
        label: "cityg/deployment-profile-manifest-v1",
        scope_id: &authority.descriptor.scope_id,
        history_authority_extension: TEST_HISTORY_AUTHORITY_EXTENSION_ID,
        gid,
        profile_version: TEST_PROFILE_VERSION,
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_h: fs_policy.h,
        fs_forward_leap_checkpoint_interval: fs_policy.checkpoint_interval,
        fs_forward_leap_slack_anchor: fs_policy.slack_anchor,
        fs_forward_leap_slack_first_device: fs_policy.slack_first_device,
        fs_forward_leap_slack_device: fs_policy.slack_device,
    })?;
    let signature = cityg_client::message_auth::detached_sign_payload(
        payload.as_slice(),
        authority.secret_key.as_slice(),
    )?;
    encode_test_cbor_det(&TestDeploymentProfileManifestWire {
        scope_id: authority.descriptor.scope_id.to_vec(),
        history_authority_extension: TEST_HISTORY_AUTHORITY_EXTENSION_ID.to_string(),
        gid: gid.to_vec(),
        profile_version: TEST_PROFILE_VERSION.to_string(),
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_h: fs_policy.h,
        fs_forward_leap_checkpoint_interval: fs_policy.checkpoint_interval,
        fs_forward_leap_slack_anchor: fs_policy.slack_anchor,
        fs_forward_leap_slack_first_device: fs_policy.slack_first_device,
        fs_forward_leap_slack_device: fs_policy.slack_device,
        signature,
    })
}

fn build_lookup_merge_acceptance_response_bytes(
    session: &AppSession,
    status: i32,
    accepted_barrier_version: Option<u64>,
    accepted_fs_ec: Option<u64>,
    accepted_reason: Option<u64>,
    accepted_digest: Option<Vec<u8>>,
    history_commitment: HistoryCommitment,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let gid = session_gid_from_room_id(session);
    let n_max = 8;
    let max_barrier_update_bytes = 1_048_576;
    let authority = build_test_history_authority(
        history_commitment,
        gid,
        accepted_barrier_version.unwrap_or(0),
        session.barrier_state.kem_tree_hash_after,
    )?;
    let deployment_profile_manifest = build_test_deployment_profile_manifest(
        &authority,
        &gid,
        n_max,
        max_barrier_update_bytes,
        &session.fs_forward_leap_policy,
    )?;
    Ok(MockBarrierLookupMergeAcceptanceResponse {
        status,
        history_view_id: history_commitment.history_view_id.to_vec(),
        accepted_barrier_version,
        accepted_fs_ec,
        accepted_reason,
        accepted_digest,
        history_commitment: Some(mock_pb_history_commitment(&history_commitment)),
        history_authority_descriptor: authority.descriptor_bytes,
        global_history_attestation: authority.attestation_bytes,
        history_authority_extension: TEST_HISTORY_AUTHORITY_EXTENSION_ID.to_string(),
        profile_version: TEST_PROFILE_VERSION.to_string(),
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_policy: Some(mock_pb_fs_forward_leap_policy(
            &session.fs_forward_leap_policy,
        )),
        deployment_profile_manifest,
    }
    .encode_to_vec())
}

fn sample_pivot_parity() -> PivotParity {
    PivotParity {
        gid: vec![0x01; 32],
        cat: vec![0x02; 32],
        parent_root: [0x03; 32],
        we_epoch_id: [0x04; 32],
        rho_commit: [0x05; 32],
        seed_ctx_hash: [0x06; 32],
        seed_commit: [0x07; 32],
        hp_commit: [0x08; 32],
        xk_hash: [0x09; 32],
        join_delta_root: [0x0A; 32],
        revoked_since_root: [0x0B; 32],
        revoked_root: [0x0C; 32],
        accept_seq: 1,
        crs_id: b"crs-v1".to_vec(),
        params_id: b"params-v1".to_vec(),
        policy_version: "7".to_string(),
        proof_mode: "lin+zkvrf".to_string(),
        vrf_id: "lb-vrf".to_string(),
        vrf_proof: vec![0x11, 0x22],
        vrf_public: vec![0x33, 0x44],
        mask_a: [0xAA; 32],
        mask_b: [0xBB; 32],
        fs_capss: vec![0x55],
        proofs_commit: [0x66; 32],
        srx_commit: Some([0x77; 32]),
        srx_root_sw: Some([0x78; 32]),
        is_join: true,
        hp_envelope: Arc::<[u8]>::from(vec![0x99, 0x88]),
        fs_epoch_commit: Some([0x42; 32]),
        fs_ec: Some(12),
        fs_dev_commit: Some([0x24; 32]),
    }
}

#[test]
fn generate_vrf_keys_are_not_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let (secret_a, public_a) = generate_vrf_keys()?;
    let (secret_b, public_b) = generate_vrf_keys()?;
    assert!(!secret_a.is_empty());
    assert!(!public_a.is_empty());
    assert_ne!(secret_a, secret_b);
    assert_ne!(public_a, public_b);
    Ok(())
}

fn build_test_session(
    seed: u64,
    server_url: &str,
    room_id: &str,
    alias: &str,
) -> Result<AppSession, Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut random_vec = |len: usize| {
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        buf
    };

    let forward_state =
        ForwardSecrecyState::with_state([0xAAu8; 32], 17, [0x55u8; 32], [0x99u8; 32]);
    let capss_witness_bundle = CapssWitnessBundle {
        branch_a: msphf_rlwe::CapssBranchWitness {
            branch_artifact: random_vec(24),
            ctx_tag: random_vec(16),
        },
        branch_b: msphf_rlwe::CapssBranchWitness {
            branch_artifact: random_vec(24),
            ctx_tag: random_vec(16),
        },
    };
    let capss_witness_bytes = encode_capss_witness(&capss_witness_bundle)?;
    let barrier_state = BarrierSecretState::default();

    let mut session = AppSession {
        server_url: server_url.to_string(),
        room_id: room_id.to_string(),
        alias: alias.to_string(),
        gid: [0x01u8; 32],
        cat: [0x02u8; 32],
        leaf_id: [0x03u8; 32],
        parent_root: [0x04u8; 32],
        join_delta_root: [0x05u8; 32],
        revoked_since_root: [0x06u8; 32],
        revoked_root: [0x07u8; 32],
        regular_fingerprint: Some([0x21u8; 32]),
        fs_fingerprint: None,
        tswe_salt_hash: [0x08u8; 32],
        pox_r_commit: [0x09u8; 32],
        we_epoch_id: [0x10u8; 32],
        xk_hash: [0x14u8; 32],
        epoch_key: [0x11u8; 32],
        forward_state,
        fs_ec: 17,
        fs_epoch_commit: [0x12u8; 32],
        fs_dev_prev_commit: [0x13u8; 32],
        fs_epoch_created_at: SystemTime::now(),
        fs_epoch_rotation_interval_secs: 300,
        pop_public_key: Vec::new(),
        pop_secret_key: Vec::new(),
        msg_sign_public_key: Vec::new(),
        msg_sign_secret_key: Vec::new(),
        vrf_secret_key: random_vec(32),
        vrf_public_key: random_vec(32),
        kbroad_public: random_vec(24),
        bootstrap_public: random_vec(24),
        proof_mode: "lin+zkvrf".to_string(),
        vrf_id: "vrf-demo".to_string(),
        policy_version: "v1".to_string(),
        msphf_crs_id: "rlwe-merkle/v1".to_string(),
        msphf_params_id: "rlwe-params/mock".to_string(),
        fs_policy_version: "7".to_string(),
        fs_epoch_base_ts: 42,
        fs_forward_leap_policy: FsForwardLeapPolicy {
            h: 300,
            checkpoint_interval: 3600,
            slack_anchor: 0,
            slack_first_device: 0,
            slack_device: 4,
        },
        last_accepted_ec: 17,
        last_fetch_timestamp_ms: Some(1_234_567),
        msg_replay_state: MsgReplayState::default(),
        capss_witness: capss_witness_bytes,
        barrier_state,
    };
    install_valid_message_identities(&mut session)?;
    session.fs_fingerprint = derive_fs_fingerprint_from_fields(
        session.fs_policy_version.as_str(),
        session.fs_ec,
        &session.fs_epoch_commit,
        session.fs_epoch_base_ts,
    );
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.barrier_roots_hash =
        compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
    session.barrier_state.current_history_view_id = [0x31; 32];
    session.barrier_state.current_history_commitment = Some(HistoryCommitment {
        history_view_id: [0x31; 32],
        history_commitment_id: [0x32; 32],
        prev_history_commitment_id: [0x00; 32],
        history_seq: 1,
    });
    session.barrier_state.current_barrier_full_verified = true;
    Ok(session)
}

fn apply_fetch_outcome_to_session(session: &mut AppSession, outcome: &FetchOutcome) {
    session.last_fetch_timestamp_ms = outcome.last_timestamp_ms;
    session.msg_replay_state = outcome.msg_replay_state.clone();
}

fn install_valid_pop_identity(
    session: &mut AppSession,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let identity = cityg_api_client::generate_room_admin_identity();
    let leaf_id = compute_leaf_id(
        LeafIdMode::PerGroup,
        &session.gid,
        "ML-DSA-65",
        identity.pop_public_key.as_slice(),
    )?;
    session.pop_public_key = identity.pop_public_key;
    session.pop_secret_key = identity.pop_secret_key;
    session.leaf_id = leaf_id;
    Ok(leaf_id)
}

fn current_pending_activation_source(
    session: &AppSession,
) -> Option<BarrierPendingActivationSource> {
    Some(capture_barrier_pending_activation_source(session))
}

fn sample_current_public_tree(n_max: u64, fill: u8) -> Result<BarrierPublicTree> {
    let n_max = validate_barrier_n_max(n_max)?;
    let node_count = expected_barrier_tree_nodes(n_max)?;
    let pk_entries =
        vec![vec![fill; cityg_client::barrier_crypto::barrier_leaf_public_key_bytes()]; node_count];
    let kem_tree_hash_after = compute_barrier_tree_hash(n_max, pk_entries.as_slice())?;
    Ok(BarrierPublicTree {
        n_max,
        kem_tree_hash_after,
        pk_entries,
    })
}

#[test]
fn install_authenticated_current_state_clears_full_verified_on_public_state_change() {
    let mut session =
        build_test_session(0xB3A1, "http://127.0.0.1:9", "room-auth-state-a", "alice")
            .expect("build test session");
    session.barrier_state.barrier_version = 4;
    session.barrier_state.barrier_roots_hash = [0x44; 32];
    session.barrier_state.kem_tree_hash_after = [0x45; 32];
    session.barrier_state.current_barrier_full_verified = true;

    install_authenticated_current_state(
        &mut session,
        5,
        [0x54; 32],
        [0x55; 32],
        HistoryCommitment {
            history_view_id: [0x61; 32],
            history_commitment_id: [0x62; 32],
            prev_history_commitment_id: [0x52; 32],
            history_seq: 7,
        },
        Some(HistoryAuthorityExtension::LocalHistoryAuthorityV1),
        vec![0xA1, 0x02],
    );

    assert!(
        !session.barrier_state.current_barrier_full_verified,
        "FULL marker must clear when authenticated public state changes"
    );
}

#[test]
fn install_authenticated_current_state_preserves_full_verified_for_same_public_state() {
    let mut session =
        build_test_session(0xB3A2, "http://127.0.0.1:9", "room-auth-state-b", "alice")
            .expect("build test session");
    session.barrier_state.barrier_version = 4;
    session.barrier_state.barrier_roots_hash = [0x44; 32];
    session.barrier_state.kem_tree_hash_after = [0x45; 32];
    session.barrier_state.current_barrier_full_verified = true;

    install_authenticated_current_state(
        &mut session,
        4,
        [0x44; 32],
        [0x45; 32],
        HistoryCommitment {
            history_view_id: [0x71; 32],
            history_commitment_id: [0x72; 32],
            prev_history_commitment_id: [0x62; 32],
            history_seq: 8,
        },
        Some(HistoryAuthorityExtension::LocalHistoryAuthorityV1),
        vec![0xB1, 0x03],
    );

    assert!(
        session.barrier_state.current_barrier_full_verified,
        "FULL marker should survive a same-tree re-attestation"
    );
    assert_eq!(
        session
            .barrier_state
            .current_global_history_attestation_bytes,
        vec![0xB1, 0x03]
    );
}

#[test]
fn non_regressing_authenticated_current_state_rejects_barrier_version_rollback() {
    let mut session = build_test_session(0xB401, "http://127.0.0.1:9", "room-rollback-a", "alice")
        .expect("build test session");
    session.barrier_state.barrier_version = 2;
    let current = session
        .barrier_state
        .current_history_commitment
        .expect("current history commitment");
    let err = ensure_non_regressing_authenticated_current_state(
        session.barrier_state.barrier_version,
        &session.barrier_state.kem_tree_hash_after,
        Some(&current),
        session.barrier_state.current_history_authority_extension,
        session.barrier_state.barrier_version.saturating_sub(1),
        &session.barrier_state.kem_tree_hash_after,
        &current,
        session.barrier_state.current_history_authority_extension,
        "merge ticket",
    )
    .expect_err("barrier_version rollback must fail closed");
    assert!(
        err.to_string().contains("barrier_version regressed"),
        "unexpected error: {err}"
    );
}

#[test]
fn non_regressing_authenticated_current_state_rejects_history_seq_rollback() {
    let session = build_test_session(0xB402, "http://127.0.0.1:9", "room-rollback-b", "alice")
        .expect("build test session");
    let mut advertised = session
        .barrier_state
        .current_history_commitment
        .expect("current history commitment");
    advertised.history_seq = advertised.history_seq.saturating_sub(1);
    let err = ensure_non_regressing_authenticated_current_state(
        session.barrier_state.barrier_version,
        &session.barrier_state.kem_tree_hash_after,
        session.barrier_state.current_history_commitment.as_ref(),
        session.barrier_state.current_history_authority_extension,
        session.barrier_state.barrier_version,
        &session.barrier_state.kem_tree_hash_after,
        &advertised,
        session.barrier_state.current_history_authority_extension,
        "epoch sync merge ticket",
    )
    .expect_err("history_seq rollback must fail closed");
    assert!(
        err.to_string().contains("history commitment regressed"),
        "unexpected error: {err}"
    );
}

#[test]
fn non_regressing_authenticated_current_state_rejects_same_seq_conflict() {
    let session = build_test_session(0xB403, "http://127.0.0.1:9", "room-rollback-c", "alice")
        .expect("build test session");
    let mut advertised = session
        .barrier_state
        .current_history_commitment
        .expect("current history commitment");
    advertised.history_commitment_id = [0xEE; 32];
    let err = ensure_non_regressing_authenticated_current_state(
        session.barrier_state.barrier_version,
        &session.barrier_state.kem_tree_hash_after,
        session.barrier_state.current_history_commitment.as_ref(),
        session.barrier_state.current_history_authority_extension,
        session.barrier_state.barrier_version,
        &session.barrier_state.kem_tree_hash_after,
        &advertised,
        session.barrier_state.current_history_authority_extension,
        "merge ticket",
    )
    .expect_err("same-seq conflicting commitment must fail closed");
    assert!(
        err.to_string().contains("history commitment conflicts"),
        "unexpected error: {err}"
    );
}

#[test]
fn non_regressing_authenticated_current_state_rejects_extension_conflict() {
    let mut session = build_test_session(0xB404, "http://127.0.0.1:9", "room-rollback-d", "alice")
        .expect("build test session");
    session.barrier_state.current_history_authority_extension =
        Some(HistoryAuthorityExtension::LocalHistoryAuthorityV1);
    let advertised = session
        .barrier_state
        .current_history_commitment
        .expect("current history commitment");
    let err = ensure_non_regressing_authenticated_current_state(
        session.barrier_state.barrier_version,
        &session.barrier_state.kem_tree_hash_after,
        session.barrier_state.current_history_commitment.as_ref(),
        session.barrier_state.current_history_authority_extension,
        session.barrier_state.barrier_version,
        &session.barrier_state.kem_tree_hash_after,
        &advertised,
        None,
        "merge ticket",
    )
    .expect_err("same-state extension conflict must fail closed");
    assert!(
        err.to_string()
            .contains("history authority extension conflicts"),
        "unexpected error: {err}"
    );
}

fn build_activation_guard_header(
    session: &AppSession,
    barrier_version: u64,
    fs_ec: u64,
    raw_update: &[u8],
) -> Result<BTreeMap<u64, Value>, Box<dyn std::error::Error>> {
    let barrier_update_digest = compute_barrier_update_digest(raw_update)?;
    let fs_dev_commit = compute_fs_dev_commit_v2(
        session.pop_public_key.as_slice(),
        fs_ec,
        &session.fs_dev_prev_commit,
        barrier_version,
        &barrier_update_digest,
    )?;
    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_POP_PK,
        Value::Bytes(session.pop_public_key.clone()),
    );
    header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(fs_ec)));
    header.insert(
        hdr::HDR_FS_EPOCH_BASE_TS,
        Value::Integer(Integer::from(session.fs_epoch_base_ts)),
    );
    header.insert(
        hdr::HDR_FS_POLICY_VERSION,
        Value::Integer(Integer::from(
            session.fs_policy_version.parse::<u64>().unwrap_or(0),
        )),
    );
    header.insert(
        hdr::HDR_FS_DEV_PREV_COMMIT,
        Value::Bytes(session.fs_dev_prev_commit.to_vec()),
    );
    header.insert(hdr::HDR_FS_DEV_COMMIT, Value::Bytes(fs_dev_commit.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_VERSION,
        Value::Integer(Integer::from(barrier_version)),
    );
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(raw_update.to_vec()));
    let commitment = session
        .barrier_state
        .current_history_commitment
        .as_ref()
        .ok_or("test session missing current_history_commitment")?;
    header.insert(
        hdr::HDR_BARRIER_HISTORY_COMMITMENT,
        Value::Bytes(encode_history_commitment_header(commitment)?),
    );
    Ok(header)
}

fn build_authority_activation_guard_header(
    session: &mut AppSession,
    extension: HistoryAuthorityExtension,
    attestation_bytes: Vec<u8>,
) -> Result<BTreeMap<u64, Value>, Box<dyn std::error::Error>> {
    let author_leaf_id = install_valid_pop_identity(session)?;
    session.barrier_state.current_history_authority_extension = Some(extension);
    session
        .barrier_state
        .current_global_history_attestation_bytes = attestation_bytes.clone();
    session.barrier_state.n_max = 1;
    session.barrier_state.max_barrier_update_bytes = 4096;
    let snapshot_pre = vec![Vec::new()];
    let kem_tree_hash_before = compute_barrier_tree_hash(1, snapshot_pre.as_slice())?;
    let built = build_barrier_update_bytes(
        &session.gid,
        1,
        0,
        1,
        0,
        session.barrier_state.barrier_roots_hash,
        kem_tree_hash_before,
        snapshot_pre.as_slice(),
    )?;
    let mut header = build_activation_guard_header(session, 1, session.fs_ec, &built.raw_update)?;
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );
    header.insert(
        hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
        Value::Bytes(attestation_bytes.clone()),
    );
    let raw_history_commitment = header
        .get(&hdr::HDR_BARRIER_HISTORY_COMMITMENT)
        .and_then(Value::as_bytes)
        .ok_or("missing test barrier history commitment header")?;
    let receipt = encode_full_verification_receipt(
        &session.gid,
        &author_leaf_id,
        1,
        0,
        raw_history_commitment,
        attestation_bytes.as_slice(),
        built.raw_update.as_slice(),
        session.pop_secret_key.as_slice(),
    )?;
    header.insert(
        hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
        Value::Bytes(receipt),
    );
    Ok(header)
}

fn fault_step(
    cut_point: FaultInjectionCutPoint,
    action: FaultInjectionAction,
) -> FaultInjectionStep {
    FaultInjectionStep { cut_point, action }
}

fn mutate_persisted_session(
    server_url: &str,
    room_id: &str,
    mutate: impl FnOnce(&mut PersistedSession),
) -> Result<(), Box<dyn std::error::Error>> {
    let path = session_file_path(server_url, room_id)?;
    let data = fs::read(&path)?;
    let mut persisted = decode_persisted_session(&data, &path)?;
    mutate(&mut persisted);
    let encoded = encrypt_persisted_session(&persisted, &path)?;
    fs::write(&path, encoded)?;
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_accepts_valid_local_bundle()
-> Result<(), Box<dyn std::error::Error>> {
    let session = build_test_session(0xB7, "http://127.0.0.1:9", "room-b6", "bob")?;
    let header = build_activation_guard_header(&session, 1, session.fs_ec, &[0xAA, 0xBB])?;
    validate_client_visible_activation_guards(&session, &header)?;
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_rejects_tampered_dev_chain_bind()
-> Result<(), Box<dyn std::error::Error>> {
    let session = build_test_session(0xB8, "http://127.0.0.1:9", "room-b7", "bob")?;
    let mut header = build_activation_guard_header(&session, 1, session.fs_ec, &[0xAA, 0xCC])?;
    header.insert(hdr::HDR_FS_DEV_COMMIT, Value::Bytes([0xEF; 32].to_vec()));
    let err = validate_client_visible_activation_guards(&session, &header)
        .expect_err("tampered fs_dev_commit must fail");
    assert!(
        err.to_string().contains("947.2"),
        "unexpected dev-chain-bind error: {err}"
    );
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_rejects_fs_epoch_base_ts_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let session = build_test_session(0xB9, "http://127.0.0.1:9", "room-b8", "bob")?;
    let mut header = build_activation_guard_header(&session, 1, session.fs_ec, &[0xAA, 0xDD])?;
    header.insert(
        hdr::HDR_FS_EPOCH_BASE_TS,
        Value::Integer(Integer::from(session.fs_epoch_base_ts.saturating_add(1))),
    );
    let err = validate_client_visible_activation_guards(&session, &header)
        .expect_err("mismatched fs_epoch_base_ts must fail");
    assert!(
        err.to_string().contains("945.0"),
        "unexpected fs_epoch_base_ts error: {err}"
    );
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_rejects_group_forward_jump()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB91, "http://127.0.0.1:9", "room-b81", "bob")?;
    session.last_accepted_ec = 10;
    let mut header =
        build_activation_guard_header(&session, 1, session.last_accepted_ec + 20, &[0xAA, 0xDE])?;
    header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0x55; 48]));
    let err = validate_client_visible_activation_guards(&session, &header)
        .expect_err("group forward jump beyond local policy window must fail");
    assert!(
        err.to_string().contains("947.6"),
        "unexpected group forward-jump error: {err}"
    );
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_rejects_new_device_forward_jump()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB92, "http://127.0.0.1:9", "room-b82", "bob")?;
    session.last_accepted_ec = 10;
    session.fs_forward_leap_policy.slack_anchor = 16;
    let mut header =
        build_activation_guard_header(&session, 1, session.last_accepted_ec + 15, &[0xAA, 0xDF])?;
    header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0x44; 48]));
    header.insert(hdr::HDR_FS_DEV_PREV_COMMIT, Value::Bytes(vec![0u8; 32]));
    let fs_dev_commit = compute_fs_dev_commit_v2(
        &[0x44; 48],
        session.last_accepted_ec + 15,
        &[0u8; 32],
        1,
        &compute_barrier_update_digest(&[0xAA, 0xDF])?,
    )?;
    header.insert(hdr::HDR_FS_DEV_COMMIT, Value::Bytes(fs_dev_commit.to_vec()));
    let err = validate_client_visible_activation_guards(&session, &header)
        .expect_err("new device forward jump beyond local first-device window must fail");
    assert!(
        err.to_string().contains("947.5"),
        "unexpected new-device forward-jump error: {err}"
    );
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_rejects_local_device_forward_jump()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB93, "http://127.0.0.1:9", "room-b83", "bob")?;
    session.fs_ec = 12;
    session.last_accepted_ec = 12;
    session.fs_forward_leap_policy.slack_anchor = 16;
    let header = build_activation_guard_header(&session, 1, session.fs_ec + 20, &[0xAA, 0xE0])?;
    let err = validate_client_visible_activation_guards(&session, &header)
        .expect_err("local device forward jump beyond local device window must fail");
    assert!(
        err.to_string().contains("947.4"),
        "unexpected local-device forward-jump error: {err}"
    );
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_rejects_full_verification_receipt_header()
-> Result<(), Box<dyn std::error::Error>> {
    let session = build_test_session(0xB94, "http://127.0.0.1:9", "room-b84", "bob")?;
    let mut header = build_activation_guard_header(&session, 1, session.fs_ec, &[0xAA, 0xE1])?;
    header.insert(
        hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
        Value::Bytes(vec![0x01]),
    );
    let err = validate_client_visible_activation_guards(&session, &header)
        .expect_err("reserved full_verification_receipt header must fail");
    assert!(
        err.to_string().contains("960.7") && err.to_string().contains("header[181]"),
        "unexpected reserved header error: {err}"
    );
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_rejects_global_history_attestation_header()
-> Result<(), Box<dyn std::error::Error>> {
    let session = build_test_session(0xB95, "http://127.0.0.1:9", "room-b85", "bob")?;
    let mut header = build_activation_guard_header(&session, 1, session.fs_ec, &[0xAA, 0xE2])?;
    header.insert(
        hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
        Value::Bytes(vec![0x02]),
    );
    let err = validate_client_visible_activation_guards(&session, &header)
        .expect_err("reserved global_history_attestation header must fail");
    assert!(
        err.to_string().contains("960.7") && err.to_string().contains("header[181]"),
        "unexpected reserved header error: {err}"
    );
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_accepts_matching_authority_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB96, "http://127.0.0.1:9", "room-b86", "bob")?;
    let header = build_authority_activation_guard_header(
        &mut session,
        HistoryAuthorityExtension::LocalHistoryAuthorityV1,
        vec![0xAA, 0xBB, 0xCC],
    )?;
    validate_client_visible_activation_guards(&session, &header)?;
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_rejects_missing_receipt_for_local_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB96, "http://127.0.0.1:9", "room-b86-miss", "bob")?;
    let mut header = build_authority_activation_guard_header(
        &mut session,
        HistoryAuthorityExtension::LocalHistoryAuthorityV1,
        vec![0xAA, 0xBB, 0xCC],
    )?;
    header.remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT);
    let err = validate_client_visible_activation_guards(&session, &header)
        .expect_err("authority-bound barrier state without receipt must fail");
    assert!(
        err.to_string().contains("960.7") && err.to_string().contains("header[181]"),
        "unexpected missing receipt error: {err}"
    );
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_accepts_matching_global_authority_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB97, "http://127.0.0.1:9", "room-b87g", "bob")?;
    let header = build_authority_activation_guard_header(
        &mut session,
        HistoryAuthorityExtension::GlobalHistoryAuthorityV1,
        vec![0xDE, 0xAD, 0xBE, 0xEF],
    )?;
    validate_client_visible_activation_guards(&session, &header)?;
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_accepts_global_authority_headers_without_pinned_local_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB972, "http://127.0.0.1:9", "room-b87g-nopin", "bob")?;
    let header = build_authority_activation_guard_header(
        &mut session,
        HistoryAuthorityExtension::GlobalHistoryAuthorityV1,
        vec![0xDE, 0xAD, 0xBE, 0xEF],
    )?;
    session.barrier_state.current_history_authority_extension = None;
    session
        .barrier_state
        .current_global_history_attestation_bytes
        .clear();
    validate_client_visible_activation_guards(&session, &header)?;
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_rejects_missing_receipt_for_global_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB97, "http://127.0.0.1:9", "room-b87g-miss", "bob")?;
    let mut header = build_authority_activation_guard_header(
        &mut session,
        HistoryAuthorityExtension::GlobalHistoryAuthorityV1,
        vec![0xDE, 0xAD, 0xBE, 0xEF],
    )?;
    header.remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT);
    let err = validate_client_visible_activation_guards(&session, &header)
        .expect_err("global authority-bound barrier state without receipt must fail");
    assert!(
        err.to_string().contains("960.7") && err.to_string().contains("header[181]"),
        "unexpected missing receipt error: {err}"
    );
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_rejects_tampered_receipt_for_local_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB971, "http://127.0.0.1:9", "room-b87g-tamper", "bob")?;
    let mut header = build_authority_activation_guard_header(
        &mut session,
        HistoryAuthorityExtension::LocalHistoryAuthorityV1,
        vec![0xAA, 0xBB, 0xCC, 0xDD],
    )?;
    let receipt = header
        .get_mut(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
        .and_then(Value::as_bytes_mut)
        .ok_or("missing test receipt bytes")?;
    let last = receipt.last_mut().ok_or("empty test receipt bytes")?;
    *last ^= 0x01;
    let err = validate_client_visible_activation_guards(&session, &header)
        .expect_err("tampered receipt must fail");
    assert!(
        err.to_string()
            .contains("invalid header[181] full_verification_receipt"),
        "unexpected tampered receipt error: {err}"
    );
    Ok(())
}

#[test]
fn validate_client_visible_activation_guards_rejects_attested_state_without_extension()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB97, "http://127.0.0.1:9", "room-b87", "bob")?;
    session
        .barrier_state
        .current_global_history_attestation_bytes = vec![0xAA, 0xBB, 0xCC];
    let mut header = build_activation_guard_header(&session, 1, session.fs_ec, &[0xAA, 0xE4])?;
    header.insert(
        hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
        Value::Bytes(
            session
                .barrier_state
                .current_global_history_attestation_bytes
                .clone(),
        ),
    );
    let err = validate_client_visible_activation_guards(&session, &header)
        .expect_err("attested local state without extension must fail");
    assert!(
        err.to_string().contains("history authority extension"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn extract_barrier_update_digest_uses_raw_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let mut header = BTreeMap::new();
    let raw = vec![0x01, 0x02, 0x03, 0x04];
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(raw.clone()));
    assert_eq!(
        extract_barrier_update_digest(&header)?,
        Some(compute_barrier_update_digest(raw.as_slice())?)
    );
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Integer(Integer::from(7u64)));
    assert!(extract_barrier_update_digest(&header).is_err());
    Ok(())
}

#[test]
fn validate_barrier_tree_snapshot_auth_checks_hash_and_content()
-> Result<(), Box<dyn std::error::Error>> {
    let n_max = 4u64;
    let pk_entries = vec![Vec::new(); 7];
    let expected_hash = compute_barrier_tree_hash(n_max, pk_entries.as_slice())?;
    let mut snapshot = BarrierPublicTree {
        n_max,
        kem_tree_hash_after: [0xAB; 32],
        pk_entries: pk_entries.clone(),
    };

    let err = validate_barrier_tree_snapshot_auth(&expected_hash, n_max, &snapshot)
        .expect_err("mismatched response hash must fail");
    assert!(
        err.to_string().contains("960.9"),
        "unexpected snapshot-auth error: {err}"
    );

    snapshot.kem_tree_hash_after = expected_hash;
    snapshot.pk_entries[3] = vec![0x11; 1184];
    let err = validate_barrier_tree_snapshot_auth(&expected_hash, n_max, &snapshot)
        .expect_err("mismatched tree content must fail");
    assert!(
        err.to_string().contains("960.9"),
        "unexpected snapshot-auth error: {err}"
    );

    let good_snapshot = BarrierPublicTree {
        n_max,
        kem_tree_hash_after: expected_hash,
        pk_entries,
    };
    validate_barrier_tree_snapshot_auth(&expected_hash, n_max, &good_snapshot)?;
    Ok(())
}

#[test]
fn try_recover_barrier_from_header_returns_none_without_matches()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xC11, "http://127.0.0.1:9", "room-c", "carol")?;
    session.barrier_state.n_max = 8;
    session.barrier_state.cover_leaf_index = 3;
    session.barrier_state.barrier_version = 4;
    session.barrier_state.kem_tree_hash_after = [0xAA; 32];

    let _ = install_test_barrier_leaf_keypair(&mut session)?;

    let revoked_since_root = [0x11; 32];
    let revoked_root = [0x22; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    let new_public_keys = vec![
        test_new_public_key_wire(0)?,
        test_new_public_key_wire(1)?,
        test_new_public_key_wire(4)?,
    ];
    let cover = KemTreeCoverPayloadWire(3, vec![10, 4, 1, 0], None, Vec::new(), new_public_keys);
    let cover_bytes = to_cbor_vec(&cover)?;
    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        5,
        4,
        8,
        rrh.to_vec(),
        session.barrier_state.kem_tree_hash_after.to_vec(),
        [0xBB; 32].to_vec(),
        cover_bytes,
    );
    let update_bytes = to_cbor_vec(&update)?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
    header.insert(
        hdr::HDR_REVOKED_SINCE_ROOT,
        Value::Bytes(revoked_since_root.to_vec()),
    );
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );
    header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xDD; 32]));

    let recovered = try_recover_barrier_from_header(
        &session,
        &header,
        &session.we_epoch_id,
        session.fs_ec,
        DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
    )?;
    assert!(recovered.is_none());
    Ok(())
}

#[test]
fn try_recover_barrier_from_header_rejects_oversized_update()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xC12, "http://127.0.0.1:9", "room-c2", "cora")?;
    session.barrier_state.n_max = 8;
    session.barrier_state.cover_leaf_index = 3;
    session.barrier_state.barrier_version = 4;
    session.barrier_state.kem_tree_hash_after = [0xAA; 32];

    let revoked_since_root = [0x11; 32];
    let revoked_root = [0x22; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    let new_public_keys = vec![
        test_new_public_key_wire(0)?,
        test_new_public_key_wire(1)?,
        test_new_public_key_wire(4)?,
    ];
    let cover = KemTreeCoverPayloadWire(3, vec![10, 4, 1, 0], None, Vec::new(), new_public_keys);
    let cover_bytes = to_cbor_vec(&cover)?;
    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        5,
        4,
        8,
        rrh.to_vec(),
        session.barrier_state.kem_tree_hash_after.to_vec(),
        [0xBB; 32].to_vec(),
        cover_bytes,
    );
    let update_bytes = to_cbor_vec(&update)?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes.clone()));
    header.insert(
        hdr::HDR_REVOKED_SINCE_ROOT,
        Value::Bytes(revoked_since_root.to_vec()),
    );
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );
    header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xDD; 32]));

    let err = try_recover_barrier_from_header(
        &session,
        &header,
        &session.we_epoch_id,
        session.fs_ec,
        update_bytes.len().saturating_sub(1),
    )
    .expect_err("oversized barrier_update must be rejected");
    assert!(
        err.to_string().contains("exceeds max_barrier_update_bytes"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn try_recover_barrier_from_header_recovers_key_and_pcs_reseed()
-> Result<(), Box<dyn std::error::Error>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };

    let mut session = build_test_session(0xD44, "http://127.0.0.1:9", "room-d", "diana")?;
    session.barrier_state.n_max = 8;
    session.barrier_state.cover_leaf_index = 3;
    session.barrier_state.barrier_version = 8;
    session.barrier_state.kem_tree_hash_after = [0xAA; 32];
    let fs_ec = 31;

    let leaf_ek_bytes = install_test_barrier_leaf_keypair(&mut session)?;

    let revoked_since_root = [0x31; 32];
    let revoked_root = [0x32; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    session.revoked_since_root = revoked_since_root;
    session.revoked_root = revoked_root;
    session.barrier_state.barrier_roots_hash = rrh;

    let source_node = 4u64;
    let target_node = 10u64;
    let path_secret_source = [0x44; 32];
    let salt_1 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(session.gid.as_slice(), 1),
    )?;
    let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
    let salt_0 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(session.gid.as_slice(), 0),
    )?;
    let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
    let (ss, ct) =
        cityg_client::barrier_crypto::encapsulate_barrier_public_key(leaf_ek_bytes.as_slice())?;
    let target_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
    let aad = to_cbor_vec(&BarrierWrapAadPreimage(
        &session.gid,
        9,
        8,
        8,
        &rrh,
        &session.barrier_state.kem_tree_hash_after,
        &[0xBB; 32],
        3,
        source_node,
        target_node,
        &target_pkhash,
    ))?;
    let nonce_full = h_l(
        "barrier/wrap/nonce",
        &BarrierWrapNoncePreimage(source_node, target_node),
    )?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    let cipher = ChaCha20Poly1305::new((&ss).into());
    let wrapped_ps = cipher.encrypt(
        (&nonce).into(),
        Payload {
            msg: path_secret_source.as_slice(),
            aad: aad.as_slice(),
        },
    )?;

    let mut target_prefix = [0u8; 16];
    target_prefix.copy_from_slice(&target_pkhash[..16]);
    let node_ciphertexts = vec![NodeCiphertextWire(
        source_node,
        target_node,
        target_prefix.to_vec(),
        ct,
        wrapped_ps,
    )];
    let (_, _, ek_0) =
        derive_internal_node_key_material(session.gid.as_slice(), &ps_0, 9, &rrh, 8, 0)?;
    let (_, _, ek_1) =
        derive_internal_node_key_material(session.gid.as_slice(), &ps_1, 9, &rrh, 8, 1)?;
    let (_, _, ek_4) = derive_internal_node_key_material(
        session.gid.as_slice(),
        &path_secret_source,
        9,
        &rrh,
        8,
        4,
    )?;
    let new_public_keys = vec![
        NewPublicKeyWire(0, ek_0),
        NewPublicKeyWire(1, ek_1),
        NewPublicKeyWire(4, ek_4),
    ];
    let cover = KemTreeCoverPayloadWire(
        3,
        vec![10, 4, 1, 0],
        None,
        node_ciphertexts,
        new_public_keys,
    );
    let cover_bytes = to_cbor_vec(&cover)?;
    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        9,
        8,
        8,
        rrh.to_vec(),
        session.barrier_state.kem_tree_hash_after.to_vec(),
        [0xBB; 32].to_vec(),
        cover_bytes,
    );
    let update_bytes = to_cbor_vec(&update)?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
    header.insert(
        hdr::HDR_REVOKED_SINCE_ROOT,
        Value::Bytes(revoked_since_root.to_vec()),
    );
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );
    header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xEE; 32]));

    let recovered = try_recover_barrier_from_header(
        &session,
        &header,
        &session.we_epoch_id,
        fs_ec,
        DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
    )?
    .ok_or_else(|| anyhow!("expected recover result"))?;

    let barrier_salt = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(session.gid.as_slice(), 9, &rrh),
    )?;
    let expected_k_barrier = hkdf_blake3(&barrier_salt, &ps_0, BARRIER_KEY_INFO);
    assert_eq!(*recovered.k_barrier_new, expected_k_barrier);
    assert_eq!(recovered.derived_node_key_material.len(), 3);
    assert!(recovered.derived_node_key_material.contains_key(&0));
    assert!(recovered.derived_node_key_material.contains_key(&1));
    assert!(recovered.derived_node_key_material.contains_key(&4));

    let expected_k_fs_after_pcs = derive_k_fs_after_pcs(
        &session.forward_state.snapshot().k_fs,
        &session.we_epoch_id,
        fs_ec,
        9,
        &expected_k_barrier,
    )?;
    assert_eq!(
        recovered.k_fs_after_pcs.as_deref().copied(),
        Some(expected_k_fs_after_pcs)
    );
    Ok(())
}

#[test]
fn try_recover_barrier_from_header_rejects_new_public_key_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };

    let mut session = build_test_session(0xD4E, "http://127.0.0.1:9", "room-f", "frank")?;
    session.barrier_state.n_max = 8;
    session.barrier_state.cover_leaf_index = 3;
    session.barrier_state.barrier_version = 8;
    session.barrier_state.kem_tree_hash_after = [0xAA; 32];

    let leaf_ek_bytes = install_test_barrier_leaf_keypair(&mut session)?;

    let revoked_since_root = [0x31; 32];
    let revoked_root = [0x32; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    session.revoked_since_root = revoked_since_root;
    session.revoked_root = revoked_root;
    session.barrier_state.barrier_roots_hash = rrh;

    let source_node = 4u64;
    let target_node = 10u64;
    let path_secret_source = [0x44; 32];
    let salt_1 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(session.gid.as_slice(), 1),
    )?;
    let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
    let salt_0 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(session.gid.as_slice(), 0),
    )?;
    let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
    let (ss, ct) =
        cityg_client::barrier_crypto::encapsulate_barrier_public_key(leaf_ek_bytes.as_slice())?;
    let target_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
    let aad = to_cbor_vec(&BarrierWrapAadPreimage(
        &session.gid,
        9,
        8,
        8,
        &rrh,
        &session.barrier_state.kem_tree_hash_after,
        &[0xBB; 32],
        3,
        source_node,
        target_node,
        &target_pkhash,
    ))?;
    let nonce_full = h_l(
        "barrier/wrap/nonce",
        &BarrierWrapNoncePreimage(source_node, target_node),
    )?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    let cipher = ChaCha20Poly1305::new((&ss).into());
    let wrapped_ps = cipher.encrypt(
        (&nonce).into(),
        Payload {
            msg: path_secret_source.as_slice(),
            aad: aad.as_slice(),
        },
    )?;

    let mut target_prefix = [0u8; 16];
    target_prefix.copy_from_slice(&target_pkhash[..16]);
    let node_ciphertexts = vec![NodeCiphertextWire(
        source_node,
        target_node,
        target_prefix.to_vec(),
        ct,
        wrapped_ps,
    )];
    let (_, _, ek_0) =
        derive_internal_node_key_material(session.gid.as_slice(), &ps_0, 9, &rrh, 8, 0)?;
    let (_, _, mut ek_1) =
        derive_internal_node_key_material(session.gid.as_slice(), &ps_1, 9, &rrh, 8, 1)?;
    let (_, _, ek_4) = derive_internal_node_key_material(
        session.gid.as_slice(),
        &path_secret_source,
        9,
        &rrh,
        8,
        4,
    )?;
    ek_1[0] ^= 0xA5;
    let new_public_keys = vec![
        NewPublicKeyWire(0, ek_0),
        NewPublicKeyWire(1, ek_1),
        NewPublicKeyWire(4, ek_4),
    ];
    let cover = KemTreeCoverPayloadWire(
        3,
        vec![10, 4, 1, 0],
        None,
        node_ciphertexts,
        new_public_keys,
    );
    let cover_bytes = to_cbor_vec(&cover)?;
    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        9,
        8,
        8,
        rrh.to_vec(),
        session.barrier_state.kem_tree_hash_after.to_vec(),
        [0xBB; 32].to_vec(),
        cover_bytes,
    );
    let update_bytes = to_cbor_vec(&update)?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
    header.insert(
        hdr::HDR_REVOKED_SINCE_ROOT,
        Value::Bytes(revoked_since_root.to_vec()),
    );
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );
    header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xEF; 32]));

    let err = try_recover_barrier_from_header(
        &session,
        &header,
        &session.we_epoch_id,
        session.fs_ec,
        DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
    )
    .expect_err("ek_n mismatch must fail closed");
    assert!(
        err.to_string().contains("new_public_keys mismatch"),
        "unexpected error for ek_n mismatch: {err}"
    );
    Ok(())
}

#[test]
fn try_recover_barrier_from_header_rejects_when_pkhash_t_breaks_aad()
-> Result<(), Box<dyn std::error::Error>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };

    let mut session = build_test_session(0xD4F, "http://127.0.0.1:9", "room-g", "gina")?;
    session.barrier_state.n_max = 8;
    session.barrier_state.cover_leaf_index = 3;
    session.barrier_state.barrier_version = 8;
    session.barrier_state.kem_tree_hash_after = [0xAA; 32];

    let leaf_ek_bytes = install_test_barrier_leaf_keypair(&mut session)?;
    let correct_pkhash = session.barrier_state.pkhash_leaf;

    let revoked_since_root = [0x31; 32];
    let revoked_root = [0x32; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    session.revoked_since_root = revoked_since_root;
    session.revoked_root = revoked_root;
    session.barrier_state.barrier_roots_hash = rrh;

    let source_node = 4u64;
    let target_node = 10u64;
    let path_secret_source = [0x44; 32];
    let salt_1 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(session.gid.as_slice(), 1),
    )?;
    let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
    let salt_0 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(session.gid.as_slice(), 0),
    )?;
    let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
    let (ss, ct) =
        cityg_client::barrier_crypto::encapsulate_barrier_public_key(leaf_ek_bytes.as_slice())?;
    let aad = to_cbor_vec(&BarrierWrapAadPreimage(
        &session.gid,
        9,
        8,
        8,
        &rrh,
        &session.barrier_state.kem_tree_hash_after,
        &[0xBB; 32],
        3,
        source_node,
        target_node,
        &correct_pkhash,
    ))?;
    let nonce_full = h_l(
        "barrier/wrap/nonce",
        &BarrierWrapNoncePreimage(source_node, target_node),
    )?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    let cipher = ChaCha20Poly1305::new((&ss).into());
    let wrapped_ps = cipher.encrypt(
        (&nonce).into(),
        Payload {
            msg: path_secret_source.as_slice(),
            aad: aad.as_slice(),
        },
    )?;

    let mut target_prefix = [0u8; 16];
    target_prefix.copy_from_slice(&correct_pkhash[..16]);
    let node_ciphertexts = vec![NodeCiphertextWire(
        source_node,
        target_node,
        target_prefix.to_vec(),
        ct,
        wrapped_ps,
    )];
    let (_, _, ek_0) =
        derive_internal_node_key_material(session.gid.as_slice(), &ps_0, 9, &rrh, 8, 0)?;
    let (_, _, ek_1) =
        derive_internal_node_key_material(session.gid.as_slice(), &ps_1, 9, &rrh, 8, 1)?;
    let (_, _, ek_4) = derive_internal_node_key_material(
        session.gid.as_slice(),
        &path_secret_source,
        9,
        &rrh,
        8,
        4,
    )?;
    let new_public_keys = vec![
        NewPublicKeyWire(0, ek_0),
        NewPublicKeyWire(1, ek_1),
        NewPublicKeyWire(4, ek_4),
    ];
    let cover = KemTreeCoverPayloadWire(
        3,
        vec![10, 4, 1, 0],
        None,
        node_ciphertexts,
        new_public_keys,
    );
    let cover_bytes = to_cbor_vec(&cover)?;
    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        9,
        8,
        8,
        rrh.to_vec(),
        session.barrier_state.kem_tree_hash_after.to_vec(),
        [0xBB; 32].to_vec(),
        cover_bytes,
    );
    let update_bytes = to_cbor_vec(&update)?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
    header.insert(
        hdr::HDR_REVOKED_SINCE_ROOT,
        Value::Bytes(revoked_since_root.to_vec()),
    );
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );
    header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xEF; 32]));

    let mut bad_pkhash = correct_pkhash;
    bad_pkhash[31] ^= 0x01;
    session.barrier_state.pkhash_leaf = bad_pkhash;

    let err = try_recover_barrier_from_header(
        &session,
        &header,
        &session.we_epoch_id,
        session.fs_ec,
        DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
    )
    .expect_err("AAD mismatch from pkhash_t must fail closed");
    assert!(
        err.to_string().contains("candidate unwrap/decrypt failure"),
        "unexpected error for pkhash_t AAD mismatch: {err}"
    );
    Ok(())
}

#[test]
fn try_recover_barrier_from_header_rejects_when_client_pkhash_t_mismatches()
-> Result<(), Box<dyn std::error::Error>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };

    let mut session = build_test_session(0xD45, "http://127.0.0.1:9", "room-e", "erin")?;
    session.barrier_state.n_max = 8;
    session.barrier_state.cover_leaf_index = 3;
    session.barrier_state.barrier_version = 8;
    session.barrier_state.kem_tree_hash_after = [0xAA; 32];

    let leaf_ek_bytes = install_test_barrier_leaf_keypair(&mut session)?;
    let target_pkhash = session.barrier_state.pkhash_leaf;

    let revoked_since_root = [0x31; 32];
    let revoked_root = [0x32; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    session.revoked_since_root = revoked_since_root;
    session.revoked_root = revoked_root;
    session.barrier_state.barrier_roots_hash = rrh;

    let source_node = 4u64;
    let target_node = 10u64;
    let path_secret_source = [0x44; 32];
    let (ss, ct) =
        cityg_client::barrier_crypto::encapsulate_barrier_public_key(leaf_ek_bytes.as_slice())?;
    let aad = to_cbor_vec(&BarrierWrapAadPreimage(
        &session.gid,
        9,
        8,
        8,
        &rrh,
        &[0xBC; 32],
        &[0xBD; 32],
        3,
        source_node,
        target_node,
        &target_pkhash,
    ))?;
    let nonce_full = h_l(
        "barrier/wrap/nonce",
        &BarrierWrapNoncePreimage(source_node, target_node),
    )?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    let cipher = ChaCha20Poly1305::new((&ss).into());
    let wrapped_ps = cipher.encrypt(
        (&nonce).into(),
        Payload {
            msg: path_secret_source.as_slice(),
            aad: aad.as_slice(),
        },
    )?;

    let mut target_prefix = [0u8; 16];
    target_prefix.copy_from_slice(&target_pkhash[..16]);
    let node_ciphertexts = vec![NodeCiphertextWire(
        source_node,
        target_node,
        target_prefix.to_vec(),
        ct,
        wrapped_ps,
    )];
    let new_public_keys = vec![
        test_new_public_key_wire(0)?,
        test_new_public_key_wire(1)?,
        test_new_public_key_wire(4)?,
    ];
    let cover = KemTreeCoverPayloadWire(
        3,
        vec![10, 4, 1, 0],
        None,
        node_ciphertexts,
        new_public_keys,
    );
    let cover_bytes = to_cbor_vec(&cover)?;
    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        9,
        8,
        8,
        rrh.to_vec(),
        session.barrier_state.kem_tree_hash_after.to_vec(),
        [0xBB; 32].to_vec(),
        cover_bytes,
    );
    let update_bytes = to_cbor_vec(&update)?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
    header.insert(
        hdr::HDR_REVOKED_SINCE_ROOT,
        Value::Bytes(revoked_since_root.to_vec()),
    );
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );
    header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xEF; 32]));

    session.barrier_state.pkhash_leaf = [0xFF; 32];
    let recovered = try_recover_barrier_from_header(
        &session,
        &header,
        &session.we_epoch_id,
        session.fs_ec,
        DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
    )?;
    assert!(
        recovered.is_none(),
        "pkhash mismatch must prevent barrier recovery"
    );
    Ok(())
}

#[test]
fn try_recover_barrier_from_header_rejects_reason_mismatch_for_local_roots()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xD50, "http://127.0.0.1:9", "room-h", "helen")?;
    session.barrier_state.n_max = 8;
    session.barrier_state.cover_leaf_index = 3;
    session.barrier_state.barrier_version = 4;
    session.barrier_state.kem_tree_hash_after = [0xAA; 32];

    let revoked_since_root = [0x41; 32];
    let revoked_root = [0x42; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    let new_public_keys = vec![
        test_new_public_key_wire(0)?,
        test_new_public_key_wire(1)?,
        test_new_public_key_wire(4)?,
    ];
    let update_bytes = to_cbor_vec(&BarrierUpdateWire(
        "barrier-v1".to_string(),
        5,
        4,
        8,
        rrh.to_vec(),
        session.barrier_state.kem_tree_hash_after.to_vec(),
        [0xBB; 32].to_vec(),
        to_cbor_vec(&KemTreeCoverPayloadWire(
            3,
            vec![10, 4, 1, 0],
            None,
            Vec::new(),
            new_public_keys,
        ))?,
    ))?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
    header.insert(
        hdr::HDR_REVOKED_SINCE_ROOT,
        Value::Bytes(revoked_since_root.to_vec()),
    );
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );

    let err = try_recover_barrier_from_header(
        &session,
        &header,
        &session.we_epoch_id,
        session.fs_ec,
        DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
    )
    .expect_err("local revocation roots mismatch must reject pcs_refresh reason");
    assert!(
        err.to_string()
            .contains("barrier_update_reason must be revocation_or_bootstrap (0)"),
        "unexpected error for reason mismatch: {err}"
    );
    Ok(())
}

#[test]
fn try_recover_barrier_from_header_rejects_local_barrier_version_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xD51, "http://127.0.0.1:9", "room-i", "irene")?;
    session.barrier_state.n_max = 8;
    session.barrier_state.cover_leaf_index = 3;
    session.barrier_state.barrier_version = 4;
    session.barrier_state.kem_tree_hash_after = [0xAA; 32];

    let revoked_since_root = [0x51; 32];
    let revoked_root = [0x52; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    let new_public_keys = vec![
        test_new_public_key_wire(0)?,
        test_new_public_key_wire(1)?,
        test_new_public_key_wire(4)?,
    ];
    let update_bytes = to_cbor_vec(&BarrierUpdateWire(
        "barrier-v1".to_string(),
        6,
        5,
        8,
        rrh.to_vec(),
        session.barrier_state.kem_tree_hash_after.to_vec(),
        [0xBB; 32].to_vec(),
        to_cbor_vec(&KemTreeCoverPayloadWire(
            3,
            vec![10, 4, 1, 0],
            None,
            Vec::new(),
            new_public_keys,
        ))?,
    ))?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
    header.insert(
        hdr::HDR_REVOKED_SINCE_ROOT,
        Value::Bytes(revoked_since_root.to_vec()),
    );
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );

    let err = try_recover_barrier_from_header(
        &session,
        &header,
        &session.we_epoch_id,
        session.fs_ec,
        DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
    )
    .expect_err("local barrier version gaps must reject recover");
    assert!(
        err.to_string()
            .contains("barrier version progression does not match local barrier state"),
        "unexpected error for local barrier progression mismatch: {err}"
    );
    Ok(())
}

#[test]
fn try_recover_barrier_best_effort_allows_local_barrier_version_gap()
-> Result<(), Box<dyn std::error::Error>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };

    let mut session = build_test_session(0xD53, "http://127.0.0.1:9", "room-k", "kate")?;
    session.barrier_state.n_max = 8;
    session.barrier_state.cover_leaf_index = 3;
    session.barrier_state.barrier_version = 7;
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.kem_tree_hash_after = [0xAA; 32];
    let fs_ec = 31;

    let leaf_ek_bytes = install_test_barrier_leaf_keypair(&mut session)?;

    let revoked_since_root = [0x71; 32];
    let revoked_root = [0x72; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    session.revoked_since_root = revoked_since_root;
    session.revoked_root = revoked_root;
    session.barrier_state.barrier_roots_hash = rrh;

    let source_node = 4u64;
    let target_node = 10u64;
    let path_secret_source = [0x74; 32];
    let salt_1 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(session.gid.as_slice(), 1),
    )?;
    let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
    let salt_0 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(session.gid.as_slice(), 0),
    )?;
    let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
    let (ss, ct) =
        cityg_client::barrier_crypto::encapsulate_barrier_public_key(leaf_ek_bytes.as_slice())?;
    let target_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
    let aad = to_cbor_vec(&BarrierWrapAadPreimage(
        &session.gid,
        9,
        8,
        8,
        &rrh,
        &[0xBC; 32],
        &[0xBD; 32],
        3,
        source_node,
        target_node,
        &target_pkhash,
    ))?;
    let nonce_full = h_l(
        "barrier/wrap/nonce",
        &BarrierWrapNoncePreimage(source_node, target_node),
    )?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    let cipher = ChaCha20Poly1305::new((&ss).into());
    let wrapped_ps = cipher.encrypt(
        (&nonce).into(),
        Payload {
            msg: path_secret_source.as_slice(),
            aad: aad.as_slice(),
        },
    )?;

    let mut target_prefix = [0u8; 16];
    target_prefix.copy_from_slice(&target_pkhash[..16]);
    let node_ciphertexts = vec![NodeCiphertextWire(
        source_node,
        target_node,
        target_prefix.to_vec(),
        ct,
        wrapped_ps,
    )];
    let (_, _, ek_0) =
        derive_internal_node_key_material(session.gid.as_slice(), &ps_0, 9, &rrh, 8, 0)?;
    let (_, _, ek_1) =
        derive_internal_node_key_material(session.gid.as_slice(), &ps_1, 9, &rrh, 8, 1)?;
    let (_, _, ek_4) = derive_internal_node_key_material(
        session.gid.as_slice(),
        &path_secret_source,
        9,
        &rrh,
        8,
        4,
    )?;
    let new_public_keys = vec![
        NewPublicKeyWire(0, ek_0),
        NewPublicKeyWire(1, ek_1),
        NewPublicKeyWire(4, ek_4),
    ];
    let cover = KemTreeCoverPayloadWire(
        3,
        vec![10, 4, 1, 0],
        None,
        node_ciphertexts,
        new_public_keys,
    );
    let cover_bytes = to_cbor_vec(&cover)?;
    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        9,
        8,
        8,
        rrh.to_vec(),
        [0xBC; 32].to_vec(),
        [0xBD; 32].to_vec(),
        cover_bytes,
    );
    let update_bytes = to_cbor_vec(&update)?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
    header.insert(
        hdr::HDR_REVOKED_SINCE_ROOT,
        Value::Bytes(revoked_since_root.to_vec()),
    );
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );
    header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xED; 32]));

    let recovered = try_recover_barrier_best_effort(
        &session,
        &header,
        &session.we_epoch_id,
        fs_ec,
        DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
    )?
    .ok_or_else(|| anyhow!("expected best-effort recover result"))?;

    let barrier_salt = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(session.gid.as_slice(), 9, &rrh),
    )?;
    let expected_k_barrier = hkdf_blake3(&barrier_salt, &ps_0, BARRIER_KEY_INFO);
    assert_eq!(*recovered.k_barrier_new, expected_k_barrier);
    assert_eq!(recovered.kem_tree_hash_after, [0xBD; 32]);
    assert_eq!(recovered.derived_node_key_material.len(), 3);

    let expected_k_fs_after_pcs = derive_k_fs_after_pcs(
        &session.forward_state.snapshot().k_fs,
        &session.we_epoch_id,
        fs_ec,
        9,
        &expected_k_barrier,
    )?;
    assert_eq!(
        recovered.k_fs_after_pcs.as_deref().copied(),
        Some(expected_k_fs_after_pcs)
    );
    apply_recovered_barrier_state(&mut session, recovered, false)?;
    assert!(!session.barrier_state.barrier_recovery_pending);
    assert!(!session.barrier_state.current_barrier_full_verified);
    assert_eq!(session.barrier_state.barrier_version, 9);
    assert_eq!(session.barrier_state.kem_tree_hash_after, [0xBD; 32]);
    Ok(())
}

#[test]
fn try_recover_barrier_best_effort_rejects_tampered_kem_tree_hash_before_in_aad()
-> Result<(), Box<dyn std::error::Error>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };

    let mut session = build_test_session(0xD54, "http://127.0.0.1:9", "room-k2", "kate")?;
    session.barrier_state.n_max = 8;
    session.barrier_state.cover_leaf_index = 3;
    session.barrier_state.barrier_version = 7;
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.kem_tree_hash_after = [0xAA; 32];

    let leaf_ek_bytes = install_test_barrier_leaf_keypair(&mut session)?;

    let revoked_since_root = [0x71; 32];
    let revoked_root = [0x72; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    session.revoked_since_root = revoked_since_root;
    session.revoked_root = revoked_root;
    session.barrier_state.barrier_roots_hash = rrh;

    let source_node = 4u64;
    let target_node = 10u64;
    let path_secret_source = [0x74; 32];
    let salt_1 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(session.gid.as_slice(), 1),
    )?;
    let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
    let salt_0 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(session.gid.as_slice(), 0),
    )?;
    let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
    let (ss, ct) =
        cityg_client::barrier_crypto::encapsulate_barrier_public_key(leaf_ek_bytes.as_slice())?;
    let target_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
    let aad = to_cbor_vec(&BarrierWrapAadPreimage(
        &session.gid,
        9,
        8,
        8,
        &rrh,
        &[0xBC; 32],
        &[0xBD; 32],
        3,
        source_node,
        target_node,
        &target_pkhash,
    ))?;
    let nonce_full = h_l(
        "barrier/wrap/nonce",
        &BarrierWrapNoncePreimage(source_node, target_node),
    )?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    let cipher = ChaCha20Poly1305::new((&ss).into());
    let wrapped_ps = cipher.encrypt(
        (&nonce).into(),
        Payload {
            msg: path_secret_source.as_slice(),
            aad: aad.as_slice(),
        },
    )?;

    let mut target_prefix = [0u8; 16];
    target_prefix.copy_from_slice(&target_pkhash[..16]);
    let node_ciphertexts = vec![NodeCiphertextWire(
        source_node,
        target_node,
        target_prefix.to_vec(),
        ct,
        wrapped_ps,
    )];
    let (_, _, ek_0) =
        derive_internal_node_key_material(session.gid.as_slice(), &ps_0, 9, &rrh, 8, 0)?;
    let (_, _, ek_1) =
        derive_internal_node_key_material(session.gid.as_slice(), &ps_1, 9, &rrh, 8, 1)?;
    let (_, _, ek_4) = derive_internal_node_key_material(
        session.gid.as_slice(),
        &path_secret_source,
        9,
        &rrh,
        8,
        4,
    )?;
    let new_public_keys = vec![
        NewPublicKeyWire(0, ek_0),
        NewPublicKeyWire(1, ek_1),
        NewPublicKeyWire(4, ek_4),
    ];
    let cover = KemTreeCoverPayloadWire(
        3,
        vec![10, 4, 1, 0],
        None,
        node_ciphertexts,
        new_public_keys,
    );
    let cover_bytes = to_cbor_vec(&cover)?;
    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        9,
        8,
        8,
        rrh.to_vec(),
        [0xBE; 32].to_vec(),
        [0xBD; 32].to_vec(),
        cover_bytes,
    );
    let update_bytes = to_cbor_vec(&update)?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
    header.insert(
        hdr::HDR_REVOKED_SINCE_ROOT,
        Value::Bytes(revoked_since_root.to_vec()),
    );
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );
    header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xED; 32]));

    let err = try_recover_barrier_best_effort(
        &session,
        &header,
        &session.we_epoch_id,
        31,
        DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
    )
    .expect_err("tampered kem_tree_hash_before must fail recovery AAD");
    assert!(
        err.to_string().contains("candidate unwrap/decrypt failure"),
        "unexpected error for kem_tree_hash_before AAD mismatch: {err}"
    );
    Ok(())
}

#[test]
fn try_recover_barrier_best_effort_rejects_tampered_kem_tree_hash_after_in_aad()
-> Result<(), Box<dyn std::error::Error>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };

    let mut session = build_test_session(0xD55, "http://127.0.0.1:9", "room-k3", "kate")?;
    session.barrier_state.n_max = 8;
    session.barrier_state.cover_leaf_index = 3;
    session.barrier_state.barrier_version = 7;
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.kem_tree_hash_after = [0xAA; 32];

    let leaf_ek_bytes = install_test_barrier_leaf_keypair(&mut session)?;

    let revoked_since_root = [0x71; 32];
    let revoked_root = [0x72; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    session.revoked_since_root = revoked_since_root;
    session.revoked_root = revoked_root;
    session.barrier_state.barrier_roots_hash = rrh;

    let source_node = 4u64;
    let target_node = 10u64;
    let path_secret_source = [0x74; 32];
    let salt_1 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(session.gid.as_slice(), 1),
    )?;
    let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
    let salt_0 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(session.gid.as_slice(), 0),
    )?;
    let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
    let (ss, ct) =
        cityg_client::barrier_crypto::encapsulate_barrier_public_key(leaf_ek_bytes.as_slice())?;
    let target_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
    let aad = to_cbor_vec(&BarrierWrapAadPreimage(
        &session.gid,
        9,
        8,
        8,
        &rrh,
        &[0xBC; 32],
        &[0xBD; 32],
        3,
        source_node,
        target_node,
        &target_pkhash,
    ))?;
    let nonce_full = h_l(
        "barrier/wrap/nonce",
        &BarrierWrapNoncePreimage(source_node, target_node),
    )?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    let cipher = ChaCha20Poly1305::new((&ss).into());
    let wrapped_ps = cipher.encrypt(
        (&nonce).into(),
        Payload {
            msg: path_secret_source.as_slice(),
            aad: aad.as_slice(),
        },
    )?;

    let mut target_prefix = [0u8; 16];
    target_prefix.copy_from_slice(&target_pkhash[..16]);
    let node_ciphertexts = vec![NodeCiphertextWire(
        source_node,
        target_node,
        target_prefix.to_vec(),
        ct,
        wrapped_ps,
    )];
    let (_, _, ek_0) =
        derive_internal_node_key_material(session.gid.as_slice(), &ps_0, 9, &rrh, 8, 0)?;
    let (_, _, ek_1) =
        derive_internal_node_key_material(session.gid.as_slice(), &ps_1, 9, &rrh, 8, 1)?;
    let (_, _, ek_4) = derive_internal_node_key_material(
        session.gid.as_slice(),
        &path_secret_source,
        9,
        &rrh,
        8,
        4,
    )?;
    let new_public_keys = vec![
        NewPublicKeyWire(0, ek_0),
        NewPublicKeyWire(1, ek_1),
        NewPublicKeyWire(4, ek_4),
    ];
    let cover = KemTreeCoverPayloadWire(
        3,
        vec![10, 4, 1, 0],
        None,
        node_ciphertexts,
        new_public_keys,
    );
    let cover_bytes = to_cbor_vec(&cover)?;
    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        9,
        8,
        8,
        rrh.to_vec(),
        [0xBC; 32].to_vec(),
        [0xBE; 32].to_vec(),
        cover_bytes,
    );
    let update_bytes = to_cbor_vec(&update)?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
    header.insert(
        hdr::HDR_REVOKED_SINCE_ROOT,
        Value::Bytes(revoked_since_root.to_vec()),
    );
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );
    header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xED; 32]));

    let err = try_recover_barrier_best_effort(
        &session,
        &header,
        &session.we_epoch_id,
        31,
        DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
    )
    .expect_err("tampered kem_tree_hash_after must fail recovery AAD");
    assert!(
        err.to_string().contains("candidate unwrap/decrypt failure"),
        "unexpected error for kem_tree_hash_after AAD mismatch: {err}"
    );
    Ok(())
}

#[test]
fn barrier_kdfs_bind_gid_directly() -> Result<(), Box<dyn std::error::Error>> {
    let gid_a = [0x11; 32];
    let gid_b = [0x22; 32];
    let rrh = [0x33; 32];
    let path_secret_leaf = [0x44; 32];

    let salt_a_1 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(gid_a.as_slice(), 1),
    )?;
    let salt_b_1 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(gid_b.as_slice(), 1),
    )?;
    assert_ne!(salt_a_1, salt_b_1, "tree path salt must bind gid");

    let ps_a_1 = hkdf_blake3(&salt_a_1, &path_secret_leaf, BARRIER_TREE_INFO);
    let ps_b_1 = hkdf_blake3(&salt_b_1, &path_secret_leaf, BARRIER_TREE_INFO);
    assert_ne!(ps_a_1, ps_b_1, "path secret lineage must separate gids");

    let salt_a_0 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(gid_a.as_slice(), 0),
    )?;
    let salt_b_0 = h_l(
        "barrier/tree/path",
        &BarrierTreePathSaltPreimage(gid_b.as_slice(), 0),
    )?;
    let ps_a_0 = hkdf_blake3(&salt_a_0, &ps_a_1, BARRIER_TREE_INFO);
    let ps_b_0 = hkdf_blake3(&salt_b_0, &ps_b_1, BARRIER_TREE_INFO);

    let barrier_salt_a = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(gid_a.as_slice(), 9, &rrh),
    )?;
    let barrier_salt_b = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(gid_b.as_slice(), 9, &rrh),
    )?;
    assert_ne!(barrier_salt_a, barrier_salt_b, "barrier salt must bind gid");

    let k_barrier_a = hkdf_blake3(&barrier_salt_a, &ps_a_0, BARRIER_KEY_INFO);
    let k_barrier_b = hkdf_blake3(&barrier_salt_b, &ps_b_0, BARRIER_KEY_INFO);
    assert_ne!(k_barrier_a, k_barrier_b, "barrier key must separate gids");

    let (_, pkhash_a, ek_a) =
        derive_internal_node_key_material(gid_a.as_slice(), &ps_a_1, 9, &rrh, 8, 1)?;
    let (_, pkhash_b, ek_b) =
        derive_internal_node_key_material(gid_b.as_slice(), &ps_b_1, 9, &rrh, 8, 1)?;
    assert_ne!(
        pkhash_a, pkhash_b,
        "internal node pkhash must separate gids"
    );
    assert_ne!(ek_a, ek_b, "internal node ek must separate gids");
    Ok(())
}

#[test]
fn try_recover_barrier_from_header_rejects_stale_genesis_after_local_init()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xD52, "http://127.0.0.1:9", "room-j", "jules")?;
    session.barrier_state.n_max = 8;
    session.barrier_state.cover_leaf_index = 3;
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.barrier_version = 0;
    session.barrier_state.barrier_roots_hash = [0x10; 32];
    session.barrier_state.kem_tree_hash_after = [0xAA; 32];

    let revoked_since_root = [0x61; 32];
    let revoked_root = [0x62; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    let new_public_keys = vec![
        test_new_public_key_wire(0)?,
        test_new_public_key_wire(1)?,
        test_new_public_key_wire(4)?,
    ];
    let update_bytes = to_cbor_vec(&BarrierUpdateWire(
        "barrier-v1".to_string(),
        0,
        0,
        8,
        rrh.to_vec(),
        session.barrier_state.kem_tree_hash_after.to_vec(),
        [0xBB; 32].to_vec(),
        to_cbor_vec(&KemTreeCoverPayloadWire(
            3,
            vec![10, 4, 1, 0],
            None,
            Vec::new(),
            new_public_keys,
        ))?,
    ))?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
    header.insert(
        hdr::HDR_REVOKED_SINCE_ROOT,
        Value::Bytes(revoked_since_root.to_vec()),
    );
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );

    let err = try_recover_barrier_from_header(
        &session,
        &header,
        &session.we_epoch_id,
        session.fs_ec,
        DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
    )
    .expect_err("post-genesis version 0 replay must reject recover");
    assert!(
        err.to_string()
            .contains("barrier version progression does not match local barrier state"),
        "unexpected error for stale genesis replay: {err}"
    );
    Ok(())
}

struct EnvVarRestore {
    original: Option<String>,
}

impl Drop for EnvVarRestore {
    fn drop(&mut self) {
        match self.original.as_deref() {
            Some(value) => {
                // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                unsafe { std::env::set_var(SESSION_PASSPHRASE_ENV, value) };
            }
            None => {
                // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                unsafe { std::env::remove_var(SESSION_PASSPHRASE_ENV) };
            }
        }
    }
}

struct MessageTokenEnvVarRestore {
    client_original: Option<String>,
    server_original: Option<String>,
}

impl Drop for MessageTokenEnvVarRestore {
    fn drop(&mut self) {
        match self.client_original.as_deref() {
            Some(value) => {
                // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                unsafe { std::env::set_var(CLIENT_MESSAGE_TOKEN_ENV, value) };
            }
            None => {
                // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                unsafe { std::env::remove_var(CLIENT_MESSAGE_TOKEN_ENV) };
            }
        }

        match self.server_original.as_deref() {
            Some(value) => {
                // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                unsafe { std::env::set_var("CITYG_SERVER_MESSAGE_AUTH_TOKEN", value) };
            }
            None => {
                // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                unsafe { std::env::remove_var("CITYG_SERVER_MESSAGE_AUTH_TOKEN") };
            }
        }
    }
}

async fn spawn_server_on(port: u16) -> JoinHandle<()> {
    init_test_auth_env();
    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut config = CityGConfig::default();
        config.server.seed_demo_room = false;
        if let Err(err) = cityg_api::run_with_config(addr, config).await {
            eprintln!("server exited with error: {err}");
        }
    })
}

async fn spawn_ready_test_server() -> Result<(u16, JoinHandle<()>), anyhow::Error> {
    for _ in 0..16 {
        let port = next_test_port();
        let handle = spawn_server_on(port).await;
        for _ in 0..40 {
            if handle.is_finished() {
                break;
            }
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                sleep(Duration::from_millis(100)).await;
                return Ok((port, handle));
            }
            sleep(Duration::from_millis(50)).await;
        }
        handle.abort();
        let _ = handle.await;
    }
    Err(anyhow!("failed to spawn ready test server"))
}

async fn spawn_server_on_with_state_path(
    port: u16,
    state_path: std::path::PathBuf,
) -> JoinHandle<()> {
    init_test_auth_env();
    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut config = CityGConfig::default();
        config.server.seed_demo_room = false;
        config.server.state_path = Some(state_path);
        if let Err(err) = cityg_api::run_with_config(addr, config).await {
            eprintln!("server exited with error: {err}");
        }
    })
}

async fn spawn_server_with_seed_demo_room(port: u16, seed_demo_room: bool) -> JoinHandle<()> {
    init_test_auth_env();
    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut config = CityGConfig::default();
        config.server.seed_demo_room = seed_demo_room;
        if let Err(err) = cityg_api::run_with_config(addr, config).await {
            eprintln!("server exited with error: {err}");
        }
    })
}

async fn bootstrap_test_room_with_admin_identity(
    server_url: &str,
    room_id: &str,
) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let identity = cityg_api_client::generate_room_admin_identity();
    let admin_proof = identity.build_kbroad_proof(
        RoomAdminOperation::Bootstrap,
        room_id,
        demo::kbroad_public(),
    )?;
    new_api_client(server_url)
        .bootstrap_room_as_admin(room_id, demo::kbroad_public(), admin_proof)
        .await
        .map_err(anyhow::Error::from)?;
    Ok((identity.pop_public_key, identity.pop_secret_key))
}

async fn bootstrap_test_room(server_url: &str, room_id: &str) -> Result<(), anyhow::Error> {
    bootstrap_test_room_with_admin_identity(server_url, room_id)
        .await
        .map(|_| ())
}

fn test_mouse_down_event() -> MouseDownEvent {
    test_mouse_down_event_with_button_and_click_count(MouseButton::Left, 1)
}

fn test_mouse_down_event_with_click_count(click_count: usize) -> MouseDownEvent {
    test_mouse_down_event_with_button_and_click_count(MouseButton::Left, click_count)
}

fn test_mouse_down_event_with_button(button: MouseButton) -> MouseDownEvent {
    test_mouse_down_event_with_button_and_click_count(button, 1)
}

fn test_mouse_down_event_with_button_and_click_count(
    button: MouseButton,
    click_count: usize,
) -> MouseDownEvent {
    MouseDownEvent {
        position: point(px(0.0), px(0.0)),
        modifiers: Modifiers::none(),
        button,
        click_count,
        first_mouse: false,
    }
}

#[gpui::test]
fn gpui_render_and_callback_paths_cover_ui_state(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    cx.refresh().expect("initial refresh");
    cx.run_until_parked();

    let session = build_test_session(
        0xC17,
        "http://127.0.0.1:9",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "sab",
    )
    .expect("build test session");

    view.update(cx, |model, _| {
        model.session = Some(session);
        model.messages.push(ChatMessageEntry {
            sender_leaf: Some([0x11; 32]),
            fallback_label: "sab".to_string(),
            plaintext: "hello".to_string(),
            ciphertext_hex: "abcd".to_string(),
            timestamp_ms: 1,
            delivery: MessageDelivery::Sent,
            pending_id: None,
        });
        model.members.push(MemberEntry {
            leaf_id: [0x11; 32],
            alias: Some("sab".to_string()),
            pop_public_key: Some(vec![0x01]),
            join_timestamp_ms: Some(1),
            last_seen_timestamp_ms: Some(2),
        });
        model.members_total = 1;
        model.members_status = MembersStatus::Idle;
        model.security_events.push(SecurityEvent {
            alias: "sab".to_string(),
            description: "security".to_string(),
            timestamp_ms: 11,
        });
        model.security_unread = 1;
        model.activity_events.push(ActivityEvent {
            timestamp_ms: 7,
            kind: ActivityKind::System,
            summary: "boot".to_string(),
            detail: Some("detail".to_string()),
        });
        model.categorized_error = Some(CategorizedError {
            category: ErrorCategory::Network,
            user_message: "network".to_string(),
            technical_details: "connection refused".to_string(),
            recovery_suggestion: "retry".to_string(),
            can_retry: true,
        });
        model.last_retry_action = Some(RetryAction::Join);
    });

    cx.refresh().expect("session refresh");
    cx.run_until_parked();

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            let event = test_mouse_down_event();

            model.on_copy_room_id(&event, window, view_cx);
            let copied_room = view_cx
                .read_from_clipboard()
                .and_then(|item| item.text())
                .expect("clipboard room id");
            assert_eq!(
                copied_room,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            );

            model.on_copy_room_invite(&event, window, view_cx);
            let copied_invite = view_cx
                .read_from_clipboard()
                .and_then(|item| item.text())
                .expect("clipboard room invite");
            assert!(copied_invite.starts_with(JOIN_INVITE_PREFIX));

            model.on_copy_regular_fingerprint(&event, window, view_cx);
            let copied_regular = view_cx
                .read_from_clipboard()
                .and_then(|item| item.text())
                .expect("clipboard regular fingerprint");
            assert_eq!(copied_regular.len(), 64);

            model.on_copy_fs_fingerprint(&event, window, view_cx);
            let copied_fs = view_cx
                .read_from_clipboard()
                .and_then(|item| item.text())
                .expect("clipboard fs fingerprint");
            assert_eq!(copied_fs.len(), 64);

            model.on_copy_error_details(&event, window, view_cx);
            model.on_report_issue(&event, window, view_cx);
            model.on_dismiss_error(&event, window, view_cx);
            assert!(model.categorized_error.is_none());

            model.on_generate_room_id(&event, window, view_cx);
            assert_eq!(model.join_form.room_id.len(), 64);

            model.on_toggle_ciphertext(&event, window, view_cx);
            assert!(model.show_ciphertext);

            model.on_security_panel_toggle_clicked(&event, window, view_cx);
            assert!(model.security_panel_expanded);
            assert_eq!(model.security_unread, 0);
            model.on_security_panel_mark_read_clicked(&event, window, view_cx);

            model.on_activity_clear_clicked(&event, window, view_cx);
            assert!(model.activity_events.is_empty());
            model.on_security_log_clear_clicked(&event, window, view_cx);
            assert!(model.security_events.is_empty());

            model.on_reset_clicked(&event, window, view_cx);
            assert!(model.session.is_none());
            model.on_leave_clicked(&event, window, view_cx);
            model.on_copy_room_id(&event, window, view_cx);
            model.on_copy_regular_fingerprint(&event, window, view_cx);
            model.on_copy_fs_fingerprint(&event, window, view_cx);
            model.on_retry_clicked(&event, window, view_cx);
        });
    });

    cx.refresh().expect("post-callback refresh");
    cx.run_until_parked();
}

#[test]
fn global_action_handlers_dispatch_to_main_app_model_from_secondary_window() {
    let mut cx = TestAppContext::single();
    cx.update(tokio_bridge::init);
    cx.update(app_actions::install_action_handlers);

    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let room_id = "fedcba98765432100123456789abcdef0123456789abcdef0123456789abcdef".to_string();
    let session = build_test_session(0xBEEF, "http://127.0.0.1:9", &room_id, "menu-forward")
        .expect("build test session");

    view.update(cx, |model, _| {
        model.session = Some(session);
    });
    cx.refresh().expect("main window refresh");
    cx.run_until_parked();

    let (_secondary_view, cx) = cx.add_window_view(|_, _| EmptyView);
    cx.update(|window, _| window.activate_window());
    cx.run_until_parked();

    cx.update(|_, app| {
        let active_is_main = app
            .active_window()
            .and_then(|window| window.downcast::<AppModel>())
            .is_some();
        assert!(
            !active_is_main,
            "secondary window should be active for menu forwarding coverage"
        );
        assert!(app.is_action_available(&CopyRoomIdAction));
    });
}

#[gpui::test]
fn gpui_missing_tokio_global_surfaces_scheduler_failures(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    init_test_auth_env();
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xD00D,
        "http://127.0.0.1:9",
        "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
        "no-tokio",
    )
    .expect("build session");

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());
        model.schedule_fetch(view_cx, Duration::ZERO);
        model.start_websocket(view_cx);
        model.start_members_refresh_task(view_cx);
    });

    view.update(cx, |model, _| {
        assert!(model.fetch_task.is_some(), "fetch task should be scheduled");
        assert!(
            model.ws_task.is_some(),
            "websocket task should be scheduled"
        );
        assert!(
            model.members_refresh_task.is_some(),
            "members refresh task should be scheduled"
        );
        assert!(model.fetch_in_flight, "fetch should be marked in-flight");
        assert!(matches!(model.fetch_status, FetchStatus::Refreshing));
    });
}

#[gpui::test]
fn gpui_missing_message_token_only_schedules_restore_sync_once(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let _env_lock = ENV_VAR_LOCK.lock().expect("env var lock");
    let _restore = MessageTokenEnvVarRestore {
        client_original: std::env::var(CLIENT_MESSAGE_TOKEN_ENV).ok(),
        server_original: std::env::var("CITYG_SERVER_MESSAGE_AUTH_TOKEN").ok(),
    };
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    unsafe { std::env::remove_var(CLIENT_MESSAGE_TOKEN_ENV) };
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    unsafe { std::env::remove_var("CITYG_SERVER_MESSAGE_AUTH_TOKEN") };

    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xBEEF,
        "http://127.0.0.1:9",
        "77aa55bb66cc11dd22ee33ff44aa55bb66cc77dd88ee99ff00aa11bb22cc33dd",
        "missing-token",
    )
    .expect("build session");

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());
        model.restore_epoch_sync_pending = true;

        model.bootstrap_session_runtime(view_cx);
        assert!(
            model.ws_task.is_none(),
            "ws task must stay absent without token"
        );
        assert!(
            model.ws_autostart_attempted,
            "autostart should be marked attempted"
        );
        assert!(
            model.epoch_sync_task.is_some(),
            "restore sync should still be scheduled once"
        );
        assert!(
            !model.restore_epoch_sync_pending,
            "restore sync marker must clear after scheduling"
        );

        model.stop_epoch_sync_task();
        model.bootstrap_session_runtime(view_cx);
        assert!(
            model.epoch_sync_task.is_none(),
            "missing token should not reschedule restore sync on later renders"
        );
    });
}

#[gpui::test]
fn gpui_root_render_does_not_bootstrap_runtime_tasks(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xCAFE,
        "http://127.0.0.1:9",
        "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
        "pure-render",
    )
    .expect("build session");

    cx.update_window_entity(&view, |model, window, view_cx| {
        model.session = Some(session);
        model.restore_epoch_sync_pending = true;
        model.fetch_task = None;
        model.fetch_in_flight = false;
        model.ws_task = None;
        model.ws_autostart_attempted = false;
        model.epoch_sync_task = None;
        model.members_refresh_task = None;
        model.room_admins_loaded = false;
        model.room_admin_status = RoomAdminStatus::Idle;

        let _ = model.render(window, view_cx);

        assert!(!model.fetch_in_flight, "render must not start fetch work");
        assert!(
            model.fetch_task.is_none(),
            "render must not spawn fetch task"
        );
        assert!(
            model.ws_task.is_none(),
            "render must not start websocket task"
        );
        assert!(
            !model.ws_autostart_attempted,
            "render must not toggle websocket autostart"
        );
        assert!(
            model.epoch_sync_task.is_none(),
            "render must not schedule epoch sync"
        );
        assert!(
            model.members_refresh_task.is_none(),
            "render must not start members refresh loop"
        );
        assert!(
            matches!(model.room_admin_status, RoomAdminStatus::Idle),
            "render must not kick off room-admin loading"
        );
        assert!(
            model.restore_epoch_sync_pending,
            "render must leave deferred restore sync untouched"
        );
    });
}

#[gpui::test]
fn gpui_handle_websocket_event_updates_state(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xA11CE,
        "http://127.0.0.1:9",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "ws",
    )
    .expect("build session");

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());
        model.handle_websocket_event(WebSocketEvent::Connected, view_cx);
        assert!(model.ws_connected);

        model.handle_websocket_event(
            WebSocketEvent::Message(WebSocketMessageSignal {
                sequence: Some(7),
                replayed: false,
            }),
            view_cx,
        );
        assert!(model.epoch_sync_task.is_some());
        assert!(!model.fetch_in_flight);
        assert!(matches!(model.fetch_status, FetchStatus::Idle));
        assert!(
            model
                .activity_events
                .iter()
                .any(|event| event.summary.contains("New message notification"))
        );

        model.handle_websocket_event(
            WebSocketEvent::Membership(MembershipSignal {
                gid: session.gid,
                leaf_id: Some(session.leaf_id),
                kind: Some(MembershipSignalKind::Join),
                sequence: Some(8),
                replayed: true,
                timestamp_ms: Some(42),
            }),
            view_cx,
        );
        assert!(
            model
                .activity_events
                .iter()
                .any(|event| event.summary.contains("Replayed roster join"))
        );

        model.handle_websocket_event(
            WebSocketEvent::SyncRequired(WebSocketSyncRequiredSignal {
                lagged_messages: 5,
                sequence: Some(11),
                timestamp_ms: Some(99),
                retained_from_sequence: Some(8),
                reason: Some("replay_window_exhausted".to_string()),
                action: Some("refetch_and_reconnect".to_string()),
                reconcile_via: Some("http".to_string()),
            }),
            view_cx,
        );
        assert!(model.epoch_sync_task.is_some());
        assert!(model.fetch_after_epoch_sync);
        assert!(model.activity_events.iter().any(|event| {
            event
                .summary
                .contains("Worker replay window exhausted; HTTP reconciliation required")
        }));

        model.handle_websocket_event(WebSocketEvent::Disconnected, view_cx);
        assert!(!model.ws_connected);
    });
}

#[gpui::test]
fn gpui_message_event_fetches_after_epoch_sync_even_when_head_is_unchanged(
    cx: &mut TestAppContext,
) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xB0B,
        "http://127.0.0.1:9",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "ws-sync",
    )
    .expect("build session");

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());

        model.handle_websocket_event(
            WebSocketEvent::Message(WebSocketMessageSignal {
                sequence: Some(12),
                replayed: true,
            }),
            view_cx,
        );
        assert!(model.epoch_sync_task.is_some());
        assert!(model.fetch_after_epoch_sync);
        assert!(model.activity_events.iter().any(|event| {
            event
                .summary
                .contains("Replayed message notification after reconnect")
        }));

        model.epoch_sync_task = None;
        model.handle_epoch_sync_result(
            Ok(EpochSyncOutcome {
                session: session.clone(),
                changed: false,
            }),
            &session.server_url,
            &session.room_id,
            session.leaf_id,
            "message notification",
            view_cx,
        );

        assert!(matches!(model.fetch_status, FetchStatus::Refreshing));
        assert!(model.fetch_in_flight);
        assert!(!model.fetch_after_epoch_sync);
    });
}

#[gpui::test]
fn gpui_render_panels_cover_conditional_branches(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xBEEF,
        "http://127.0.0.1:9",
        "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        "render",
    )
    .expect("build session");

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.session = Some(session);
            model.ws_connected = true;
            let panel_session = model.session.clone().expect("session available");
            model.room_admins = vec![panel_session.pop_public_key.clone()];
            model.room_admins_loaded = true;
            model.room_admin_target.focus();
            model
                .room_admin_target
                .set_value(hex_encode(vec![0xAA; room_admin_public_key_bytes()]));
            model.room_admin_revoke_confirmation = Some(vec![0xAA; room_admin_public_key_bytes()]);
            let _ = model.render_room_admin_panel(window, &panel_session, view_cx);
            let mut other_admin = panel_session.pop_public_key.clone();
            other_admin[0] ^= 0xFF;
            model.room_admins = vec![other_admin];
            let _ = model.render_room_admin_panel(window, &panel_session, view_cx);
            model.members = vec![MemberEntry {
                leaf_id: [0x11; 32],
                alias: Some("alice".to_string()),
                pop_public_key: Some(vec![0xAA; room_admin_public_key_bytes()]),
                join_timestamp_ms: Some(1),
                last_seen_timestamp_ms: Some(2),
            }];
            model.members_total = 3;
            model.members_next_offset = Some(1);
            model.members_mode = MembersMode::Search {
                query: "ali".to_string(),
            };
            model.members_search.focus();
            model.members_search.set_query("ali".to_string());
            let _ = model.render_members_panel(window, view_cx);

            model.security_events = vec![SecurityEvent {
                alias: "alice".to_string(),
                description: "joined".to_string(),
                timestamp_ms: 7,
            }];
            model.security_unread = 1;
            model.security_panel_expanded = true;
            let _ = model.render_security_panel(window, view_cx);

            model.security_events.clear();
            let _ = model.render_security_panel(window, view_cx);

            model.security_events = vec![SecurityEvent {
                alias: "bob".to_string(),
                description: "revoked".to_string(),
                timestamp_ms: 9,
            }];
            model.security_panel_expanded = false;
            let _ = model.render_security_panel(window, view_cx);

            model.activity_events = vec![
                ActivityEvent {
                    timestamp_ms: 1,
                    kind: ActivityKind::Connection,
                    summary: "connected".to_string(),
                    detail: Some("ws".to_string()),
                },
                ActivityEvent {
                    timestamp_ms: 2,
                    kind: ActivityKind::Roster,
                    summary: "roster".to_string(),
                    detail: None,
                },
                ActivityEvent {
                    timestamp_ms: 3,
                    kind: ActivityKind::Message,
                    summary: "message".to_string(),
                    detail: Some("cipher".to_string()),
                },
                ActivityEvent {
                    timestamp_ms: 4,
                    kind: ActivityKind::Sync,
                    summary: "sync".to_string(),
                    detail: None,
                },
                ActivityEvent {
                    timestamp_ms: 5,
                    kind: ActivityKind::System,
                    summary: "system".to_string(),
                    detail: Some("ok".to_string()),
                },
            ];
            let _ = model.render_activity_panel(window, view_cx);
        });
    });
}

#[gpui::test]
fn gpui_render_material_shells_with_inactive_window(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xBEE0,
        "http://127.0.0.1:9",
        "22334455667788990011aabbccddeeff22334455667788990011aabbccddeeff",
        "inactive-materials",
    )
    .expect("build session");

    cx.deactivate_window();
    cx.update(|window, app| {
        assert!(!window.is_window_active());
        view.update(app, |model, view_cx| {
            model.session = Some(session.clone());
            model.ws_connected = true;
            model.inspector_visible = true;

            let panel_session = model.session.clone().expect("session available");
            model.room_admins = vec![panel_session.pop_public_key.clone()];
            model.room_admins_loaded = true;
            model.members = vec![MemberEntry {
                leaf_id: [0x22; 32],
                alias: Some("inactive".to_string()),
                pop_public_key: Some(vec![0xBB; room_admin_public_key_bytes()]),
                join_timestamp_ms: Some(10),
                last_seen_timestamp_ms: Some(11),
            }];
            model.members_total = 1;
            model.members_search.set_query("inactive".to_string());
            model.members_mode = MembersMode::Search {
                query: "inactive".to_string(),
            };
            model.security_events = vec![SecurityEvent {
                alias: "inactive".to_string(),
                description: "security".to_string(),
                timestamp_ms: 12,
            }];
            model.activity_events = vec![ActivityEvent {
                timestamp_ms: 13,
                kind: ActivityKind::System,
                summary: "inactive".to_string(),
                detail: Some("window".to_string()),
            }];

            let _ = model.render_join(window, view_cx);
            let _ = model.render_session(window, &panel_session, view_cx);
            let _ = model.render_members_panel(window, view_cx);
            let _ = model.render_room_admin_panel(window, &panel_session, view_cx);
            let _ = model.render_security_panel(window, view_cx);
            let _ = model.render_activity_panel(window, view_cx);
        });
    });
}

#[gpui::test]
fn gpui_room_admin_controls_block_local_mutation_when_device_is_not_admin(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xC001,
        "http://127.0.0.1:9",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "not-admin",
    )
    .expect("build session");

    view.update(cx, |model, view_cx| {
        let mut other_admin = session.pop_public_key.clone();
        other_admin[0] ^= 0xFF;
        model.session = Some(session.clone());
        model.room_admins = vec![other_admin];
        model.room_admins_loaded = true;
        model
            .room_admin_target
            .set_value(hex_encode(vec![0x33; room_admin_public_key_bytes()]));

        model.start_room_admin_mutation_from_input(RoomAdminMutationKind::Grant, view_cx);

        assert!(matches!(
            &model.room_admin_status,
            RoomAdminStatus::Error(message)
                if message.contains("does not currently hold room-admin authority")
        ));
        assert!(model.room_admin_revoke_confirmation.is_none());
    });
}

#[gpui::test]
fn gpui_room_admin_revoke_requires_confirmation_and_clears_on_target_change(
    cx: &mut TestAppContext,
) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xC002,
        "http://127.0.0.1:9",
        "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        "revoke-stage",
    )
    .expect("build session");

    view.update(cx, |model, view_cx| {
        let first_target = vec![0x44; room_admin_public_key_bytes()];
        let second_target = vec![0x55; room_admin_public_key_bytes()];
        model.session = Some(session.clone());
        model.room_admins = vec![session.pop_public_key.clone(), second_target.clone()];
        model.room_admins_loaded = true;
        model
            .room_admin_target
            .set_value(hex_encode(first_target.clone()));

        model.start_room_admin_mutation_from_input(RoomAdminMutationKind::Revoke, view_cx);

        assert_eq!(
            model.room_admin_revoke_confirmation.as_ref(),
            Some(&first_target)
        );
        assert!(matches!(model.room_admin_status, RoomAdminStatus::Idle));
        assert!(
            model
                .info_message
                .as_deref()
                .is_some_and(|message| message.contains("Revoke staged"))
        );

        model.set_room_admin_target(second_target, view_cx);

        assert!(model.room_admin_revoke_confirmation.is_none());
    });
}

#[gpui::test]
fn gpui_members_refresh_and_search_cover_branch_paths(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xFACE,
        "http://127.0.0.1:9",
        "33445566778899aabbccddeeff00112233445566778899aabbccddeeff001122",
        "members",
    )
    .expect("build session");

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());

        model.members_mode = MembersMode::Full;
        model.members_search.clear();
        model.submit_members_search(view_cx);

        model.members_mode = MembersMode::Search {
            query: "old".to_string(),
        };
        model.members_search.clear();
        model.submit_members_search(view_cx);

        model.members_search.set_query("ali".to_string());
        model.submit_members_search(view_cx);

        model.members_mode = MembersMode::Full;
        model.members_search.set_query("ali".to_string());
        model.clear_members_search(view_cx);

        model.members_mode = MembersMode::Search {
            query: "ali".to_string(),
        };
        model.members_search.set_query("ali".to_string());
        model.clear_members_search(view_cx);

        model.members_status = MembersStatus::Idle;
        model.members_mode = MembersMode::Search {
            query: "ali".to_string(),
        };
        model.refresh_members_soft(view_cx);

        model.members_status = MembersStatus::Loading("busy".to_string());
        model.refresh_members_soft(view_cx);
        model.members_status = MembersStatus::Idle;

        model.members_total = 3;
        model.members_next_offset = Some(1);
        model.load_more_members_with_mode(view_cx, false);
        model.members_next_offset = Some(3);
        model.load_more_members_with_mode(view_cx, true);

        model.members_loading_append = false;
        model.members_mode = MembersMode::Full;
        model.members_alias_dirty = true;
        model.members_auto_page = false;
        model.on_members_refreshed(
            Ok(MembersPage {
                members: vec![MemberEntry {
                    leaf_id: [0xAA; 32],
                    alias: Some("ali".to_string()),
                    pop_public_key: Some(vec![0x42]),
                    join_timestamp_ms: Some(1),
                    last_seen_timestamp_ms: Some(2),
                }],
                root: [0xAA; 32],
                total_count: 1,
                next_offset: 1,
            }),
            view_cx,
        );
        assert!(!model.members_alias_dirty);

        model.members_mode = MembersMode::Search {
            query: "ali".to_string(),
        };
        model.members_auto_page = true;
        model.on_members_refreshed(
            Ok(MembersPage {
                members: vec![MemberEntry {
                    leaf_id: [0xBB; 32],
                    alias: Some("bob".to_string()),
                    pop_public_key: Some(vec![0x24]),
                    join_timestamp_ms: Some(3),
                    last_seen_timestamp_ms: Some(4),
                }],
                root: [0xAA; 32],
                total_count: 2,
                next_offset: 1,
            }),
            view_cx,
        );
    });
}

#[gpui::test]
fn gpui_callback_and_shortcut_branches_cover_edge_paths(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0x7E57,
        "http://127.0.0.1:9",
        "5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344",
        "edges",
    )
    .expect("build session");

    let session_path =
        session_file_path(&session.server_url, &session.room_id).expect("session path");
    fs::create_dir_all(&session_path).expect("create blocking session path");

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            let event = test_mouse_down_event();
            model.session = Some(session.clone());

            model.last_error = Some("join-fallback".to_string());
            model.categorized_error = None;
            model.info_message = Some("join-info".to_string());
            let _ = model.render_join(window, view_cx);

            let mut session_for_render = session.clone();
            session_for_render.regular_fingerprint = None;
            session_for_render.fs_fingerprint = None;
            model.last_error = Some("session-fallback".to_string());
            let _ = model.render_session(window, &session_for_render, view_cx);
            model.session = Some(session_for_render.clone());
            model.on_copy_regular_fingerprint(&event, window, view_cx);
            model.on_copy_fs_fingerprint(&event, window, view_cx);
            assert!(
                model
                    .toasts
                    .iter()
                    .any(|toast| toast.message.contains("fingerprint unavailable"))
            );
            model.session = Some(session.clone());

            model.focus_field(ActiveField::Alias, view_cx);
            assert!(matches!(model.join_form.active, Some(ActiveField::Alias)));

            model.categorized_error = Some(CategorizedError {
                category: ErrorCategory::Server,
                user_message: "err".to_string(),
                technical_details: "detail".to_string(),
                recovery_suggestion: "retry".to_string(),
                can_retry: true,
            });
            model.on_report_issue(&event, window, view_cx);

            model.join_form.active = Some(ActiveField::Alias);
            model.join_form.alias = "ab".to_string();
            view_cx.write_to_clipboard(ClipboardItem::new_string("c".to_string()));
            let paste = Keystroke::parse("cmd-v").expect("parse cmd-v");
            assert!(matches!(
                model.handle_join_form_clipboard_shortcuts(&paste, view_cx),
                KeyOutcome::Updated
            ));

            model.join_form.active = None;
            model.composer.focus();
            model.composer.set_text("pre".to_string());
            view_cx.write_to_clipboard(ClipboardItem::new_string("\npost".to_string()));
            assert!(matches!(
                model.handle_composer_clipboard_shortcuts(&paste, view_cx),
                KeyOutcome::Updated
            ));
            assert_eq!(model.composer.text(), "pre post");

            model.composer.blur();
            model.members_search.focus();
            model.members_search.set_query("xy".to_string());
            let members_query = model.members_search.query().to_string();
            model.members_search.editor.select_all(&members_query);
            let copy = Keystroke::parse("cmd-c").expect("parse cmd-c");
            let cut = Keystroke::parse("cmd-x").expect("parse cmd-x");
            assert!(matches!(
                model.handle_members_search_clipboard_shortcuts(&copy, view_cx),
                KeyOutcome::Updated
            ));
            assert!(matches!(
                model.handle_members_search_clipboard_shortcuts(&cut, view_cx),
                KeyOutcome::Updated
            ));
            view_cx.write_to_clipboard(ClipboardItem::new_string("zz".to_string()));
            assert!(matches!(
                model.handle_members_search_clipboard_shortcuts(&paste, view_cx),
                KeyOutcome::Updated
            ));

            model.join_status = JoinStatus::Joining;
            model.start_join(view_cx);
            model.join_status = JoinStatus::Idle;
            model.join_form.room_id.clear();
            model.start_join(view_cx);

            model.session = None;
            model.start_send(view_cx);
            model.session = Some(session.clone());
            model.composer.clear();
            model.start_send(view_cx);
            model.composer.set_text("hello".to_string());
            model.send_status = SendStatus::Sending;
            model.start_send(view_cx);
            model.send_status = SendStatus::Idle;
            model.composer.set_text("   ".to_string());
            model.start_send(view_cx);

            model.security_events.clear();
            model.security_unread = 0;
            model.session = Some(session.clone());
            for index in 0..(MAX_SECURITY_EVENTS + 2) {
                model.record_security_event("sab", format!("evt {index}"), view_cx);
            }
            assert_eq!(model.security_events.len(), MAX_SECURITY_EVENTS);
            assert!(model.security_unread > 0);

            model.session = None;
            model.fetch_in_flight = true;
            model.fetch_status = FetchStatus::Refreshing;
            model.ensure_fetch_loop(view_cx);
            assert!(matches!(model.fetch_status, FetchStatus::Idle));
            model.schedule_fetch(view_cx, Duration::ZERO);

            model.session = Some(session.clone());
            model.ensure_fetch_loop(view_cx);
            model.schedule_fetch(view_cx, Duration::from_millis(1));

            model.epoch_sync_task = Some(view_cx.spawn(async move |_, _| {}));
            model.session = None;
            model.ensure_epoch_sync_task(view_cx);
            assert!(model.epoch_sync_task.is_none());

            model.session = Some(session.clone());
            model.fetch_in_flight = false;
            model.handle_fetch_result(
                Ok(FetchOutcome {
                    messages: vec![ChatMessageEntry {
                        sender_leaf: Some(session.leaf_id),
                        fallback_label: session.alias.clone(),
                        plaintext: "ignored".to_string(),
                        ciphertext_hex: String::new(),
                        timestamp_ms: 1,
                        delivery: MessageDelivery::Sent,
                        pending_id: None,
                    }],
                    last_timestamp_ms: Some(99),
                    msg_replay_state: MsgReplayState::default(),
                }),
                session.we_epoch_id,
                view_cx,
            );
            model.handle_fetch_result(
                Err(anyhow::anyhow!("404 not found resource not found")),
                session.we_epoch_id,
                view_cx,
            );

            model.last_retry_action = Some(RetryAction::Leave);
            model.session = Some(session.clone());
            model.on_retry_clicked(&event, window, view_cx);
            assert!(matches!(model.leave_status, LeaveStatus::Leaving));

            model.leave_status = LeaveStatus::Leaving;
            model.on_leave_clicked(&event, window, view_cx);

            model.session = Some(session.clone());
            let pending_id = model.queue_pending_message(&session, "queued");
            model.fetch_in_flight = false;
            model.on_send_finished(
                Ok(ChatMessageEntry {
                    sender_leaf: Some(session.leaf_id),
                    fallback_label: session.alias.clone(),
                    plaintext: "sent".to_string(),
                    ciphertext_hex: "aa".to_string(),
                    timestamp_ms: 555,
                    delivery: MessageDelivery::Sent,
                    pending_id: None,
                }),
                pending_id,
                view_cx,
            );
            model.on_send_finished(
                Err(anyhow::anyhow!("404 not found resource not found")),
                pending_id.saturating_add(1),
                view_cx,
            );
        });
    });

    cx.run_until_parked();
}

#[test]
fn rollup_strip_and_pivot_selection_rules() {
    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_ROLLUP_PROVENANCE_COMMIT, Value::Bytes(vec![1]));
    header.insert(hdr::HDR_ROLLUP_EPOCH_REPLAY, Value::Bytes(vec![2]));
    header.insert(hdr::HDR_ROLLUP_VCK_COMMIT, Value::Bytes(vec![3]));
    header.insert(99, Value::Text("keep".to_string()));
    strip_rollup_metadata(&mut header);
    assert!(!header.contains_key(&hdr::HDR_ROLLUP_PROVENANCE_COMMIT));
    assert!(!header.contains_key(&hdr::HDR_ROLLUP_EPOCH_REPLAY));
    assert!(!header.contains_key(&hdr::HDR_ROLLUP_VCK_COMMIT));
    assert!(header.contains_key(&99));

    let mut low = sample_pivot_parity();
    low.accept_seq = 1;
    low.xk_hash = [0x10; 32];
    let mut high = sample_pivot_parity();
    high.accept_seq = 2;
    high.xk_hash = [0x20; 32];
    let mut tie_break = sample_pivot_parity();
    tie_break.accept_seq = 2;
    tie_break.xk_hash = [0x01; 32];

    let parities = [low, high, tie_break];
    let selected = select_pivot_parity(&parities).expect("must select pivot");
    assert_eq!(selected.accept_seq, 2, "highest accept_seq should win");
    assert_eq!(
        selected.xk_hash, [0x01; 32],
        "ties use lexicographically smallest xk_hash"
    );
}

#[test]
fn header_helpers_and_label_formatting() -> Result<(), Box<dyn std::error::Error>> {
    let mut header = BTreeMap::new();
    header.insert(1, Value::Text("hello".to_string()));
    header.insert(2, Value::Integer(Integer::from(77u64)));
    header.insert(3, Value::Bytes([0x11; 32].to_vec()));
    header.insert(4, Value::Bytes(vec![1, 2, 3]));
    header.insert(5, Value::Null);

    assert_eq!(header_text(&header, 1), Some("hello"));
    assert_eq!(header_u64(&header, 2), Some(77));
    assert_eq!(header_bytes32(&header, 3), Some([0x11; 32]));
    assert_eq!(header_bytes(&header, 4, "field4")?, vec![1, 2, 3]);
    assert_eq!(header_bytes_opt(&header, 4)?, Some(vec![1, 2, 3]));
    assert_eq!(header_bytes_opt(&header, 5)?, None);
    assert_eq!(header_bytes_opt(&header, 99)?, None);
    assert_eq!(header_bytes32_opt(&header, 3)?, Some([0x11; 32]));
    assert_eq!(header_bytes32_opt(&header, 5)?, None);
    assert!(
        header_bytes32_opt(&header, 4).is_err(),
        "not 32 bytes must fail"
    );
    assert!(
        header_bytes(&header, 2, "field2").is_err(),
        "wrong type must fail"
    );
    assert!(
        header_bytes(&header, 99, "missing").is_err(),
        "missing must fail"
    );

    let member_with_alias = MemberEntry {
        leaf_id: [0xAA; 32],
        alias: Some("alice".to_string()),
        pop_public_key: None,
        join_timestamp_ms: None,
        last_seen_timestamp_ms: None,
    };
    let member_without_alias = MemberEntry {
        alias: None,
        ..member_with_alias.clone()
    };
    assert_eq!(
        format_alias_display("alice", &[0xAA; 32]),
        "alice (aaaaaaaa…)"
    );
    assert_eq!(format_member_label(&member_with_alias), "alice (aaaaaaaa…)");
    assert_eq!(
        format_member_label(&member_without_alias),
        hex_encode([0xAA; 32])
    );
    assert_eq!(hex_encode_prefix(&[0xBB; 32], 8), "bbbbbbbb…");
    assert_eq!(hex_encode_prefix(&[0xBB; 32], 128), hex_encode([0xBB; 32]));
    assert_eq!(
        room_admin_identity_preview(&vec![0x11; room_admin_public_key_bytes()]),
        format!("{}…{}", "11".repeat(6), "11".repeat(6))
    );
    assert_eq!(decode_hex_32(&hex_encode([0xCD; 32])), Some([0xCD; 32]));
    assert!(decode_hex_32("bad").is_none());
    assert!(decode_hex_32("aa").is_none());
    assert_eq!(
        decode_room_admin_target_hex(&hex_encode(vec![0x22; room_admin_public_key_bytes()]))?,
        vec![0x22; room_admin_public_key_bytes()]
    );
    assert!(decode_room_admin_target_hex("aa").is_err());
    assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
    assert_eq!(bytes32("good", &[0xEF; 32])?, [0xEF; 32]);
    assert!(bytes32("bad", &[0xEF; 31]).is_err());
    Ok(())
}

#[test]
fn pivot_alignment_and_commit_recomputations() -> Result<(), Box<dyn std::error::Error>> {
    let mut pivot = sample_pivot_parity();
    pivot.fs_ec = Some(44);
    pivot.fs_epoch_commit = Some([0x33; 32]);
    pivot.fs_dev_commit = Some([0x22; 32]);

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(7u64)));
    header.insert(hdr::HDR_FS_EPOCH_COMMIT, Value::Bytes([0x11; 32].to_vec()));
    apply_pivot_alignment(&mut header, &pivot);
    assert_eq!(
        header.get(&hdr::HDR_FS_POLICY_VERSION),
        Some(&Value::Integer(Integer::from(7u64)))
    );
    assert_eq!(
        header.get(&hdr::HDR_FS_EC),
        Some(&Value::Integer(Integer::from(7u64))),
        "existing fs_ec should not be overwritten"
    );
    assert_eq!(
        header.get(&hdr::HDR_FS_CHECKPOINT_EC),
        Some(&Value::Integer(Integer::from(44u64)))
    );
    assert_eq!(
        header.get(&hdr::HDR_FS_EPOCH_COMMIT),
        Some(&Value::Bytes([0x11; 32].to_vec())),
        "existing epoch commit should remain"
    );
    assert_eq!(
        header.get(&hdr::HDR_FS_DEV_PREV_COMMIT),
        Some(&Value::Bytes([0x22; 32].to_vec()))
    );
    assert_eq!(
        header.get(&hdr::HDR_FS_DEV_COMMIT),
        Some(&Value::Bytes([0x22; 32].to_vec()))
    );

    let hydrated = hydrate_parities(
        &[{
            let mut p = sample_pivot_parity();
            p.fs_ec = None;
            p.fs_epoch_commit = None;
            p.fs_dev_commit = None;
            p
        }],
        88,
        [0xAB; 32],
        [0xBC; 32],
    );
    assert_eq!(hydrated[0].fs_ec, Some(88));
    assert_eq!(hydrated[0].fs_epoch_commit, Some([0xAB; 32]));
    assert_eq!(hydrated[0].fs_dev_commit, Some([0xBC; 32]));

    let mut commit_header = BTreeMap::new();
    commit_header.insert(hdr::HDR_VRF_PROOF, Value::Bytes(vec![0x01, 0x02]));
    commit_header.insert(hdr::HDR_FS_CAPSS, Value::Bytes(vec![0x03, 0x04]));
    let base_commit = recompute_proofs_commit(&commit_header)?;
    commit_header.insert(hdr::HDR_SRX_ROOT_SW, Value::Bytes([0x10; 32].to_vec()));
    commit_header.insert(hdr::HDR_SRX_SMALLWOOD, Value::Bytes(vec![0x20, 0x21]));
    let with_srx_commit = recompute_proofs_commit(&commit_header)?;
    assert_ne!(base_commit, with_srx_commit);
    commit_header.insert(hdr::HDR_SRX_ROOT_SW, Value::Bytes(vec![0x10]));
    assert!(recompute_proofs_commit(&commit_header).is_err());
    commit_header.insert(hdr::HDR_SRX_ROOT_SW, Value::Bytes([0x10; 32].to_vec()));
    commit_header.insert(hdr::HDR_VRF_PROOF, Value::Text("bad".to_string()));
    assert!(recompute_proofs_commit(&commit_header).is_err());

    let mut srx_header = BTreeMap::new();
    srx_header.insert(hdr::HDR_SRX_PAYLOAD, Value::Bytes(vec![0xAA, 0xBB]));
    assert!(recompute_srx_commit(&srx_header)?.is_some());
    srx_header.insert(hdr::HDR_SRX_PAYLOAD, Value::Text("bad".to_string()));
    assert!(recompute_srx_commit(&srx_header).is_err());
    Ok(())
}

#[test]
fn fs_fingerprint_header_helper_roundtrip() {
    let fs_epoch_commit = [0xAA; 32];
    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_FS_POLICY_VERSION,
        Value::Integer(Integer::from(7u64)),
    );
    header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(21u64)));
    header.insert(
        hdr::HDR_FS_EPOCH_COMMIT,
        Value::Bytes(fs_epoch_commit.to_vec()),
    );
    header.insert(
        hdr::HDR_FS_EPOCH_BASE_TS,
        Value::Integer(Integer::from(777u64)),
    );

    let direct = derive_fs_fingerprint_from_fields("7", 21, &fs_epoch_commit, 777);
    let from_header = compute_fs_fingerprint_from_header(&header);
    assert_eq!(from_header, direct);
    assert!(compute_fs_fingerprint_from_header(&header).is_some());
}

#[test]
fn pivot_alignment_inserts_optional_fs_fields_when_missing() {
    let mut header = BTreeMap::new();
    let mut pivot = sample_pivot_parity();
    pivot.fs_ec = Some(91);
    pivot.fs_epoch_commit = Some([0x9A; 32]);
    pivot.fs_dev_commit = Some([0xBC; 32]);

    apply_pivot_alignment(&mut header, &pivot);

    assert_eq!(
        header.get(&hdr::HDR_FS_EC),
        Some(&Value::Integer(Integer::from(91u64)))
    );
    assert_eq!(
        header.get(&hdr::HDR_FS_CHECKPOINT_EC),
        Some(&Value::Integer(Integer::from(91u64)))
    );
    assert_eq!(
        header.get(&hdr::HDR_FS_EPOCH_COMMIT),
        Some(&Value::Bytes([0x9A; 32].to_vec()))
    );
    assert_eq!(
        header.get(&hdr::HDR_FS_DEV_PREV_COMMIT),
        Some(&Value::Bytes([0xBC; 32].to_vec()))
    );
    assert_eq!(
        header.get(&hdr::HDR_FS_DEV_COMMIT),
        Some(&Value::Bytes([0xBC; 32].to_vec()))
    );
}

#[test]
fn helper_none_and_error_paths_cover_header_and_fingerprint_logic()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(format_regular_fingerprint(None), "Not available");
    assert_eq!(format_fs_fingerprint(None, 12), "Not available");

    let mut typed = BTreeMap::new();
    typed.insert(1, Value::Integer(Integer::from(9u64)));
    typed.insert(2, Value::Text("bad".to_string()));
    typed.insert(3, Value::Integer(Integer::from(7u64)));
    typed.insert(4, Value::Integer(Integer::from(1u64)));
    assert_eq!(header_text(&typed, 1), None);
    assert_eq!(header_u64(&typed, 2), None);
    assert_eq!(header_bytes32(&typed, 3), None);
    assert!(
        header_bytes_opt(&typed, 4).is_err(),
        "header_bytes_opt should reject non-bytes"
    );
    assert!(
        header_bytes32_opt(&typed, 4).is_err(),
        "header_bytes32_opt should reject non-bytes"
    );

    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_FS_POLICY_VERSION,
        Value::Integer(Integer::from(7u64)),
    );
    assert!(
        compute_fs_fingerprint_from_header(&header).is_none(),
        "missing fs_ec should fail"
    );
    header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(7u64)));
    assert!(
        compute_fs_fingerprint_from_header(&header).is_none(),
        "missing fs_epoch_commit should fail"
    );
    header.insert(hdr::HDR_FS_EPOCH_COMMIT, Value::Bytes([0x44; 32].to_vec()));
    assert!(
        compute_fs_fingerprint_from_header(&header).is_none(),
        "missing fs_epoch_base_ts should fail"
    );
    header.insert(
        hdr::HDR_FS_EPOCH_BASE_TS,
        Value::Integer(Integer::from(99u64)),
    );
    assert!(
        compute_fs_fingerprint_from_header(&header).is_some(),
        "fully populated header should derive a fingerprint"
    );
    Ok(())
}

#[test]
fn env_hex_parsing_and_kgen_helper_paths() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_var = "CITYG_GUI_TEST_HEX_ENV";
    let temp_original = std::env::var_os(temp_var);

    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    unsafe { std::env::set_var(temp_var, "zz") };
    assert!(
        configured_hex_from_env(temp_var).is_err(),
        "invalid hex should fail parsing"
    );

    #[cfg(unix)]
    {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(temp_var, OsString::from_vec(vec![0xFF, 0xFE])) };
        assert!(
            configured_hex_from_env(temp_var).is_err(),
            "invalid unicode env var should be surfaced"
        );
    }

    let (public_key, secret_key) = generate_kbroad_keypair();
    assert!(
        !public_key.is_empty(),
        "generated public key should be non-empty"
    );
    assert!(
        !secret_key.is_empty(),
        "generated secret key should be non-empty"
    );

    let now_ms = current_unix_timestamp_ms();
    assert!(
        now_ms > 1_000_000_000,
        "current timestamp should be epoch milliseconds"
    );

    match temp_original {
        Some(value) => {
            // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
            unsafe { std::env::set_var(temp_var, value) };
        }
        None => {
            // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
            unsafe { std::env::remove_var(temp_var) };
        }
    }
    Ok(())
}

#[test]
fn authenticated_message_decode_reports_precise_truncation_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let encoded = encode_authenticated_message(7, b"abc", b"key!", b"siggg");

    let mut truncated_plaintext = encoded.clone();
    truncated_plaintext[12..16].copy_from_slice(&(99u32).to_le_bytes());
    let err = decode_authenticated_message(&truncated_plaintext).expect_err("must fail");
    assert!(
        err.to_string().contains("truncated (plaintext)"),
        "expected plaintext truncation error"
    );

    let mut truncated_public = encoded.clone();
    truncated_public[19..23].copy_from_slice(&(77u32).to_le_bytes());
    let err = decode_authenticated_message(&truncated_public).expect_err("must fail");
    assert!(
        err.to_string().contains("truncated (public key)"),
        "expected public key truncation error"
    );

    let mut truncated_signature = encoded.clone();
    truncated_signature[27..31].copy_from_slice(&(9u32).to_le_bytes());
    let err = decode_authenticated_message(&truncated_signature).expect_err("must fail");
    assert!(
        err.to_string().contains("truncated (signature)"),
        "expected signature truncation error"
    );
    Ok(())
}

#[test]
fn signing_helpers_reject_invalid_key_material() -> Result<(), Box<dyn std::error::Error>> {
    let leaf = [0x11; 32];
    let ts = 42u64;
    let payload = b"hello";

    assert!(
        sign_message(&leaf, ts, payload, &[0u8; 8]).is_err(),
        "invalid secret key bytes should fail"
    );

    let (pk, sk) = cityg_client::message_auth::generate_message_signing_keypair();
    let signature = sign_message(&leaf, ts, payload, &sk)?;

    assert!(
        verify_message_signature(&leaf, ts, payload, &signature, &[0u8; 8]).is_err(),
        "invalid public key bytes should fail"
    );
    assert!(
        verify_message_signature(&leaf, ts, payload, &[0u8; 8], &pk).is_err(),
        "invalid signature bytes should fail"
    );
    Ok(())
}

#[test]
fn primary_shortcut_detection_accepts_cmd_and_ctrl() -> Result<(), Box<dyn std::error::Error>> {
    let cmd_v = Keystroke::parse("cmd-v")?;
    let ctrl_c = Keystroke::parse("ctrl-c")?;
    let alt_v = Keystroke::parse("alt-v")?;

    assert!(is_primary_shortcut(&cmd_v, "v"));
    assert!(is_primary_shortcut(&ctrl_c, "c"));
    assert!(!is_primary_shortcut(&alt_v, "v"));
    Ok(())
}

#[test]
fn text_input_editor_double_click_selects_all_text() {
    let mut editor = TextInputEditorState::default();
    let text = "double click";
    editor.selected_range = 3..3;

    let updated = editor.on_mouse_down(text, &test_mouse_down_event_with_click_count(2));

    assert!(updated);
    assert_eq!(editor.selected_range, 0..text.len());
    assert!(!editor.selection_reversed);
    assert!(!editor.is_selecting);
}

#[test]
fn text_input_editor_secondary_click_preserves_existing_selection() {
    let mut editor = TextInputEditorState::default();
    let text = "member lookup";
    editor.selected_range = 0..6;

    let updated = editor
        .on_secondary_mouse_down(text, &test_mouse_down_event_with_button(MouseButton::Right));

    assert!(!updated);
    assert_eq!(editor.selected_range, 0..6);
    assert!(!editor.is_selecting);
}

#[test]
fn text_input_editor_secondary_click_moves_caret_when_outside_selection() {
    let mut editor = TextInputEditorState::default();
    let text = "member lookup";
    editor.selected_range = 4..8;

    let updated = editor
        .on_secondary_mouse_down(text, &test_mouse_down_event_with_button(MouseButton::Right));

    assert!(updated);
    assert_eq!(editor.selected_range, 0..0);
    assert!(!editor.is_selecting);
}

#[test]
fn sidebar_width_rules_hide_when_narrow_and_clamp_when_wide() {
    assert!(
        AppModel::available_sidebar_width_for_window(520.0).is_none(),
        "narrow windows should collapse the sidebar"
    );

    let compact = AppModel::available_sidebar_width_for_window(620.0)
        .expect("compact-width sidebar should fit");
    assert!((compact - 248.0).abs() < 0.5);

    let wide = AppModel::available_sidebar_width_for_window(1440.0)
        .expect("wide-window sidebar should fit");
    assert!((wide - 300.0).abs() < 0.5);
}

#[test]
fn inspector_width_rules_hide_when_narrow_and_clamp_when_wide() {
    assert!(
        AppModel::available_inspector_width_for_window(720.0, Some(228.0)).is_none(),
        "narrow windows should collapse the inspector"
    );

    let medium = AppModel::available_inspector_width_for_window(1000.0, Some(228.0))
        .expect("medium-width inspector should fit");
    assert!((medium - 332.0).abs() < 0.5);

    let wide = AppModel::available_inspector_width_for_window(1440.0, Some(228.0))
        .expect("wide-window inspector should fit");
    assert!((wide - 460.0).abs() < 0.5);
}

#[test]
fn clipboard_text_sanitization_and_room_paste_rules() {
    assert_eq!(
        sanitize_clipboard_text("one\ntwo\tthree\r"),
        "one two three "
    );

    let existing = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let pasted_room = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let replaced = apply_join_field_paste(ActiveField::Room, existing, pasted_room);
    assert_eq!(replaced, pasted_room);

    let appended = apply_join_field_paste(ActiveField::Alias, "alice", "\n bob");
    assert_eq!(appended, "alice  bob");
}

#[test]
fn join_invite_roundtrip_and_form_import() -> Result<(), Box<dyn std::error::Error>> {
    let session = build_test_session(
        31337,
        "http://127.0.0.1:8080",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "alice",
    )?;
    let invite = build_join_invite(&session)?;
    let parsed =
        parse_join_invite(&invite)?.ok_or_else(|| anyhow!("expected City-G invite payload"))?;

    let mut form = JoinFormState {
        server: String::new(),
        room_id: String::new(),
        alias: "bob".to_string(),
        active: Some(ActiveField::Room),
        ..Default::default()
    };
    form.apply_invite(parsed)?;
    assert_eq!(form.server, session.server_url);
    assert_eq!(form.room_id, session.room_id);

    let _params = form.join_params();
    Ok(())
}

#[test]
fn message_composer_keystroke_paths() -> Result<(), Box<dyn std::error::Error>> {
    let mut composer = MessageComposer::default();
    let a = Keystroke::parse("a")?;
    assert!(matches!(composer.handle_keystroke(&a), KeyOutcome::None));

    composer.focus();
    composer.set_text("hi".to_string());
    assert_eq!(composer.text(), "hi");

    let backspace = Keystroke::parse("backspace")?;
    assert!(matches!(
        composer.handle_keystroke(&backspace),
        KeyOutcome::Updated
    ));
    assert_eq!(composer.text(), "h");

    let space = Keystroke::parse("space")?;
    assert!(matches!(
        composer.handle_keystroke(&space),
        KeyOutcome::Updated
    ));
    assert_eq!(composer.text(), "h ");

    let delete = Keystroke::parse("delete")?;
    assert!(matches!(
        composer.handle_keystroke(&delete),
        KeyOutcome::Updated
    ));
    assert_eq!(composer.text(), "");

    composer.set_text("ok".to_string());
    let enter = Keystroke::parse("enter")?;
    assert!(matches!(
        composer.handle_keystroke(&enter),
        KeyOutcome::Submit
    ));

    let escape = Keystroke::parse("escape")?;
    assert!(matches!(
        composer.handle_keystroke(&escape),
        KeyOutcome::Updated
    ));
    assert!(!composer.active);
    Ok(())
}

#[test]
fn members_search_keystroke_paths() -> Result<(), Box<dyn std::error::Error>> {
    let mut search = MembersSearchState::default();
    let a = Keystroke::parse("a")?;
    assert!(matches!(search.handle_keystroke(&a), KeyOutcome::None));

    search.focus();
    search.set_query("ab".to_string());
    assert_eq!(search.query(), "ab");

    let backspace = Keystroke::parse("backspace")?;
    assert!(matches!(
        search.handle_keystroke(&backspace),
        KeyOutcome::Updated
    ));
    assert_eq!(search.query(), "a");

    let delete = Keystroke::parse("delete")?;
    assert!(matches!(
        search.handle_keystroke(&delete),
        KeyOutcome::Updated
    ));
    assert_eq!(search.query(), "");

    let enter = Keystroke::parse("enter")?;
    assert!(matches!(
        search.handle_keystroke(&enter),
        KeyOutcome::Submit
    ));

    let tab = Keystroke::parse("tab")?;
    assert!(matches!(search.handle_keystroke(&tab), KeyOutcome::Updated));
    assert!(!search.active);
    Ok(())
}

#[test]
fn join_form_keystroke_paths() -> Result<(), Box<dyn std::error::Error>> {
    let mut form = JoinFormState {
        server: "http://127.0.0.1:18080".to_string(),
        room_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        alias: "alice".to_string(),
        active: Some(ActiveField::Server),
        ..Default::default()
    };

    assert!(JoinFormState::next_field(ActiveField::Server) == ActiveField::Room);
    assert!(JoinFormState::previous_field(ActiveField::Server) == ActiveField::Alias);

    let tab = Keystroke::parse("tab")?;
    assert!(matches!(form.handle_keystroke(&tab), KeyOutcome::Updated));
    assert!(form.active == Some(ActiveField::Room));
    assert_eq!(form.field(ActiveField::Alias), "alice");

    {
        let room = form.field_mut(ActiveField::Room);
        room.truncate(63);
    }
    assert!(!form.is_ready());
    form.field_mut(ActiveField::Room).push('f');
    assert!(form.is_ready());

    let enter = Keystroke::parse("enter")?;
    assert!(matches!(form.handle_keystroke(&enter), KeyOutcome::Submit));

    let escape = Keystroke::parse("escape")?;
    assert!(matches!(
        form.handle_keystroke(&escape),
        KeyOutcome::Updated
    ));
    assert!(form.active.is_none());
    Ok(())
}

#[test]
fn helper_and_model_state_paths_cover_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let mut model = AppModel::new(CityGConfig::default());
    let room_id = AppModel::random_room_id();
    assert_eq!(room_id.len(), 64);
    assert!(room_id.chars().all(|c| c.is_ascii_hexdigit()));

    let success = Toast::success("ok");
    let error = Toast::error("err");
    let info = Toast::info("info");
    assert_eq!(success.kind, ToastKind::Success);
    assert_eq!(error.kind, ToastKind::Error);
    assert_eq!(info.kind, ToastKind::Info);
    assert!(!success.is_expired());

    let mut expired = Toast::info("expired");
    expired.created_at = SystemTime::now() - Duration::from_secs(10);
    expired.duration_secs = 1;
    model.toasts.push(expired);
    model.toasts.push(success.clone());
    model.cleanup_expired_toasts();
    assert_eq!(model.toasts.len(), 1);
    assert_eq!(model.toasts[0].kind, ToastKind::Success);

    let err = anyhow!("connection reset by peer");
    model.set_error(&err, "send", Some(RetryAction::Send));
    assert!(model.last_error.is_some());
    assert!(model.categorized_error.is_some());
    assert_eq!(model.last_retry_action, Some(RetryAction::Send));
    model.clear_error();
    assert!(model.last_error.is_none());
    assert!(model.categorized_error.is_none());
    assert!(model.last_retry_action.is_none());
    Ok(())
}

#[test]
fn app_model_new_restores_saved_session() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        4242,
        "https://restore.example.com",
        "restore-room-123",
        "restorer",
    )?;
    persist_session(&session)?;

    let model = AppModel::new(CityGConfig::default());
    let restored = model
        .session
        .as_ref()
        .ok_or_else(|| anyhow!("expected restored session"))?;
    assert_eq!(restored.server_url, session.server_url);
    assert_eq!(restored.room_id, session.room_id);
    assert_eq!(restored.alias, session.alias);
    assert_eq!(model.join_form.server, session.server_url);
    assert_eq!(model.join_form.room_id, session.room_id);
    assert_eq!(model.join_form.alias, session.alias);
    assert!(model.join_form.active.is_none());
    assert_eq!(
        model.info_message.as_deref(),
        Some("Restored saved session.")
    );
    assert!(matches!(model.fetch_status, FetchStatus::Idle));
    assert!(matches!(model.send_status, SendStatus::Idle));
    assert!(model.messages.is_empty());
    assert!(model.message_keys.is_empty());
    assert!(model.fetch_task.is_none());
    assert!(!model.fetch_in_flight);
    assert!(!model.show_ciphertext);
    assert!(!model.composer.active);
    Ok(())
}

#[test]
fn app_model_new_prefers_worker_first_blank_server_for_legacy_default()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let model = AppModel::new(CityGConfig::default());
    assert!(model.session.is_none());
    assert!(model.join_form.server.is_empty());
    Ok(())
}

#[test]
fn app_model_new_preserves_explicit_nonlocal_server_default()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let mut config = CityGConfig::default();
    config.client.default_server_url = "https://cityg.example.workers.dev".to_string();

    let model = AppModel::new(config);
    assert!(model.session.is_none());
    assert_eq!(model.join_form.server, "https://cityg.example.workers.dev");
    Ok(())
}

#[test]
fn app_model_new_handles_invalid_saved_session_pointer() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let pointer_path = last_session_pointer_path()?;
    fs::create_dir_all(
        pointer_path
            .parent()
            .ok_or_else(|| anyhow!("missing pointer parent"))?,
    )?;
    fs::write(pointer_path, "{invalid-json")?;

    let model = AppModel::new(CityGConfig::default());
    assert!(model.session.is_none());
    Ok(())
}

#[test]
fn keystroke_helpers_cover_modifier_and_empty_paths() -> Result<(), Box<dyn std::error::Error>> {
    let mut composer = MessageComposer::default();
    composer.focus();
    let backspace = Keystroke::parse("backspace")?;
    assert!(matches!(
        composer.handle_keystroke(&backspace),
        KeyOutcome::None
    ));
    let delete = Keystroke::parse("delete")?;
    assert!(matches!(
        composer.handle_keystroke(&delete),
        KeyOutcome::None
    ));
    composer.set_text("  ".to_string());
    assert!(!composer.is_ready());
    composer.clear();
    assert_eq!(composer.text(), "");
    let x = Keystroke::parse("x->x")?;
    assert!(matches!(composer.handle_keystroke(&x), KeyOutcome::Updated));
    assert_eq!(composer.text(), "x");
    let ctrl_a = Keystroke::parse("ctrl-a")?;
    assert!(matches!(
        composer.handle_keystroke(&ctrl_a),
        KeyOutcome::None
    ));
    composer.blur();

    let mut search = MembersSearchState::default();
    search.focus();
    assert!(matches!(
        search.handle_keystroke(&backspace),
        KeyOutcome::None
    ));
    assert!(matches!(search.handle_keystroke(&delete), KeyOutcome::None));
    search.set_query("abc".to_string());
    search.clear();
    assert_eq!(search.query(), "");
    assert!(matches!(search.handle_keystroke(&x), KeyOutcome::Updated));
    let escape = Keystroke::parse("escape")?;
    assert!(matches!(
        search.handle_keystroke(&escape),
        KeyOutcome::Updated
    ));
    assert!(!search.active);
    search.focus();
    assert!(matches!(search.handle_keystroke(&ctrl_a), KeyOutcome::None));
    search.blur();
    Ok(())
}

#[test]
fn join_form_and_shortcut_edge_paths() -> Result<(), Box<dyn std::error::Error>> {
    let mut form = JoinFormState {
        server: " http://127.0.0.1:18080 ".to_string(),
        room_id: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        alias: " alice ".to_string(),
        active: None,
        ..Default::default()
    };
    let tab = Keystroke::parse("tab")?;
    assert!(matches!(form.handle_keystroke(&tab), KeyOutcome::None));

    form.active = Some(ActiveField::Server);
    let shift_tab = Keystroke::parse("shift-tab")?;
    assert!(matches!(
        form.handle_keystroke(&shift_tab),
        KeyOutcome::Updated
    ));
    assert!(form.active == Some(ActiveField::Alias));

    let backspace = Keystroke::parse("backspace")?;
    form.alias.clear();
    assert!(matches!(
        form.handle_keystroke(&backspace),
        KeyOutcome::None
    ));

    let delete = Keystroke::parse("delete")?;
    assert!(matches!(
        form.handle_keystroke(&delete),
        KeyOutcome::Updated
    ));
    assert_eq!(form.alias, "");

    let space = Keystroke::parse("space")?;
    assert!(matches!(form.handle_keystroke(&space), KeyOutcome::Updated));
    assert_eq!(form.alias, " ");

    let ctrl_a = Keystroke::parse("ctrl-a")?;
    assert!(matches!(form.handle_keystroke(&ctrl_a), KeyOutcome::None));

    let x = Keystroke::parse("x->x")?;
    assert!(matches!(form.handle_keystroke(&x), KeyOutcome::Updated));
    assert_eq!(form.alias, " x");

    form.room_id = "bad-room".to_string();
    let enter = Keystroke::parse("enter")?;
    assert!(matches!(form.handle_keystroke(&enter), KeyOutcome::None));
    form.room_id = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string();
    form.alias = "zed".to_string();
    assert!(matches!(form.handle_keystroke(&enter), KeyOutcome::Submit));

    form.active = Some(ActiveField::Alias);
    form.alias = " zed ".to_string();
    let params = form.join_params();
    assert_eq!(params.server_url, "http://127.0.0.1:18080");
    assert_eq!(params.alias, "zed");
    assert_eq!(
        params.room_id,
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    );

    assert!(JoinFormState::is_valid_room_id(&params.room_id));
    assert!(!JoinFormState::is_valid_room_id("too-short"));

    let plain_v = Keystroke::parse("v")?;
    assert!(!is_primary_shortcut(&plain_v, "v"));
    Ok(())
}

#[test]
fn persist_session_fault_injection_truncates_session_file_after_write()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        5151,
        "https://fault.example.com",
        "fault-room-truncate",
        "alice",
    )?;
    with_fault_injection(
        vec![fault_step(
            FaultInjectionCutPoint::AfterSessionWrite,
            FaultInjectionAction::TruncatePrimary,
        )],
        || persist_session(&session),
    )?;
    assert_fault_plan_consumed();

    let err = match load_session_at(&session.server_url, &session.room_id) {
        Ok(_) => return Err(anyhow!("truncated encrypted session must fail to load").into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("invalid")
            || err.to_string().contains("decrypt")
            || err.to_string().contains("session"),
        "unexpected error for truncated session: {err:#}"
    );
    Ok(())
}

#[test]
fn persist_session_fault_injection_rewrites_pointer_to_missing_session()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

    let session = build_test_session(
        5252,
        "https://fault.example.com",
        "fault-room-pointer",
        "alice",
    )?;
    with_fault_injection(
        vec![fault_step(
            FaultInjectionCutPoint::AfterPointerWrite,
            FaultInjectionAction::RewritePointerToMissing,
        )],
        || persist_session(&session),
    )?;
    assert_fault_plan_consumed();

    assert!(
        load_last_session()?.is_none(),
        "missing pointed session should be ignored instead of restoring stale state"
    );
    assert!(
        read_last_session_pointer()?.is_none(),
        "missing pointed session should prune the broken pointer"
    );
    Ok(())
}

#[test]
fn persisted_pending_state_mismatch_survives_restart_without_normalization()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let mut session = build_test_session(
        5353,
        "https://fault.example.com",
        "fault-room-pending",
        "alice",
    )?;
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 8,
        we_epoch_id: [0x44; 32],
        fs_ec: 31,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash: [0x45; 32],
        kem_tree_hash_after: [0x46; 32],
        k_barrier_new: Zeroizing::new([0x47; 32]),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(2),
        barrier_update_digest: [0x48; 32],
        on_path_key_material: BTreeMap::new(),
        activation_source: current_pending_activation_source(&session),
    });
    persist_session(&session)?;

    mutate_persisted_session(&session.server_url, &session.room_id, |persisted| {
        if let Some(pending) = persisted.barrier_state.pending.as_mut() {
            pending.barrier_version = 99;
            pending.we_epoch_id_hex = "aa".repeat(32);
            pending.barrier_update_digest_hex = "bb".repeat(32);
        }
    })?;

    let reloaded = load_session_at(&session.server_url, &session.room_id)?
        .ok_or_else(|| anyhow!("expected reloaded session"))?;
    let pending = reloaded
        .barrier_state
        .pending
        .clone()
        .ok_or_else(|| anyhow!("expected pending state after reload"))?;
    assert_eq!(pending.barrier_version, 99);
    assert_eq!(pending.we_epoch_id, [0xAA; 32]);
    assert_eq!(pending.barrier_update_digest, [0xBB; 32]);

    let changed = apply_pending_barrier_activation(
        &mut reloaded.clone(),
        8,
        Some(31),
        Some(2),
        Some([0x48; 32]),
    )?;
    assert!(
        !changed,
        "mismatched persisted pending fields must not be silently normalized into an activation"
    );
    Ok(())
}

#[test]
fn pending_barrier_activation_fault_injection_preserves_pending_state_on_error()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session =
        build_test_session(5454, "http://127.0.0.1:9", "fault-activation-room", "alice")?;
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 10,
        we_epoch_id: [0x24; 32],
        fs_ec: 31,
        next_forward_fs_ec: 77,
        next_forward_fs_dev_commit: [0x55; 32],
        next_forward_last_weid: [0x24; 32],
        revocation_roots_hash: [0x35; 32],
        kem_tree_hash_after: [0x45; 32],
        k_barrier_new: Zeroizing::new([0x56; 32]),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(2),
        barrier_update_digest: [0x67; 32],
        on_path_key_material: BTreeMap::new(),
        activation_source: current_pending_activation_source(&session),
    });

    let err = with_fault_injection(
        vec![fault_step(
            FaultInjectionCutPoint::AfterAuthenticatedAcceptBeforePersist,
            FaultInjectionAction::Fail("inject activation failure"),
        )],
        || apply_pending_barrier_activation(&mut session, 10, Some(31), Some(2), Some([0x67; 32])),
    )
    .expect_err("fault injection should abort activation before pending clear");
    assert_fault_plan_consumed();
    assert!(err.to_string().contains("inject activation failure"));
    assert!(
        session.barrier_state.pending.is_some(),
        "pending state must remain present if activation fails before persistence"
    );
    assert!(
        session.barrier_state.barrier_recovery_pending,
        "recovery pending must not clear on injected pre-persist failure"
    );
    Ok(())
}

#[tokio::test]
async fn join_finalize_fault_injection_persists_pending_state_before_publish()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;

    let temp_dir = TempDir::new()?;
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let (port, handle) = spawn_ready_test_server().await?;

    let server_url = format!("http://127.0.0.1:{port}");
    let mut room_id_bytes = [0x92u8; 32];
    room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
    let room_id = hex_encode(room_id_bytes);
    bootstrap_test_room(&server_url, &room_id).await?;

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        let mut alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        alice.barrier_state.barrier_recovery_pending = false;
        persist_session(&alice)?;
    }

    let join_result = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        with_fault_injection_async(
            vec![fault_step(
                FaultInjectionCutPoint::BeforePublishJoinFinalize,
                FaultInjectionAction::Fail("inject join finalize pre-publish failure"),
            )],
            || {
                perform_join(JoinParams {
                    server_url: server_url.clone(),
                    room_id: room_id.clone(),
                    alias: "bob".to_string(),
                })
            },
        )
        .await
    };
    if let Err(err) = &join_result {
        assert!(
            format!("{err:#}").contains("inject join finalize pre-publish failure"),
            "unexpected join finalize error: {err:#}"
        );
    }

    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        let persisted = load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted bob session after injected failure"))?;
        let pending = persisted
            .barrier_state
            .pending
            .as_ref()
            .ok_or_else(|| anyhow!("expected persisted pending join_finalize state"))?;
        assert!(
            persisted.barrier_state.barrier_recovery_pending,
            "pre-publish join_finalize failure must keep recovery pending across restart"
        );
        assert_eq!(pending.barrier_update_reason, Some(2));
        assert!(
            pending.barrier_version > persisted.barrier_state.barrier_version,
            "pending barrier version should still describe the unpublished join_finalize candidate"
        );
        if let Ok(session) = &join_result {
            assert!(
                session.barrier_state.barrier_recovery_pending,
                "reloaded session should preserve recovery-pending join_finalize state"
            );
        }

        let send_err =
            match SendParams::from_session(&persisted, "blocked while pending".to_string(), 1) {
                Ok(params) => match perform_send(params).await {
                    Ok(_) => {
                        return Err(anyhow!(
                            "send must stay blocked while join_finalize recovery is pending"
                        )
                        .into());
                    }
                    Err(err) => err,
                },
                Err(err) => err,
            };
        assert!(
            send_err.to_string().contains("barrier recovery is pending"),
            "expected recover-before-send error: {send_err:#}"
        );
    }

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn join_finalize_fault_injection_after_publish_recovers_via_epoch_sync()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;

    let temp_dir = TempDir::new()?;
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let (port, handle) = spawn_ready_test_server().await?;

    let server_url = format!("http://127.0.0.1:{port}");
    let mut room_id_bytes = [0x93u8; 32];
    room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
    let room_id = hex_encode(room_id_bytes);
    bootstrap_test_room(&server_url, &room_id).await?;

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        let mut alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        alice.barrier_state.barrier_recovery_pending = false;
        persist_session(&alice)?;
    }

    let join_result = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        with_fault_injection_async(
            vec![fault_step(
                FaultInjectionCutPoint::AfterPublishBeforeReload,
                FaultInjectionAction::Fail("inject join finalize post-publish failure"),
            )],
            || {
                perform_join(JoinParams {
                    server_url: server_url.clone(),
                    room_id: room_id.clone(),
                    alias: "bob".to_string(),
                })
            },
        )
        .await
    };
    if let Err(err) = &join_result {
        assert!(
            format!("{err:#}").contains("inject join finalize post-publish failure"),
            "unexpected join finalize error: {err:#}"
        );
    }

    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        let persisted = load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted bob session after post-publish fault"))?;
        let pending = persisted.barrier_state.pending.clone().ok_or_else(|| {
            anyhow!("expected pending join_finalize state after post-publish fault")
        })?;
        assert!(
            persisted.barrier_state.barrier_recovery_pending,
            "post-publish failure must keep restart path in recovery-pending state"
        );
        assert_eq!(pending.barrier_update_reason, Some(2));
        if let Ok(session) = &join_result {
            assert!(
                session.barrier_state.barrier_recovery_pending,
                "reloaded session should preserve post-publish recovery-pending state"
            );
        }

        let synced = perform_epoch_sync(persisted).await?;
        assert!(
            !synced.session.barrier_state.barrier_recovery_pending,
            "epoch sync should recover a published join_finalize after restart"
        );
        assert!(
            synced.session.barrier_state.pending.is_none(),
            "published join_finalize must clear pending state after recovery"
        );
        assert_eq!(
            synced.session.barrier_state.barrier_version, pending.barrier_version,
            "restart recovery must converge to the already-published barrier version"
        );
    }

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn restart_during_pending_join_finalize_activation_recovers_via_epoch_sync()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;

    let temp_dir = TempDir::new()?;
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");
    let journal_dir = temp_dir.path().join("cityg").join("server");
    std::fs::create_dir_all(&journal_dir)?;
    let journal_path = journal_dir.join("restart-pending-join-finalize.journal");

    let port = next_test_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let mut room_id_bytes = [0xB3u8; 32];
    room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
    let room_id = hex_encode(room_id_bytes);
    bootstrap_test_room(&server_url, &room_id).await?;

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        let mut alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        alice.barrier_state.barrier_recovery_pending = false;
        persist_session(&alice)?;
    }

    let join_result = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        with_fault_injection_async(
            vec![fault_step(
                FaultInjectionCutPoint::AfterPublishBeforeReload,
                FaultInjectionAction::Fail("inject join finalize post-publish failure"),
            )],
            || {
                perform_join(JoinParams {
                    server_url: server_url.clone(),
                    room_id: room_id.clone(),
                    alias: "bob".to_string(),
                })
            },
        )
        .await
    };
    if let Err(err) = &join_result {
        assert!(
            format!("{err:#}").contains("inject join finalize post-publish failure"),
            "unexpected join finalize error: {err:#}"
        );
    }

    let persisted = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        let persisted = load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted bob session after post-publish fault"))?;
        let pending = persisted.barrier_state.pending.clone().ok_or_else(|| {
            anyhow!("expected pending join_finalize state after post-publish fault")
        })?;
        assert!(persisted.barrier_state.barrier_recovery_pending);
        assert_eq!(pending.barrier_update_reason, Some(2));
        persisted
    };

    let before_restart_members = new_api_client(&server_url)
        .members(&persisted.gid, None)
        .await?;
    assert!(
        before_restart_members
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == persisted.leaf_id.as_slice()),
        "published join_finalize must already admit the new joiner before restart"
    );

    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path).await;
    sleep(Duration::from_millis(250)).await;

    let client = new_api_client(&server_url);
    let after_restart_members = client.members(&persisted.gid, None).await?;
    assert!(
        after_restart_members
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == persisted.leaf_id.as_slice()),
        "restart must preserve the admitted joiner in the roster"
    );
    let refresh_ticket = client
        .merge_ticket_refresh(&room_id, &persisted.leaf_id)
        .await
        .map_err(|err| anyhow!("merge_ticket_refresh after restart: {err:#}"))?;
    client
        .get_bundle(&refresh_ticket.we_epoch_id)
        .await
        .map_err(|err| anyhow!("replayed get_bundle after restart: {err:#}"))?;

    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        let synced = perform_epoch_sync(persisted)
            .await
            .map_err(|err| anyhow!("epoch_sync after restart: {err:#}"))?;
        assert!(
            !synced.session.barrier_state.barrier_recovery_pending,
            "epoch sync should recover a published join_finalize after restart"
        );
        assert!(
            synced.session.barrier_state.pending.is_none(),
            "published join_finalize must clear pending state after restart recovery"
        );
    }

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[test]
fn room_identity_persists_reuses_same_room_and_survives_session_removal()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let server_url = "https://example.invalid";
    let room_id = "room-identity-a";

    let first = load_or_create_room_identity(server_url, room_id)?;
    assert!(!first.pop_public_key.is_empty());
    assert!(!first.pop_secret_key.is_empty());

    let path = room_identity_file_path(server_url, room_id)?;
    let raw = fs::read(&path)?;
    let raw_text = String::from_utf8_lossy(&raw);
    assert!(
        raw_text.contains("ciphertext_hex"),
        "room identity file must store encrypted payload envelope"
    );
    assert!(
        !raw_text.contains(&hex_encode(&first.pop_secret_key)),
        "room identity file must not expose plaintext secret bytes"
    );

    let loaded = load_room_identity(server_url, room_id)?
        .ok_or_else(|| anyhow!("expected persisted room identity"))?;
    assert_eq!(loaded, first);

    let reused = load_or_create_room_identity(server_url, room_id)?;
    assert_eq!(reused, first, "same room must reuse persisted identity");

    let session = build_test_session(0xC31, server_url, room_id, "alice")?;
    persist_session(&session)?;
    remove_persisted_session(server_url, room_id)?;

    let after_session_removal = load_room_identity(server_url, room_id)?
        .ok_or_else(|| anyhow!("room identity must survive session removal"))?;
    assert_eq!(after_session_removal, first);
    Ok(())
}

#[test]
fn room_identity_is_scoped_per_room() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let server_url = "https://example.invalid";

    let room_a = load_or_create_room_identity(server_url, "room-identity-a")?;
    let room_b = load_or_create_room_identity(server_url, "room-identity-b")?;

    assert_ne!(
        room_a.pop_public_key, room_b.pop_public_key,
        "different rooms must not share the same persisted identity"
    );
    assert_ne!(
        room_a.pop_secret_key, room_b.pop_secret_key,
        "different rooms must not share the same persisted identity secret"
    );
    Ok(())
}

#[test]
fn persisted_session_into_app_session_covers_version_and_legacy_fallbacks()
-> Result<(), Box<dyn std::error::Error>> {
    let session = build_test_session(
        0xCAFE,
        "https://example.invalid",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "legacy",
    )?;

    let mut unsupported = PersistedSession::from_session(&session);
    unsupported.version = 999;
    assert!(
        unsupported.into_app_session().is_err(),
        "unsupported persisted session versions must be rejected"
    );

    let mut persisted = PersistedSession::from_session(&session);
    persisted.regular_fingerprint_hex.clear();
    persisted.forward_state.fs_last_weid_hex.clear();
    persisted.fs_epoch_created_at_unix_ms = 0;

    let restored = persisted.into_app_session()?;
    assert!(
        restored.regular_fingerprint.is_none(),
        "empty regular fingerprint should deserialize as missing"
    );
    assert_eq!(
        restored.forward_state.snapshot().last_weid,
        restored.we_epoch_id,
        "missing forward_state.last_weid should fall back to we_epoch_id"
    );
    let restored_ms = restored
        .fs_epoch_created_at
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    assert!(
        restored_ms > 0,
        "zero persisted epoch timestamp should fall back to current time"
    );
    Ok(())
}

#[tokio::test]
async fn epoch_sync_adopts_new_member_head() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?; // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x44u8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let mut alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    alice.barrier_state.barrier_recovery_pending = false;
    let mut bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };
    bob.barrier_state.barrier_recovery_pending = false;
    assert_ne!(
        alice.we_epoch_id, bob.we_epoch_id,
        "second join should advance the epoch head"
    );

    let sync = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_epoch_sync(alice.clone()).await?
    };
    assert!(sync.changed, "sync should detect and adopt newer head");
    assert_eq!(sync.session.we_epoch_id, bob.we_epoch_id);
    assert_eq!(
        sync.session.epoch_key, bob.epoch_key,
        "adopted session should derive current epoch key"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn epoch_sync_noop_when_already_current() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x55u8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let alice = perform_join(JoinParams {
        server_url: server_url.clone(),
        room_id: room_id.clone(),
        alias: "alice".to_string(),
    })
    .await?;
    let sync = perform_epoch_sync(alice.clone()).await?;

    let barrier_delta = sync.session.barrier_state.barrier_version
        != alice.barrier_state.barrier_version
        || sync.session.barrier_state.k_barrier != alice.barrier_state.k_barrier
        || sync.session.barrier_state.kem_tree_hash_after
            != alice.barrier_state.kem_tree_hash_after
        || sync.session.barrier_state.n_max != alice.barrier_state.n_max
        || sync.session.barrier_state.cover_leaf_index != alice.barrier_state.cover_leaf_index;
    assert_eq!(
        sync.changed, barrier_delta,
        "sync.changed should reflect barrier-only reconciliation when head is unchanged"
    );
    assert_eq!(sync.session.we_epoch_id, alice.we_epoch_id);
    assert_eq!(sync.session.epoch_key, alice.epoch_key);

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn pending_barrier_history_activation_succeeds_even_when_current_version_is_newer()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?; // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x56u8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let mut alice = perform_join(JoinParams {
        server_url: server_url.clone(),
        room_id: room_id.clone(),
        alias: "alice".to_string(),
    })
    .await?;
    alice.barrier_state.barrier_recovery_pending = false;

    persist_session(&alice)?;
    perform_pcs_refresh(LeaveRequest::from_session(&alice)).await?;

    let mut pending_alice = load_session_at(&alice.server_url, &alice.room_id)?
        .ok_or_else(|| anyhow!("expected persisted alice session after pcs refresh"))?;
    let pending_state = pending_alice
        .barrier_state
        .pending
        .as_ref()
        .ok_or_else(|| anyhow!("expected pending barrier state after pcs refresh"))?;
    let pending_snapshot = pending_state.clone();
    let pending_we_epoch_id = pending_state.we_epoch_id;

    let client = new_api_client(&server_url);
    let outcome = apply_pending_barrier_activation_from_history(
        &client,
        &mut pending_alice,
        pending_snapshot.barrier_version.saturating_add(1),
    )
    .await?;
    assert_eq!(
        outcome,
        PendingBarrierHistoryOutcome::Activated(pending_we_epoch_id)
    );
    assert!(
        pending_alice.barrier_state.pending.is_none(),
        "pending updater state must clear after historical activation"
    );
    assert!(pending_alice.barrier_state.barrier_initialized);
    assert_eq!(
        pending_alice.barrier_state.barrier_version,
        pending_snapshot.barrier_version
    );
    assert_eq!(
        pending_alice.barrier_state.barrier_roots_hash,
        pending_snapshot.revocation_roots_hash
    );
    assert_eq!(
        pending_alice.barrier_state.kem_tree_hash_after,
        pending_snapshot.kem_tree_hash_after
    );
    assert_eq!(
        *pending_alice.barrier_state.k_barrier,
        *pending_snapshot.k_barrier_new
    );
    if let Some(k_fs_after_pcs) = pending_snapshot.k_fs_after_pcs.as_ref() {
        assert_eq!(
            pending_alice.forward_state.snapshot().k_fs,
            **k_fs_after_pcs
        );
    }
    assert_eq!(
        pending_alice.we_epoch_id, alice.we_epoch_id,
        "historical activation should not itself rewrite the session head"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn pending_join_finalize_history_lookup_retains_state_after_history_404()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let client = new_api_client(&server_url);
    let room_id = hex_encode([0xC6u8; 32]);
    let mut session = build_test_session(0xC61, &server_url, &room_id, "carol")?;
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 5,
        we_epoch_id: [0xD1; 32],
        fs_ec: 31,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash: [0xD2; 32],
        kem_tree_hash_after: [0xD3; 32],
        k_barrier_new: Zeroizing::new([0xD4; 32]),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(2),
        barrier_update_digest: [0xD5; 32],
        on_path_key_material: BTreeMap::new(),
        activation_source: current_pending_activation_source(&session),
    });

    let outcome = apply_pending_barrier_activation_from_history(&client, &mut session, 5).await?;
    assert_eq!(outcome, PendingBarrierHistoryOutcome::Unchanged);
    assert!(
        session.barrier_state.pending.is_some(),
        "404 or missing acceptance history must retain pending state fail-closed"
    );
    assert!(
        session.barrier_state.barrier_recovery_pending,
        "history discard alone must not falsely mark the session as recovered"
    );
    assert!(
        session.barrier_state.barrier_recovery_issue.is_none(),
        "plain 404 without a newer committed barrier version should stay pending, not escalate to recovery-required"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn pending_join_finalize_history_lookup_404_after_newer_version_requires_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let client = new_api_client(&server_url);
    let room_id = hex_encode([0xC7u8; 32]);
    let mut session = build_test_session(0xC64, &server_url, &room_id, "erin")?;
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 5,
        we_epoch_id: [0xD1; 32],
        fs_ec: 31,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash: [0xD2; 32],
        kem_tree_hash_after: [0xD3; 32],
        k_barrier_new: Zeroizing::new([0xD4; 32]),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(2),
        barrier_update_digest: [0xD5; 32],
        on_path_key_material: BTreeMap::new(),
        activation_source: current_pending_activation_source(&session),
    });

    let outcome = apply_pending_barrier_activation_from_history(&client, &mut session, 6).await?;
    assert_eq!(
        outcome,
        PendingBarrierHistoryOutcome::RecoveryRequired(
            BarrierRecoveryIssue::InsufficientAuthenticatedHistory
        )
    );
    assert!(
        session.barrier_state.pending.is_some(),
        "recovery-required escalation must retain pending state for later authenticated resolution"
    );
    assert!(
        session.barrier_state.barrier_recovery_pending,
        "recovery-required escalation must keep the session fail-closed"
    );
    assert_eq!(
        session.barrier_state.barrier_recovery_issue,
        Some(BarrierRecoveryIssue::InsufficientAuthenticatedHistory)
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn pending_barrier_history_lookup_discards_superseded_locator()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let room_id = hex_encode([0x57u8; 32]);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server_url = format!("http://{addr}");
    let mut session = build_test_session(0xC62, &server_url, &room_id, "carol")?;
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 5,
        we_epoch_id: [0xEF; 32],
        fs_ec: 31,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash: [0xD2; 32],
        kem_tree_hash_after: [0xD3; 32],
        k_barrier_new: Zeroizing::new([0xD4; 32]),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(2),
        barrier_update_digest: [0xEE; 32],
        on_path_key_material: BTreeMap::new(),
        activation_source: current_pending_activation_source(&session),
    });
    let body = build_lookup_merge_acceptance_response_bytes(
        &session,
        2,
        Some(5),
        Some(31),
        Some(2),
        Some(vec![0xAA; 32]),
        HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        },
    )?;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = Vec::new();
        let mut header_end = None;
        let mut expected_len = None;
        loop {
            let mut chunk = [0u8; 4096];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if header_end.is_none()
                && let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n")
            {
                let end = offset + 4;
                header_end = Some(end);
                let header_text = String::from_utf8_lossy(&request[..end]);
                expected_len = header_text
                    .lines()
                    .find_map(|line| {
                        let mut parts = line.splitn(2, ':');
                        let name = parts.next()?.trim();
                        let value = parts.next()?.trim();
                        if name.eq_ignore_ascii_case("content-length") {
                            value.parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .or(Some(0));
            }
            if let (Some(end), Some(content_len)) = (header_end, expected_len)
                && request.len() >= end.saturating_add(content_len)
            {
                break;
            }
        }

        let response_head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/protobuf\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response_head.as_bytes()).await?;
        stream.write_all(body.as_slice()).await?;
        stream.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });

    let client = new_api_client(&server_url);
    let outcome = apply_pending_barrier_activation_from_history(&client, &mut session, 6).await?;
    assert_eq!(outcome, PendingBarrierHistoryOutcome::Discarded);
    assert!(
        session.barrier_state.pending.is_none(),
        "superseded authenticated locator must discard stale pending state"
    );

    tokio::time::timeout(Duration::from_secs(1), server).await???;
    Ok(())
}

#[tokio::test]
async fn pending_barrier_history_lookup_discards_final_rejected_locator()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server_url = format!("http://{addr}");
    let room_id = hex_encode([0x58u8; 32]);
    let mut session = build_test_session(0xC63, &server_url, &room_id, "diana")?;
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 7,
        we_epoch_id: [0xA1; 32],
        fs_ec: 41,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash: [0xB2; 32],
        kem_tree_hash_after: [0xC3; 32],
        k_barrier_new: Zeroizing::new([0xD4; 32]),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(1),
        barrier_update_digest: [0xE5; 32],
        on_path_key_material: BTreeMap::new(),
        activation_source: current_pending_activation_source(&session),
    });
    let body = build_lookup_merge_acceptance_response_bytes(
        &session,
        3,
        None,
        None,
        None,
        None,
        HistoryCommitment {
            history_view_id: [0xD2; 32],
            history_commitment_id: [0xE2; 32],
            prev_history_commitment_id: [0xE1; 32],
            history_seq: 8,
        },
    )?;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = Vec::new();
        let mut header_end = None;
        let mut expected_len = None;
        loop {
            let mut chunk = [0u8; 4096];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if header_end.is_none()
                && let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n")
            {
                let end = offset + 4;
                header_end = Some(end);
                let header_text = String::from_utf8_lossy(&request[..end]);
                expected_len = header_text
                    .lines()
                    .find_map(|line| {
                        let mut parts = line.splitn(2, ':');
                        let name = parts.next()?.trim();
                        let value = parts.next()?.trim();
                        if name.eq_ignore_ascii_case("content-length") {
                            value.parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .or(Some(0));
            }
            if let (Some(end), Some(content_len)) = (header_end, expected_len)
                && request.len() >= end.saturating_add(content_len)
            {
                break;
            }
        }

        let response_head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/protobuf\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response_head.as_bytes()).await?;
        stream.write_all(body.as_slice()).await?;
        stream.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });

    let client = new_api_client(&server_url);
    let outcome = apply_pending_barrier_activation_from_history(&client, &mut session, 8).await?;
    assert_eq!(outcome, PendingBarrierHistoryOutcome::Discarded);
    assert!(
        session.barrier_state.pending.is_none(),
        "final_rejected authenticated locator must discard stale pending state"
    );

    tokio::time::timeout(Duration::from_secs(1), server).await???;
    Ok(())
}

#[tokio::test]
async fn pending_barrier_history_lookup_accepted_mismatch_requires_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server_url = format!("http://{addr}");
    let room_id = hex_encode([0x59u8; 32]);
    let mut session = build_test_session(0xC65, &server_url, &room_id, "frank")?;
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 9,
        we_epoch_id: [0xA1; 32],
        fs_ec: 41,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash: [0xB2; 32],
        kem_tree_hash_after: [0xC3; 32],
        k_barrier_new: Zeroizing::new([0xD4; 32]),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(1),
        barrier_update_digest: [0xE5; 32],
        on_path_key_material: BTreeMap::new(),
        activation_source: current_pending_activation_source(&session),
    });
    let body = build_lookup_merge_acceptance_response_bytes(
        &session,
        1,
        Some(9),
        Some(42),
        Some(1),
        Some(vec![0xA9; 32]),
        HistoryCommitment {
            history_view_id: [0xD3; 32],
            history_commitment_id: [0xE3; 32],
            prev_history_commitment_id: [0xE2; 32],
            history_seq: 9,
        },
    )?;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = Vec::new();
        let mut header_end = None;
        let mut expected_len = None;
        loop {
            let mut chunk = [0u8; 4096];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if header_end.is_none()
                && let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n")
            {
                let end = offset + 4;
                header_end = Some(end);
                let header_text = String::from_utf8_lossy(&request[..end]);
                expected_len = header_text
                    .lines()
                    .find_map(|line| {
                        let mut parts = line.splitn(2, ':');
                        let name = parts.next()?.trim();
                        let value = parts.next()?.trim();
                        if name.eq_ignore_ascii_case("content-length") {
                            value.parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .or(Some(0));
            }
            if let (Some(end), Some(content_len)) = (header_end, expected_len)
                && request.len() >= end.saturating_add(content_len)
            {
                break;
            }
        }

        let response_head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/protobuf\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response_head.as_bytes()).await?;
        stream.write_all(body.as_slice()).await?;
        stream.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });

    let client = new_api_client(&server_url);
    let outcome = apply_pending_barrier_activation_from_history(&client, &mut session, 9).await?;
    assert_eq!(
        outcome,
        PendingBarrierHistoryOutcome::RecoveryRequired(
            BarrierRecoveryIssue::ContradictoryAuthenticatedHistory
        )
    );
    assert!(
        session.barrier_state.pending.is_some(),
        "contradictory acceptance evidence must retain pending state fail-closed"
    );
    assert_eq!(
        session.barrier_state.barrier_recovery_issue,
        Some(BarrierRecoveryIssue::ContradictoryAuthenticatedHistory)
    );

    tokio::time::timeout(Duration::from_secs(1), server).await???;
    Ok(())
}

#[tokio::test]
async fn sequential_member_leaves_succeed() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let mut room_id_bytes = [0x66u8; 32];
    room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
    let room_id = hex_encode(room_id_bytes);
    let (admin_pop_public_key, admin_pop_secret_key) =
        bootstrap_test_room_with_admin_identity(&server_url, &room_id).await?;

    let mut alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    alice.barrier_state.barrier_recovery_pending = false;
    let mut bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };
    bob.barrier_state.barrier_recovery_pending = false;

    let client = new_api_client(&server_url);
    let before_leave = client.members(&alice.gid, None).await?;
    assert_eq!(before_leave.total_count, 2);
    assert!(
        before_leave
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == alice.leaf_id.as_slice())
    );
    assert!(
        before_leave
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == bob.leaf_id.as_slice())
    );

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        persist_session(&alice)?;
        perform_leave(LeaveRequest::from_session(&alice)).await?;
    }
    let after_alice_leave = client.members(&alice.gid, None).await?;
    assert_eq!(after_alice_leave.total_count, 1);
    assert!(
        !after_alice_leave
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == alice.leaf_id.as_slice())
    );
    assert!(
        after_alice_leave
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == bob.leaf_id.as_slice())
    );

    // Membership changes require KBROAD rotation before the next merge ticket.
    let (rotated_kbroad_public, _) = generate_kbroad_keypair();
    let admin_identity =
        RoomIdentity::new(admin_pop_public_key.clone(), admin_pop_secret_key.clone());
    let admin_proof = admin_identity.build_kbroad_proof(
        RoomAdminOperation::RotateKbroad,
        &room_id,
        &rotated_kbroad_public,
    )?;
    client
        .rotate_room_kbroad_as_admin(&room_id, &rotated_kbroad_public, admin_proof)
        .await?;

    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        persist_session(&bob)?;
        perform_leave(LeaveRequest::from_session(&bob)).await?;
    }
    let after_bob_leave = client.members(&alice.gid, None).await?;
    assert_eq!(after_bob_leave.total_count, 0);
    assert!(after_bob_leave.members.is_empty());

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn rejoin_with_same_persisted_identity_succeeds_after_room_becomes_empty()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let mut room_id_bytes = [0x67u8; 32];
    room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
    let room_id = hex_encode(room_id_bytes);
    let (admin_pop_public_key, admin_pop_secret_key) =
        bootstrap_test_room_with_admin_identity(&server_url, &room_id).await?;

    let mut alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    alice.barrier_state.barrier_recovery_pending = false;
    let mut bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };
    bob.barrier_state.barrier_recovery_pending = false;

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        persist_session(&alice)?;
        perform_leave(LeaveRequest::from_session(&alice)).await?;
    }

    let (rotated_kbroad_public, _) = generate_kbroad_keypair();
    let admin_identity =
        RoomIdentity::new(admin_pop_public_key.clone(), admin_pop_secret_key.clone());
    let admin_proof = admin_identity.build_kbroad_proof(
        RoomAdminOperation::RotateKbroad,
        &room_id,
        &rotated_kbroad_public,
    )?;
    new_api_client(&server_url)
        .rotate_room_kbroad_as_admin(&room_id, &rotated_kbroad_public, admin_proof)
        .await?;

    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        persist_session(&bob)?;
        perform_leave(LeaveRequest::from_session(&bob)).await?;
    }

    let client = new_api_client(&server_url);
    let empty_members = client.members(&alice.gid, None).await?;
    assert_eq!(empty_members.total_count, 0);
    assert!(empty_members.members.is_empty());

    let rejoined = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };

    assert_eq!(
        rejoined.pop_public_key, alice.pop_public_key,
        "rejoin should reuse the persisted room identity"
    );
    assert_eq!(
        rejoined.leaf_id, alice.leaf_id,
        "same persisted room identity should map to the same leaf id"
    );

    let after_rejoin = client.members(&alice.gid, None).await?;
    assert_eq!(after_rejoin.total_count, 1);
    assert!(
        after_rejoin
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == rejoined.leaf_id.as_slice()),
        "rejoined member should be visible again"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn send_fetch_and_members_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?; // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x77u8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let mut alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    alice.barrier_state.barrier_recovery_pending = false;
    let mut bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };
    bob.barrier_state.barrier_recovery_pending = false;

    let members = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch_members(MembersParams::from_session(&bob, 0, 50, MembersMode::Full)).await?
    };
    assert!(
        members.total_count >= members.members.len() as u64,
        "total_count should bound page length"
    );
    assert!(
        members.next_offset >= members.members.len() as u64 || members.next_offset == 0,
        "next_offset should be coherent with page size"
    );

    let search = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch_members(MembersParams::from_session(
            &bob,
            0,
            50,
            MembersMode::Search {
                query: "ali".to_string(),
            },
        ))
        .await?
    };
    assert!(
        search.total_count >= search.members.len() as u64,
        "search total_count should bound page length"
    );

    let plaintext = "hello-from-bob".to_string();
    let sent = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_send(SendParams::from_session(&bob, plaintext.clone(), 0)?).await?
    };
    assert_eq!(sent.plaintext, plaintext);
    assert_eq!(sent.sender_leaf, Some(bob.leaf_id));

    let stale_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice, None)?).await?
    };
    assert!(
        stale_fetch
            .messages
            .iter()
            .all(|message| message.plaintext != plaintext),
        "pre-sync fetch should not decrypt messages from a newer epoch"
    );

    let alice_members = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch_members(MembersParams::from_session(
            &alice,
            0,
            50,
            MembersMode::Full,
        ))
        .await?
    };
    let mut alice_with_latest_root = alice.clone();
    alice_with_latest_root.parent_root = alice_members.root;
    let synced_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_epoch_sync(alice_with_latest_root).await?
    };
    assert!(
        synced_alice.changed,
        "epoch sync should adopt latest head after another member joins"
    );

    let mut synced_alice_session = synced_alice.session;
    synced_alice_session.barrier_state.barrier_recovery_pending = false;
    let synced_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&synced_alice_session, None)?).await?
    };
    assert!(
        synced_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == plaintext
                && message.sender_leaf == Some(bob.leaf_id)),
        "post-sync fetch should include messages from the latest epoch"
    );

    let fetched = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch(FetchParams::from_session(&bob, None)?).await?
    };
    assert!(
        !fetched.messages.is_empty(),
        "fetch should return at least one message"
    );
    assert!(
        fetched
            .messages
            .iter()
            .any(|message| message.plaintext == plaintext
                && message.sender_leaf == Some(bob.leaf_id)),
        "fetch should include sent message"
    );

    let since = fetched.last_timestamp_ms;
    let fetched_after = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_fetch(FetchParams::from_session(&bob, since)?).await?
    };
    if let Some(threshold) = since {
        assert!(
            fetched_after
                .messages
                .iter()
                .all(|message| message.timestamp_ms > threshold),
            "since filter must drop already-seen messages"
        );
    }

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[test]
#[ignore = "manual benchmark for msg_index persistence cost"]
fn benchmark_msg_index_persistence_cost_profile() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut session = build_test_session(0xBEEF, "http://127.0.0.1:9", "bench-room", "bench")?;

    let iterations: u64 = 2_000;
    let start_counter = std::time::Instant::now();
    let mut counter: u64 = 0;
    for _ in 0..iterations {
        counter = counter.saturating_add(1);
    }
    let counter_elapsed = start_counter.elapsed();
    assert_eq!(counter, iterations);

    let start_persist = std::time::Instant::now();
    for i in 0..iterations {
        session.last_fetch_timestamp_ms = Some(i);
        persist_session(&session)?;
    }
    let persist_elapsed = start_persist.elapsed();

    let persist_ops = (iterations as f64) / persist_elapsed.as_secs_f64().max(1e-9);
    let persist_ms = persist_elapsed.as_secs_f64() * 1_000.0 / (iterations as f64);
    let counter_ops = (iterations as f64) / counter_elapsed.as_secs_f64().max(1e-9);
    eprintln!(
        "BENCH[msg_index_persist] iterations={iterations} persist_total_ms={:.2} persist_per_op_ms={persist_ms:.4} persist_ops_per_sec={persist_ops:.1} counter_ops_per_sec={counter_ops:.1}",
        persist_elapsed.as_secs_f64() * 1_000.0
    );
    Ok(())
}

#[tokio::test]
#[ignore = "manual benchmark for send throughput with and without msg_index persistence"]
async fn benchmark_send_throughput_with_vs_without_msg_index_persist()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?; // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0xE1u8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;
    let session = perform_join(JoinParams {
        server_url: server_url.clone(),
        room_id,
        alias: "bench-sender".to_string(),
    })
    .await?;

    let iterations: u64 = 120;
    let mut msg_index: u64 = 0;

    for i in 0..10u64 {
        perform_send(SendParams::from_session(
            &session,
            format!("warmup-no-persist-{i}"),
            msg_index,
        )?)
        .await?;
        msg_index = msg_index.saturating_add(1);
    }

    let no_persist_start = std::time::Instant::now();
    for i in 0..iterations {
        perform_send(SendParams::from_session(
            &session,
            format!("bench-no-persist-{i}"),
            msg_index,
        )?)
        .await?;
        msg_index = msg_index.saturating_add(1);
    }
    let no_persist_elapsed = no_persist_start.elapsed();

    let mut strict_session = session.clone();
    let mut strict_msg_index = msg_index;
    let persist_start = std::time::Instant::now();
    for i in 0..iterations {
        let current = strict_msg_index;
        strict_msg_index = strict_msg_index.saturating_add(1);
        strict_session.last_fetch_timestamp_ms = Some(current);
        persist_session(&strict_session)?;
        perform_send(SendParams::from_session(
            &strict_session,
            format!("bench-with-persist-{i}"),
            current,
        )?)
        .await?;
    }
    let persist_elapsed = persist_start.elapsed();

    let no_persist_tps = (iterations as f64) / no_persist_elapsed.as_secs_f64().max(1e-9);
    let persist_tps = (iterations as f64) / persist_elapsed.as_secs_f64().max(1e-9);
    eprintln!(
        "BENCH[send_throughput] iterations={iterations} no_persist_total_ms={:.2} no_persist_msg_per_sec={no_persist_tps:.1} with_persist_total_ms={:.2} with_persist_msg_per_sec={persist_tps:.1}",
        no_persist_elapsed.as_secs_f64() * 1_000.0,
        persist_elapsed.as_secs_f64() * 1_000.0
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
#[ignore = "manual benchmark for barrier chain-check latency and large-n hashing"]
async fn benchmark_barrier_chain_check_latency_profile() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    fn synthetic_entries(n_max: u64) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        let n_max_usize = usize::try_from(n_max)?;
        let total = n_max_usize
            .checked_mul(2)
            .and_then(|v| v.checked_sub(1))
            .ok_or_else(|| anyhow!("synthetic entry length overflow"))?;
        let mut out = Vec::with_capacity(total);
        for i in 0..total {
            if i % 7 == 0 {
                out.push(vec![0xA5; 1184]);
            } else {
                out.push(Vec::new());
            }
        }
        Ok(out)
    }

    let mut hash_profiles = Vec::new();
    for &n_max in &[1024u64, 2048u64] {
        let mut entries_post = synthetic_entries(n_max)?;
        let entries_pre = synthetic_entries(n_max)?;
        // Simulate post-update tree delta on a handful of nodes.
        for idx in (0..entries_post.len()).step_by(257) {
            entries_post[idx] = vec![0x5A; 1184];
        }
        let pre = Arc::new(entries_pre);
        let post = Arc::new(entries_post);
        let rounds = 20u64;
        let cpu_start = std::time::Instant::now();
        let mut last = [0u8; 32];
        for _ in 0..rounds {
            let before = compute_barrier_tree_hash(n_max, pre.as_slice())?;
            let after = compute_barrier_tree_hash(n_max, post.as_slice())?;
            last = before;
            for i in 0..last.len() {
                last[i] ^= after[i];
            }
        }
        let cpu_elapsed = cpu_start.elapsed();

        let blocking_start = std::time::Instant::now();
        for _ in 0..rounds {
            let pre = Arc::clone(&pre);
            let post = Arc::clone(&post);
            let _: ([u8; 32], [u8; 32]) =
                tokio::task::spawn_blocking(move || -> Result<_, anyhow::Error> {
                    Ok((
                        compute_barrier_tree_hash(n_max, pre.as_slice())?,
                        compute_barrier_tree_hash(n_max, post.as_slice())?,
                    ))
                })
                .await??;
        }
        let blocking_elapsed = blocking_start.elapsed();
        hash_profiles.push((n_max, cpu_elapsed, blocking_elapsed, rounds, last));
    }

    for (n_max, cpu_elapsed, blocking_elapsed, rounds, last) in hash_profiles {
        let cpu_per_round_ms = cpu_elapsed.as_secs_f64() * 1_000.0 / (rounds as f64);
        let blocking_per_round_ms = blocking_elapsed.as_secs_f64() * 1_000.0 / (rounds as f64);
        eprintln!(
            "BENCH[barrier_chain_check] n_max={n_max} rounds={rounds} cpu_total_ms={:.2} cpu_mean_ms={cpu_per_round_ms:.3} spawn_blocking_total_ms={:.2} spawn_blocking_mean_ms={blocking_per_round_ms:.3} hash_prefix={}",
            cpu_elapsed.as_secs_f64() * 1_000.0,
            blocking_elapsed.as_secs_f64() * 1_000.0,
            hex_encode(&last[..4])
        );
    }
    Ok(())
}

#[tokio::test]
async fn members_fetch_recovers_from_stale_parent_root() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x79u8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
    }
    let mut bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };

    // Simulate stale local state (e.g., restored session with outdated parent_root).
    bob.parent_root = [0xAB; 32];

    let members = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch_members(MembersParams::from_session(&bob, 0, 50, MembersMode::Full)).await?
    };
    assert!(
        !members.members.is_empty(),
        "fallback to latest root should return members"
    );
    assert_ne!(
        members.root, [0xAB; 32],
        "fallback should adopt the server-reported root"
    );

    let search = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_fetch_members(MembersParams::from_session(
            &bob,
            0,
            50,
            MembersMode::Search {
                query: "ali".to_string(),
            },
        ))
        .await?
    };
    assert!(
        search.total_count >= search.members.len() as u64,
        "search fallback should produce coherent pagination metadata"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn members_fetch_recovers_from_stale_parent_root_on_nonzero_offset()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x7Bu8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
    }
    let mut bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };

    bob.parent_root = [0xCD; 32];
    let full_page = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch_members(MembersParams::from_session(&bob, 1, 1, MembersMode::Full)).await?
    };
    assert!(
        full_page.total_count >= 2,
        "fallback on nonzero offset should preserve roster total"
    );
    assert_ne!(
        full_page.root, [0xCD; 32],
        "fallback should replace stale root on nonzero offset"
    );

    let search_page = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_fetch_members(MembersParams::from_session(
            &bob,
            1,
            1,
            MembersMode::Search {
                query: "a".to_string(),
            },
        ))
        .await?
    };
    assert!(
        search_page.total_count >= search_page.members.len() as u64,
        "search fallback should return coherent pagination metadata"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn members_fetch_prefers_latest_root_when_old_root_is_still_valid()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x7Au8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let mut alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    alice.barrier_state.barrier_recovery_pending = false;
    let bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };
    assert_ne!(
        alice.parent_root, bob.parent_root,
        "second join should advance parent root"
    );

    // Alice's root is still valid, but stale. Members fetch should now resolve
    // against latest server root for page 0.
    let page = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_fetch_members(MembersParams::from_session(
            &alice,
            0,
            50,
            MembersMode::Full,
        ))
        .await?
    };
    assert!(
        page.total_count >= 2,
        "latest-root roster should include both members"
    );
    assert_ne!(
        page.root, alice.parent_root,
        "page 0 should not remain on stale local root"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn latest_bundle_after_second_join_retains_hp_envelope_for_sync()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?; // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x46u8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    let bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };

    let client = new_api_client(&server_url);
    let ticket = client
        .merge_ticket_refresh(&room_id, &alice.leaf_id)
        .await?;
    assert_eq!(
        ticket.we_epoch_id.as_slice(),
        bob.we_epoch_id.as_slice(),
        "latest merge ticket should point at bob's accepted head"
    );
    let bundle_response = client.get_bundle(&bob.we_epoch_id).await?;
    let bundle = ClientEpochBundle::from_cbor(&bundle_response.bundle_cbor)?;
    let hp_mode = bundle
        .header_map
        .get(&hdr::HDR_HP_BYTES)
        .and_then(|value| match value {
            Value::Array(items) => items.first(),
            _ => None,
        })
        .and_then(|value| match value {
            Value::Text(mode) => Some(mode.as_str()),
            _ => None,
        });
    assert_eq!(
        hp_mode,
        Some(BARRIER_HP_MODE),
        "latest accepted bundle should carry a barrier-sealed HP envelope for sync recovery"
    );
    let synced = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_epoch_sync(alice).await?.session
    };
    assert_eq!(
        synced.we_epoch_id, bob.we_epoch_id,
        "peer sync should adopt the accepted latest epoch without a room secret"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn epoch_sync_rejects_gid_mismatch_between_session_and_bundle()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?; // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x7Cu8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let mut alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    alice.barrier_state.barrier_recovery_pending = false;
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?;
    }

    let mut mismatched = alice.clone();
    mismatched.gid = [0xEE; 32];
    let sync_result = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_epoch_sync(mismatched).await
    };
    let err = match sync_result {
        Ok(_) => return Err(anyhow!("epoch sync should fail when gid mismatches").into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("bundle gid mismatch"),
        "expected explicit gid mismatch error: {err}"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn epoch_sync_after_second_join_does_not_require_kbroad_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x7Du8; 32]);

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?;
    }

    assert!(
        !{
            let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
            perform_epoch_sync(alice)
                .await?
                .session
                .barrier_state
                .barrier_recovery_pending
        },
        "epoch sync after second join should complete without a room KBROAD secret"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn epoch_sync_rejects_barrier_bundle_history_commitment_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x7Eu8; 32]);

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?;
    }

    let synced_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let synced = perform_epoch_sync(alice).await?.session;
        persist_session(&synced)?;
        synced
    };

    let current_commitment = synced_alice
        .barrier_state
        .current_history_commitment
        .ok_or_else(|| anyhow!("expected local current history commitment after epoch sync"))?;
    let mut mismatched = synced_alice.clone();
    mismatched.barrier_state.current_history_commitment = Some(HistoryCommitment {
        history_view_id: current_commitment.history_view_id,
        history_commitment_id: [0xEF; 32],
        prev_history_commitment_id: current_commitment.prev_history_commitment_id,
        history_seq: current_commitment.history_seq,
    });
    let sync_result = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_epoch_sync(mismatched).await
    };
    let err = match sync_result {
        Ok(_) => {
            return Err(anyhow!(
                "epoch sync should fail when the local authenticated current history commitment is falsified"
            )
            .into());
        }
        Err(err) => err,
    };
    assert!(
        err.to_string().contains(
            "epoch sync merge ticket current history commitment conflicts with locally authenticated state"
        ) || err.to_string().contains(
            "bundle barrier history commitment mismatch with local authenticated current state"
        ),
        "expected explicit history commitment mismatch error: {err}"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn epoch_sync_rejects_barrier_bundle_fs_policy_version_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x7Fu8; 32]);

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?;
    }

    let mut mismatched = alice.clone();
    mismatched.fs_policy_version = "999".to_string();
    let sync_result = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_epoch_sync(mismatched).await
    };
    let err = match sync_result {
        Ok(_) => {
            return Err(anyhow!(
                "epoch sync should fail when fs_policy_version diverges from the persisted client policy"
            )
            .into());
        }
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("client-side activation guard failed (944.6): fs_policy_version mismatch"),
        "expected explicit fs_policy_version mismatch error: {err}"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn perform_join_succeeds_with_bootstrap_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x88u8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let alice = perform_join(JoinParams {
        server_url: server_url.clone(),
        room_id: room_id.clone(),
        alias: "alice".to_string(),
    })
    .await?;
    assert!(
        alice.bootstrap_public.is_empty(),
        "bootstrap key should be absent when bootstrap policy is disabled"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn perform_join_populates_barrier_leaf_key_material() -> Result<(), Box<dyn std::error::Error>>
{
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x8Fu8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let session = perform_join(JoinParams {
        server_url: server_url.clone(),
        room_id: room_id.clone(),
        alias: "barrier-keys".to_string(),
    })
    .await?;

    assert_eq!(
        session.barrier_state.dk_leaf.len(),
        cityg_client::barrier_crypto::barrier_leaf_secret_key_bytes(),
        "join should persist ML-KEM leaf private key material"
    );
    assert_ne!(
        session.barrier_state.pkhash_leaf, [0u8; 32],
        "join should persist non-zero leaf public key hash"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn perform_join_bootstraps_unprovisioned_room() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x89u8; 32]);

    let session = perform_join(JoinParams {
        server_url: server_url.clone(),
        room_id: room_id.clone(),
        alias: "alice".to_string(),
    })
    .await?;
    assert!(
        !session.kbroad_public.is_empty(),
        "auto-bootstrap join should persist room KBROAD public key"
    );
    assert!(
        !session.barrier_state.barrier_recovery_pending,
        "auto-bootstrap join should finalize initial barrier setup"
    );
    assert_eq!(
        session.barrier_state.barrier_version, 1,
        "initial barrier setup should advance barrier version"
    );
    assert_ne!(
        *session.barrier_state.k_barrier, [0u8; 32],
        "initial barrier setup should derive a non-zero barrier key"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn perform_join_bootstrapped_room_can_send_immediately()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x90u8; 32]);

    let session = perform_join(JoinParams {
        server_url: server_url.clone(),
        room_id,
        alias: "alice".to_string(),
    })
    .await?;
    assert!(
        !session.barrier_state.barrier_recovery_pending,
        "bootstrapped join should leave the creator message-ready"
    );

    perform_send(SendParams::from_session(
        &session,
        "hello after create".to_string(),
        1,
    )?)
    .await?;

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn perform_join_second_member_can_send_immediately() -> Result<(), Box<dyn std::error::Error>>
{
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x92u8; 32]);

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    assert!(
        !alice.barrier_state.barrier_recovery_pending,
        "first join should leave room creator message-ready"
    );

    let bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };
    assert!(
        !bob.barrier_state.barrier_recovery_pending,
        "second join should self-finalize without waiting for another client"
    );
    assert!(
        bob.barrier_state.current_barrier_full_verified,
        "second join should bootstrap FULL public-state verification before join_finalize"
    );
    assert!(
        bob.barrier_state
            .bootstrap_current_barrier_update
            .is_empty()
            && bob.barrier_state.bootstrap_history_commitment.is_none()
            && bob.barrier_state.bootstrap_join_finalize_auth_token == [0u8; 32],
        "post-finalize session should clear bootstrap provisioning artifact"
    );
    assert!(
        bob.barrier_state.barrier_version >= alice.barrier_state.barrier_version,
        "second join should not regress barrier version"
    );

    let sent = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_send(SendParams::from_session(
            &bob,
            "hello from bob immediately".to_string(),
            0,
        )?)
        .await?
    };
    assert_eq!(sent.sender_leaf, Some(bob.leaf_id));

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn perform_join_bootstrapped_room_can_refresh_immediately()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x91u8; 32]);

    let session = perform_join(JoinParams {
        server_url: server_url.clone(),
        room_id: room_id.clone(),
        alias: "alice".to_string(),
    })
    .await?;
    assert!(
        !session.barrier_state.barrier_recovery_pending,
        "bootstrapped join should leave the creator message-ready"
    );

    let client = new_api_client(&server_url);
    let ticket = client
        .merge_ticket_refresh(&room_id, &session.leaf_id)
        .await
        .context("fetch merge ticket after bootstrapped join")?;
    assert_eq!(
        ticket.we_epoch_id, session.we_epoch_id,
        "bootstrapped join must already track the latest accepted epoch"
    );
    let bundle_response = client
        .get_bundle(&ticket.we_epoch_id)
        .await
        .context("fetch latest bundle after bootstrapped join")?;
    let bundle = ClientEpochBundle::from_cbor(&bundle_response.bundle_cbor)
        .context("decode latest bundle after bootstrapped join")?;
    let server_dev_commit = header_bytes32(&bundle.header_map, hdr::HDR_FS_DEV_COMMIT)
        .ok_or_else(|| anyhow!("latest bundle missing fs_dev_commit"))?;
    assert_eq!(
        session.fs_dev_prev_commit, server_dev_commit,
        "bootstrapped join must persist the latest accepted fs_dev_commit"
    );
    assert_eq!(
        session.forward_state.snapshot().fs_dev_commit,
        server_dev_commit,
        "bootstrapped join must also advance local FS state to the latest accepted dev commit"
    );
    assert!(
        session.forward_state.snapshot().fs_ec > session.fs_ec,
        "local FS state should advance beyond the visible anchor fs_ec after a refresh"
    );

    perform_pcs_refresh(LeaveRequest::from_session(&session)).await?;

    let persisted = load_session_at(&server_url, &room_id)?
        .ok_or_else(|| anyhow!("expected persisted session after pcs refresh"))?;
    assert!(
        persisted.barrier_state.pending.is_some(),
        "pcs refresh should persist pending barrier state for later activation"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn epoch_sync_after_second_join_keeps_local_pcs_refresh_valid()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x93u8; 32]);

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    let alice_prev_commit_before_sync = alice.fs_dev_prev_commit;

    let _bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };

    let synced_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let synced = perform_epoch_sync(alice).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert_eq!(
        synced_alice.fs_dev_prev_commit, alice_prev_commit_before_sync,
        "syncing another member's join_finalize must not overwrite local device fs_dev_prev_commit"
    );
    let synced_current_commitment = synced_alice
        .barrier_state
        .current_history_commitment
        .as_ref()
        .ok_or_else(|| {
            anyhow!("epoch sync should persist authenticated current history commitment")
        })?;
    assert_eq!(
        synced_alice.barrier_state.current_history_view_id,
        synced_current_commitment.history_view_id,
        "epoch sync should keep current_history_view_id aligned with the authenticated current history commitment"
    );

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_pcs_refresh(LeaveRequest::from_session(&synced_alice)).await?;
    }

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn stale_dueling_pcs_refreshes_converge_and_preserve_messaging()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0xA2u8; 32]);

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    let bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let latest_members = perform_fetch_members(MembersParams::from_session(
            &alice,
            0,
            50,
            MembersMode::Full,
        ))
        .await?;
        let mut alice_with_latest_root = alice.clone();
        alice_with_latest_root.parent_root = latest_members.root;
        let synced = perform_epoch_sync(alice_with_latest_root).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert!(
        !alice.barrier_state.barrier_recovery_pending
            && !bob.barrier_state.barrier_recovery_pending,
        "both members should start message-ready before the refresh race"
    );

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_pcs_refresh(LeaveRequest::from_session(&alice)).await?;
    }
    let alice_after_refresh = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let pending = load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted alice session after refresh"))?;
        let synced = perform_epoch_sync(pending).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert!(
        !alice_after_refresh.barrier_state.barrier_recovery_pending,
        "refresh winner must converge back to a message-ready state"
    );

    let bob_refresh_result = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        persist_session(&bob)?;
        perform_pcs_refresh(LeaveRequest::from_session(&bob)).await
    };
    let bob_after_refresh = match bob_refresh_result {
        Ok(()) => {
            let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
            let pending = load_session_at(&server_url, &room_id)?
                .ok_or_else(|| anyhow!("expected persisted bob session after refresh"))?;
            let synced = perform_epoch_sync(pending).await?.session;
            persist_session(&synced)?;
            synced
        }
        Err(_) => {
            let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
            let synced = perform_epoch_sync(bob).await?.session;
            persist_session(&synced)?;
            synced
        }
    };
    assert!(
        !bob_after_refresh.barrier_state.barrier_recovery_pending,
        "refresh loser must still recover cleanly via epoch sync"
    );

    let alice_latest = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let synced = perform_epoch_sync(alice_after_refresh).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert_eq!(
        alice_latest.we_epoch_id, bob_after_refresh.we_epoch_id,
        "dueling refresh attempts must converge to a single epoch head"
    );
    assert_eq!(
        alice_latest.barrier_state.barrier_version, bob_after_refresh.barrier_state.barrier_version,
        "dueling refresh attempts must converge to a single barrier version"
    );

    let alice_plaintext = "alice-after-refresh-race".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_send(SendParams::from_session(
            &alice_latest,
            alice_plaintext.clone(),
            0,
        )?)
        .await?;
    }
    let bob_plaintext = "bob-after-refresh-race".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_send(SendParams::from_session(
            &bob_after_refresh,
            bob_plaintext.clone(),
            0,
        )?)
        .await?;
    }

    let alice_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_fetch(FetchParams::from_session(&alice_latest, None)?).await?
    };
    assert!(
        alice_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == alice_plaintext),
        "post-race fetch should preserve the local member's traffic"
    );
    assert!(
        alice_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == bob_plaintext),
        "post-race fetch should preserve the remote member's traffic"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn offline_member_restart_then_epoch_sync_after_pcs_refresh_decrypts_new_messages()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0xA6u8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    let bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };
    let alice_synced = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let latest_members = perform_fetch_members(MembersParams::from_session(
            &alice,
            0,
            50,
            MembersMode::Full,
        ))
        .await?;
        let mut alice_with_latest_root = alice.clone();
        alice_with_latest_root.parent_root = latest_members.root;
        let synced = perform_epoch_sync(alice_with_latest_root).await?.session;
        persist_session(&synced)?;
        synced
    };

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        persist_session(&alice_synced)?;
    }

    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        persist_session(&bob)?;
        perform_pcs_refresh(LeaveRequest::from_session(&bob)).await?;
    }
    let bob_after_refresh = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        let pending = load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted bob session after refresh"))?;
        let synced = perform_epoch_sync(pending).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert!(
        !bob_after_refresh.barrier_state.barrier_recovery_pending,
        "refresh author should return to message-ready before sending offline traffic"
    );

    let offline_plaintext = "bob-while-alice-offline".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_send(SendParams::from_session(
            &bob_after_refresh,
            offline_plaintext.clone(),
            0,
        )?)
        .await?;
    }

    let stale_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted stale alice session before catch-up"))?
    };
    let stale_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&stale_alice, None)?).await?
    };
    assert!(
        stale_fetch
            .messages
            .iter()
            .all(|message| message.plaintext != offline_plaintext),
        "offline member must not decrypt traffic from a newer epoch before syncing"
    );

    let alice_after_restart_and_sync = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let reloaded = load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted alice session after simulated restart"))?;
        let synced = perform_epoch_sync(reloaded).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert!(
        !alice_after_restart_and_sync
            .barrier_state
            .barrier_recovery_pending,
        "offline member should become message-ready again after epoch sync"
    );

    let caught_up_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(
            &alice_after_restart_and_sync,
            None,
        )?)
        .await?
    };
    assert!(
        caught_up_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == offline_plaintext
                && message.sender_leaf == Some(bob_after_refresh.leaf_id)),
        "offline member should decrypt post-refresh traffic after restart and sync"
    );

    let reply_plaintext = "alice-after-offline-catchup".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_send(SendParams::from_session(
            &alice_after_restart_and_sync,
            reply_plaintext.clone(),
            1,
        )?)
        .await?;
    }
    let bob_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_fetch(FetchParams::from_session(&bob_after_refresh, None)?).await?
    };
    assert!(
        bob_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == reply_plaintext
                && message.sender_leaf == Some(alice_after_restart_and_sync.leaf_id)),
        "sender should still decrypt the offline member's reply after catch-up"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn restart_after_leave_preserves_survivor_refresh_and_new_join()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");
    let charlie_base = temp_dir.path().join("cityg").join("gui-charlie");
    let journal_dir = temp_dir.path().join("cityg").join("server");
    std::fs::create_dir_all(&journal_dir)?;
    let journal_path = journal_dir.join("restart-after-leave.journal");

    let port = next_test_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let mut room_id_bytes = [0x94u8; 32];
    room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
    let room_id = hex_encode(room_id_bytes);

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    let bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };
    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let synced = perform_epoch_sync(alice).await?.session;
        persist_session(&synced)?;
        synced
    };

    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        persist_session(&bob)?;
        perform_leave(LeaveRequest::from_session(&bob)).await?;
    }
    let _after_leave_ticket = new_api_client(&server_url)
        .merge_ticket_refresh(&room_id, &alice.leaf_id)
        .await?;

    let synced_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let synced = perform_epoch_sync(alice).await?.session;
        persist_session(&synced)?;
        synced
    };
    let client = new_api_client(&server_url);
    let after_leave = client.members(&synced_alice.gid, None).await?;
    assert_eq!(after_leave.total_count, 1);
    assert!(
        after_leave
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == synced_alice.leaf_id.as_slice()),
        "survivor must remain visible before restart"
    );
    assert!(
        !after_leave
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == bob.leaf_id.as_slice()),
        "revoked leaver must stay absent before restart"
    );

    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path).await;
    sleep(Duration::from_millis(250)).await;

    let after_restart = new_api_client(&server_url)
        .members(&synced_alice.gid, None)
        .await?;
    assert_eq!(after_restart.total_count, 1);
    assert!(
        after_restart
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == synced_alice.leaf_id.as_slice()),
        "survivor must remain visible after restart"
    );
    assert!(
        !after_restart
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == bob.leaf_id.as_slice()),
        "revoked leaver must stay absent after restart"
    );

    let post_restart_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let synced = perform_epoch_sync(synced_alice)
            .await
            .map_err(|err| anyhow!("post-restart alice epoch sync: {err:#}"))?
            .session;
        persist_session(&synced)?;
        synced
    };

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_pcs_refresh(LeaveRequest::from_session(&post_restart_alice))
            .await
            .map_err(|err| anyhow!("post-restart alice PCS refresh: {err:#}"))?;
    }

    let charlie = {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id,
            alias: "charlie".to_string(),
        })
        .await
        .map_err(|err| anyhow!("post-restart charlie join: {err:#}"))?
    };
    let charlie = if charlie.barrier_state.barrier_recovery_pending {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base));
        perform_epoch_sync(charlie)
            .await
            .map_err(|err| anyhow!("post-restart charlie join epoch sync: {err:#}"))?
            .session
    } else {
        charlie
    };
    assert!(
        !charlie.barrier_state.barrier_recovery_pending,
        "new join must become message-ready after restart"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn multi_author_messaging_across_refresh_epoch_change_preserves_delivery()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0xA9u8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    let bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };
    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let latest_members = perform_fetch_members(MembersParams::from_session(
            &alice,
            0,
            50,
            MembersMode::Full,
        ))
        .await?;
        let mut alice_with_latest_root = alice.clone();
        alice_with_latest_root.parent_root = latest_members.root;
        let synced = perform_epoch_sync(alice_with_latest_root).await?.session;
        persist_session(&synced)?;
        synced
    };

    let pre_refresh_messages = [
        ("alice-before-refresh", &alice),
        ("bob-before-refresh", &bob),
    ];
    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_send(SendParams::from_session(
            pre_refresh_messages[0].1,
            pre_refresh_messages[0].0.to_string(),
            0,
        )?)
        .await?;
    }
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_send(SendParams::from_session(
            pre_refresh_messages[1].1,
            pre_refresh_messages[1].0.to_string(),
            0,
        )?)
        .await?;
    }

    let mut alice_after_pre_fetch = alice.clone();
    let alice_pre_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_pre_fetch, None)?).await?
    };
    for (plaintext, sender) in pre_refresh_messages {
        assert!(
            alice_pre_fetch
                .messages
                .iter()
                .any(|message| message.plaintext == plaintext
                    && message.sender_leaf == Some(sender.leaf_id)),
            "pre-refresh fetch should include {plaintext}"
        );
    }
    apply_fetch_outcome_to_session(&mut alice_after_pre_fetch, &alice_pre_fetch);

    let alice_after_refresh = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        persist_session(&alice_after_pre_fetch)?;
        perform_pcs_refresh(LeaveRequest::from_session(&alice_after_pre_fetch)).await?;
        let pending = load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted alice session after refresh"))?;
        let synced = perform_epoch_sync(pending).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert!(
        !alice_after_refresh.barrier_state.barrier_recovery_pending,
        "refresh author must return to message-ready before post-refresh messaging"
    );

    let alice_post_refresh_plaintext = "alice-after-refresh".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_send(SendParams::from_session(
            &alice_after_refresh,
            alice_post_refresh_plaintext.clone(),
            1,
        )?)
        .await?;
    }

    let stale_bob_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch(FetchParams::from_session(&bob, None)?).await?
    };
    assert!(
        stale_bob_fetch
            .messages
            .iter()
            .all(|message| message.plaintext != alice_post_refresh_plaintext),
        "stale member must not decrypt post-refresh traffic before syncing"
    );

    let bob_after_sync = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        let synced = perform_epoch_sync(bob).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert!(
        !bob_after_sync.barrier_state.barrier_recovery_pending,
        "stale member should become message-ready after syncing the refresh"
    );

    let bob_post_refresh_plaintext = "bob-after-refresh".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_send(SendParams::from_session(
            &bob_after_sync,
            bob_post_refresh_plaintext.clone(),
            1,
        )?)
        .await?;
    }

    let mut bob_after_fetch = bob_after_sync.clone();
    let bob_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch(FetchParams::from_session(&bob_after_fetch, None)?).await?
    };
    assert!(
        bob_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == alice_post_refresh_plaintext
                && message.sender_leaf == Some(alice_after_refresh.leaf_id)),
        "synced stale member should decrypt the post-refresh traffic"
    );
    assert!(
        bob_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == bob_post_refresh_plaintext
                && message.sender_leaf == Some(bob_after_sync.leaf_id)),
        "post-sync fetch should also include the sender's own new traffic"
    );
    assert!(
        bob_fetch.messages.iter().all(|message| {
            message.plaintext != "alice-before-refresh" && message.plaintext != "bob-before-refresh"
        }),
        "post-refresh fetch must not replay pre-refresh traffic after replay-state advanced"
    );
    apply_fetch_outcome_to_session(&mut bob_after_fetch, &bob_fetch);

    let mut alice_after_fetch = alice_after_refresh.clone();
    let alice_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_fetch, None)?).await?
    };
    assert!(
        alice_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == bob_post_refresh_plaintext
                && message.sender_leaf == Some(bob_after_sync.leaf_id)),
        "refresh author should decrypt the stale member's first post-sync traffic"
    );
    apply_fetch_outcome_to_session(&mut alice_after_fetch, &alice_fetch);

    let alice_final_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_fetch(FetchParams::from_session(&alice_after_fetch, None)?).await?
    };
    let bob_final_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_fetch(FetchParams::from_session(&bob_after_fetch, None)?).await?
    };
    assert!(
        alice_final_fetch.messages.is_empty() && bob_final_fetch.messages.is_empty(),
        "once replay-state advances on both sides, repeated fetches should be empty again"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn epoch_sync_survives_multi_version_barrier_gap_after_refresh_and_leave()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let mut room_id_bytes = [0x95u8; 32];
    room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
    let room_id = hex_encode(room_id_bytes);

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    let bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };

    let synced_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let synced = perform_epoch_sync(alice).await?.session;
        persist_session(&synced)?;
        synced
    };

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_pcs_refresh(LeaveRequest::from_session(&synced_alice)).await?;
    }

    let refreshed_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let pending = load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted alice session after pcs refresh"))?;
        let synced = perform_epoch_sync(pending).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert!(
        !refreshed_alice.barrier_state.barrier_recovery_pending,
        "refresh author should finalize local pending barrier state before leaving"
    );

    let (rotated_kbroad_public, _) = generate_kbroad_keypair();
    let admin_identity = RoomIdentity::new(
        refreshed_alice.pop_public_key.clone(),
        refreshed_alice.pop_secret_key.clone(),
    );
    let admin_proof = admin_identity.build_kbroad_proof(
        RoomAdminOperation::RotateKbroad,
        &room_id,
        &rotated_kbroad_public,
    )?;
    new_api_client(&server_url)
        .rotate_room_kbroad_as_admin(&room_id, &rotated_kbroad_public, admin_proof)
        .await?;

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_leave(LeaveRequest::from_session(&refreshed_alice)).await?;
    }

    let bob_previous_we_epoch_id = bob.we_epoch_id;
    let bob_previous_barrier_version = bob.barrier_state.barrier_version;
    let synced_bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_epoch_sync(bob).await?
    };
    assert!(
        synced_bob.changed,
        "stale client should adopt the latest head instead of failing on a version gap"
    );
    assert_ne!(
        synced_bob.session.we_epoch_id, bob_previous_we_epoch_id,
        "sync should move the stale client to a newer epoch head"
    );
    assert!(
        synced_bob.session.barrier_state.barrier_version > bob_previous_barrier_version,
        "sync should advance barrier version even when local state skipped intermediate updates"
    );
    let members_after = new_api_client(&server_url)
        .members(&synced_bob.session.gid, None)
        .await?;
    assert_eq!(members_after.total_count, 1);
    assert!(
        members_after
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == synced_bob.session.leaf_id.as_slice()),
        "surviving member must remain present after catch-up sync"
    );
    if synced_bob.session.barrier_state.barrier_recovery_pending {
        assert_eq!(
            synced_bob.session.epoch_key, [0u8; 32],
            "pending sessions must not derive an epoch key from a stale barrier key"
        );
        assert!(
            FetchParams::from_session(&synced_bob.session, None).is_err(),
            "pending sessions must keep message fetch disabled until recovery completes"
        );
    } else {
        assert_ne!(
            synced_bob.session.epoch_key, [0u8; 32],
            "fully recovered sessions should derive the latest epoch key"
        );
    }

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn perform_join_existing_room_can_self_finalize_without_room_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x8Cu8; 32]);

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    assert!(
        !alice.barrier_state.barrier_recovery_pending,
        "creator should remain message-ready before a second join"
    );

    let bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id,
            alias: "bob".to_string(),
        })
        .await?
    };
    assert!(
        !bob.barrier_state.barrier_recovery_pending,
        "second join should self-finalize without a shared room secret"
    );
    assert!(
        bob.barrier_state.current_barrier_full_verified,
        "existing-room join should bootstrap FULL public-state verification before join_finalize"
    );
    assert!(
        bob.barrier_state
            .bootstrap_current_barrier_update
            .is_empty()
            && bob.barrier_state.bootstrap_history_commitment.is_none()
            && bob.barrier_state.bootstrap_predecessor_kem_tree_hash_after == [0u8; 32]
            && bob.barrier_state.bootstrap_join_records.is_empty()
            && bob.barrier_state.bootstrap_revoked_leaf_indices.is_empty()
            && bob.barrier_state.bootstrap_join_finalize_auth_token == [0u8; 32],
        "post-finalize session should clear bootstrap provisioning artifacts"
    );
    assert!(
        bob.barrier_state.barrier_version >= alice.barrier_state.barrier_version,
        "second join should not regress barrier version"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn perform_fetch_skips_malformed_ciphertexts_and_invalid_auth_envelopes()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x8Cu8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let mut alice = perform_join(JoinParams {
        server_url: server_url.clone(),
        room_id: room_id.clone(),
        alias: "alice".to_string(),
    })
    .await?;
    alice.barrier_state.barrier_recovery_pending = false;

    let client = new_api_client(&server_url);
    client
        .send_message(
            &alice.we_epoch_id,
            &[0x01, 0x02, 0x03],
            Some(&alice.leaf_id),
        )
        .await?;

    let short_payload = encrypt_message(b"tiny", &alice.epoch_key)?;
    client
        .send_message(&alice.we_epoch_id, &short_payload, Some(&alice.leaf_id))
        .await?;

    let mut wrong_prefix = encode_authenticated_message(
        2,
        &vec![b'a'; 2100],
        &vec![0x11; ml_dsa_public_key_bytes()],
        &vec![0x22; ml_dsa_signature_bytes()],
    );
    wrong_prefix[0] = b'X';
    let wrong_prefix_ct = encrypt_message(&wrong_prefix, &alice.epoch_key)?;
    client
        .send_message(&alice.we_epoch_id, &wrong_prefix_ct, Some(&alice.leaf_id))
        .await?;

    let short_public_key = encode_authenticated_message(
        3,
        &vec![b'b'; 2200],
        b"pk",
        &vec![0x33; ml_dsa_signature_bytes()],
    );
    let short_public_key_ct = encrypt_message(&short_public_key, &alice.epoch_key)?;
    client
        .send_message(
            &alice.we_epoch_id,
            &short_public_key_ct,
            Some(&alice.leaf_id),
        )
        .await?;

    let short_signature = encode_authenticated_message(
        4,
        &vec![b'c'; 3500],
        &vec![0x44; ml_dsa_public_key_bytes()],
        b"sig",
    );
    let short_signature_ct = encrypt_message(&short_signature, &alice.epoch_key)?;
    client
        .send_message(
            &alice.we_epoch_id,
            &short_signature_ct,
            Some(&alice.leaf_id),
        )
        .await?;

    let invalid_signature = encode_authenticated_message(
        5,
        b"invalid-signature",
        &vec![0x55; ml_dsa_public_key_bytes()],
        &vec![0x66; ml_dsa_signature_bytes()],
    );
    let invalid_signature_ct = encrypt_message(&invalid_signature, &alice.epoch_key)?;
    client
        .send_message(
            &alice.we_epoch_id,
            &invalid_signature_ct,
            Some(&alice.leaf_id),
        )
        .await?;

    let senderless_payload = encode_authenticated_message(
        6,
        &vec![b'd'; 2200],
        &vec![0x77; ml_dsa_public_key_bytes()],
        &vec![0x88; ml_dsa_signature_bytes()],
    );
    let senderless_payload_ct = encrypt_message(&senderless_payload, &alice.epoch_key)?;
    let senderless_err = client
        .send_message(&alice.we_epoch_id, &senderless_payload_ct, None)
        .await
        .expect_err("server should reject messages without a sender leaf");
    assert!(
        senderless_err
            .to_string()
            .contains("sender must be 32 bytes"),
        "missing sender should fail validation"
    );

    let marker = "valid-message-marker".to_string();
    perform_send(SendParams::from_session(&alice, marker.clone(), 0)?).await?;

    let fetched = perform_fetch(FetchParams::from_session(&alice, None)?).await?;
    assert!(
        fetched
            .messages
            .iter()
            .any(|message| message.plaintext == marker),
        "valid authenticated messages should still be returned"
    );
    assert!(
        fetched
            .messages
            .iter()
            .all(|message| message.ciphertext_hex != hex_encode(&short_payload)),
        "messages failing minimum authenticated size should be skipped"
    );
    assert!(
        fetched
            .messages
            .iter()
            .all(|message| message.ciphertext_hex != hex_encode(&wrong_prefix_ct)),
        "messages with invalid authenticated prefix should be skipped"
    );
    assert!(
        fetched
            .messages
            .iter()
            .all(|message| message.ciphertext_hex != hex_encode(&invalid_signature_ct)),
        "messages with invalid signatures should be skipped"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn perform_fetch_rejects_sender_leaf_spoofing_with_mismatched_public_key()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x8Du8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let mut alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    alice.barrier_state.barrier_recovery_pending = false;

    let bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };

    let client = new_api_client(&server_url);
    let spoofed_plaintext = "spoofed-sender-marker";
    let spoofed_timestamp_ms = 7u64;
    let spoofed_signature = sign_message(
        &alice.leaf_id,
        spoofed_timestamp_ms,
        spoofed_plaintext.as_bytes(),
        &bob.pop_secret_key,
    )?;
    let spoofed_authenticated = encode_authenticated_message(
        spoofed_timestamp_ms,
        spoofed_plaintext.as_bytes(),
        &bob.pop_public_key,
        &spoofed_signature,
    );
    let spoofed_ciphertext = encrypt_message_v2(
        &spoofed_authenticated,
        &MessageCryptoContext {
            gid: &alice.gid,
            we_epoch_id: &alice.we_epoch_id,
            xk_hash: &alice.xk_hash,
            fs_ec: alice.fs_ec,
            barrier_version: alice.barrier_state.barrier_version,
            sender_leaf: &alice.leaf_id,
            epoch_key: &alice.epoch_key,
            k_barrier: &alice.barrier_state.k_barrier,
        },
        1,
    )?;
    client
        .send_message(
            &alice.we_epoch_id,
            &spoofed_ciphertext,
            Some(&alice.leaf_id),
        )
        .await?;

    let fetched = perform_fetch(FetchParams::from_session(&alice, None)?).await?;
    assert!(
        fetched
            .messages
            .iter()
            .all(|message| message.plaintext != spoofed_plaintext),
        "messages whose authenticated sender public key maps to a different leaf must be dropped"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

// ============================================================
// Tests for categorize_error function
// ============================================================

#[test]
fn categorize_error_connection_refused() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("connection refused by server");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Network));
    assert_eq!(result.user_message, "Connection refused");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("request timeout after 30s");
    let result = categorize_error(&err, "send");
    assert!(matches!(result.category, ErrorCategory::Network));
    assert_eq!(result.user_message, "Connection timeout");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_dns_failure() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("DNS resolution failed");
    let result = categorize_error(&err, "fetch");
    assert!(matches!(result.category, ErrorCategory::Network));
    assert_eq!(result.user_message, "Unable to connect to server");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_network_unreachable() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("network unreachable");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Network));
    assert_eq!(result.user_message, "Unable to connect to server");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_404_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("404 not found");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Server));
    assert_eq!(result.user_message, "Resource not found");
    assert!(!result.can_retry);
    Ok(())
}

#[test]
fn stale_server_session_detection_matches_expected_http_errors() {
    let not_found = anyhow!(ApiClientError::HttpStatus {
        status: "404".parse().expect("parse 404 status"),
        message: "resource not found".to_string(),
        freeze_code: None,
        freeze_reason: None,
        failed_index: None,
    });
    assert!(is_stale_server_session_error(&not_found));

    let missing_group = anyhow!(ApiClientError::HttpStatus {
        status: "500".parse().expect("parse 500 status"),
        message: "invalid input: no anchors accepted for group".to_string(),
        freeze_code: None,
        freeze_reason: None,
        failed_index: None,
    });
    assert!(is_stale_server_session_error(&missing_group));

    let unrelated = anyhow!(ApiClientError::HttpStatus {
        status: "500".parse().expect("parse 500 status"),
        message: "internal error".to_string(),
        freeze_code: None,
        freeze_reason: None,
        failed_index: None,
    });
    assert!(!is_stale_server_session_error(&unrelated));
}

#[test]
fn append_messages_dedupes_same_ciphertext_across_timestamp_drift()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut model = AppModel::new(CityGConfig::default());
    let leaf = [0x11; 32];

    let first = ChatMessageEntry {
        sender_leaf: Some(leaf),
        fallback_label: "alice".to_string(),
        plaintext: "hello".to_string(),
        ciphertext_hex: "deadbeef".to_string(),
        timestamp_ms: 1_000,
        delivery: MessageDelivery::Sent,
        pending_id: None,
    };
    let second = ChatMessageEntry {
        sender_leaf: Some(leaf),
        fallback_label: "alice".to_string(),
        plaintext: "hello".to_string(),
        ciphertext_hex: "deadbeef".to_string(),
        timestamp_ms: 1_350,
        delivery: MessageDelivery::Sent,
        pending_id: None,
    };

    assert_eq!(model.append_messages(vec![first]), 1);
    assert_eq!(model.append_messages(vec![second]), 0);
    assert_eq!(model.messages.len(), 1);
    Ok(())
}

#[test]
fn validate_members_root_from_leaves_accepts_matching_root()
-> Result<(), Box<dyn std::error::Error>> {
    let leaves = vec![[0x01; 32], [0x02; 32]];
    let root = canonical_set_root(&leaves)?;
    validate_members_root_from_leaves(root, vec![leaves[1], leaves[0]], 2)?;
    Ok(())
}

#[test]
fn validate_members_root_from_leaves_rejects_duplicates() -> Result<(), Box<dyn std::error::Error>>
{
    let leaf = [0xAA; 32];
    let result = validate_members_root_from_leaves(leaf, vec![leaf, leaf], 2);
    assert!(
        result.is_err(),
        "duplicate leaves should fail root validation"
    );
    Ok(())
}

#[test]
fn validate_members_root_from_leaves_rejects_incorrect_total_count()
-> Result<(), Box<dyn std::error::Error>> {
    let leaves = vec![[0x0Au8; 32], [0x0Bu8; 32]];
    let root = canonical_set_root(&leaves)?;
    let result = validate_members_root_from_leaves(root, leaves, 3);
    assert!(
        result
            .as_ref()
            .err()
            .is_some_and(|err| err.to_string().contains("expected 3 leaves")),
        "mismatched roster totals must fail validation: {result:?}"
    );
    Ok(())
}

#[test]
fn activity_log_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut model = AppModel::new(CityGConfig::default());

    for index in 0..(MAX_ACTIVITY_EVENTS + 10) {
        model.record_activity(ActivityKind::System, format!("event {index}"));
    }

    assert_eq!(model.activity_events.len(), MAX_ACTIVITY_EVENTS);
    assert_eq!(model.activity_events[0].summary, "event 10");
    let expected_last = format!("event {}", MAX_ACTIVITY_EVENTS + 9);
    assert_eq!(
        model.activity_events.last().map(|e| e.summary.as_str()),
        Some(expected_last.as_str())
    );
    Ok(())
}

#[test]
fn confirm_pending_message_replaces_placeholder() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut model = AppModel::new(CityGConfig::default());
    let pending_id = 42;
    let leaf = [0x22; 32];

    model.messages.push(ChatMessageEntry {
        sender_leaf: Some(leaf),
        fallback_label: "sab".to_string(),
        plaintext: "Test".to_string(),
        ciphertext_hex: String::new(),
        timestamp_ms: 2_000,
        delivery: MessageDelivery::Pending,
        pending_id: Some(pending_id),
    });

    model.confirm_pending_message(
        pending_id,
        ChatMessageEntry {
            sender_leaf: Some(leaf),
            fallback_label: "sab".to_string(),
            plaintext: "Test".to_string(),
            ciphertext_hex: "cafebabe".to_string(),
            timestamp_ms: 2_010,
            delivery: MessageDelivery::Sent,
            pending_id: None,
        },
    );

    assert_eq!(model.messages.len(), 1);
    assert_eq!(model.messages[0].ciphertext_hex, "cafebabe");
    assert_eq!(model.messages[0].delivery, MessageDelivery::Sent);
    assert_eq!(model.messages[0].pending_id, None);
    Ok(())
}

#[test]
fn pending_message_lifecycle_marks_failed() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut model = AppModel::new(CityGConfig::default());
    let session = build_test_session(
        0xA11CE,
        "http://127.0.0.1:18080",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "alice",
    )?;

    let pending_id = model.queue_pending_message(&session, "hello");
    assert_eq!(model.messages.len(), 1);
    assert_eq!(model.messages[0].delivery, MessageDelivery::Pending);
    assert_eq!(model.messages[0].pending_id, Some(pending_id));
    assert_eq!(model.messages[0].fallback_label, "alice");

    model.mark_pending_message_failed(pending_id);
    assert_eq!(model.messages[0].delivery, MessageDelivery::Failed);
    assert_eq!(model.messages[0].pending_id, None);

    // Missing pending IDs should be ignored.
    model.mark_pending_message_failed(u64::MAX);
    assert_eq!(model.messages.len(), 1);
    Ok(())
}

#[test]
fn render_helpers_cover_session_and_message_list_paths() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut model = AppModel::new(CityGConfig::default());

    // No-panics smoke tests for helper UI builders.
    let _ = model.render_spinner();
    let _ = model.session_row("Server", "http://127.0.0.1:18080");

    let mut session = build_test_session(
        0xE0C0,
        "http://127.0.0.1:18080",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "sab",
    )?;

    session.fs_epoch_created_at = SystemTime::now() - Duration::from_secs(42);
    let _ = model.render_epoch_age_row(&session);
    session.fs_epoch_created_at = SystemTime::now() - Duration::from_secs(15 * 60);
    let _ = model.render_epoch_age_row(&session);
    session.fs_epoch_created_at = SystemTime::now() - Duration::from_secs(3 * 3600);
    let _ = model.render_epoch_age_row(&session);

    // Empty list branch.
    let _ = model.render_message_list();

    model.messages = vec![
        ChatMessageEntry {
            sender_leaf: Some([0x01; 32]),
            fallback_label: "pending".to_string(),
            plaintext: "pending text".to_string(),
            ciphertext_hex: "aa".to_string(),
            timestamp_ms: 1,
            delivery: MessageDelivery::Pending,
            pending_id: Some(1),
        },
        ChatMessageEntry {
            sender_leaf: Some([0x02; 32]),
            fallback_label: "failed".to_string(),
            plaintext: "failed text".to_string(),
            ciphertext_hex: "bb".to_string(),
            timestamp_ms: 2,
            delivery: MessageDelivery::Failed,
            pending_id: None,
        },
        ChatMessageEntry {
            sender_leaf: Some([0x03; 32]),
            fallback_label: "sent".to_string(),
            plaintext: "sent text".to_string(),
            ciphertext_hex: "cc".to_string(),
            timestamp_ms: 3,
            delivery: MessageDelivery::Sent,
            pending_id: None,
        },
    ];
    model.show_ciphertext = false;
    let _ = model.render_message_list();
    model.show_ciphertext = true;
    let _ = model.render_message_list();

    Ok(())
}

#[test]
fn sender_resolution_membership_activity_and_security_persist()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut model = AppModel::new(CityGConfig::default());
    let leaf = [0xAB; 32];

    model.members.push(MemberEntry {
        leaf_id: leaf,
        alias: Some("goy".to_string()),
        pop_public_key: Some(vec![0x01]),
        join_timestamp_ms: Some(1),
        last_seen_timestamp_ms: Some(2),
    });
    let from_member = ChatMessageEntry {
        sender_leaf: Some(leaf),
        fallback_label: "fallback".to_string(),
        plaintext: "hello".to_string(),
        ciphertext_hex: "abcd".to_string(),
        timestamp_ms: 100,
        delivery: MessageDelivery::Sent,
        pending_id: None,
    };
    assert!(model.resolve_sender_label(&from_member).contains("goy"));

    model.members.clear();
    model.leaf_alias_index.insert(leaf, "sab".to_string());
    assert!(model.resolve_sender_label(&from_member).contains("sab"));

    model.leaf_alias_index.clear();
    assert_eq!(model.resolve_sender_label(&from_member), "fallback");

    model.record_membership_activity(&MembershipSignal {
        gid: [0x11; 32],
        leaf_id: Some(leaf),
        kind: Some(MembershipSignalKind::Join),
        sequence: Some(1),
        replayed: false,
        timestamp_ms: Some(1234),
    });
    model.record_membership_activity(&MembershipSignal {
        gid: [0x11; 32],
        leaf_id: Some(leaf),
        kind: Some(MembershipSignalKind::Revoke),
        sequence: Some(2),
        replayed: true,
        timestamp_ms: None,
    });
    model.record_membership_activity(&MembershipSignal {
        gid: [0x11; 32],
        leaf_id: None,
        kind: None,
        sequence: None,
        replayed: false,
        timestamp_ms: None,
    });
    assert_eq!(model.activity_events.len(), 3);
    assert!(model.activity_events[0].summary.contains("Roster join"));
    assert!(
        model.activity_events[0]
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("sequence 1"))
    );
    assert!(
        model.activity_events[1]
            .summary
            .contains("Replayed roster revoke")
    );
    assert!(
        model.activity_events[1]
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("replayed after reconnect"))
    );
    assert!(model.activity_events[2].summary.contains("Roster changed"));

    let session = build_test_session(
        0x5EED,
        "http://127.0.0.1:18080",
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "sab",
    )?;
    model.session = Some(session.clone());
    model.security_events = vec![SecurityEvent {
        alias: "sab".to_string(),
        description: "security check".to_string(),
        timestamp_ms: 88,
    }];
    model.persist_security_events_to_disk();
    let loaded = load_security_log(&session.server_url, &session.room_id)?;
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].description, "security check");

    // Early-return path when no session.
    model.session = None;
    model.persist_security_events_to_disk();
    Ok(())
}

#[test]
fn helper_formatters_cover_http_epoch_and_leaf_paths() -> Result<(), Box<dyn std::error::Error>> {
    let no_freeze = describe_http_failure("500", "internal", None, None);
    assert_eq!(no_freeze, "server error (500): internal");

    let freeze_only = describe_http_failure("500", "bad", Some(925), None);
    assert!(freeze_only.contains("[freeze 925]"));

    let freeze_with_reason = describe_http_failure("400", "invalid", Some(910), Some("rho"));
    assert!(freeze_with_reason.contains("[freeze 910 rho]"));

    assert_eq!(default_epoch_rotation_interval(), 300);

    let leaf = [0xCD; 32];
    let short = short_leaf_display(&leaf);
    assert!(short.ends_with('…'));
    assert_eq!(short.chars().count(), 9);
    Ok(())
}

#[test]
fn categorize_error_401_unauthorized() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("401 unauthorized");
    let result = categorize_error(&err, "send");
    assert!(matches!(result.category, ErrorCategory::Policy));
    assert_eq!(result.user_message, "Authentication failed");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_admin_token_not_configured() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("request failed with status 401 Unauthorized: admin token is not configured");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Policy));
    assert_eq!(result.user_message, "Admin authentication required");
    assert!(
        result
            .technical_details
            .contains("admin token is not configured")
    );
    assert!(
        result
            .recovery_suggestion
            .contains("CITYG_CLIENT_ADMIN_TOKEN")
    );
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_message_token_not_configured() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("server error (401): message auth token is not configured");
    let result = categorize_error(&err, "send");
    assert!(matches!(result.category, ErrorCategory::Policy));
    assert_eq!(result.user_message, "Message authentication required");
    assert!(
        result
            .technical_details
            .contains("message auth token is not configured")
    );
    assert!(
        result
            .recovery_suggestion
            .contains("CITYG_CLIENT_MESSAGE_AUTH_TOKEN")
    );
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_403_forbidden() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("403 forbidden");
    let result = categorize_error(&err, "leave");
    assert!(matches!(result.category, ErrorCategory::Policy));
    assert_eq!(result.user_message, "Access denied");
    assert!(!result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_crypto_proof_failure() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("proof generation failed");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Crypto));
    assert_eq!(result.user_message, "Cryptographic operation failed");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_crypto_verification() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("verification failed");
    let result = categorize_error(&err, "send");
    assert!(matches!(result.category, ErrorCategory::Crypto));
    assert_eq!(result.user_message, "Cryptographic operation failed");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_crypto_witness() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("witness bundle generation failed");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Crypto));
    assert_eq!(result.user_message, "Cryptographic operation failed");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_crypto_signature() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("signature validation error");
    let result = categorize_error(&err, "fetch");
    assert!(matches!(result.category, ErrorCategory::Crypto));
    assert_eq!(result.user_message, "Cryptographic operation failed");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_rho_replay() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("rho_replay detected");
    let result = categorize_error(&err, "send");
    assert!(matches!(result.category, ErrorCategory::Policy));
    assert_eq!(result.user_message, "Duplicate message detected");
    assert!(!result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_freeze_violation() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("freeze policy violated");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Policy));
    assert_eq!(result.user_message, "Room policy violation");
    assert!(!result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_policy_check() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("policy check failed");
    let result = categorize_error(&err, "send");
    assert!(matches!(result.category, ErrorCategory::Policy));
    assert_eq!(result.user_message, "Policy check failed");
    assert!(!result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_empty_field() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("field must not be empty");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Validation));
    assert_eq!(result.user_message, "Required field missing");
    assert!(!result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_invalid_input() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("invalid room ID format");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Validation));
    assert_eq!(result.user_message, "Invalid input");
    assert!(!result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_not_valid() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("room ID is not valid");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Validation));
    assert_eq!(result.user_message, "Invalid input");
    assert!(!result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_required_field() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("alias is required");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Validation));
    assert_eq!(result.user_message, "Missing required information");
    assert!(!result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_500_internal_server() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("500 internal server error");
    let result = categorize_error(&err, "send");
    assert!(matches!(result.category, ErrorCategory::Server));
    assert_eq!(result.user_message, "Internal server error");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_502_bad_gateway() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("502 bad gateway");
    let result = categorize_error(&err, "fetch");
    assert!(matches!(result.category, ErrorCategory::Network));
    assert_eq!(result.user_message, "Bad gateway");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_503_service_unavailable() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("503 service unavailable");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Server));
    assert_eq!(result.user_message, "Service temporarily unavailable");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_generic_server_error() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("server error occurred");
    let result = categorize_error(&err, "send");
    assert!(matches!(result.category, ErrorCategory::Server));
    assert_eq!(result.user_message, "Server error occurred");
    assert!(result.can_retry);
    Ok(())
}

#[test]
fn categorize_error_default_fallback_join() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("some unknown error");
    let result = categorize_error(&err, "join");
    assert!(matches!(result.category, ErrorCategory::Server));
    assert!(result.user_message.contains("Failed to join room"));
    Ok(())
}

#[test]
fn categorize_error_default_fallback_send() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("some unknown error");
    let result = categorize_error(&err, "send");
    assert!(matches!(result.category, ErrorCategory::Server));
    assert!(result.user_message.contains("Failed to send message"));
    Ok(())
}

#[test]
fn categorize_error_default_fallback_leave() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("some unknown error");
    let result = categorize_error(&err, "leave");
    assert!(matches!(result.category, ErrorCategory::Server));
    assert!(result.user_message.contains("Failed to leave room"));
    Ok(())
}

#[test]
fn categorize_error_default_fallback_fetch() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("some unknown error");
    let result = categorize_error(&err, "fetch");
    assert!(matches!(result.category, ErrorCategory::Server));
    assert!(result.user_message.contains("Failed to fetch messages"));
    Ok(())
}

#[test]
fn categorize_error_default_fallback_generic() -> Result<(), Box<dyn std::error::Error>> {
    let err = anyhow!("some unknown error");
    let result = categorize_error(&err, "unknown_context");
    assert!(matches!(result.category, ErrorCategory::Server));
    assert!(result.user_message.contains("Operation failed"));
    Ok(())
}

#[test]
fn categorize_error_case_insensitive() -> Result<(), Box<dyn std::error::Error>> {
    // Test that error matching is case insensitive
    let err1 = anyhow!("CONNECTION REFUSED");
    let result1 = categorize_error(&err1, "join");
    assert!(matches!(result1.category, ErrorCategory::Network));

    let err2 = anyhow!("TIMEOUT");
    let result2 = categorize_error(&err2, "send");
    assert!(matches!(result2.category, ErrorCategory::Network));

    let err3 = anyhow!("PROOF generation failed");
    let result3 = categorize_error(&err3, "join");
    assert!(matches!(result3.category, ErrorCategory::Crypto));
    Ok(())
}

// ============================================================
// Tests for authenticated message encoding/decoding
// ============================================================

#[test]
fn encode_decode_authenticated_message_empty_plaintext() -> Result<(), Box<dyn std::error::Error>> {
    let (msg_sign_public_key, msg_sign_secret_key) =
        cityg_client::message_auth::generate_message_signing_keypair();

    let leaf_id = [0x42u8; 32];
    let plaintext = b"";
    let timestamp_ms = 1_234_567_890u64;

    let signature = sign_message(&leaf_id, timestamp_ms, plaintext, &msg_sign_secret_key)?;
    let authenticated_msg =
        encode_authenticated_message(timestamp_ms, plaintext, &msg_sign_public_key, &signature);

    let envelope = decode_authenticated_message(&authenticated_msg)?;
    assert_eq!(envelope.timestamp_ms, timestamp_ms);
    assert_eq!(envelope.plaintext, plaintext);
    assert_eq!(envelope.public_key, msg_sign_public_key.as_slice());
    assert_eq!(envelope.signature, signature.as_slice());
    Ok(())
}

#[test]
fn encode_decode_authenticated_message_large_plaintext() -> Result<(), Box<dyn std::error::Error>> {
    let (msg_sign_public_key, msg_sign_secret_key) =
        cityg_client::message_auth::generate_message_signing_keypair();

    let leaf_id = [0x42u8; 32];
    let plaintext = vec![b'A'; 5000]; // 5KB message
    let timestamp_ms = 1_234_567_890u64;

    let signature = sign_message(&leaf_id, timestamp_ms, &plaintext, &msg_sign_secret_key)?;
    let authenticated_msg =
        encode_authenticated_message(timestamp_ms, &plaintext, &msg_sign_public_key, &signature);

    let envelope = decode_authenticated_message(&authenticated_msg)?;
    assert_eq!(envelope.timestamp_ms, timestamp_ms);
    assert_eq!(envelope.plaintext, plaintext.as_slice());
    assert_eq!(envelope.public_key, msg_sign_public_key.as_slice());
    assert_eq!(envelope.signature, signature.as_slice());
    Ok(())
}

#[test]
fn decode_authenticated_message_too_short() -> Result<(), Box<dyn std::error::Error>> {
    // Message shorter than minimum size should fail
    let short_data = vec![0u8; 10];
    let result = decode_authenticated_message(&short_data);
    assert!(result.is_err());
    let err = match result {
        Err(e) => e,
        Ok(_) => return Err("expected error".into()),
    };
    assert!(err.to_string().contains("authenticated message too short"));
    Ok(())
}

#[test]
fn decode_authenticated_message_wrong_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let (msg_sign_public_key, msg_sign_secret_key) =
        cityg_client::message_auth::generate_message_signing_keypair();

    let leaf_id = [0x42u8; 32];
    let plaintext = b"test";
    let timestamp_ms = 1_234_567_890u64;

    let signature = sign_message(&leaf_id, timestamp_ms, plaintext, &msg_sign_secret_key)?;
    let mut authenticated_msg =
        encode_authenticated_message(timestamp_ms, plaintext, &msg_sign_public_key, &signature);

    // Corrupt the prefix
    authenticated_msg[0] ^= 0xFF;

    let result = decode_authenticated_message(&authenticated_msg);
    assert!(result.is_err());
    let err = match result {
        Err(e) => e,
        Ok(_) => return Err("expected error".into()),
    };
    assert!(err.to_string().contains("invalid message prefix"));
    Ok(())
}

// ============================================================
// Tests for CAPSS witness encoding/decoding
// ============================================================

#[test]
fn encode_decode_capss_witness_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    use msphf_rlwe::CapssBranchWitness;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    let mut rng = StdRng::seed_from_u64(12345);
    let mut random_vec = |len: usize| {
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        buf
    };

    let witness = CapssWitnessBundle {
        branch_a: CapssBranchWitness {
            branch_artifact: random_vec(24),
            ctx_tag: random_vec(16),
        },
        branch_b: CapssBranchWitness {
            branch_artifact: random_vec(24),
            ctx_tag: random_vec(16),
        },
    };

    let encoded = encode_capss_witness(&witness)?;
    let decoded = decode_capss_witness(&encoded)?;

    assert_eq!(decoded, witness);
    Ok(())
}

#[test]
fn decode_capss_witness_invalid_data() -> Result<(), Box<dyn std::error::Error>> {
    // Try to decode garbage data
    let invalid_data = vec![0xFF; 100];
    let result = decode_capss_witness(&invalid_data);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn decode_capss_witness_empty_data() -> Result<(), Box<dyn std::error::Error>> {
    let empty_data = vec![];
    let result = decode_capss_witness(&empty_data);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn format_regular_fingerprint_blocks_hex() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let formatted = format_regular_fingerprint(Some(&bytes));
    assert_eq!(formatted, "0001-0203 0405-0607 …");
    Ok(())
}

#[test]
fn format_fs_fingerprint_includes_epoch() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = [0xABu8; 32];
    let formatted = format_fs_fingerprint(Some(&bytes), 42);
    assert_eq!(formatted, "abab-abab abab-abab … · fs_ec 42");
    Ok(())
}

#[test]
fn format_fs_fingerprint_reports_missing() -> Result<(), Box<dyn std::error::Error>> {
    let formatted = format_fs_fingerprint(None, 99);
    assert_eq!(formatted, "Not available");
    Ok(())
}

// ============================================================
// Tests for session removal
// ============================================================

#[test]
fn session_removal_after_persistence() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let mut rng = StdRng::seed_from_u64(999);
    let mut random_vec = |len: usize| {
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        buf
    };

    let forward_state =
        ForwardSecrecyState::with_state([0xAAu8; 32], 17, [0x55u8; 32], [0x99u8; 32]);
    let capss_witness_bundle = CapssWitnessBundle {
        branch_a: msphf_rlwe::CapssBranchWitness {
            branch_artifact: random_vec(24),
            ctx_tag: random_vec(16),
        },
        branch_b: msphf_rlwe::CapssBranchWitness {
            branch_artifact: random_vec(24),
            ctx_tag: random_vec(16),
        },
    };
    let capss_witness_bytes = encode_capss_witness(&capss_witness_bundle)?;

    let mut session = AppSession {
        server_url: "https://remove-test.example.com".to_string(),
        room_id: "remove-room-123".to_string(),
        alias: "test-user".to_string(),
        gid: [0x01u8; 32],
        cat: [0x02u8; 32],
        leaf_id: [0x03u8; 32],
        parent_root: [0x04u8; 32],
        join_delta_root: [0x05u8; 32],
        revoked_since_root: [0x06u8; 32],
        revoked_root: [0x07u8; 32],
        regular_fingerprint: Some([0x21u8; 32]),
        fs_fingerprint: None,
        tswe_salt_hash: [0x08u8; 32],
        pox_r_commit: [0x09u8; 32],
        we_epoch_id: [0x10u8; 32],
        xk_hash: [0x14u8; 32],
        epoch_key: [0x11u8; 32],
        forward_state,
        fs_ec: 17,
        fs_epoch_commit: [0x12u8; 32],
        fs_dev_prev_commit: [0x13u8; 32],
        fs_epoch_created_at: SystemTime::now(),
        fs_epoch_rotation_interval_secs: 300,
        pop_public_key: Vec::new(),
        pop_secret_key: Vec::new(),
        msg_sign_public_key: Vec::new(),
        msg_sign_secret_key: Vec::new(),
        vrf_secret_key: random_vec(32),
        vrf_public_key: random_vec(32),
        kbroad_public: random_vec(24),
        bootstrap_public: random_vec(24),
        proof_mode: "lin+zkvrf".to_string(),
        vrf_id: "vrf-demo".to_string(),
        policy_version: "v1".to_string(),
        msphf_crs_id: "rlwe-merkle/v1".to_string(),
        msphf_params_id: "rlwe-params/mock".to_string(),
        fs_policy_version: "7".to_string(),
        fs_epoch_base_ts: 42,
        fs_forward_leap_policy: FsForwardLeapPolicy {
            h: 300,
            checkpoint_interval: 3600,
            slack_anchor: 0,
            slack_first_device: 0,
            slack_device: 4,
        },
        last_accepted_ec: 17,
        last_fetch_timestamp_ms: Some(1_234_567),
        msg_replay_state: MsgReplayState::default(),
        capss_witness: capss_witness_bytes,
        barrier_state: BarrierSecretState::default(),
    };
    install_valid_message_identities(&mut session)?;
    session.fs_fingerprint = derive_fs_fingerprint_from_fields(
        session.fs_policy_version.as_str(),
        session.fs_ec,
        &session.fs_epoch_commit,
        session.fs_epoch_base_ts,
    );

    // Persist, then remove
    persist_session(&session)?;
    let loaded = load_session_at(&session.server_url, &session.room_id)?
        .ok_or_else(|| anyhow!("expected persisted session to load"))?;
    assert_eq!(loaded.room_id, session.room_id);

    // Remove and verify it's gone
    remove_persisted_session(&session.server_url, &session.room_id)?;
    let after_removal = load_session_at(&session.server_url, &session.room_id)?;
    assert!(after_removal.is_none(), "session should be removed");
    Ok(())
}

#[test]
fn session_load_nonexistent() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    // Try to load a session that doesn't exist
    let result = load_session_at("https://nonexistent.example.com", "nonexistent-room")?;
    assert!(result.is_none(), "nonexistent session should return None");
    Ok(())
}
