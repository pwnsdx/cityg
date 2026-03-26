use super::*;
use futures::SinkExt;
use gpui::{EmptyView, Modifiers, TestAppContext};
use msphf_rlwe::CapssBranchWitness;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::sync::{Arc, Once, atomic::AtomicU16};
use tempfile::TempDir;
use tokio::{task::JoinHandle, time::sleep};

use crate::native::app_actions::{
    CopyRoomIdAction, ShowSessionOverviewAction, TextSelectAllAction, ToggleSidebarAction,
};

#[path = "client_state_props.rs"]
mod client_state_props;

static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(18400);
static ENV_VAR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
const TEST_ADMIN_TOKEN: &str = "cityg-test-admin-token";
const TEST_MESSAGE_TOKEN: &str = "cityg-test-message-token";
static TEST_AUTH_ENV_INIT: Once = Once::new();

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
        pop_public_key: random_vec(48),
        pop_secret_key: random_vec(96),
        msg_sign_public_key: random_vec(1952),
        msg_sign_secret_key: random_vec(4032),
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
        last_fetch_timestamp_ms: Some(1_234_567),
        msg_replay_state: MsgReplayState::default(),
        capss_witness: capss_witness_bytes,
        barrier_state,
    };
    session.fs_fingerprint = derive_fs_fingerprint_from_fields(
        session.fs_policy_version.as_str(),
        session.fs_ec,
        &session.fs_epoch_commit,
        session.fs_epoch_base_ts,
    );
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.barrier_roots_hash =
        compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
    session.barrier_state.current_barrier_full_verified = true;
    Ok(session)
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
fn pending_barrier_activation_applies_on_digest_match() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xA11, "http://127.0.0.1:9", "room-a", "alice")?;
    let mut on_path = BTreeMap::new();
    on_path.insert(
        7,
        BarrierNodeKeyMaterial {
            dk: Zeroizing::new(vec![0x11; 32]),
            pkhash: [0x22; 32],
        },
    );
    let raw_update = vec![0xAB, 0xCD, 0xEF];
    let digest = compute_barrier_update_digest(raw_update.as_slice())?;
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 9,
        we_epoch_id: [0x21; 32],
        fs_ec: 31,
        next_forward_fs_ec: 32,
        next_forward_fs_dev_commit: [0x77; 32],
        next_forward_last_weid: [0x21; 32],
        revocation_roots_hash: [0x33; 32],
        kem_tree_hash_after: [0x44; 32],
        k_barrier_new: Zeroizing::new([0x55; 32]),
        k_fs_after_pcs: Some(Zeroizing::new([0x66; 32])),
        barrier_update_reason: Some(1),
        barrier_update_digest: digest,
        on_path_key_material: on_path,
    });

    let changed =
        apply_pending_barrier_activation(&mut session, 9, Some(31), Some(1), Some(digest))?;
    assert!(changed);
    assert!(session.barrier_state.pending.is_none());
    assert!(session.barrier_state.barrier_initialized);
    assert_eq!(session.barrier_state.barrier_version, 9);
    assert_eq!(session.barrier_state.barrier_roots_hash, [0x33; 32]);
    assert_eq!(*session.barrier_state.k_barrier, [0x55; 32]);
    assert_eq!(session.barrier_state.kem_tree_hash_after, [0x44; 32]);
    assert_eq!(
        session
            .barrier_state
            .dk_nodes
            .get(&7)
            .expect("node material persisted")
            .pkhash,
        [0x22; 32]
    );
    assert_eq!(session.forward_state.snapshot().k_fs, [0x66; 32]);
    assert_eq!(session.forward_state.snapshot().fs_ec, 32);
    assert_eq!(session.forward_state.snapshot().fs_dev_commit, [0x77; 32]);
    assert_eq!(session.forward_state.snapshot().last_weid, [0x21; 32]);
    Ok(())
}

#[test]
fn pending_join_finalize_activation_advances_barrier_without_reseeding_k_fs()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xA12, "http://127.0.0.1:9", "room-a2", "alice")?;
    let original_fs = session.forward_state.snapshot().k_fs;
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
    });

    let changed =
        apply_pending_barrier_activation(&mut session, 10, Some(31), Some(2), Some([0x67; 32]))?;
    assert!(changed);
    assert!(session.barrier_state.pending.is_none());
    assert!(!session.barrier_state.barrier_recovery_pending);
    assert_eq!(session.barrier_state.barrier_version, 10);
    assert_eq!(session.barrier_state.barrier_roots_hash, [0x35; 32]);
    assert_eq!(session.barrier_state.kem_tree_hash_after, [0x45; 32]);
    assert_eq!(*session.barrier_state.k_barrier, [0x56; 32]);
    assert_eq!(
        session.forward_state.snapshot().k_fs,
        original_fs,
        "join_finalize must not reseed K_fs"
    );
    assert_eq!(
        session.forward_state.snapshot().fs_ec,
        77,
        "join_finalize should preserve K_fs while advancing the local device snapshot"
    );
    Ok(())
}

#[test]
fn pending_barrier_activation_keeps_state_when_overtaken_without_exact_match()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB22, "http://127.0.0.1:9", "room-b", "bob")?;
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 5,
        we_epoch_id: [0x41; 32],
        fs_ec: 31,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash: [0x11; 32],
        kem_tree_hash_after: [0x22; 32],
        k_barrier_new: Zeroizing::new([0x33; 32]),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(1),
        barrier_update_digest: [0x44; 32],
        on_path_key_material: BTreeMap::new(),
    });

    let changed = apply_pending_barrier_activation(&mut session, 6, None, None, None)?;
    assert!(!changed);
    assert!(session.barrier_state.pending.is_some());
    assert_eq!(session.barrier_state.barrier_version, 0);
    Ok(())
}

#[test]
fn pending_barrier_activation_keeps_state_on_digest_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB3, "http://127.0.0.1:9", "room-b2", "bob")?;
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 7,
        we_epoch_id: [0x42; 32],
        fs_ec: 31,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash: [0x51; 32],
        kem_tree_hash_after: [0x61; 32],
        k_barrier_new: Zeroizing::new([0x71; 32]),
        k_fs_after_pcs: Some(Zeroizing::new([0x81; 32])),
        barrier_update_reason: Some(1),
        barrier_update_digest: [0x91; 32],
        on_path_key_material: BTreeMap::new(),
    });

    let changed =
        apply_pending_barrier_activation(&mut session, 7, Some(31), Some(1), Some([0x92; 32]))?;
    assert!(!changed);
    assert!(session.barrier_state.pending.is_some());
    assert_eq!(session.barrier_state.barrier_version, 0);
    assert_eq!(session.forward_state.snapshot().k_fs, [0xAAu8; 32]);
    Ok(())
}

#[test]
fn pending_barrier_activation_does_not_activate_on_digest_match_with_newer_observed_version()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB4, "http://127.0.0.1:9", "room-b3", "bob")?;
    let digest = [0x31; 32];
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 7,
        we_epoch_id: [0x43; 32],
        fs_ec: 31,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash: [0x41; 32],
        kem_tree_hash_after: [0x51; 32],
        k_barrier_new: Zeroizing::new([0x61; 32]),
        k_fs_after_pcs: Some(Zeroizing::new([0x71; 32])),
        barrier_update_reason: Some(1),
        barrier_update_digest: digest,
        on_path_key_material: BTreeMap::new(),
    });

    let changed =
        apply_pending_barrier_activation(&mut session, 8, Some(31), Some(1), Some(digest))?;
    assert!(!changed);
    assert!(session.barrier_state.pending.is_some());
    assert_eq!(
        session.barrier_state.barrier_version, 0,
        "newer observed version must not activate older pending state"
    );
    assert_eq!(
        session.forward_state.snapshot().k_fs,
        [0xAAu8; 32],
        "PCS reseed must not activate when observed version overtook pending state"
    );
    Ok(())
}

#[test]
fn pending_join_finalize_activation_does_not_activate_on_digest_match_with_newer_observed_version()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB41, "http://127.0.0.1:9", "room-b31", "bob")?;
    let digest = [0x35; 32];
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 7,
        we_epoch_id: [0x45; 32],
        fs_ec: 31,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash: [0x46; 32],
        kem_tree_hash_after: [0x56; 32],
        k_barrier_new: Zeroizing::new([0x66; 32]),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(2),
        barrier_update_digest: digest,
        on_path_key_material: BTreeMap::new(),
    });

    let changed =
        apply_pending_barrier_activation(&mut session, 8, Some(31), Some(2), Some(digest))?;
    assert!(!changed);
    assert!(session.barrier_state.pending.is_some());
    assert!(
        session.barrier_state.barrier_recovery_pending,
        "join_finalize race loss must keep pending recovery active"
    );
    assert_eq!(session.barrier_state.barrier_version, 0);
    assert_eq!(
        session.forward_state.snapshot().k_fs,
        [0xAAu8; 32],
        "observing a newer barrier version must not falsely activate join_finalize"
    );
    Ok(())
}

#[test]
fn pending_barrier_activation_keeps_state_on_fs_ec_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB5, "http://127.0.0.1:9", "room-b4", "bob")?;
    let digest = [0x41; 32];
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 7,
        we_epoch_id: [0x44; 32],
        fs_ec: 31,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash: [0x51; 32],
        kem_tree_hash_after: [0x61; 32],
        k_barrier_new: Zeroizing::new([0x71; 32]),
        k_fs_after_pcs: Some(Zeroizing::new([0x81; 32])),
        barrier_update_reason: Some(1),
        barrier_update_digest: digest,
        on_path_key_material: BTreeMap::new(),
    });

    let changed =
        apply_pending_barrier_activation(&mut session, 7, Some(32), Some(1), Some(digest))?;
    assert!(!changed);
    assert!(session.barrier_state.pending.is_some());
    assert_eq!(session.barrier_state.barrier_version, 0);
    assert_eq!(session.forward_state.snapshot().k_fs, [0xAAu8; 32]);
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

    let (leaf_ek, leaf_dk) = kyber768::keypair();
    session.barrier_state.dk_leaf = Zeroizing::new(KemSecretKey::as_bytes(&leaf_dk).to_vec());
    session.barrier_state.pkhash_leaf = compute_barrier_pkhash(KemPublicKey::as_bytes(&leaf_ek))?;

    let revoked_since_root = [0x11; 32];
    let revoked_root = [0x22; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    let new_public_keys = vec![
        NewPublicKeyWire(0, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        NewPublicKeyWire(1, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        NewPublicKeyWire(4, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
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
        NewPublicKeyWire(0, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        NewPublicKeyWire(1, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        NewPublicKeyWire(4, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
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

    let (leaf_ek, leaf_dk) = kyber768::keypair();
    let leaf_ek_bytes = KemPublicKey::as_bytes(&leaf_ek).to_vec();
    session.barrier_state.dk_leaf = Zeroizing::new(KemSecretKey::as_bytes(&leaf_dk).to_vec());
    session.barrier_state.pkhash_leaf = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;

    let revoked_since_root = [0x31; 32];
    let revoked_root = [0x32; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    session.revoked_since_root = revoked_since_root;
    session.revoked_root = revoked_root;
    session.barrier_state.barrier_roots_hash = rrh;

    let source_node = 4u64;
    let target_node = 10u64;
    let path_secret_source = [0x44; 32];
    let salt_1 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(1))?;
    let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
    let salt_0 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(0))?;
    let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
    let target_pk = kyber768::PublicKey::from_bytes(leaf_ek_bytes.as_slice())?;
    let (ss, ct) = kyber768::encapsulate(&target_pk);
    let target_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
    let aad = to_cbor_vec(&BarrierWrapAadPreimage(
        &session.gid,
        9,
        &rrh,
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
    let cipher = ChaCha20Poly1305::new(ss.as_bytes().into());
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
        KemCiphertext::as_bytes(&ct).to_vec(),
        wrapped_ps,
    )];
    let (_, _, ek_0) = derive_internal_node_key_material(&ps_0, 9, &rrh, 8, 0)?;
    let (_, _, ek_1) = derive_internal_node_key_material(&ps_1, 9, &rrh, 8, 1)?;
    let (_, _, ek_4) = derive_internal_node_key_material(&path_secret_source, 9, &rrh, 8, 4)?;
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

    let barrier_salt = h_l("barrier/derive/salt", &BarrierDeriveSaltPreimage(9, &rrh))?;
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

    let (leaf_ek, leaf_dk) = kyber768::keypair();
    let leaf_ek_bytes = KemPublicKey::as_bytes(&leaf_ek).to_vec();
    session.barrier_state.dk_leaf = Zeroizing::new(KemSecretKey::as_bytes(&leaf_dk).to_vec());
    session.barrier_state.pkhash_leaf = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;

    let revoked_since_root = [0x31; 32];
    let revoked_root = [0x32; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    session.revoked_since_root = revoked_since_root;
    session.revoked_root = revoked_root;
    session.barrier_state.barrier_roots_hash = rrh;

    let source_node = 4u64;
    let target_node = 10u64;
    let path_secret_source = [0x44; 32];
    let salt_1 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(1))?;
    let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
    let salt_0 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(0))?;
    let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
    let target_pk = kyber768::PublicKey::from_bytes(leaf_ek_bytes.as_slice())?;
    let (ss, ct) = kyber768::encapsulate(&target_pk);
    let target_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
    let aad = to_cbor_vec(&BarrierWrapAadPreimage(
        &session.gid,
        9,
        &rrh,
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
    let cipher = ChaCha20Poly1305::new(ss.as_bytes().into());
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
        KemCiphertext::as_bytes(&ct).to_vec(),
        wrapped_ps,
    )];
    let (_, _, ek_0) = derive_internal_node_key_material(&ps_0, 9, &rrh, 8, 0)?;
    let (_, _, mut ek_1) = derive_internal_node_key_material(&ps_1, 9, &rrh, 8, 1)?;
    let (_, _, ek_4) = derive_internal_node_key_material(&path_secret_source, 9, &rrh, 8, 4)?;
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

    let (leaf_ek, leaf_dk) = kyber768::keypair();
    let leaf_ek_bytes = KemPublicKey::as_bytes(&leaf_ek).to_vec();
    session.barrier_state.dk_leaf = Zeroizing::new(KemSecretKey::as_bytes(&leaf_dk).to_vec());
    let correct_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
    session.barrier_state.pkhash_leaf = correct_pkhash;

    let revoked_since_root = [0x31; 32];
    let revoked_root = [0x32; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    session.revoked_since_root = revoked_since_root;
    session.revoked_root = revoked_root;
    session.barrier_state.barrier_roots_hash = rrh;

    let source_node = 4u64;
    let target_node = 10u64;
    let path_secret_source = [0x44; 32];
    let salt_1 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(1))?;
    let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
    let salt_0 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(0))?;
    let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
    let target_pk = kyber768::PublicKey::from_bytes(leaf_ek_bytes.as_slice())?;
    let (ss, ct) = kyber768::encapsulate(&target_pk);
    let aad = to_cbor_vec(&BarrierWrapAadPreimage(
        &session.gid,
        9,
        &rrh,
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
    let cipher = ChaCha20Poly1305::new(ss.as_bytes().into());
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
        KemCiphertext::as_bytes(&ct).to_vec(),
        wrapped_ps,
    )];
    let (_, _, ek_0) = derive_internal_node_key_material(&ps_0, 9, &rrh, 8, 0)?;
    let (_, _, ek_1) = derive_internal_node_key_material(&ps_1, 9, &rrh, 8, 1)?;
    let (_, _, ek_4) = derive_internal_node_key_material(&path_secret_source, 9, &rrh, 8, 4)?;
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

    let (leaf_ek, leaf_dk) = kyber768::keypair();
    let leaf_ek_bytes = KemPublicKey::as_bytes(&leaf_ek).to_vec();
    session.barrier_state.dk_leaf = Zeroizing::new(KemSecretKey::as_bytes(&leaf_dk).to_vec());
    let target_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
    session.barrier_state.pkhash_leaf = target_pkhash;

    let revoked_since_root = [0x31; 32];
    let revoked_root = [0x32; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    session.revoked_since_root = revoked_since_root;
    session.revoked_root = revoked_root;
    session.barrier_state.barrier_roots_hash = rrh;

    let source_node = 4u64;
    let target_node = 10u64;
    let path_secret_source = [0x44; 32];
    let target_pk = kyber768::PublicKey::from_bytes(leaf_ek_bytes.as_slice())?;
    let (ss, ct) = kyber768::encapsulate(&target_pk);
    let aad = to_cbor_vec(&BarrierWrapAadPreimage(
        &session.gid,
        9,
        &rrh,
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
    let cipher = ChaCha20Poly1305::new(ss.as_bytes().into());
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
        KemCiphertext::as_bytes(&ct).to_vec(),
        wrapped_ps,
    )];
    let new_public_keys = vec![
        NewPublicKeyWire(0, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        NewPublicKeyWire(1, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        NewPublicKeyWire(4, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
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
        NewPublicKeyWire(0, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        NewPublicKeyWire(1, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        NewPublicKeyWire(4, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
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
        NewPublicKeyWire(0, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        NewPublicKeyWire(1, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        NewPublicKeyWire(4, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
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

    let (leaf_ek, leaf_dk) = kyber768::keypair();
    let leaf_ek_bytes = KemPublicKey::as_bytes(&leaf_ek).to_vec();
    session.barrier_state.dk_leaf = Zeroizing::new(KemSecretKey::as_bytes(&leaf_dk).to_vec());
    session.barrier_state.pkhash_leaf = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;

    let revoked_since_root = [0x71; 32];
    let revoked_root = [0x72; 32];
    let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    session.revoked_since_root = revoked_since_root;
    session.revoked_root = revoked_root;
    session.barrier_state.barrier_roots_hash = rrh;

    let source_node = 4u64;
    let target_node = 10u64;
    let path_secret_source = [0x74; 32];
    let salt_1 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(1))?;
    let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
    let salt_0 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(0))?;
    let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
    let target_pk = kyber768::PublicKey::from_bytes(leaf_ek_bytes.as_slice())?;
    let (ss, ct) = kyber768::encapsulate(&target_pk);
    let target_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
    let aad = to_cbor_vec(&BarrierWrapAadPreimage(
        &session.gid,
        9,
        &rrh,
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
    let cipher = ChaCha20Poly1305::new(ss.as_bytes().into());
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
        KemCiphertext::as_bytes(&ct).to_vec(),
        wrapped_ps,
    )];
    let (_, _, ek_0) = derive_internal_node_key_material(&ps_0, 9, &rrh, 8, 0)?;
    let (_, _, ek_1) = derive_internal_node_key_material(&ps_1, 9, &rrh, 8, 1)?;
    let (_, _, ek_4) = derive_internal_node_key_material(&path_secret_source, 9, &rrh, 8, 4)?;
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

    let barrier_salt = h_l("barrier/derive/salt", &BarrierDeriveSaltPreimage(9, &rrh))?;
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
        NewPublicKeyWire(0, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        NewPublicKeyWire(1, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        NewPublicKeyWire(4, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
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
    let (pop_public_key, pop_secret_key) = cityg_api_client::generate_room_admin_keypair();
    let admin_proof = build_room_admin_proof(
        RoomAdminOperation::Bootstrap,
        room_id,
        demo::kbroad_public(),
        &pop_public_key,
        &pop_secret_key,
    )?;
    new_api_client(server_url)
        .bootstrap_room_as_admin(room_id, demo::kbroad_public(), admin_proof)
        .await
        .map_err(anyhow::Error::from)?;
    Ok((pop_public_key, pop_secret_key))
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

        model.handle_websocket_event(WebSocketEvent::Message, view_cx);
        assert!(model.epoch_sync_task.is_some());
        assert!(!model.fetch_in_flight);
        assert!(matches!(model.fetch_status, FetchStatus::Idle));

        model.handle_websocket_event(
            WebSocketEvent::Membership(MembershipSignal {
                gid: session.gid,
                leaf_id: Some(session.leaf_id),
                kind: Some(MembershipSignalKind::Join),
                timestamp_ms: Some(42),
            }),
            view_cx,
        );
        assert!(
            model
                .activity_events
                .iter()
                .any(|event| event.summary.contains("Roster join"))
        );

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

        model.handle_websocket_event(WebSocketEvent::Message, view_cx);
        assert!(model.epoch_sync_task.is_some());
        assert!(model.fetch_after_epoch_sync);

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
                .set_value(hex_encode(vec![0xAA; dilithium5::public_key_bytes()]));
            model.room_admin_revoke_confirmation = Some(vec![0xAA; dilithium5::public_key_bytes()]);
            let _ = model.render_room_admin_panel(window, &panel_session, view_cx);
            let mut other_admin = panel_session.pop_public_key.clone();
            other_admin[0] ^= 0xFF;
            model.room_admins = vec![other_admin];
            let _ = model.render_room_admin_panel(window, &panel_session, view_cx);
            model.members = vec![MemberEntry {
                leaf_id: [0x11; 32],
                alias: Some("alice".to_string()),
                pop_public_key: Some(vec![0xAA; dilithium5::public_key_bytes()]),
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
                pop_public_key: Some(vec![0xBB; dilithium5::public_key_bytes()]),
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
            .set_value(hex_encode(vec![0x33; dilithium5::public_key_bytes()]));

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
        let first_target = vec![0x44; dilithium5::public_key_bytes()];
        let second_target = vec![0x55; dilithium5::public_key_bytes()];
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

#[gpui::test]
fn gpui_on_leave_finished_surfaces_session_cleanup_error(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xBADD,
        "http://127.0.0.1:18080",
        "99aabbccddeeff00112233445566778899aabbccddeeff001122334455667788",
        "leave-err",
    )
    .expect("build session");
    let blocking_path =
        session_file_path(&session.server_url, &session.room_id).expect("session path");
    fs::create_dir_all(&blocking_path).expect("create blocking path");

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());
        model.on_leave_finished(Ok(()), view_cx);
        assert!(
            model
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("failed to remove session data")
        );
    });
}

#[gpui::test]
fn gpui_on_refresh_finished_reloads_persisted_pending_barrier_state(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let stale_session = build_test_session(
        0xCAFE,
        "http://127.0.0.1:18081",
        "11aabbccddeeff00112233445566778899aabbccddeeff001122334455667799",
        "refresh-reload",
    )
    .expect("build stale session");
    let mut persisted_session = stale_session.clone();
    persisted_session.barrier_state.barrier_initialized = true;
    persisted_session.barrier_state.barrier_version = 7;
    persisted_session.barrier_state.barrier_recovery_pending = true;
    persisted_session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 8,
        we_epoch_id: [0x44; 32],
        barrier_update_digest: [0x55; 32],
        barrier_update_reason: Some(1),
        ..BarrierPendingState::default()
    });
    persist_session(&persisted_session).expect("persist session with pending barrier state");

    view.update(cx, |model, view_cx| {
        model.session = Some(stale_session);
        model.on_refresh_finished(Ok(()), view_cx);

        let reloaded = model.session.as_ref().expect("reloaded session");
        assert_eq!(reloaded.barrier_state.barrier_version, 7);
        assert!(reloaded.barrier_state.barrier_recovery_pending);
        assert!(
            reloaded.barrier_state.pending.is_some(),
            "refresh completion must reload pending barrier activation data"
        );
        assert_eq!(
            model.info_message.as_deref(),
            Some("PCS refresh submitted. Syncing latest epoch…")
        );
    });
}

#[gpui::test]
fn gpui_handle_fetch_result_requires_replay_persistence_before_release(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xD15C,
        "http://127.0.0.1:18082",
        "22aabbccddeeff00112233445566778899aabbccddeeff001122334455667799",
        "fetch-persist",
    )
    .expect("build session");
    let mut session = session;
    session.last_fetch_timestamp_ms = None;
    let blocking_path =
        session_file_path(&session.server_url, &session.room_id).expect("session path");
    fs::create_dir_all(&blocking_path).expect("create blocking path");

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());
        model.handle_fetch_result(
            Ok(FetchOutcome {
                messages: vec![ChatMessageEntry {
                    sender_leaf: Some(session.leaf_id),
                    fallback_label: session.alias.clone(),
                    plaintext: "must-not-release".to_string(),
                    ciphertext_hex: "deadbeef".to_string(),
                    timestamp_ms: 2_000_000,
                    delivery: MessageDelivery::Sent,
                    pending_id: None,
                }],
                last_timestamp_ms: Some(2_000_000),
                msg_replay_state: MsgReplayState::default(),
            }),
            session.we_epoch_id,
            view_cx,
        );

        assert!(
            model.messages.is_empty(),
            "messages must not be released before replay persistence succeeds"
        );
        assert!(
            model
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("Failed to persist session after fetch update"),
            "persist failure must surface as fetch persistence failure"
        );
        assert_eq!(
            model.session.as_ref().and_then(|s| s.last_fetch_timestamp_ms),
            None,
            "failed replay persistence must not advance in-memory fetch watermark"
        );
    });
}

#[gpui::test]
fn gpui_keystroke_routing_covers_clipboard_shortcuts(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));

    cx.write_to_clipboard(ClipboardItem::new_string("http://demo".to_string()));
    view.update(cx, |model, view_cx| {
        model.join_form.server.clear();
        model.join_form.room_id.clear();
        model.join_form.alias = "sab".to_string();
        model.join_form.active = Some(ActiveField::Server);
        model.on_keystroke(&Keystroke::parse("cmd-v").expect("parse cmd-v"), view_cx);
        assert_eq!(model.join_form.server, "http://demo");

        let server_text = model.join_form.server.clone();
        model.join_form.server_editor.select_all(&server_text);
        model.on_keystroke(&Keystroke::parse("cmd-c").expect("parse cmd-c"), view_cx);
        let copied = view_cx
            .read_from_clipboard()
            .and_then(|item| item.text())
            .expect("clipboard join field");
        assert_eq!(copied, "http://demo");

        model.on_keystroke(&Keystroke::parse("cmd-x").expect("parse cmd-x"), view_cx);
        assert!(model.join_form.server.is_empty());

        model.join_status = JoinStatus::Joining;
        model.join_form.alias = "keep".to_string();
        model.on_keystroke(&Keystroke::parse("x->z").expect("parse x"), view_cx);
        assert_eq!(model.join_form.alias, "keep");
        model.join_status = JoinStatus::Idle;
        model.join_form.active = Some(ActiveField::Alias);
        model.on_keystroke(&Keystroke::parse("ctrl-a").expect("parse ctrl-a"), view_cx);
        model.on_keystroke(&Keystroke::parse("x->q").expect("parse x->q"), view_cx);
    });

    let session = build_test_session(
        0x77,
        "http://127.0.0.1:9",
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "goy",
    )
    .expect("build test session");
    cx.write_to_clipboard(ClipboardItem::new_string("\nxyz".to_string()));
    view.update(cx, |model, view_cx| {
        model.session = Some(session);
        model.join_form.active = None;

        model.members_search.focus();
        model.members_search.set_query("ab".to_string());
        model.on_keystroke(&Keystroke::parse("cmd-v").expect("parse cmd-v"), view_cx);
        assert_eq!(model.members_search.query(), "ab xyz");
        model.on_keystroke(&Keystroke::parse("x->d").expect("parse x->d"), view_cx);
        model.on_keystroke(&Keystroke::parse("ctrl-a").expect("parse ctrl-a"), view_cx);
        model.on_keystroke(&Keystroke::parse("enter").expect("parse enter"), view_cx);

        let members_query = model.members_search.query().to_string();
        model.members_search.editor.select_all(&members_query);
        model.on_keystroke(&Keystroke::parse("cmd-x").expect("parse cmd-x"), view_cx);
        assert!(model.members_search.query().is_empty());

        model.members_search.blur();
        model.composer.focus();
        model.composer.set_text("hello".to_string());
        model.on_keystroke(&Keystroke::parse("x->r").expect("parse x->r"), view_cx);
        assert_eq!(model.composer.text(), "hello");
        let composer_text = model.composer.text().to_string();
        model.composer.editor.select_all(&composer_text);
        model.on_keystroke(&Keystroke::parse("cmd-c").expect("parse cmd-c"), view_cx);
        let copied = view_cx
            .read_from_clipboard()
            .and_then(|item| item.text())
            .expect("clipboard composer");
        assert_eq!(copied, "hello");

        model.on_keystroke(&Keystroke::parse("cmd-x").expect("parse cmd-x"), view_cx);
        assert!(model.composer.text().is_empty());
        model.composer.set_text("ok".to_string());
        model.on_keystroke(&Keystroke::parse("enter").expect("parse enter"), view_cx);
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            let event = test_mouse_down_event();
            model.composer.set_text(String::new());
            model.on_send_clicked(&event, window, view_cx);
            model.on_composer_clicked(&event, window, view_cx);
            model.on_join_clicked(&event, window, view_cx);
            model.on_members_search_field_clicked(&event, window, view_cx);
            model.on_members_search_button_clicked(&event, window, view_cx);
            model.on_members_search_clear_clicked(&event, window, view_cx);
            model.on_members_refresh_clicked(&event, window, view_cx);
            model.on_members_load_more_clicked(&event, window, view_cx);
        });
    });
}

#[gpui::test]
fn gpui_async_handler_paths_cover_state_machine(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    cx.refresh().expect("initial refresh");
    cx.run_until_parked();

    let session = build_test_session(
        0xA11CE,
        "http://127.0.0.1:9",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "async",
    )
    .expect("build test session");

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            let event = test_mouse_down_event();

            model.join_form.server = "http://127.0.0.1:9".to_string();
            model.join_form.room_id =
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string();
            model.join_form.alias = "async".to_string();
            model.start_join(view_cx);
            assert!(matches!(model.join_status, JoinStatus::Joining));

            model.on_join_finished(Err(anyhow::anyhow!("join failed")), view_cx);
            assert!(matches!(model.join_status, JoinStatus::Idle));

            model.on_join_finished(Ok(session.clone()), view_cx);
            assert!(model.session.is_some());

            model.composer.set_text("hello".to_string());
            model.start_send(view_cx);
            assert!(matches!(model.send_status, SendStatus::Sending));
            let pending_id = model.next_pending_message_id.saturating_sub(1);
            model.on_send_finished(
                Ok(ChatMessageEntry {
                    sender_leaf: Some(session.leaf_id),
                    fallback_label: session.alias.clone(),
                    plaintext: "hello".to_string(),
                    ciphertext_hex: "abcd".to_string(),
                    timestamp_ms: 42,
                    delivery: MessageDelivery::Sent,
                    pending_id: None,
                }),
                pending_id,
                view_cx,
            );
            model.on_send_finished(
                Err(anyhow::anyhow!("send failed")),
                pending_id.saturating_add(10),
                view_cx,
            );

            let expected_weid = session.we_epoch_id;
            model.handle_fetch_result(
                Ok(FetchOutcome {
                    messages: vec![ChatMessageEntry {
                        sender_leaf: Some(session.leaf_id),
                        fallback_label: session.alias.clone(),
                        plaintext: "synced".to_string(),
                        ciphertext_hex: "beef".to_string(),
                        timestamp_ms: 100,
                        delivery: MessageDelivery::Sent,
                        pending_id: None,
                    }],
                    last_timestamp_ms: Some(100),
                    msg_replay_state: MsgReplayState::default(),
                }),
                expected_weid,
                view_cx,
            );
            model.handle_fetch_result(Err(anyhow::anyhow!("fetch failed")), expected_weid, view_cx);
            model.handle_fetch_result(
                Ok(FetchOutcome {
                    messages: vec![],
                    last_timestamp_ms: None,
                    msg_replay_state: MsgReplayState::default(),
                }),
                [0xFF; 32],
                view_cx,
            );

            model.on_members_refreshed(
                Ok(MembersPage {
                    members: vec![MemberEntry {
                        leaf_id: session.leaf_id,
                        alias: Some(session.alias.clone()),
                        pop_public_key: Some(vec![0x01]),
                        join_timestamp_ms: Some(10),
                        last_seen_timestamp_ms: Some(11),
                    }],
                    root: session.parent_root,
                    total_count: 1,
                    next_offset: 1,
                }),
                view_cx,
            );
            model.on_members_refreshed(Err(anyhow::anyhow!("members failed")), view_cx);

            model.handle_epoch_sync_result(
                Ok(EpochSyncOutcome {
                    session: session.clone(),
                    changed: false,
                }),
                &session.server_url,
                &session.room_id,
                session.leaf_id,
                "noop",
                view_cx,
            );
            let mut changed_session = session.clone();
            changed_session.we_epoch_id = [0x55; 32];
            model.handle_epoch_sync_result(
                Ok(EpochSyncOutcome {
                    session: changed_session,
                    changed: true,
                }),
                &session.server_url,
                &session.room_id,
                session.leaf_id,
                "changed",
                view_cx,
            );
            model.handle_epoch_sync_result(
                Err(anyhow::anyhow!("sync failed")),
                &session.server_url,
                &session.room_id,
                session.leaf_id,
                "err",
                view_cx,
            );

            model.handle_stale_server_session("stale", view_cx);
            assert!(model.session.is_none());

            model.session = Some(session.clone());
            model.on_leave_clicked(&event, window, view_cx);
            assert!(matches!(model.leave_status, LeaveStatus::Leaving));
            model.on_leave_finished(Err(anyhow::anyhow!("leave failed")), view_cx);
            model.on_leave_finished(Ok(()), view_cx);
        });
    });

    cx.refresh().expect("post async state refresh");
    cx.run_until_parked();
}

#[gpui::test]
fn gpui_session_overview_action_toggles_inline_inspector(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        0x1234,
        "http://127.0.0.1:9",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "alice",
    )
    .expect("build test session");

    let (view, cx) = cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        model.session = Some(session);
        model
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_inspector_width(window_width).is_some());

            model.on_show_session_overview_action(&ShowSessionOverviewAction, window, view_cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, app| {
        view.update(app, |model, _| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_inspector_width(window_width).is_none());
        });
    });
    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.on_show_session_overview_action(&ShowSessionOverviewAction, window, view_cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, app| {
        view.update(app, |model, _| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_inspector_width(window_width).is_some());
        });
    });
}

#[gpui::test]
fn gpui_toggle_sidebar_action_toggles_inline_sidebar(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        0x2233,
        "http://127.0.0.1:9",
        "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        "sidebar",
    )
    .expect("build test session");

    let (view, cx) = cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        model.session = Some(session);
        model
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_sidebar_width(window_width).is_some());

            model.on_toggle_sidebar_action(&ToggleSidebarAction, window, view_cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, app| {
        view.update(app, |model, _| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_sidebar_width(window_width).is_none());
        });
    });
    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.on_toggle_sidebar_action(&ToggleSidebarAction, window, view_cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, app| {
        view.update(app, |model, _| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_sidebar_width(window_width).is_some());
        });
    });
}

#[gpui::test]
fn gpui_dispatch_toggle_inspector_action_from_focused_search_field(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        0x7788,
        "http://127.0.0.1:9",
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "focus",
    )
    .expect("build test session");

    let (view, cx) = cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        model.session = Some(session);
        model
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.focus_members_search(window, view_cx);
        });
    });
    cx.run_until_parked();

    cx.dispatch_action(ShowSessionOverviewAction);

    cx.update(|window, app| {
        view.update(app, |model, _| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_inspector_width(window_width).is_none());
        });
    });
}

#[gpui::test]
fn gpui_double_click_members_search_selects_all_text(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        0x3344,
        "http://127.0.0.1:9",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "search",
    )
    .expect("build test session");

    let (view, cx) = cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        model.session = Some(session);
        model.members_search.set_query("member-lookup".to_string());
        model
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.on_text_field_mouse_down(
                NativeTextFieldKind::MembersSearch,
                &test_mouse_down_event_with_click_count(2),
                window,
                view_cx,
            );

            let query = model.members_search.query().to_string();
            assert_eq!(model.members_search.editor.selected_range, 0..query.len());
            assert!(model.members_search.active);
        });
    });
}

#[gpui::test]
fn gpui_secondary_click_members_search_preserves_selection_and_focuses(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        0x4455,
        "http://127.0.0.1:9",
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "search-secondary",
    )
    .expect("build test session");

    let (view, cx) = cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        model.session = Some(session);
        model.members_search.set_query("member-lookup".to_string());
        model.members_search.editor.selected_range = 0..6;
        model
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.on_text_field_secondary_mouse_down(
                NativeTextFieldKind::MembersSearch,
                &test_mouse_down_event_with_button(MouseButton::Right),
                window,
                view_cx,
            );

            assert_eq!(model.members_search.editor.selected_range, 0..6);
            assert!(model.members_search.active);
            assert!(!model.members_search.editor.is_selecting);
        });
    });
}

#[gpui::test]
fn gpui_text_select_all_action_selects_focused_members_search_text(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        0x5566,
        "http://127.0.0.1:9",
        "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        "search-select-all",
    )
    .expect("build test session");

    let (view, cx) = cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        model.session = Some(session);
        model.members_search.set_query("member-lookup".to_string());
        model.members_search.editor.selected_range = 3..3;
        model
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.focus_text_field(NativeTextFieldKind::MembersSearch, window, view_cx);
            model.on_text_select_all_action(&TextSelectAllAction, window, view_cx);

            let query = model.members_search.query().to_string();
            assert_eq!(model.members_search.editor.selected_range, 0..query.len());
            assert!(model.members_search.active);
        });
    });
}

#[gpui::test]
fn gpui_pending_barrier_recovery_surfaces_guidance_instead_of_errors(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let mut session = build_test_session(
        0xBADA55,
        "http://127.0.0.1:9",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "pending",
    )
    .expect("build test session");
    session.barrier_state.barrier_recovery_pending = true;
    session.last_fetch_timestamp_ms = None;

    cx.update(|_, app| {
        view.update(app, |model, view_cx| {
            model.on_join_finished(Ok(session.clone()), view_cx);
            assert_eq!(
                model.info_message.as_deref(),
                Some(AppModel::barrier_recovery_wait_message())
            );
            assert!(
                !model.fetch_in_flight,
                "fetch should stay deferred while pending"
            );
            assert!(
                model.last_error.is_none(),
                "pending recovery is expected state"
            );

            model.composer.set_text("hello".to_string());
            model.start_send(view_cx);
            assert!(matches!(model.send_status, SendStatus::Idle));
            assert_eq!(
                model.info_message.as_deref(),
                Some(AppModel::barrier_recovery_wait_message())
            );
            assert!(
                model.last_error.is_none(),
                "blocked send should not become an error"
            );
        });
    });
}

#[gpui::test]
fn gpui_pending_barrier_recovery_defers_fetch_without_setting_error(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let mut session = build_test_session(
        0xBADA56,
        "http://127.0.0.1:9",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "pending-fetch",
    )
    .expect("build test session");
    session.barrier_state.barrier_recovery_pending = true;

    cx.update(|_, app| {
        view.update(app, |model, view_cx| {
            model.session = Some(session.clone());
            model.schedule_fetch(view_cx, Duration::ZERO);
            assert!(matches!(model.fetch_status, FetchStatus::Idle));
            assert!(
                !model.fetch_in_flight,
                "fetch should not be scheduled while pending"
            );
            assert_eq!(
                model.info_message.as_deref(),
                Some(AppModel::barrier_recovery_wait_message())
            );
            assert!(
                model.last_error.is_none(),
                "deferred fetch should not set an error"
            );
        });
    });
}

#[test]
fn session_encryption_key_prefers_env_passphrase() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let _restore = EnvVarRestore {
        original: std::env::var(SESSION_PASSPHRASE_ENV).ok(),
    };

    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    unsafe { std::env::set_var(SESSION_PASSPHRASE_ENV, "cityg-test-passphrase") };

    let temp_dir = TempDir::new()?;
    let session_path = temp_dir
        .path()
        .join("cityg")
        .join("gui")
        .join("session.json");
    let (key, source) = session_encryption_key(&session_path)?;

    assert_eq!(source.as_str(), SessionKeySource::EnvPassphrase.as_str());
    assert_eq!(
        key,
        blake3::derive_key(SESSION_KEY_DERIVE_CONTEXT, b"cityg-test-passphrase")
    );
    assert!(
        !session_local_key_path(&session_path)?.exists(),
        "env-derived key path must not create local key file"
    );
    Ok(())
}

#[test]
fn session_encryption_key_uses_local_key_file_when_env_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let _restore = EnvVarRestore {
        original: std::env::var(SESSION_PASSPHRASE_ENV).ok(),
    };

    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    unsafe { std::env::remove_var(SESSION_PASSPHRASE_ENV) };

    let temp_dir = TempDir::new()?;
    let session_path = temp_dir
        .path()
        .join("cityg")
        .join("gui")
        .join("session.json");

    let (first_key, first_source) = session_encryption_key(&session_path)?;
    assert_eq!(
        first_source.as_str(),
        SessionKeySource::LocalKeyFile.as_str(),
        "missing env passphrase should use local key file"
    );
    let key_path = session_local_key_path(&session_path)?;
    assert!(key_path.exists(), "local key file should be created");
    assert_eq!(fs::read(&key_path)?.len(), 32, "local key must be 32 bytes");

    let (second_key, second_source) = session_encryption_key(&session_path)?;
    assert_eq!(
        second_source.as_str(),
        SessionKeySource::LocalKeyFile.as_str()
    );
    assert_eq!(
        first_key, second_key,
        "local key should be stable across reads"
    );
    Ok(())
}

#[test]
fn load_or_create_local_session_key_rejects_invalid_file_len()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let session_path = temp_dir
        .path()
        .join("cityg")
        .join("gui")
        .join("session.json");
    let key_path = session_local_key_path(&session_path)?;
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&key_path, vec![0xAB; 31])?;

    let err = load_or_create_local_session_key(&session_path)
        .expect_err("invalid key length should fail");
    assert!(
        err.to_string()
            .contains("session local key must be 32 bytes"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn read_last_session_pointer_missing_invalid_and_valid() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

    assert!(
        read_last_session_pointer()?.is_none(),
        "missing pointer => None"
    );

    let pointer_path = last_session_pointer_path()?;
    if let Some(parent) = pointer_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&pointer_path, b"{not-json")?;
    assert!(
        read_last_session_pointer().is_err(),
        "invalid pointer JSON should error"
    );

    let pointer = LastSessionPointer {
        server_url: "http://127.0.0.1:8080".to_string(),
        room_id: "room-a".to_string(),
    };
    fs::write(&pointer_path, serde_json::to_vec(&pointer)?)?;
    let loaded = read_last_session_pointer()?
        .ok_or_else(|| anyhow!("expected valid pointer to be loaded"))?;
    assert_eq!(loaded.server_url, pointer.server_url);
    assert_eq!(loaded.room_id, pointer.room_id);
    Ok(())
}

#[test]
fn session_dir_respects_cityg_gui_config_dir_env() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let _config_guard = set_config_dir_override_for_tests(None);

    let original = std::env::var("CITYG_GUI_CONFIG_DIR").ok();
    let override_root = TempDir::new()?;
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    unsafe {
        std::env::set_var(
            "CITYG_GUI_CONFIG_DIR",
            override_root.path().to_string_lossy().to_string(),
        )
    };

    let resolved = session_dir()?;
    assert_eq!(
        resolved,
        override_root.path().join("cityg").join("gui"),
        "session dir should respect CITYG_GUI_CONFIG_DIR override"
    );

    match original {
        Some(value) => {
            // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
            unsafe { std::env::set_var("CITYG_GUI_CONFIG_DIR", value) };
        }
        None => {
            // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
            unsafe { std::env::remove_var("CITYG_GUI_CONFIG_DIR") };
        }
    }
    Ok(())
}

#[test]
fn session_dir_falls_back_to_user_config_directory() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let _config_guard = set_config_dir_override_for_tests(None);

    let original = std::env::var("CITYG_GUI_CONFIG_DIR").ok();
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    unsafe { std::env::remove_var("CITYG_GUI_CONFIG_DIR") };

    let resolved = session_dir()?;
    assert!(
        resolved.ends_with("cityg/gui"),
        "fallback session dir should include cityg/gui suffix: {}",
        resolved.display()
    );

    match original {
        Some(value) => {
            // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
            unsafe { std::env::set_var("CITYG_GUI_CONFIG_DIR", value) };
        }
        None => {
            // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
            unsafe { std::env::remove_var("CITYG_GUI_CONFIG_DIR") };
        }
    }
    Ok(())
}

#[test]
fn load_last_session_removes_dangling_pointer() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

    let pointer = LastSessionPointer {
        server_url: "http://127.0.0.1:8080".to_string(),
        room_id: "missing-room".to_string(),
    };
    let pointer_path = last_session_pointer_path()?;
    if let Some(parent) = pointer_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&pointer_path, serde_json::to_vec(&pointer)?)?;

    let session = load_last_session()?;
    assert!(
        session.is_none(),
        "dangling pointer should return no session"
    );
    assert!(
        !pointer_path.exists(),
        "dangling pointer should be removed automatically"
    );
    Ok(())
}

#[test]
fn load_last_session_invalid_pointer_json_errors() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

    let pointer_path = last_session_pointer_path()?;
    if let Some(parent) = pointer_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&pointer_path, b"not-json")?;
    assert!(
        load_last_session().is_err(),
        "invalid pointer JSON should produce an error"
    );
    Ok(())
}

#[test]
fn remove_persisted_session_keeps_unrelated_pointer() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

    let pointer = LastSessionPointer {
        server_url: "http://127.0.0.1:8080".to_string(),
        room_id: "room-a".to_string(),
    };
    let pointer_path = last_session_pointer_path()?;
    if let Some(parent) = pointer_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&pointer_path, serde_json::to_vec(&pointer)?)?;

    remove_persisted_session("http://127.0.0.1:8080", "room-b")?;
    assert!(
        pointer_path.exists(),
        "pointer should remain when removing unrelated session"
    );
    let loaded = read_last_session_pointer()?
        .ok_or_else(|| anyhow!("expected pointer to remain present"))?;
    assert_eq!(loaded.server_url, pointer.server_url);
    assert_eq!(loaded.room_id, pointer.room_id);
    Ok(())
}

#[test]
fn reload_join_finalization_session_rejects_other_identity_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let alice = build_test_session(
        0xA11C,
        "http://127.0.0.1:18080",
        "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
        "alice",
    )?;
    let mut bob = build_test_session(
        0xB0B0,
        "http://127.0.0.1:18080",
        "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
        "bob",
    )?;
    bob.gid = [0xB0; 32];
    bob.leaf_id = [0x0B; 32];

    persist_session(&alice)?;

    let err = match reload_join_finalization_session(
        &bob,
        anyhow!("join finalization failed"),
        "complete join barrier finalization",
    ) {
        Ok(_) => {
            return Err(anyhow!(
                "mismatched persisted identity must not be treated as a finalized session"
            )
            .into());
        }
        Err(err) => err,
    };
    let text = format!("{err:#}");
    assert!(text.contains("complete join barrier finalization"));
    assert!(text.contains("join finalization failed"));
    Ok(())
}

#[test]
fn reset_session_state_uses_pointer_and_handles_security_log_remove_error()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

    let pointer = LastSessionPointer {
        server_url: "http://127.0.0.1:8080".to_string(),
        room_id: "room-reset".to_string(),
    };
    let pointer_path = last_session_pointer_path()?;
    if let Some(parent) = pointer_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&pointer_path, serde_json::to_vec(&pointer)?)?;

    // Force remove_security_log to fail with "is a directory".
    let log_path = security_log_file_path(&pointer.server_url, &pointer.room_id)?;
    fs::create_dir_all(&log_path)?;

    let mut model = AppModel::new(CityGConfig::default());
    model.reset_session_state()?;
    assert!(model.session.is_none());
    assert!(model.members.is_empty());
    assert!(model.security_events.is_empty());
    Ok(())
}

#[test]
fn reset_session_state_without_session_or_pointer_is_ok() -> Result<(), Box<dyn std::error::Error>>
{
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut model = AppModel::new(CityGConfig::default());
    model.reset_session_state()?;
    assert!(model.session.is_none());
    Ok(())
}

#[test]
fn alias_bindings_persist_load_legacy_and_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));
    let server = "http://127.0.0.1:8080";
    let room = "room-alias";

    let mut bindings = AHashMap::new();
    bindings.insert(
        "alice".to_string(),
        AliasBindingRecord {
            pop_public_key: vec![0x01, 0x02, 0x03],
            leaf_id: [0xAA; 32],
        },
    );
    persist_alias_bindings(server, room, &bindings)?;

    let loaded = load_alias_bindings(server, room)?;
    let alice = loaded
        .get("alice")
        .ok_or_else(|| anyhow!("alice binding missing"))?;
    assert_eq!(alice.pop_public_key, vec![0x01, 0x02, 0x03]);
    assert_eq!(alice.leaf_id, [0xAA; 32]);

    let roster_path = roster_file_path(server, room)?;
    let legacy: AHashMap<String, String> = [("bob".to_string(), "0a0b".to_string())]
        .into_iter()
        .collect();
    fs::write(&roster_path, serde_json::to_vec(&legacy)?)?;
    let legacy_loaded = load_alias_bindings(server, room)?;
    let bob = legacy_loaded
        .get("bob")
        .ok_or_else(|| anyhow!("legacy bob binding missing"))?;
    assert_eq!(bob.pop_public_key, vec![0x0A, 0x0B]);
    assert_eq!(bob.leaf_id, [0u8; 32], "legacy format has zero leaf id");

    let invalid_store = PersistedAliasStore {
        version: ALIAS_STORE_VERSION,
        bindings: [
            (
                "bad_pop".to_string(),
                PersistedAliasBinding {
                    pop_public_key_hex: "zzzz".to_string(),
                    leaf_id_hex: hex_encode([0x11; 32]),
                },
            ),
            (
                "bad_leaf".to_string(),
                PersistedAliasBinding {
                    pop_public_key_hex: "aa".to_string(),
                    leaf_id_hex: "not-hex".to_string(),
                },
            ),
            (
                "empty_pop".to_string(),
                PersistedAliasBinding {
                    pop_public_key_hex: String::new(),
                    leaf_id_hex: hex_encode([0x22; 32]),
                },
            ),
        ]
        .into_iter()
        .collect(),
    };
    fs::write(&roster_path, serde_json::to_vec(&invalid_store)?)?;
    let invalid_loaded = load_alias_bindings(server, room)?;
    assert!(
        !invalid_loaded.contains_key("bad_pop"),
        "invalid pop key entry should be skipped"
    );
    let bad_leaf = invalid_loaded
        .get("bad_leaf")
        .ok_or_else(|| anyhow!("bad_leaf binding should remain with zeroed leaf id"))?;
    assert_eq!(bad_leaf.pop_public_key, vec![0xAA]);
    assert_eq!(bad_leaf.leaf_id, [0u8; 32]);
    assert!(
        !invalid_loaded.contains_key("empty_pop"),
        "entries with empty pop keys should be skipped"
    );

    persist_alias_bindings(server, room, &AHashMap::new())?;
    assert!(
        !roster_path.exists(),
        "empty bindings should remove roster file"
    );
    Ok(())
}

#[test]
fn load_alias_bindings_invalid_json_errors() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));
    let server = "http://127.0.0.1:8080";
    let room = "room-alias-invalid";
    let roster_path = roster_file_path(server, room)?;
    if let Some(parent) = roster_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&roster_path, b"not-json")?;
    assert!(
        load_alias_bindings(server, room).is_err(),
        "invalid alias store JSON should error"
    );
    Ok(())
}

#[test]
fn security_log_persist_load_and_remove() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));
    let server = "http://127.0.0.1:8080";
    let room = "room-sec";

    assert!(
        load_security_log(server, room)?.is_empty(),
        "missing security log should return empty vec"
    );

    let events = vec![
        SecurityEvent {
            alias: "alice".to_string(),
            description: "joined".to_string(),
            timestamp_ms: 1,
        },
        SecurityEvent {
            alias: "bob".to_string(),
            description: "revoked".to_string(),
            timestamp_ms: 2,
        },
    ];
    persist_security_log(server, room, &events)?;
    let loaded = load_security_log(server, room)?;
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].alias, "alice");
    assert_eq!(loaded[1].description, "revoked");

    let log_path = security_log_file_path(server, room)?;
    assert!(
        log_path.exists(),
        "security log file should exist after persist"
    );

    persist_security_log(server, room, &[])?;
    assert!(!log_path.exists(), "empty security log should remove file");

    persist_security_log(server, room, &events)?;
    remove_security_log(server, room)?;
    assert!(!log_path.exists(), "remove_security_log should delete file");
    Ok(())
}

#[test]
fn load_security_events_from_disk_handles_invalid_and_missing_session()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut model = AppModel::new(CityGConfig::default());

    let session = build_test_session(
        0x5151,
        "http://127.0.0.1:18080",
        "feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed",
        "security",
    )?;
    let log_path = security_log_file_path(&session.server_url, &session.room_id)?;
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&log_path, b"not-json")?;

    model.session = Some(session);
    model.security_events = vec![SecurityEvent {
        alias: "seed".to_string(),
        description: "stale".to_string(),
        timestamp_ms: 1,
    }];
    model.security_unread = 7;
    model.security_panel_expanded = true;
    model.load_security_events_from_disk();
    assert!(model.security_events.is_empty());
    assert_eq!(model.security_unread, 0);
    assert!(!model.security_panel_expanded);

    model.session = None;
    model.security_events = vec![SecurityEvent {
        alias: "seed".to_string(),
        description: "stale".to_string(),
        timestamp_ms: 2,
    }];
    model.security_unread = 3;
    model.security_panel_expanded = true;
    model.load_security_events_from_disk();
    assert!(model.security_events.is_empty());
    assert_eq!(model.security_unread, 0);
    assert!(!model.security_panel_expanded);
    Ok(())
}

#[test]
fn hydrate_alias_bindings_from_disk_handles_invalid_and_missing_session()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut model = AppModel::new(CityGConfig::default());

    let session = build_test_session(
        0x5152,
        "http://127.0.0.1:18080",
        "deafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeaf",
        "aliases",
    )?;
    let bindings_path = roster_file_path(&session.server_url, &session.room_id)?;
    if let Some(parent) = bindings_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&bindings_path, b"not-json")?;

    model.session = Some(session);
    model.alias_bindings.insert(
        "seed".to_string(),
        AliasBindingRecord {
            pop_public_key: vec![0xAA],
            leaf_id: [0x11; 32],
        },
    );
    model
        .leaf_alias_index
        .insert([0x11; 32], "seed".to_string());
    model.hydrate_alias_bindings_from_disk();
    assert!(model.alias_bindings.is_empty());
    assert!(model.leaf_alias_index.is_empty());

    model.session = None;
    model.alias_bindings.insert(
        "stale".to_string(),
        AliasBindingRecord {
            pop_public_key: vec![0xBB],
            leaf_id: [0x22; 32],
        },
    );
    model
        .leaf_alias_index
        .insert([0x22; 32], "stale".to_string());
    model.hydrate_alias_bindings_from_disk();
    assert!(model.alias_bindings.is_empty());
    assert!(model.leaf_alias_index.is_empty());
    Ok(())
}

#[gpui::test]
fn gpui_reconcile_alias_bindings_covers_mismatch_and_early_return(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xABCD,
        "http://127.0.0.1:18080",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sab",
    )
    .expect("build session");

    view.update(cx, |model, view_cx| {
        model.session = None;
        model.alias_bindings.insert(
            "keep".to_string(),
            AliasBindingRecord {
                pop_public_key: vec![0x01],
                leaf_id: [0x01; 32],
            },
        );
        model.reconcile_alias_bindings(view_cx);
        assert!(
            model.alias_bindings.contains_key("keep"),
            "early return without session should keep existing bindings"
        );
    });

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());
        model.alias_bindings.insert(
            "sab".to_string(),
            AliasBindingRecord {
                pop_public_key: vec![0xAA],
                leaf_id: [0x10; 32],
            },
        );
        model.members = vec![
            MemberEntry {
                leaf_id: [0x20; 32],
                alias: Some("sab".to_string()),
                pop_public_key: Some(vec![0xBB]),
                join_timestamp_ms: Some(1),
                last_seen_timestamp_ms: Some(2),
            },
            MemberEntry {
                leaf_id: [0x21; 32],
                alias: None,
                pop_public_key: Some(vec![0xCC]),
                join_timestamp_ms: None,
                last_seen_timestamp_ms: None,
            },
            MemberEntry {
                leaf_id: [0x22; 32],
                alias: Some(String::new()),
                pop_public_key: Some(vec![0xDD]),
                join_timestamp_ms: None,
                last_seen_timestamp_ms: None,
            },
            MemberEntry {
                leaf_id: [0x23; 32],
                alias: Some("dock".to_string()),
                pop_public_key: None,
                join_timestamp_ms: None,
                last_seen_timestamp_ms: None,
            },
        ];

        model.reconcile_alias_bindings(view_cx);

        let updated = model.alias_bindings.get("sab").expect("alias updated");
        assert_eq!(updated.pop_public_key, vec![0xBB]);
        assert_eq!(updated.leaf_id, [0x20; 32]);
        assert_eq!(
            model.leaf_alias_index.get(&[0x20; 32]).map(String::as_str),
            Some("sab")
        );
        assert_eq!(model.security_events.len(), 1);
        assert!(
            model.security_events[0].description.contains("TOFU alert"),
            "TOFU mismatch should record a security event"
        );
        assert!(
            !model.toasts.is_empty(),
            "TOFU mismatch should show a toast"
        );
    });
}

#[gpui::test]
fn gpui_reconcile_alias_bindings_handles_persist_failure(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base_file = temp_dir.path().join("not-a-directory");
    fs::write(&base_file, b"blocking dir").expect("create blocking file");
    let _override_guard = set_config_dir_override_for_tests(Some(base_file));
    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xABCE,
        "http://127.0.0.1:18080",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "dock",
    )
    .expect("build session");

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());
        model.members = vec![MemberEntry {
            leaf_id: [0x42; 32],
            alias: Some("dock".to_string()),
            pop_public_key: Some(vec![0x42]),
            join_timestamp_ms: None,
            last_seen_timestamp_ms: None,
        }];
        model.reconcile_alias_bindings(view_cx);
        assert!(
            model.alias_bindings.contains_key("dock"),
            "binding should still update when disk persistence fails"
        );
    });
}

#[test]
fn decode_persisted_session_rejects_bad_envelope_metadata() -> Result<(), Box<dyn std::error::Error>>
{
    let temp_dir = TempDir::new()?;
    let session_path = temp_dir
        .path()
        .join("cityg")
        .join("gui")
        .join("session.json");

    let bad_version = EncryptedSessionEnvelope {
        version: ENCRYPTED_SESSION_ENVELOPE_VERSION + 1,
        alg: ENCRYPTED_SESSION_ALG.to_string(),
        key_source: SessionKeySource::LocalKeyFile.as_str().to_string(),
        nonce_hex: "000102030405060708090a0b".to_string(),
        ciphertext_hex: "00".to_string(),
    };
    let err = match decode_persisted_session(&serde_json::to_vec(&bad_version)?, &session_path) {
        Ok(_) => return Err(anyhow!("unsupported envelope version should fail").into()),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("unsupported encrypted session envelope version"),
        "unexpected error: {err}"
    );

    let bad_alg = EncryptedSessionEnvelope {
        version: ENCRYPTED_SESSION_ENVELOPE_VERSION,
        alg: "aes-gcm".to_string(),
        key_source: SessionKeySource::LocalKeyFile.as_str().to_string(),
        nonce_hex: "000102030405060708090a0b".to_string(),
        ciphertext_hex: "00".to_string(),
    };
    let err = match decode_persisted_session(&serde_json::to_vec(&bad_alg)?, &session_path) {
        Ok(_) => return Err(anyhow!("unsupported envelope algorithm should fail").into()),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("unsupported encrypted session algorithm"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn decode_persisted_session_rejects_bad_nonce_and_ciphertext_hex()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let session_path = temp_dir
        .path()
        .join("cityg")
        .join("gui")
        .join("session.json");

    let bad_nonce = EncryptedSessionEnvelope {
        version: ENCRYPTED_SESSION_ENVELOPE_VERSION,
        alg: ENCRYPTED_SESSION_ALG.to_string(),
        key_source: SessionKeySource::LocalKeyFile.as_str().to_string(),
        nonce_hex: "000102".to_string(),
        ciphertext_hex: "00".to_string(),
    };
    let err = match decode_persisted_session(&serde_json::to_vec(&bad_nonce)?, &session_path) {
        Ok(_) => return Err(anyhow!("invalid nonce length should fail").into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("nonce must be 12 bytes"),
        "unexpected error: {err}"
    );

    let bad_ciphertext = EncryptedSessionEnvelope {
        version: ENCRYPTED_SESSION_ENVELOPE_VERSION,
        alg: ENCRYPTED_SESSION_ALG.to_string(),
        key_source: SessionKeySource::LocalKeyFile.as_str().to_string(),
        nonce_hex: "000102030405060708090a0b".to_string(),
        ciphertext_hex: "zzzz".to_string(),
    };
    let err = match decode_persisted_session(&serde_json::to_vec(&bad_ciphertext)?, &session_path) {
        Ok(_) => return Err(anyhow!("invalid ciphertext hex should fail").into()),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("encrypted session envelope ciphertext is not valid hex"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn decode_persisted_session_accepts_payload_when_key_source_label_mismatches()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let session_path = temp_dir
        .path()
        .join("cityg")
        .join("gui")
        .join("session.json");
    if let Some(parent) = session_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let session = build_test_session(
        0xDA7A,
        "https://example.invalid",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "mismatch",
    )?;
    let persisted = PersistedSession::from_session(&session);
    let encrypted = encrypt_persisted_session(&persisted, &session_path)?;
    let mut envelope: EncryptedSessionEnvelope = serde_json::from_slice(&encrypted)?;
    envelope.key_source = SessionKeySource::EnvPassphrase.as_str().to_string();

    let decoded = decode_persisted_session(&serde_json::to_vec(&envelope)?, &session_path)?;
    assert_eq!(decoded.room_id, session.room_id);
    assert_eq!(decoded.server_url, session.server_url);
    Ok(())
}

#[test]
fn decode_hex_helpers_validate_shape() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(decode_hex32("gid", &hex_encode([0xAB; 32]))?, [0xAB; 32]);
    assert_eq!(decode_hex_vec("vec", "0a0b")?, vec![0x0A, 0x0B]);
    assert_eq!(decode_hex_vec("empty", "")?, Vec::<u8>::new());
    assert!(decode_hex32("gid", "zz").is_err());
    assert!(decode_hex32("gid", "aa").is_err());
    assert!(decode_hex_vec("vec", "gg").is_err());
    Ok(())
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
        room_admin_identity_preview(&vec![0x11; dilithium5::public_key_bytes()]),
        format!("{}…{}", "11".repeat(6), "11".repeat(6))
    );
    assert_eq!(decode_hex_32(&hex_encode([0xCD; 32])), Some([0xCD; 32]));
    assert!(decode_hex_32("bad").is_none());
    assert!(decode_hex_32("aa").is_none());
    assert_eq!(
        decode_room_admin_target_hex(&hex_encode(vec![0x22; dilithium5::public_key_bytes()]))?,
        vec![0x22; dilithium5::public_key_bytes()]
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

    let (pk, sk) = dilithium3::keypair();
    let signature = sign_message(&leaf, ts, payload, sk.as_bytes())?;

    assert!(
        verify_message_signature(&leaf, ts, payload, &signature, &[0u8; 8]).is_err(),
        "invalid public key bytes should fail"
    );
    assert!(
        verify_message_signature(&leaf, ts, payload, &[0u8; 8], pk.as_bytes()).is_err(),
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

#[tokio::test]
async fn websocket_worker_reports_revoke_membership_event() -> Result<(), Box<dyn std::error::Error>>
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let membership_gid = [0x24u8; 32];
    let membership_gid_hex = hex_encode(membership_gid);
    let membership_leaf = [0xCDu8; 32];
    let membership_leaf_hex = hex_encode(membership_leaf);

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.send(WsMessage::Text(
                format!(
                    r#"{{"type":"membership","gid":"{membership_gid_hex}","leaf_id":"{membership_leaf_hex}","event":"revoke","timestamp_ms":55}}"#
                )
                .into(),
            ))
            .await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_millis(20),
        tx,
    ));

    let mut saw_revoke = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        if let WebSocketEvent::Membership(signal) = event
            && signal.gid == membership_gid
            && signal.leaf_id == Some(membership_leaf)
            && signal.kind == Some(MembershipSignalKind::Revoke)
        {
            saw_revoke = true;
            break;
        }
    }
    assert!(saw_revoke, "expected revoke membership event");

    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_returns_when_event_channel_is_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    drop(rx);

    tokio::time::timeout(
        Duration::from_secs(1),
        run_websocket_worker(
            format!("ws://{addr}/v1/ws"),
            None,
            Duration::from_secs(1),
            tx,
        ),
    )
    .await??;

    tokio::time::timeout(Duration::from_secs(1), server).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_emits_membership_and_message_events()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let membership_gid = [0x42u8; 32];
    let membership_gid_hex = hex_encode(membership_gid);
    let membership_leaf = [0xABu8; 32];
    let membership_leaf_hex = hex_encode(membership_leaf);

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.send(WsMessage::Text(r#"{"type":"message"}"#.to_string().into()))
            .await?;
        ws.send(WsMessage::Text(
                format!(
                    r#"{{"type":"membership","gid":"{membership_gid_hex}","leaf_id":"{membership_leaf_hex}","event":"join","timestamp_ms":12345}}"#
                )
                .into(),
            ))
            .await?;
        ws.send(WsMessage::Text(
            r#"{"type":"membership","gid":"not-hex"}"#.to_string().into(),
        ))
        .await?;
        ws.send(WsMessage::Text(
            r#"{"type":"lag","detail":"slow_consumer"}"#.to_string().into(),
        ))
        .await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_millis(20),
        tx,
    ));

    let mut saw_connected = false;
    let mut saw_message = false;
    let mut saw_membership = false;
    let mut saw_disconnected = false;
    for _ in 0..12 {
        let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        let Some(event) = next else {
            break;
        };

        match event {
            WebSocketEvent::Connected => saw_connected = true,
            WebSocketEvent::Message => saw_message = true,
            WebSocketEvent::Membership(signal) => {
                if signal.gid == membership_gid
                    && signal.leaf_id == Some(membership_leaf)
                    && signal.kind == Some(MembershipSignalKind::Join)
                {
                    saw_membership = true;
                }
            }
            WebSocketEvent::Disconnected => {
                saw_disconnected = true;
                if saw_connected && saw_message && saw_membership {
                    break;
                }
            }
        }
    }

    assert!(saw_connected, "expected Connected event");
    assert!(saw_message, "expected Message event");
    assert!(saw_membership, "expected Membership event");
    assert!(saw_disconnected, "expected Disconnected event");

    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_parses_unknown_membership_and_ping()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let membership_gid = [0x66u8; 32];
    let membership_gid_hex = hex_encode(membership_gid);
    let membership_leaf = [0x99u8; 32];
    let membership_leaf_hex = hex_encode(membership_leaf);

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.send(WsMessage::Text(
                format!(
                    r#"{{"type":"membership","gid":"{membership_gid_hex}","leaf_id":"{membership_leaf_hex}","event":"unknown","timestamp_ms":77}}"#
                )
                .into(),
            ))
            .await?;
        ws.send(WsMessage::Ping(vec![1, 2, 3].into())).await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_millis(20),
        tx,
    ));

    let mut saw_unknown_kind = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        if let WebSocketEvent::Membership(signal) = event
            && signal.gid == membership_gid
            && signal.leaf_id == Some(membership_leaf)
        {
            saw_unknown_kind = signal.kind.is_none();
            break;
        }
    }
    assert!(
        saw_unknown_kind,
        "expected membership event with unknown kind"
    );

    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_returns_when_message_delivery_channel_closes()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        sleep(Duration::from_millis(60)).await;
        ws.send(WsMessage::Text(r#"{"type":"message"}"#.to_string().into()))
            .await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_secs(1),
        tx,
    ));

    let first = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
    assert!(matches!(first, Some(WebSocketEvent::Connected)));
    drop(rx);

    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_returns_when_membership_delivery_channel_closes()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let gid_hex = hex_encode([0x33u8; 32]);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        sleep(Duration::from_millis(60)).await;
        ws.send(WsMessage::Text(
            format!(r#"{{"type":"membership","gid":"{gid_hex}","event":"join"}}"#).into(),
        ))
        .await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_secs(1),
        tx,
    ));

    let first = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
    assert!(matches!(first, Some(WebSocketEvent::Connected)));
    drop(rx);

    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_ignores_invalid_json_and_unknown_notification_type()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.send(WsMessage::Text("not-json".to_string().into()))
            .await?;
        ws.send(WsMessage::Text(r#"{"type":"other"}"#.to_string().into()))
            .await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_millis(20),
        tx,
    ));

    let mut saw_connected = false;
    let mut saw_disconnected = false;
    for _ in 0..6 {
        let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        match event {
            WebSocketEvent::Connected => saw_connected = true,
            WebSocketEvent::Disconnected => {
                saw_disconnected = true;
                break;
            }
            WebSocketEvent::Message | WebSocketEvent::Membership(_) => {
                return Err(anyhow!("unexpected event from invalid payloads").into());
            }
        }
    }

    assert!(saw_connected, "expected Connected event");
    assert!(saw_disconnected, "expected Disconnected event");

    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_handles_stream_protocol_errors() -> Result<(), Box<dyn std::error::Error>>
{
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.get_mut().write_all(b"not-a-websocket-frame").await?;
        ws.get_mut().shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_millis(20),
        tx,
    ));

    let mut saw_disconnected = false;
    for _ in 0..6 {
        let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        if matches!(event, WebSocketEvent::Disconnected) {
            saw_disconnected = true;
            break;
        }
    }
    assert!(
        saw_disconnected,
        "protocol errors should produce a disconnected event"
    );

    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    Ok(())
}

#[test]
fn session_persistence_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let mut rng = StdRng::seed_from_u64(42);
    let array = |val: u8| {
        let mut bytes = [0u8; 32];
        bytes.fill(val);
        bytes
    };

    let mut random_vec = |len: usize| {
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        buf
    };

    let forward_state = ForwardSecrecyState::with_state(array(0xAA), 17, array(0x55), array(0x99));
    let capss_witness_bundle = CapssWitnessBundle {
        branch_a: CapssBranchWitness {
            branch_artifact: random_vec(24),
            ctx_tag: random_vec(16),
        },
        branch_b: CapssBranchWitness {
            branch_artifact: random_vec(24),
            ctx_tag: random_vec(16),
        },
    };
    let capss_witness_bytes = encode_capss_witness(&capss_witness_bundle)?;

    let mut session = AppSession {
        server_url: "https://example.invalid".to_string(),
        room_id: "room-123".to_string(),
        alias: "alice".to_string(),
        gid: array(0x01),
        cat: array(0x02),
        leaf_id: array(0x03),
        parent_root: array(0x04),
        join_delta_root: array(0x05),
        revoked_since_root: array(0x06),
        revoked_root: array(0x07),
        regular_fingerprint: Some(array(0x0A)),
        fs_fingerprint: None,
        tswe_salt_hash: array(0x08),
        pox_r_commit: array(0x09),
        we_epoch_id: array(0x10),
        xk_hash: array(0x14),
        epoch_key: array(0x11),
        forward_state,
        fs_ec: 17,
        fs_epoch_commit: array(0x12),
        fs_dev_prev_commit: array(0x13),
        fs_epoch_created_at: SystemTime::now(),
        fs_epoch_rotation_interval_secs: 300,
        pop_public_key: random_vec(48),
        pop_secret_key: random_vec(96),
        msg_sign_public_key: random_vec(1952), // ML-DSA-65 public key
        msg_sign_secret_key: random_vec(4032), // ML-DSA-65 secret key
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
        last_fetch_timestamp_ms: Some(1_234_567),
        msg_replay_state: MsgReplayState::default(),
        capss_witness: capss_witness_bytes.clone(),
        barrier_state: BarrierSecretState::default(),
    };
    let mut barrier_dk_nodes = BTreeMap::new();
    barrier_dk_nodes.insert(
        1,
        BarrierNodeKeyMaterial {
            dk: Zeroizing::new(random_vec(kyber768::secret_key_bytes())),
            pkhash: array(0x24),
        },
    );
    let mut pending_on_path = BTreeMap::new();
    pending_on_path.insert(
        0,
        BarrierNodeKeyMaterial {
            dk: Zeroizing::new(random_vec(kyber768::secret_key_bytes())),
            pkhash: array(0x2A),
        },
    );
    pending_on_path.insert(
        1,
        BarrierNodeKeyMaterial {
            dk: Zeroizing::new(random_vec(kyber768::secret_key_bytes())),
            pkhash: array(0x2B),
        },
    );
    session.barrier_state = BarrierSecretState {
        barrier_initialized: true,
        barrier_version: 5,
        barrier_roots_hash: array(0x20),
        current_history_view_id: array(0x24),
        bootstrap_history_commitment: Some(HistoryCommitment {
            history_view_id: array(0x24),
            history_commitment_id: array(0x31),
            prev_history_commitment_id: array(0x32),
            history_seq: 5,
        }),
        bootstrap_predecessor_kem_tree_hash_after: array(0x33),
        bootstrap_join_records: vec![BarrierJoinRecord {
            device_pk: vec![0x41; 32],
            leaf_index: 3,
            ek_leaf: vec![0x42; kyber768::public_key_bytes()],
        }],
        bootstrap_revoked_leaf_indices: vec![1, 2],
        bootstrap_join_finalize_auth_token: array(0x34),
        k_barrier: Zeroizing::new(array(0x21)),
        kem_tree_hash_after: array(0x22),
        bootstrap_current_barrier_update: vec![0xAB, 0xCD],
        max_barrier_update_bytes: DEFAULT_MAX_BARRIER_UPDATE_BYTES,
        n_max: 8,
        cover_leaf_index: 3,
        dk_leaf: Zeroizing::new(random_vec(kyber768::secret_key_bytes())),
        pkhash_leaf: array(0x23),
        dk_nodes: barrier_dk_nodes,
        pending: Some(BarrierPendingState {
            barrier_version: 6,
            we_epoch_id: array(0x2A),
            fs_ec: 18,
            next_forward_fs_ec: 19,
            next_forward_fs_dev_commit: array(0x24),
            next_forward_last_weid: array(0x2A),
            revocation_roots_hash: array(0x25),
            kem_tree_hash_after: array(0x26),
            k_barrier_new: Zeroizing::new(array(0x27)),
            k_fs_after_pcs: Some(Zeroizing::new(array(0x28))),
            barrier_update_reason: Some(1),
            barrier_update_digest: array(0x29),
            on_path_key_material: pending_on_path,
        }),
        barrier_recovery_pending: true,
        barrier_recovery_issue: Some(BarrierRecoveryIssue::InsufficientAuthenticatedHistory),
        current_barrier_full_verified: false,
    };
    let tuple_tag = array(0x30);
    let replay_context = array(0x31);
    let mut replay_state = MsgReplayState::default();
    replay_state.ensure_tuple(tuple_tag, replay_context);
    replay_state.record(tuple_tag, replay_context, 11);
    replay_state.record(tuple_tag, replay_context, 22);
    replay_state.record(tuple_tag, replay_context, 33);
    replay_state.record(tuple_tag, replay_context, 44);
    session.msg_replay_state = replay_state;
    session.fs_fingerprint = derive_fs_fingerprint_from_fields(
        session.fs_policy_version.as_str(),
        session.fs_ec,
        &session.fs_epoch_commit,
        session.fs_epoch_base_ts,
    );

    persist_session(&session)?;
    let session_path = session_file_path(&session.server_url, &session.room_id)?;
    let raw_session_file = fs::read(&session_path)?;
    let raw_session_text = String::from_utf8_lossy(&raw_session_file);
    assert!(
        raw_session_text.contains("ciphertext_hex"),
        "session file must store encrypted payload envelope"
    );
    assert!(
        !raw_session_text.contains("pop_secret_hex"),
        "session file must not expose plaintext secret field names"
    );
    assert!(
        !raw_session_text.contains(&hex_encode(&session.pop_secret_key)),
        "session file must not expose plaintext pop secret bytes"
    );
    assert!(
        !raw_session_text.contains(&hex_encode(&session.msg_sign_secret_key)),
        "session file must not expose plaintext message signing secret bytes"
    );
    assert!(
        !raw_session_text.contains(&hex_encode(&session.vrf_secret_key)),
        "session file must not expose plaintext vrf secret bytes"
    );
    let loaded = load_session_at(&session.server_url, &session.room_id)?
        .ok_or_else(|| anyhow!("expected persisted session to load"))?;

    assert_eq!(loaded.server_url, session.server_url);
    assert_eq!(loaded.room_id, session.room_id);
    assert_eq!(loaded.alias, session.alias);
    assert_eq!(loaded.gid, session.gid);
    assert_eq!(loaded.cat, session.cat);
    assert_eq!(loaded.leaf_id, session.leaf_id);
    assert_eq!(loaded.parent_root, session.parent_root);
    assert_eq!(loaded.join_delta_root, session.join_delta_root);
    assert_eq!(loaded.revoked_since_root, session.revoked_since_root);
    assert_eq!(loaded.revoked_root, session.revoked_root);
    assert_eq!(loaded.regular_fingerprint, session.regular_fingerprint);
    assert_eq!(loaded.fs_fingerprint, session.fs_fingerprint);
    assert_eq!(loaded.tswe_salt_hash, session.tswe_salt_hash);
    assert_eq!(loaded.pox_r_commit, session.pox_r_commit);
    assert_eq!(loaded.we_epoch_id, session.we_epoch_id);
    assert_eq!(loaded.epoch_key, session.epoch_key);
    assert_eq!(loaded.kbroad_public, session.kbroad_public);
    assert_eq!(loaded.bootstrap_public, session.bootstrap_public);
    assert_eq!(loaded.pop_public_key, session.pop_public_key);
    assert_eq!(loaded.pop_secret_key, session.pop_secret_key);
    assert_eq!(loaded.vrf_public_key, session.vrf_public_key);
    assert_eq!(loaded.vrf_secret_key, session.vrf_secret_key);
    assert_eq!(loaded.proof_mode, session.proof_mode);
    assert_eq!(loaded.vrf_id, session.vrf_id);
    assert_eq!(loaded.policy_version, session.policy_version);
    assert_eq!(loaded.msphf_crs_id, session.msphf_crs_id);
    assert_eq!(loaded.msphf_params_id, session.msphf_params_id);
    assert_eq!(loaded.fs_policy_version, session.fs_policy_version);
    assert_eq!(loaded.fs_epoch_base_ts, session.fs_epoch_base_ts);
    assert_eq!(
        loaded.last_fetch_timestamp_ms,
        session.last_fetch_timestamp_ms
    );
    assert_eq!(loaded.msg_replay_state, session.msg_replay_state);

    assert_eq!(
        loaded.forward_state.snapshot(),
        session.forward_state.snapshot()
    );
    assert_eq!(loaded.fs_ec, session.fs_ec);
    assert_eq!(loaded.fs_epoch_commit, session.fs_epoch_commit);
    assert_eq!(loaded.fs_dev_prev_commit, session.fs_dev_prev_commit);
    assert_eq!(
        loaded.fs_epoch_rotation_interval_secs,
        session.fs_epoch_rotation_interval_secs
    );
    // Verify epoch timestamp is persisted (allow small time difference)
    let epoch_age_diff = loaded
        .fs_epoch_created_at
        .duration_since(session.fs_epoch_created_at)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    assert!(
        epoch_age_diff <= 1,
        "epoch timestamp should be preserved within 1 second"
    );
    assert_eq!(loaded.capss_witness, capss_witness_bytes);
    assert_eq!(
        loaded.barrier_state.barrier_version,
        session.barrier_state.barrier_version
    );
    assert_eq!(
        loaded.barrier_state.barrier_initialized,
        session.barrier_state.barrier_initialized
    );
    assert_eq!(
        loaded.barrier_state.barrier_roots_hash,
        session.barrier_state.barrier_roots_hash
    );
    assert_eq!(
        loaded.barrier_state.k_barrier,
        session.barrier_state.k_barrier
    );
    assert_eq!(
        loaded.barrier_state.kem_tree_hash_after,
        session.barrier_state.kem_tree_hash_after
    );
    assert_eq!(loaded.barrier_state.n_max, session.barrier_state.n_max);
    assert_eq!(
        loaded.barrier_state.cover_leaf_index,
        session.barrier_state.cover_leaf_index
    );
    assert_eq!(
        loaded.barrier_state.barrier_recovery_pending,
        session.barrier_state.barrier_recovery_pending
    );
    assert_eq!(
        loaded.barrier_state.barrier_recovery_issue,
        session.barrier_state.barrier_recovery_issue
    );
    assert_eq!(
        loaded.barrier_state.current_barrier_full_verified,
        session.barrier_state.current_barrier_full_verified
    );
    assert_eq!(
        loaded.barrier_state.bootstrap_history_commitment,
        session.barrier_state.bootstrap_history_commitment
    );
    assert_eq!(
        loaded
            .barrier_state
            .bootstrap_predecessor_kem_tree_hash_after,
        session
            .barrier_state
            .bootstrap_predecessor_kem_tree_hash_after
    );
    assert_eq!(
        loaded.barrier_state.bootstrap_current_barrier_update,
        session.barrier_state.bootstrap_current_barrier_update
    );
    assert_eq!(
        loaded.barrier_state.bootstrap_join_records,
        session.barrier_state.bootstrap_join_records
    );
    assert_eq!(
        loaded.barrier_state.bootstrap_revoked_leaf_indices,
        session.barrier_state.bootstrap_revoked_leaf_indices
    );
    assert_eq!(
        loaded.barrier_state.bootstrap_join_finalize_auth_token,
        session.barrier_state.bootstrap_join_finalize_auth_token
    );
    assert_eq!(loaded.barrier_state.dk_leaf, session.barrier_state.dk_leaf);
    assert_eq!(
        loaded.barrier_state.pkhash_leaf,
        session.barrier_state.pkhash_leaf
    );
    assert_eq!(
        loaded.barrier_state.dk_nodes.len(),
        session.barrier_state.dk_nodes.len()
    );
    for (node, expected) in &session.barrier_state.dk_nodes {
        let actual = loaded
            .barrier_state
            .dk_nodes
            .get(node)
            .ok_or_else(|| anyhow!("missing dk_nodes entry for node {node}"))?;
        assert_eq!(actual.dk, expected.dk);
        assert_eq!(actual.pkhash, expected.pkhash);
    }
    let loaded_pending = loaded
        .barrier_state
        .pending
        .as_ref()
        .ok_or_else(|| anyhow!("missing persisted barrier pending state"))?;
    let expected_pending = session
        .barrier_state
        .pending
        .as_ref()
        .ok_or_else(|| anyhow!("missing expected barrier pending state"))?;
    assert_eq!(
        loaded_pending.barrier_version,
        expected_pending.barrier_version
    );
    assert_eq!(loaded_pending.we_epoch_id, expected_pending.we_epoch_id);
    assert_eq!(loaded_pending.fs_ec, expected_pending.fs_ec);
    assert_eq!(
        loaded_pending.revocation_roots_hash,
        expected_pending.revocation_roots_hash
    );
    assert_eq!(
        loaded_pending.kem_tree_hash_after,
        expected_pending.kem_tree_hash_after
    );
    assert_eq!(loaded_pending.k_barrier_new, expected_pending.k_barrier_new);
    assert_eq!(
        loaded_pending.k_fs_after_pcs,
        expected_pending.k_fs_after_pcs
    );
    assert_eq!(
        loaded_pending.barrier_update_reason,
        expected_pending.barrier_update_reason
    );
    assert_eq!(
        loaded_pending.barrier_update_digest,
        expected_pending.barrier_update_digest
    );
    assert_eq!(
        loaded_pending.on_path_key_material.len(),
        expected_pending.on_path_key_material.len()
    );
    for (node, expected) in &expected_pending.on_path_key_material {
        let actual = loaded_pending
            .on_path_key_material
            .get(node)
            .ok_or_else(|| anyhow!("missing pending key material for node {node}"))?;
        assert_eq!(actual.dk, expected.dk);
        assert_eq!(actual.pkhash, expected.pkhash);
    }

    let decoded = decode_capss_witness(&loaded.capss_witness)?;
    assert_eq!(decoded, capss_witness_bundle);

    // Clean up persisted files to avoid leaking into other tests.
    remove_persisted_session(&session.server_url, &session.room_id)?;
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

    let err = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        match with_fault_injection_async(
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
        {
            Ok(_) => {
                return Err(
                    anyhow!("fault injection should abort join finalize before publish").into(),
                );
            }
            Err(err) => err,
        }
    };
    assert!(
        format!("{err:#}").contains("inject join finalize pre-publish failure"),
        "unexpected join finalize error: {err:#}"
    );

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

    let err = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        match with_fault_injection_async(
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
        {
            Ok(_) => {
                return Err(
                    anyhow!("fault injection should abort join finalize after publish").into(),
                );
            }
            Err(err) => err,
        }
    };
    assert!(
        format!("{err:#}").contains("inject join finalize post-publish failure"),
        "unexpected join finalize error: {err:#}"
    );

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
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.

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
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone, PartialEq, Message)]
    struct MockHistoryCommitment {
        #[prost(bytes = "vec", tag = "1")]
        history_view_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        history_commitment_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "3")]
        prev_history_commitment_id: Vec<u8>,
        #[prost(uint64, tag = "4")]
        history_seq: u64,
    }

    #[derive(Clone, PartialEq, Message)]
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
        history_commitment: Option<MockHistoryCommitment>,
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
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

        let body = MockBarrierLookupMergeAcceptanceResponse {
            status: 2,
            history_view_id: vec![0xD1; 32],
            accepted_barrier_version: Some(5),
            accepted_fs_ec: Some(31),
            accepted_reason: Some(2),
            accepted_digest: Some(vec![0xAA; 32]),
            history_commitment: Some(MockHistoryCommitment {
                history_view_id: vec![0xD1; 32],
                history_commitment_id: vec![0xE1; 32],
                prev_history_commitment_id: vec![0x00; 32],
                history_seq: 7,
            }),
        }
        .encode_to_vec();
        let response_head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/protobuf\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response_head.as_bytes()).await?;
        stream.write_all(body.as_slice()).await?;
        stream.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });

    let server_url = format!("http://{addr}");
    let room_id = hex_encode([0x57u8; 32]);
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
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone, PartialEq, Message)]
    struct MockHistoryCommitment {
        #[prost(bytes = "vec", tag = "1")]
        history_view_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        history_commitment_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "3")]
        prev_history_commitment_id: Vec<u8>,
        #[prost(uint64, tag = "4")]
        history_seq: u64,
    }

    #[derive(Clone, PartialEq, Message)]
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
        history_commitment: Option<MockHistoryCommitment>,
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
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

        let body = MockBarrierLookupMergeAcceptanceResponse {
            status: 3,
            history_view_id: vec![0xD2; 32],
            accepted_barrier_version: None,
            accepted_fs_ec: None,
            accepted_reason: None,
            accepted_digest: None,
            history_commitment: Some(MockHistoryCommitment {
                history_view_id: vec![0xD2; 32],
                history_commitment_id: vec![0xE2; 32],
                prev_history_commitment_id: vec![0xE1; 32],
                history_seq: 8,
            }),
        }
        .encode_to_vec();
        let response_head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/protobuf\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response_head.as_bytes()).await?;
        stream.write_all(body.as_slice()).await?;
        stream.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });

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
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone, PartialEq, Message)]
    struct MockHistoryCommitment {
        #[prost(bytes = "vec", tag = "1")]
        history_view_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        history_commitment_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "3")]
        prev_history_commitment_id: Vec<u8>,
        #[prost(uint64, tag = "4")]
        history_seq: u64,
    }

    #[derive(Clone, PartialEq, Message)]
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
        history_commitment: Option<MockHistoryCommitment>,
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
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

        let body = MockBarrierLookupMergeAcceptanceResponse {
            status: 1,
            history_view_id: vec![0xD3; 32],
            accepted_barrier_version: Some(9),
            accepted_fs_ec: Some(42),
            accepted_reason: Some(1),
            accepted_digest: Some(vec![0xA9; 32]),
            history_commitment: Some(MockHistoryCommitment {
                history_view_id: vec![0xD3; 32],
                history_commitment_id: vec![0xE3; 32],
                prev_history_commitment_id: vec![0xE2; 32],
                history_seq: 9,
            }),
        }
        .encode_to_vec();
        let response_head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/protobuf\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response_head.as_bytes()).await?;
        stream.write_all(body.as_slice()).await?;
        stream.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });

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
    let admin_proof = build_room_admin_proof(
        RoomAdminOperation::RotateKbroad,
        &room_id,
        &rotated_kbroad_public,
        &admin_pop_public_key,
        &admin_pop_secret_key,
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
    let admin_proof = build_room_admin_proof(
        RoomAdminOperation::RotateKbroad,
        &room_id,
        &rotated_kbroad_public,
        &admin_pop_public_key,
        &admin_pop_secret_key,
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
        kyber768::secret_key_bytes(),
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
async fn perform_leave_rejects_while_barrier_recovery_is_pending()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xC31, "http://127.0.0.1:9", "room-leave-guard", "alice")?;
    session.barrier_state.barrier_recovery_pending = true;

    let err = perform_leave(LeaveRequest::from_session(&session))
        .await
        .expect_err("leave should be blocked while barrier recovery is pending");
    assert!(
        err.to_string()
            .contains("complete FULL barrier recovery first"),
        "expected explicit recover-before-update guidance: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn perform_leave_rejects_without_full_barrier_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(
        0xC33,
        "http://127.0.0.1:9",
        "room-leave-recover-only",
        "alice",
    )?;
    session.barrier_state.barrier_recovery_pending = false;
    session.barrier_state.current_barrier_full_verified = false;

    let err = perform_leave(LeaveRequest::from_session(&session))
        .await
        .expect_err("leave should be blocked while barrier state is recover-only");
    assert!(
        err.to_string().contains("recover-only barrier state"),
        "expected explicit FULL-verification guidance: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn perform_pcs_refresh_rejects_while_barrier_recovery_is_pending()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session =
        build_test_session(0xC32, "http://127.0.0.1:9", "room-refresh-guard", "alice")?;
    session.barrier_state.barrier_recovery_pending = true;

    let err = perform_pcs_refresh(LeaveRequest::from_session(&session))
        .await
        .expect_err("pcs refresh should be blocked while barrier recovery is pending");
    assert!(
        err.to_string()
            .contains("complete FULL barrier recovery first"),
        "expected explicit recover-before-update guidance: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn perform_pcs_refresh_rejects_without_full_barrier_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(
        0xC34,
        "http://127.0.0.1:9",
        "room-refresh-recover-only",
        "alice",
    )?;
    session.barrier_state.barrier_recovery_pending = false;
    session.barrier_state.current_barrier_full_verified = false;

    let err = perform_pcs_refresh(LeaveRequest::from_session(&session))
        .await
        .expect_err("pcs refresh should be blocked while barrier state is recover-only");
    assert!(
        err.to_string().contains("recover-only barrier state"),
        "expected explicit FULL-verification guidance: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn perform_join_finalize_rejects_pending_session_without_bootstrap_artifact()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new().expect("create temp dir");
    let _override_guard = set_config_dir_override_for_tests(Some(temp_dir.path().to_path_buf()));
    let mut session = build_test_session(
        0xC35,
        "http://127.0.0.1:9",
        "room-join-finalize-bootstrap-guard",
        "alice",
    )?;
    session.parent_root = [0x44; 32];
    session.barrier_state.barrier_version = 3;
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.current_barrier_full_verified = false;
    session.barrier_state.bootstrap_history_commitment = None;
    session
        .barrier_state
        .bootstrap_current_barrier_update
        .clear();
    persist_session(&session)?;

    let err = match perform_join_finalize_inner(LeaveRequest::from_session(&session)).await {
        Ok(_) => {
            return Err("pending join_finalize must fail closed without bootstrap artifact".into());
        }
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("bootstrap missing"),
        "expected explicit bootstrap-artifact guidance: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn perform_join_finalize_rejects_pending_session_without_auth_token()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(
        0xC36,
        "http://127.0.0.1:9",
        "room-join-finalize-auth-guard",
        "alice",
    )?;
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.current_barrier_full_verified = true;
    session.barrier_state.bootstrap_join_finalize_auth_token = [0u8; 32];

    let err = match perform_join_finalize_inner(LeaveRequest::from_session(&session)).await {
        Ok(_) => {
            return Err("pending join_finalize must fail closed without auth token".into());
        }
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("join_finalize auth token"),
        "expected explicit join_finalize auth-token guidance: {err}"
    );
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

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_pcs_refresh(LeaveRequest::from_session(&synced_alice)).await?;
    }

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

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        persist_session(&synced_alice)?;
        perform_pcs_refresh(LeaveRequest::from_session(&synced_alice))
            .await
            .context("post-restart alice PCS refresh")?;
    }

    let charlie = {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id,
            alias: "charlie".to_string(),
        })
        .await
        .context("post-restart charlie join")?
    };
    assert!(
        !charlie.barrier_state.barrier_recovery_pending,
        "new join must remain self-finalizing after restart"
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
    let admin_proof = build_room_admin_proof(
        RoomAdminOperation::RotateKbroad,
        &room_id,
        &rotated_kbroad_public,
        &refreshed_alice.pop_public_key,
        &refreshed_alice.pop_secret_key,
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

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0x8Du8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let mut alice = perform_join(JoinParams {
        server_url: server_url.clone(),
        room_id: room_id.clone(),
        alias: "alice".to_string(),
    })
    .await?;
    alice.barrier_state.barrier_recovery_pending = false;

    let bob = perform_join(JoinParams {
        server_url: server_url.clone(),
        room_id: room_id.clone(),
        alias: "bob".to_string(),
    })
    .await?;

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

#[test]
fn encrypt_decrypt_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let plaintext = b"Hello, City-G! This is a test message.";

    let ciphertext = encrypt_message(plaintext, &key)?;
    let decrypted = decrypt_message(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn payload_envelope_v2_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let gid = [0x11u8; 32];
    let we_epoch_id = [0x22u8; 32];
    let xk_hash = [0x23u8; 32];
    let epoch_key = [0x33u8; 32];
    let k_barrier = [0x44u8; 32];
    let sender_leaf = [0x45u8; 32];
    let context = MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec: 9,
        barrier_version: 5,
        sender_leaf: &sender_leaf,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    };
    let plaintext = b"payload-v2-roundtrip";
    let envelope = encrypt_message_v2(plaintext, &context, 7)?;
    let decrypted = decrypt_message_v2(&envelope, &context)?;
    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn payload_envelope_v2_roundtrip_exposes_msg_index() -> Result<(), Box<dyn std::error::Error>> {
    let gid = [0x71u8; 32];
    let we_epoch_id = [0x72u8; 32];
    let xk_hash = [0x73u8; 32];
    let epoch_key = [0x74u8; 32];
    let k_barrier = [0x75u8; 32];
    let sender_leaf = [0x76u8; 32];
    let context = MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec: 5,
        barrier_version: 2,
        sender_leaf: &sender_leaf,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    };
    let envelope = encrypt_message_v2(b"payload-v2-index", &context, 42)?;
    let (msg_index, decrypted) = decrypt_message_v2_with_index(&envelope, &context)?;
    assert_eq!(msg_index, 42);
    assert_eq!(decrypted, b"payload-v2-index");
    Ok(())
}

#[test]
fn payload_envelope_v2_context_mismatch_fails() -> Result<(), Box<dyn std::error::Error>> {
    let gid = [0x51u8; 32];
    let we_epoch_id = [0x52u8; 32];
    let xk_hash = [0x53u8; 32];
    let epoch_key = [0x53u8; 32];
    let k_barrier = [0x54u8; 32];
    let sender_leaf = [0x55u8; 32];
    let good_context = MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec: 12,
        barrier_version: 4,
        sender_leaf: &sender_leaf,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    };
    let bad_context = MessageCryptoContext {
        barrier_version: 5,
        ..good_context
    };
    let envelope = encrypt_message_v2(b"context-bound", &good_context, 1)?;
    assert!(
        decrypt_message_v2(&envelope, &bad_context).is_err(),
        "barrier_version mismatch must fail decryption"
    );
    Ok(())
}

#[test]
fn payload_envelope_v2_msg_index_changes_ciphertext() -> Result<(), Box<dyn std::error::Error>> {
    let gid = [0x61u8; 32];
    let we_epoch_id = [0x62u8; 32];
    let xk_hash = [0x63u8; 32];
    let epoch_key = [0x63u8; 32];
    let k_barrier = [0x64u8; 32];
    let sender_leaf = [0x65u8; 32];
    let context = MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec: 3,
        barrier_version: 1,
        sender_leaf: &sender_leaf,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    };
    let payload_a = encrypt_message_v2(b"same-plaintext", &context, 1)?;
    let payload_b = encrypt_message_v2(b"same-plaintext", &context, 2)?;
    assert_ne!(payload_a, payload_b, "msg_index must influence ciphertext");
    Ok(())
}

#[test]
fn payload_envelope_v2_sender_scope_changes_ciphertext() -> Result<(), Box<dyn std::error::Error>> {
    let gid = [0x81u8; 32];
    let we_epoch_id = [0x82u8; 32];
    let xk_hash = [0x83u8; 32];
    let epoch_key = [0x84u8; 32];
    let k_barrier = [0x85u8; 32];
    let sender_leaf_a = [0x86u8; 32];
    let sender_leaf_b = [0x87u8; 32];
    let context_a = MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec: 7,
        barrier_version: 3,
        sender_leaf: &sender_leaf_a,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    };
    let context_b = MessageCryptoContext {
        sender_leaf: &sender_leaf_b,
        ..context_a
    };
    let payload_a = encrypt_message_v2(b"same-plaintext", &context_a, 11)?;
    let payload_b = encrypt_message_v2(b"same-plaintext", &context_b, 11)?;
    assert_ne!(payload_a, payload_b, "sender scope must affect ciphertext");
    assert!(
        decrypt_message_v2(&payload_a, &context_b).is_err(),
        "wrong sender scope must fail decryption"
    );
    Ok(())
}

#[test]
fn msg_replay_state_tracks_multiple_tuples_and_caps_window()
-> Result<(), Box<dyn std::error::Error>> {
    let mut replay = MsgReplayState::default();
    let tuple_a = [0xA1; 32];
    let context_id = [0xC1; 32];
    replay.ensure_tuple(tuple_a, context_id);
    for msg_index in 0..(MAX_MSGS_PER_REPLAY_TUPLE as u64 + 8) {
        replay.record(tuple_a, context_id, msg_index);
    }
    assert_eq!(replay.len(tuple_a), MAX_MSGS_PER_REPLAY_TUPLE);
    assert!(
        !replay.contains(tuple_a, 0),
        "oldest indices should be evicted"
    );
    assert!(replay.contains(tuple_a, MAX_MSGS_PER_REPLAY_TUPLE as u64 + 7));

    let tuple_b = [0xB2; 32];
    replay.ensure_tuple(tuple_b, context_id);
    assert!(
        replay.contains(tuple_a, MAX_MSGS_PER_REPLAY_TUPLE as u64 + 7),
        "adding a second tuple must preserve the first tuple window"
    );
    assert_eq!(replay.len(tuple_b), 0);
    replay.record(tuple_b, context_id, 99);
    assert!(replay.contains(tuple_b, 99));
    Ok(())
}

#[test]
fn msg_replay_state_ignores_duplicate_indices() -> Result<(), Box<dyn std::error::Error>> {
    let mut replay = MsgReplayState::default();
    let tuple = [0x42; 32];
    let context_id = [0x43; 32];
    replay.ensure_tuple(tuple, context_id);
    replay.record(tuple, context_id, 7);
    replay.record(tuple, context_id, 7);
    replay.record(tuple, context_id, 7);
    assert_eq!(
        replay.len(tuple),
        1,
        "duplicate indices must not grow replay state"
    );
    assert!(replay.contains(tuple, 7));
    Ok(())
}

#[test]
fn msg_replay_state_allows_reuse_after_window_eviction() -> Result<(), Box<dyn std::error::Error>> {
    let mut replay = MsgReplayState::default();
    let tuple = [0x55; 32];
    let context_id = [0x56; 32];
    replay.ensure_tuple(tuple, context_id);
    for msg_index in 0..=(MAX_MSGS_PER_REPLAY_TUPLE as u64) {
        replay.record(tuple, context_id, msg_index);
    }
    assert!(
        !replay.contains(tuple, 0),
        "oldest index must be evicted once window is exceeded"
    );
    replay.record(tuple, context_id, 0);
    assert!(
        replay.contains(tuple, 0),
        "evicted index can be re-seen by design outside replay window"
    );
    Ok(())
}

#[test]
fn derive_msg_replay_tuple_tag_changes_with_tuple_inputs() -> Result<(), Box<dyn std::error::Error>>
{
    let gid = [0x31u8; 32];
    let we_epoch_id = [0x32u8; 32];
    let xk_hash = [0x33u8; 32];
    let epoch_key = [0x34u8; 32];
    let k_barrier = [0x35u8; 32];
    let sender_leaf_a = [0x36u8; 32];
    let sender_leaf_b = [0x37u8; 32];
    let context_a = MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec: 8,
        barrier_version: 1,
        sender_leaf: &sender_leaf_a,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    };
    let context_b = MessageCryptoContext {
        sender_leaf: &sender_leaf_b,
        ..context_a
    };
    let tag_a = derive_msg_replay_tuple_tag(&context_a)?;
    let tag_b = derive_msg_replay_tuple_tag(&context_b)?;
    assert_ne!(tag_a, tag_b, "sender scope must affect replay tuple tag");
    Ok(())
}

#[test]
fn encrypt_produces_different_ciphertexts() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let plaintext = b"Same message, different ciphertext";

    let ciphertext1 = encrypt_message(plaintext, &key)?;
    let ciphertext2 = encrypt_message(plaintext, &key)?;

    // Different nonces should produce different ciphertexts
    assert_ne!(ciphertext1, ciphertext2);

    // But both should decrypt to the same plaintext
    let decrypted1 = decrypt_message(&ciphertext1, &key)?;
    let decrypted2 = decrypt_message(&ciphertext2, &key)?;
    assert_eq!(decrypted1, plaintext);
    assert_eq!(decrypted2, plaintext);
    Ok(())
}

#[test]
fn decrypt_with_wrong_key_fails() -> Result<(), Box<dyn std::error::Error>> {
    let correct_key = [42u8; 32];
    let wrong_key = [99u8; 32];
    let plaintext = b"Secret message";

    let ciphertext = encrypt_message(plaintext, &correct_key)?;
    let result = decrypt_message(&ciphertext, &wrong_key);

    assert!(result.is_err(), "Decryption should fail with wrong key");
    let err = match result {
        Err(e) => e,
        Ok(_) => return Err("expected error".into()),
    };
    assert!(
        err.to_string().contains("decryption failed"),
        "Error message should indicate decryption failure"
    );
    Ok(())
}

#[test]
fn decrypt_tampered_ciphertext_fails() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let plaintext = b"Authenticated message";

    let mut ciphertext = encrypt_message(plaintext, &key)?;

    // Tamper with the ciphertext (flip a bit in the middle)
    if ciphertext.len() > 20 {
        ciphertext[20] ^= 0x01;
    }

    let result = decrypt_message(&ciphertext, &key);

    assert!(result.is_err(), "Decryption should fail for tampered data");
    let err = match result {
        Err(e) => e,
        Ok(_) => return Err("expected error".into()),
    };
    assert!(
        err.to_string().contains("decryption failed"),
        "Error message should indicate decryption failure"
    );
    Ok(())
}

#[test]
fn decrypt_short_ciphertext_fails() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let short_data = b"short"; // Less than 12 bytes (nonce size)

    let result = decrypt_message(short_data, &key);

    assert!(result.is_err(), "Decryption should fail for short data");
    let err = match result {
        Err(e) => e,
        Ok(_) => return Err("expected error".into()),
    };
    assert!(
        err.to_string().contains("too short"),
        "Error should mention data is too short"
    );
    Ok(())
}

#[test]
fn encrypt_empty_message() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let plaintext = b"";

    let ciphertext = encrypt_message(plaintext, &key)?;
    let decrypted = decrypt_message(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    assert_eq!(decrypted.len(), 0);
    Ok(())
}

#[test]
fn encrypt_large_message() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let plaintext = vec![b'A'; 10_000]; // 10KB message

    let ciphertext = encrypt_message(&plaintext, &key)?;
    let decrypted = decrypt_message(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn ciphertext_format_validation() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let plaintext = b"Test message";

    let ciphertext = encrypt_message(plaintext, &key)?;

    // Ciphertext should be: nonce (12) + encrypted_data + tag (16)
    // Minimum size: 12 (nonce) + 16 (tag) = 28 bytes
    assert!(
        ciphertext.len() >= 28,
        "Ciphertext should be at least 28 bytes (nonce + tag)"
    );

    // For non-empty plaintext, should be larger
    assert_eq!(
        ciphertext.len(),
        12 + plaintext.len() + 16,
        "Ciphertext size should be nonce + plaintext + tag"
    );
    Ok(())
}

#[test]
fn multiple_keys_independence() -> Result<(), Box<dyn std::error::Error>> {
    let key1 = [1u8; 32];
    let key2 = [2u8; 32];
    let plaintext = b"Multi-key test";

    let ciphertext1 = encrypt_message(plaintext, &key1)?;
    let ciphertext2 = encrypt_message(plaintext, &key2)?;

    // Same plaintext with different keys should produce different ciphertexts
    assert_ne!(ciphertext1, ciphertext2);

    // Each key should only decrypt its own ciphertext
    assert!(decrypt_message(&ciphertext1, &key1).is_ok());
    assert!(decrypt_message(&ciphertext2, &key2).is_ok());
    assert!(decrypt_message(&ciphertext1, &key2).is_err());
    assert!(decrypt_message(&ciphertext2, &key1).is_err());
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
        timestamp_ms: Some(1234),
    });
    model.record_membership_activity(&MembershipSignal {
        gid: [0x11; 32],
        leaf_id: Some(leaf),
        kind: Some(MembershipSignalKind::Revoke),
        timestamp_ms: None,
    });
    model.record_membership_activity(&MembershipSignal {
        gid: [0x11; 32],
        leaf_id: None,
        kind: None,
        timestamp_ms: None,
    });
    assert_eq!(model.activity_events.len(), 3);
    assert!(model.activity_events[0].summary.contains("Roster join"));
    assert!(model.activity_events[1].summary.contains("Roster revoke"));
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
    let (pk, sk) = dilithium3::keypair();
    let msg_sign_public_key = pk.as_bytes().to_vec();
    let msg_sign_secret_key = sk.as_bytes().to_vec();

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
    let (pk, sk) = dilithium3::keypair();
    let msg_sign_public_key = pk.as_bytes().to_vec();
    let msg_sign_secret_key = sk.as_bytes().to_vec();

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
    let (pk, sk) = dilithium3::keypair();
    let msg_sign_public_key = pk.as_bytes().to_vec();
    let msg_sign_secret_key = sk.as_bytes().to_vec();

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
        pop_public_key: random_vec(48),
        pop_secret_key: random_vec(96),
        msg_sign_public_key: random_vec(1952),
        msg_sign_secret_key: random_vec(4032),
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
        last_fetch_timestamp_ms: Some(1_234_567),
        msg_replay_state: MsgReplayState::default(),
        capss_witness: capss_witness_bytes,
        barrier_state: BarrierSecretState::default(),
    };
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
