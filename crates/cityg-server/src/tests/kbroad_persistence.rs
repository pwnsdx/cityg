use super::*;

#[test]
fn kbroad_state_persists_across_restart() -> Result<(), CityGError> {
    let _serial = crate::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("kbroad-state.journal");
    let gid = [0xC1; 32];
    let initial_key = vec![0x44; 16];
    let rotated_key = vec![0x66; 16];
    let persisted_device_pk = vec![0x91; 32];
    let persisted_device_state = msphf_orchestrator::DeviceChainState {
        last_commit: Some([0xEF; 32]),
        last_ec: 88,
        last_pcs_refresh_ec: Some(77),
    };
    let persisted_roots_hash = crate::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;
    let mut persisted_entries = crate::build_all_blank_pk_entries(4)?;
    persisted_entries[0] = vec![0xA5; 1184];
    let persisted_hash = crate::compute_barrier_tree_hash(4, persisted_entries.as_slice())?;

    {
        let mut cfg = ServerConfig::new();
        cfg.state_path = Some(journal_path.clone());
        let mut server = CityGServer::new(cfg);
        server.register_group(&gid, initial_key.clone())?;
        server.roster.mark_kbroad_rotation_required(gid.as_slice());
        let generation = server.rotate_group_kbroad(&gid, rotated_key.clone())?;
        assert_eq!(generation, 1);
        assert_eq!(server.kbroad_generation(&gid), 1);
        assert!(!server.kbroad_rotation_required(&gid));
        {
            let state = server
                .roster
                .groups
                .get_mut(gid.as_slice())
                .expect("registered group state must exist");
            state.barrier_initialized = true;
            state.barrier_version = 9;
            state.barrier_roots_hash = persisted_roots_hash;
            state.kem_tree_hash_after = persisted_hash;
            state.srx_root_sw = Some([0xD7; 32]);
            state.n_max = 4;
            state.last_checkpoint_ec = 66;
            state.last_accepted_ec = 88;
            state.barrier_pk_entries = persisted_entries.clone();
            state.last_pcs_refresh_ec = Some(77);
            state.pcs_refresh_min_delta_device_ec = 3;
            state.pcs_refresh_min_delta_group_ec = 4;
            state.pcs_refresh_slot_width_ec = 5;
            state.max_barrier_update_bytes = 7777;
        }
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
        server.ctx.insert_device_chain_state(
            gid.as_slice(),
            persisted_device_pk.as_slice(),
            persisted_device_state.clone(),
        );
        server.persist_kbroad_state()?;
    }

    let mut cfg = ServerConfig::new();
    cfg.state_path = Some(journal_path.clone());
    let mut server = CityGServer::new(cfg);
    assert_eq!(server.kbroad_generation(&gid), 1);
    assert!(!server.kbroad_rotation_required(&gid));
    let ticket = server.build_join_ticket(&gid)?;
    assert_eq!(ticket.kbroad_public, rotated_key);
    assert_eq!(ticket.kbroad_generation, 1);
    let state = server
        .roster
        .groups
        .get(gid.as_slice())
        .expect("recovered group state must exist");
    assert!(state.barrier_initialized);
    assert_eq!(state.barrier_version, 9);
    assert_eq!(state.barrier_roots_hash, persisted_roots_hash);
    assert_eq!(state.kem_tree_hash_after, persisted_hash);
    assert_eq!(state.srx_root_sw, Some([0xD7; 32]));
    assert_eq!(state.n_max, 4);
    assert_eq!(state.last_checkpoint_ec, 66);
    assert_eq!(state.last_accepted_ec, 88);
    assert_eq!(state.barrier_pk_entries, persisted_entries);
    assert_eq!(state.last_pcs_refresh_ec, Some(77));
    assert_eq!(state.pcs_refresh_min_delta_device_ec, 3);
    assert_eq!(state.pcs_refresh_min_delta_group_ec, 4);
    assert_eq!(state.pcs_refresh_slot_width_ec, 5);
    assert_eq!(state.max_barrier_update_bytes, 7777);
    assert_eq!(
        crate::history_barrier_public_tree_entries(state, &persisted_hash).as_ref(),
        Some(&state.barrier_pk_entries),
        "persisted live tree should be promoted into history on reload"
    );
    assert!(
        server
            .ctx
            .barrier_group_state(gid.as_slice())
            .expect("recovered barrier group state must exist")
            .barrier_initialized
    );
    assert_eq!(
        server
            .ctx
            .barrier_group_state(gid.as_slice())
            .expect("recovered barrier group state must exist")
            .barrier_version,
        9
    );
    assert_eq!(
        server
            .ctx
            .barrier_group_state(gid.as_slice())
            .expect("recovered barrier group state must exist")
            .barrier_roots_hash,
        persisted_roots_hash
    );
    assert_eq!(
        server
            .ctx
            .barrier_group_state(gid.as_slice())
            .expect("recovered barrier group state must exist")
            .max_barrier_update_bytes,
        7777
    );
    assert_eq!(
        server
            .ctx
            .barrier_group_state(gid.as_slice())
            .expect("recovered barrier group state must exist")
            .last_checkpoint_ec,
        66
    );
    assert_eq!(
        server
            .ctx
            .barrier_group_state(gid.as_slice())
            .expect("recovered barrier group state must exist")
            .last_accepted_ec,
        88
    );
    assert_eq!(
        server
            .ctx
            .barrier_group_state(gid.as_slice())
            .expect("recovered barrier group state must exist")
            .kem_tree_hash_after,
        persisted_hash
    );
    assert_eq!(
        server
            .ctx
            .barrier_group_state(gid.as_slice())
            .expect("recovered barrier group state must exist")
            .srx_root_sw,
        Some([0xD7; 32])
    );
    assert_eq!(
        server
            .ctx
            .device_chain_get(gid.as_slice(), persisted_device_pk.as_slice()),
        Some(&persisted_device_state)
    );
    let snapshot = server.fetch_barrier_public_tree(&gid, &persisted_hash)?;
    assert_eq!(snapshot.kem_tree_hash_after, persisted_hash);
    assert_eq!(snapshot.pk_entries, persisted_entries);
    let duplicate = server
        .register_group(&gid, initial_key)
        .expect_err("restart must preserve registered room kbroad key");
    assert!(matches!(
        duplicate,
        CityGError::InvalidInput("kbroad key already registered")
    ));
    Ok(())
}

#[test]
fn kbroad_state_persists_historical_barrier_tree_snapshots() -> Result<(), CityGError> {
    let _serial = crate::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("kbroad-history.journal");
    let gid = cityg_client::demo::DEMO_GID;
    let generated = build_genesis_member_bundle(0x73)?;
    let historical_hash: [u8; 32];
    let historical_entries: Vec<Vec<u8>>;
    let current_hash: [u8; 32];
    let current_entries: Vec<Vec<u8>>;

    {
        let mut server = demo_server_with_journal(&journal_path);
        server.accept_epoch(&generated.bundle)?;
        {
            let group = server
                .roster
                .groups
                .get(gid.as_slice())
                .ok_or(CityGError::InvalidInput("group not found"))?;
            historical_hash = group.kem_tree_hash_after;
            historical_entries = group.barrier_pk_entries.clone();
        }

        (current_hash, current_entries) =
            advance_committed_tree_for_tests(&mut server, &gid, 0x73)?;
        assert_ne!(current_hash, historical_hash);

        server.persist_kbroad_state()?;
    }

    std::fs::remove_file(&journal_path).ok();

    let mut reloaded = demo_server_with_journal(&journal_path);
    let historical_snapshot = reloaded.fetch_barrier_public_tree(&gid, &historical_hash)?;
    let current_snapshot = reloaded.fetch_barrier_public_tree(&gid, &current_hash)?;
    assert_eq!(historical_snapshot.kem_tree_hash_after, historical_hash);
    assert_eq!(historical_snapshot.pk_entries, historical_entries);
    assert_eq!(current_snapshot.kem_tree_hash_after, current_hash);
    assert_eq!(current_snapshot.pk_entries, current_entries);

    let history_len = reloaded
        .roster
        .groups
        .get(gid.as_slice())
        .ok_or(CityGError::InvalidInput("reloaded group missing"))?
        .barrier_public_tree_history
        .len();
    assert!(
        history_len >= 2,
        "reloaded persisted state should retain historical committed snapshots"
    );
    Ok(())
}

#[test]
fn invalid_persisted_kbroad_state_is_ignored_on_boot() -> Result<(), CityGError> {
    let _serial = crate::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("invalid-kbroad-state.journal");
    let kbroad_path = crate::kbroad_state_path_for_journal(&journal_path);
    std::fs::write(&kbroad_path, [0xA1, 0x01, 0x02])?;

    let mut cfg = ServerConfig::new();
    cfg.state_path = Some(journal_path);
    let mut server = CityGServer::new(cfg);
    let gid = [0x91; 32];

    assert!(matches!(
        server.build_join_ticket(&gid),
        Err(CityGError::InvalidInput("kbroad key missing"))
    ));
    server.register_group(&gid, vec![0x11; 16])?;
    assert_eq!(server.kbroad_generation(&gid), 0);
    Ok(())
}

#[test]
fn initialize_group_barrier_bootstrap_state_preserves_existing_state() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x92; 32];
    let existing_hash = [0xA5; 32];
    let existing_roots_hash = [0xB6; 32];
    let existing_srx = [0xC7; 32];

    let state = server.roster.groups.entry(gid.to_vec()).or_default();
    state.barrier_initialized = true;
    state.barrier_version = 9;
    state.barrier_roots_hash = existing_roots_hash;
    state.kem_tree_hash_after = existing_hash;
    state.n_max = 8;
    state.last_pcs_refresh_ec = Some(44);
    state.pcs_refresh_min_delta_device_ec = 0;
    state.pcs_refresh_min_delta_group_ec = 0;
    state.pcs_refresh_slot_width_ec = 0;
    state.max_barrier_update_bytes = 0;
    state.srx_root_sw = Some(existing_srx);

    server.initialize_group_barrier_bootstrap_state(&gid)?;

    let ctx_state = server
        .ctx
        .barrier_group_state(&gid)
        .ok_or(CityGError::InvalidInput("missing ctx barrier state"))?;
    assert!(ctx_state.barrier_initialized);
    assert_eq!(ctx_state.barrier_version, 9);
    assert_eq!(ctx_state.barrier_roots_hash, existing_roots_hash);
    assert_eq!(ctx_state.kem_tree_hash_after, existing_hash);
    assert_eq!(ctx_state.n_max, 8);
    assert_eq!(ctx_state.last_pcs_refresh_ec, Some(44));
    assert_eq!(ctx_state.pcs_refresh_min_delta_device_ec, 1);
    assert_eq!(ctx_state.pcs_refresh_min_delta_group_ec, 1);
    assert_eq!(ctx_state.pcs_refresh_slot_width_ec, 1);
    assert_eq!(ctx_state.max_barrier_update_bytes, 1);
    assert_eq!(ctx_state.srx_root_sw, Some(existing_srx));
    Ok(())
}

#[test]
fn initialize_group_barrier_bootstrap_state_skips_history_only_group() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x93; 32];
    let state = server.roster.groups.entry(gid.to_vec()).or_default();
    state.revoked.insert([0x44; 32]);
    state.barrier_initialized = false;
    state.n_max = 8;
    state.max_barrier_update_bytes = 77;

    server.initialize_group_barrier_bootstrap_state(&gid)?;

    let roster_state = server
        .roster
        .groups
        .get(gid.as_slice())
        .ok_or(CityGError::InvalidInput("missing roster group"))?;
    assert!(!roster_state.barrier_initialized);
    assert!(roster_state.barrier_public_tree_history.is_empty());

    let ctx_state = server
        .ctx
        .barrier_group_state(&gid)
        .ok_or(CityGError::InvalidInput("missing ctx barrier state"))?;
    assert!(!ctx_state.barrier_initialized);
    assert_eq!(ctx_state.n_max, 8);
    assert_eq!(ctx_state.max_barrier_update_bytes, 77);
    Ok(())
}

#[test]
fn initialize_registered_groups_barrier_state_bootstraps_registry_groups() -> Result<(), CityGError>
{
    let mut server = CityGServer::new(ServerConfig::new());
    let gid1 = [0x31; 32];
    let gid2 = [0x32; 32];
    let registry = BTreeMap::from([
        (gid1.to_vec(), vec![0x11; 16]),
        (gid2.to_vec(), vec![0x22; 16]),
    ]);
    server.ctx.set_kbroad_registry(Some(registry));

    server.initialize_registered_groups_barrier_state()?;

    for gid in [gid1, gid2] {
        let roster_state = server
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("missing roster group"))?;
        assert!(roster_state.barrier_initialized);
        assert_eq!(roster_state.barrier_version, 0);
        assert_eq!(roster_state.n_max, crate::DEFAULT_BARRIER_N_MAX);
        assert!(roster_state.max_barrier_update_bytes >= 1);
        assert!(
            roster_state
                .barrier_public_tree_history
                .contains_key(&roster_state.kem_tree_hash_after),
            "bootstrapped registry group should retain its committed tree snapshot"
        );

        let ctx_state = server
            .ctx
            .barrier_group_state(&gid)
            .ok_or(CityGError::InvalidInput("missing ctx barrier group"))?;
        assert!(ctx_state.barrier_initialized);
        assert_eq!(ctx_state.barrier_version, 0);
        assert_eq!(ctx_state.n_max, crate::DEFAULT_BARRIER_N_MAX);
        assert_eq!(
            ctx_state.kem_tree_hash_after,
            roster_state.kem_tree_hash_after
        );
    }

    Ok(())
}

#[test]
fn initialize_registered_groups_barrier_state_ignores_non_32_byte_registry_keys()
-> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x33; 32];
    let registry = BTreeMap::from([
        (gid.to_vec(), vec![0x11; 16]),
        (vec![0x22; 31], vec![0x33; 16]),
    ]);
    server.ctx.set_kbroad_registry(Some(registry));

    server.initialize_registered_groups_barrier_state()?;

    assert!(server.roster.groups.contains_key(gid.as_slice()));
    assert!(
        !server.roster.groups.contains_key(vec![0x22; 31].as_slice()),
        "malformed registry gid must be ignored during bootstrap"
    );
    Ok(())
}

#[test]
fn register_group_reuses_existing_historyless_state_and_clears_stale_metadata()
-> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x34; 32];
    let state = server.roster.groups.entry(gid.to_vec()).or_default();
    state.rotation_required = true;
    state.kbroad_generation = 9;
    state.n_max = 8;

    server.register_group(&gid, vec![0x77; 16])?;

    let roster_state = server
        .roster
        .groups
        .get(gid.as_slice())
        .ok_or(CityGError::InvalidInput("missing roster state"))?;
    assert!(!roster_state.rotation_required);
    assert_eq!(roster_state.kbroad_generation, 0);
    assert_eq!(roster_state.n_max, 8);
    assert!(roster_state.barrier_initialized);
    assert!(
        roster_state
            .barrier_public_tree_history
            .contains_key(&roster_state.kem_tree_hash_after)
    );
    Ok(())
}

#[test]
fn apply_persisted_kbroad_state_rebuilds_current_snapshot_when_history_is_invalid()
-> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x93; 32];
    let pk_entries = vec![vec![0x11; 4], vec![0x22; 4], vec![0x33; 4]];
    let current_hash = compute_barrier_tree_hash(2, pk_entries.as_slice())?;
    let state = BTreeMap::from([(
        gid.to_vec(),
        PersistedKbroadRoomState {
            kbroad_public: vec![0x44; 16],
            kbroad_generation: 7,
            rotation_required: true,
            room_admin_pop_keys: Vec::new(),
            room_admin_proof_replay_keys: Vec::new(),
            revoked_leaf_ids_hex: Vec::new(),
            barrier_initialized: true,
            barrier_version: 5,
            barrier_roots_hash: [0x55; 32],
            kem_tree_hash_after: current_hash,
            last_checkpoint_ec: 21,
            last_accepted_ec: 34,
            srx_root_sw: Some([0x66; 32]),
            barrier_pk_entries: pk_entries.clone(),
            barrier_public_tree_blobs: Vec::new(),
            barrier_public_tree_history: vec![PersistedBarrierPublicTreeSnapshot {
                kem_tree_hash_after_hex: "not-hex".to_string(),
                barrier_version: 5,
                history_view_id_hex: String::new(),
                history_commitment: crate::PersistedHistoryCommitment::default(),
                blob_indices: Vec::new(),
                pk_entries: vec![vec![0x99; 3]],
            }],
            n_max: 2,
            last_pcs_refresh_ec: Some(12),
            pcs_refresh_min_delta_device_ec: 0,
            pcs_refresh_min_delta_group_ec: 0,
            pcs_refresh_slot_width_ec: 0,
            max_barrier_update_bytes: 0,
            accepted_barrier_merges: Vec::new(),
            current_history_commitment: crate::PersistedHistoryCommitment::default(),
            current_accepted_barrier_update: Vec::new(),
            current_accepted_barrier_predecessor_hash: [0u8; 32],
            pending_join_finalize_auth: Vec::new(),
            active_slot_leases: Vec::new(),
            revoked_slot_leases: Vec::new(),
            device_chain_states: Vec::new(),
        },
    )]);

    server.apply_persisted_kbroad_state(&state)?;

    let group = server
        .roster
        .groups
        .get(gid.as_slice())
        .ok_or(CityGError::InvalidInput("missing restored group"))?;
    assert_eq!(group.kbroad_generation, 7);
    assert!(group.rotation_required);
    assert_eq!(group.barrier_public_tree_history.len(), 1);
    assert_eq!(
        crate::history_barrier_public_tree_entries(group, &current_hash).as_ref(),
        Some(&pk_entries)
    );
    assert_eq!(group.max_barrier_update_bytes, 1);

    let ctx_state = server
        .ctx
        .barrier_group_state(&gid)
        .ok_or(CityGError::InvalidInput("missing restored ctx state"))?;
    assert_eq!(ctx_state.kem_tree_hash_after, current_hash);
    assert_eq!(ctx_state.n_max, 2);
    assert_eq!(ctx_state.last_checkpoint_ec, 21);
    assert_eq!(ctx_state.last_accepted_ec, 34);
    assert_eq!(ctx_state.max_barrier_update_bytes, 1);
    Ok(())
}

#[test]
fn apply_persisted_kbroad_state_keeps_history_and_adds_missing_current_snapshot()
-> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x94; 32];
    let historical_entries = vec![vec![0x01; 4], vec![0x02; 4], vec![0x03; 4]];
    let current_entries = vec![vec![0x04; 4], vec![0x05; 4], vec![0x06; 4]];
    let historical_hash = compute_barrier_tree_hash(2, historical_entries.as_slice())?;
    let current_hash = compute_barrier_tree_hash(2, current_entries.as_slice())?;
    let state = BTreeMap::from([(
        gid.to_vec(),
        PersistedKbroadRoomState {
            kbroad_public: vec![0x77; 16],
            kbroad_generation: 2,
            rotation_required: false,
            room_admin_pop_keys: Vec::new(),
            room_admin_proof_replay_keys: Vec::new(),
            revoked_leaf_ids_hex: Vec::new(),
            barrier_initialized: true,
            barrier_version: 8,
            barrier_roots_hash: [0x88; 32],
            kem_tree_hash_after: current_hash,
            last_checkpoint_ec: 55,
            last_accepted_ec: 89,
            srx_root_sw: None,
            barrier_pk_entries: current_entries.clone(),
            barrier_public_tree_blobs: Vec::new(),
            barrier_public_tree_history: vec![PersistedBarrierPublicTreeSnapshot {
                kem_tree_hash_after_hex: hex::encode(historical_hash),
                barrier_version: 7,
                history_view_id_hex: String::new(),
                history_commitment: crate::PersistedHistoryCommitment::default(),
                blob_indices: Vec::new(),
                pk_entries: historical_entries.clone(),
            }],
            n_max: 2,
            last_pcs_refresh_ec: None,
            pcs_refresh_min_delta_device_ec: 3,
            pcs_refresh_min_delta_group_ec: 4,
            pcs_refresh_slot_width_ec: 5,
            max_barrier_update_bytes: 99,
            accepted_barrier_merges: Vec::new(),
            current_history_commitment: crate::PersistedHistoryCommitment::default(),
            current_accepted_barrier_update: Vec::new(),
            current_accepted_barrier_predecessor_hash: [0u8; 32],
            pending_join_finalize_auth: Vec::new(),
            active_slot_leases: Vec::new(),
            revoked_slot_leases: Vec::new(),
            device_chain_states: Vec::new(),
        },
    )]);

    server.apply_persisted_kbroad_state(&state)?;

    let group = server
        .roster
        .groups
        .get(gid.as_slice())
        .ok_or(CityGError::InvalidInput("missing restored group"))?;
    assert_eq!(group.barrier_public_tree_history.len(), 2);
    assert_eq!(
        crate::history_barrier_public_tree_entries(group, &historical_hash).as_ref(),
        Some(&historical_entries)
    );
    assert_eq!(
        crate::history_barrier_public_tree_entries(group, &current_hash).as_ref(),
        Some(&current_entries)
    );
    assert_eq!(group.pcs_refresh_min_delta_device_ec, 3);
    assert_eq!(group.pcs_refresh_min_delta_group_ec, 4);
    assert_eq!(group.pcs_refresh_slot_width_ec, 5);
    assert_eq!(group.max_barrier_update_bytes, 99);
    assert_eq!(group.last_checkpoint_ec, 55);
    assert_eq!(group.last_accepted_ec, 89);
    Ok(())
}

#[test]
fn apply_persisted_kbroad_state_restores_revoked_leaf_set() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x9Au8; 32];
    let revoked_leaf = [0xBC; 32];
    let state = BTreeMap::from([(
        gid.to_vec(),
        PersistedKbroadRoomState {
            kbroad_public: vec![0x77; 16],
            revoked_leaf_ids_hex: vec![hex::encode(revoked_leaf)],
            ..PersistedKbroadRoomState::default()
        },
    )]);

    server.apply_persisted_kbroad_state(&state)?;

    let group = server
        .roster
        .groups
        .get(gid.as_slice())
        .ok_or(CityGError::InvalidInput("missing restored group"))?;
    assert!(group.revoked.contains(&revoked_leaf));
    assert!(server.roster.has_history(&gid));
    Ok(())
}

#[test]
fn apply_persisted_kbroad_state_restores_accepted_barrier_merges() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x95; 32];
    let state = BTreeMap::from([(
        gid.to_vec(),
        PersistedKbroadRoomState {
            kbroad_public: vec![0x77; 16],
            barrier_initialized: true,
            barrier_version: 11,
            last_accepted_ec: 22,
            n_max: 2,
            accepted_barrier_merges: vec![crate::PersistedAcceptedBarrierMergeRecord {
                barrier_version: 11,
                fs_ec: 22,
                reason: 1,
                digest_hex: "ab".repeat(32),
                we_epoch_id_hex: "cd".repeat(32),
            }],
            ..PersistedKbroadRoomState::default()
        },
    )]);

    server.apply_persisted_kbroad_state(&state)?;
    let lookup = server.lookup_merge_acceptance(&gid, 11, &[0xAB; 32], &[0xCD; 32])?;
    assert_eq!(lookup.status, crate::MergeAcceptanceStatus::Accepted);
    assert_eq!(lookup.accepted_barrier_version, Some(11));
    assert_eq!(lookup.accepted_fs_ec, Some(22));
    assert_eq!(lookup.accepted_reason, Some(1));
    assert_eq!(lookup.accepted_digest, Some([0xAB; 32]));
    Ok(())
}

#[test]
fn apply_persisted_kbroad_state_rejects_oversized_n_max() {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x95; 32];
    let state = BTreeMap::from([(
        gid.to_vec(),
        PersistedKbroadRoomState {
            kbroad_public: vec![0x11; 16],
            n_max: crate::MAX_BARRIER_N_MAX * 2,
            ..PersistedKbroadRoomState::default()
        },
    )]);

    let err = server
        .apply_persisted_kbroad_state(&state)
        .expect_err("oversized n_max must fail closed");
    assert!(matches!(
        err,
        CityGError::InvalidInput(message) if message.contains("MAX_BARRIER_N_MAX")
    ));
}

#[test]
fn validate_barrier_n_max_rejects_invalid_shapes_and_oversized_values() {
    assert_eq!(
        crate::validate_barrier_n_max(crate::DEFAULT_BARRIER_N_MAX)
            .expect("default n_max must be valid"),
        crate::DEFAULT_BARRIER_N_MAX
    );
    assert!(crate::validate_barrier_n_max(0).is_err());
    assert!(crate::validate_barrier_n_max(3).is_err());
    assert!(crate::validate_barrier_n_max(crate::MAX_BARRIER_N_MAX * 2).is_err());
}

#[test]
fn snapshot_kbroad_state_captures_group_state_and_registry_defaults() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid_with_group = [0x95; 32];
    let gid_without_group = [0x96; 32];
    let tree_entries = vec![vec![0x10; 4], vec![0x20; 4], vec![0x30; 4]];
    let tree_hash = compute_barrier_tree_hash(2, tree_entries.as_slice())?;

    let registry = BTreeMap::from([
        (gid_with_group.to_vec(), vec![0xAA; 16]),
        (gid_without_group.to_vec(), vec![0xBB; 16]),
    ]);
    server.ctx.set_kbroad_registry(Some(registry));
    server.ctx.insert_device_chain_state(
        gid_with_group.as_slice(),
        &[0xD1; 32],
        msphf_orchestrator::DeviceChainState {
            last_commit: Some([0xE2; 32]),
            last_ec: 17,
            last_pcs_refresh_ec: Some(9),
        },
    );

    let group = server
        .roster
        .groups
        .entry(gid_with_group.to_vec())
        .or_default();
    group.kbroad_generation = 4;
    group.rotation_required = true;
    group.barrier_initialized = true;
    group.barrier_version = 6;
    group.barrier_roots_hash = [0xC3; 32];
    group.kem_tree_hash_after = tree_hash;
    group.srx_root_sw = Some([0xF4; 32]);
    group.barrier_pk_entries = tree_entries.clone();
    crate::record_barrier_public_tree_snapshot(&gid_with_group, group)?;
    group.n_max = 0;
    group.last_pcs_refresh_ec = Some(11);
    group.pcs_refresh_min_delta_device_ec = 0;
    group.pcs_refresh_min_delta_group_ec = 0;
    group.pcs_refresh_slot_width_ec = 0;
    group.max_barrier_update_bytes = 0;

    let snapshot = server.snapshot_kbroad_state();
    let with_group = snapshot
        .get(gid_with_group.as_slice())
        .ok_or(CityGError::InvalidInput("missing persisted grouped room"))?;
    assert_eq!(with_group.kbroad_public, vec![0xAA; 16]);
    assert_eq!(with_group.kbroad_generation, 4);
    assert!(with_group.rotation_required);
    assert!(with_group.barrier_initialized);
    assert_eq!(with_group.barrier_version, 6);
    assert_eq!(with_group.kem_tree_hash_after, tree_hash);
    assert_eq!(with_group.srx_root_sw, Some([0xF4; 32]));
    assert_eq!(with_group.n_max, 1);
    assert_eq!(with_group.pcs_refresh_min_delta_device_ec, 1);
    assert_eq!(with_group.pcs_refresh_min_delta_group_ec, 1);
    assert_eq!(with_group.pcs_refresh_slot_width_ec, 1);
    assert_eq!(with_group.device_chain_states.len(), 1);
    assert_eq!(
        with_group.barrier_public_tree_history[0].kem_tree_hash_after_hex,
        hex::encode(tree_hash)
    );
    assert!(
        with_group
            .barrier_public_tree_blobs
            .starts_with(tree_entries.as_slice()),
        "persisted blobs must retain the live tree entries in-order"
    );
    assert!(
        with_group.barrier_public_tree_blobs[tree_entries.len()..]
            .iter()
            .all(|entry| entry.is_empty()),
        "any additional persisted blobs must be empty placeholders"
    );
    assert!(
        with_group.barrier_public_tree_history[0]
            .blob_indices
            .starts_with(&[0, 1, 2]),
        "persisted history must reference the live tree-entry blob prefix"
    );
    assert!(
        with_group.barrier_public_tree_history[0]
            .pk_entries
            .is_empty()
    );

    let without_group = snapshot
        .get(gid_without_group.as_slice())
        .ok_or(CityGError::InvalidInput("missing default persisted room"))?;
    assert_eq!(without_group.kbroad_public, vec![0xBB; 16]);
    assert_eq!(without_group.kbroad_generation, 0);
    assert!(!without_group.rotation_required);
    assert!(!without_group.barrier_initialized);
    assert_eq!(without_group.n_max, crate::DEFAULT_BARRIER_N_MAX);
    assert_eq!(
        without_group.max_barrier_update_bytes,
        crate::default_max_barrier_update_bytes()
    );
    assert!(without_group.barrier_public_tree_history.is_empty());
    assert!(without_group.device_chain_states.is_empty());
    Ok(())
}
