use super::*;

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
        activation_source: current_pending_activation_source(&session),
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
    let current_snapshot = sample_current_public_tree(session.barrier_state.n_max, 0x54)?;
    session.barrier_state.kem_tree_hash_after = current_snapshot.kem_tree_hash_after;
    install_current_public_tree_cache(&mut session, current_snapshot)?;
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
        activation_source: current_pending_activation_source(&session),
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
    assert!(
        session.barrier_state.current_public_tree.is_none(),
        "activation must clear the previous current public-tree cache until a matching authenticated snapshot is reinstalled"
    );
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
fn enter_barrier_recovery_required_sets_issue_and_clears_current_public_tree()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xA15, "http://127.0.0.1:9", "room-a5", "alice")?;
    let current_snapshot = sample_current_public_tree(session.barrier_state.n_max, 0x66)?;
    session.barrier_state.kem_tree_hash_after = current_snapshot.kem_tree_hash_after;
    install_current_public_tree_cache(&mut session, current_snapshot)?;
    retain_authenticated_current_public_tree(&mut session)?;
    session.barrier_state.current_barrier_full_verified = true;

    enter_barrier_recovery_required(
        &mut session,
        BarrierRecoveryIssue::InsufficientAuthenticatedHistory,
    )?;
    assert!(session.barrier_state.barrier_recovery_pending);
    assert_eq!(
        session.barrier_state.barrier_recovery_issue,
        Some(BarrierRecoveryIssue::InsufficientAuthenticatedHistory)
    );
    assert!(!session.barrier_state.current_barrier_full_verified);
    assert!(
        session.barrier_state.current_public_tree.is_none(),
        "recovery-required must clear the current public-tree cache"
    );
    assert!(
        session.barrier_state.retained_public_trees.is_empty(),
        "recovery-required must clear retained historical public-tree snapshots too"
    );
    Ok(())
}

#[test]
fn persisted_barrier_state_roundtrip_preserves_current_history_commitment()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = BarrierSecretState {
        barrier_initialized: true,
        barrier_version: 7,
        barrier_roots_hash: [0x11; 32],
        current_history_view_id: [0x22; 32],
        current_history_commitment: Some(HistoryCommitment {
            history_view_id: [0x22; 32],
            history_commitment_id: [0x23; 32],
            prev_history_commitment_id: [0x21; 32],
            history_seq: 9,
        }),
        current_history_authority_extension: Some(
            HistoryAuthorityExtension::LocalHistoryAuthorityV1,
        ),
        current_public_tree: None,
        bootstrap_history_commitment: Some(HistoryCommitment {
            history_view_id: [0x22; 32],
            history_commitment_id: [0x20; 32],
            prev_history_commitment_id: [0x19; 32],
            history_seq: 8,
        }),
        kem_tree_hash_after: [0x33; 32],
        max_barrier_update_bytes: DEFAULT_MAX_BARRIER_UPDATE_BYTES,
        n_max: 8,
        ..BarrierSecretState::default()
    };

    let roundtrip = PersistedBarrierState::from_runtime(&runtime).into_runtime()?;
    assert_eq!(
        roundtrip.current_history_view_id,
        runtime.current_history_view_id
    );
    assert_eq!(
        roundtrip.current_history_commitment,
        runtime.current_history_commitment
    );
    assert_eq!(
        roundtrip.current_history_authority_extension,
        runtime.current_history_authority_extension
    );
    assert_eq!(
        roundtrip.bootstrap_history_commitment,
        runtime.bootstrap_history_commitment
    );
    Ok(())
}

#[test]
fn persisted_barrier_state_roundtrip_preserves_global_history_authority_extension()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = BarrierSecretState {
        barrier_initialized: true,
        barrier_version: 7,
        barrier_roots_hash: [0x11; 32],
        current_history_view_id: [0x12; 32],
        current_history_commitment: Some(HistoryCommitment {
            history_view_id: [0x12; 32],
            history_commitment_id: [0x13; 32],
            prev_history_commitment_id: [0x14; 32],
            history_seq: 10,
        }),
        current_history_authority_extension: Some(
            HistoryAuthorityExtension::GlobalHistoryAuthorityV1,
        ),
        current_global_history_attestation_bytes: vec![0xAA, 0xBB, 0xCC],
        ..BarrierSecretState::default()
    };

    let persisted = PersistedBarrierState::from_runtime(&runtime);
    let roundtrip = persisted.into_runtime()?;
    assert_eq!(
        roundtrip.current_history_authority_extension,
        Some(HistoryAuthorityExtension::GlobalHistoryAuthorityV1)
    );
    Ok(())
}

#[test]
fn persisted_barrier_state_roundtrip_preserves_pending_history_trace()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = BarrierSecretState {
        barrier_initialized: true,
        barrier_version: 9,
        barrier_recovery_pending: true,
        barrier_recovery_issue: Some(BarrierRecoveryIssue::InsufficientAuthenticatedHistory),
        last_pending_history_trace: Some(BarrierPendingHistoryTrace {
            pending_barrier_version: 8,
            pending_we_epoch_id: [0x71; 32],
            current_barrier_version: 9,
            lookup_status: BarrierPendingLookupTraceStatus::NotFound,
            accepted_barrier_version: None,
            accepted_fs_ec: None,
            accepted_reason: None,
            accepted_digest: None,
            decision: BarrierPendingTraceDecision::RecoveryRequired,
            recovery_issue: Some(BarrierRecoveryIssue::InsufficientAuthenticatedHistory),
            detail: Some("history 404 after newer committed barrier".to_string()),
        }),
        ..BarrierSecretState::default()
    };

    let roundtrip = PersistedBarrierState::from_runtime(&runtime).into_runtime()?;
    assert_eq!(
        roundtrip.last_pending_history_trace,
        runtime.last_pending_history_trace
    );
    Ok(())
}

#[test]
fn barrier_recovery_message_includes_last_pending_trace_summary()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xA18, "http://127.0.0.1:9", "room-a8", "alice")?;
    session.barrier_state.barrier_recovery_pending = true;
    session.barrier_state.last_pending_history_trace = Some(BarrierPendingHistoryTrace {
        pending_barrier_version: 8,
        pending_we_epoch_id: [0x81; 32],
        current_barrier_version: 9,
        lookup_status: BarrierPendingLookupTraceStatus::NotFound,
        accepted_barrier_version: None,
        accepted_fs_ec: None,
        accepted_reason: None,
        accepted_digest: None,
        decision: BarrierPendingTraceDecision::RecoveryRequired,
        recovery_issue: Some(BarrierRecoveryIssue::InsufficientAuthenticatedHistory),
        detail: None,
    });

    let message = AppModel::barrier_recovery_message_for_session(&session);
    assert!(
        message.contains(
            "Barrier recovery requires authenticated history before messaging can resume."
        ),
        "base recovery guidance must stay visible"
    );
    assert!(
        message
            .contains("acceptance record is still missing after a newer barrier version appeared"),
        "last pending trace summary should be surfaced in user-visible recovery guidance"
    );
    Ok(())
}

#[test]
fn pending_history_trace_technical_summary_captures_resolution_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let trace = BarrierPendingHistoryTrace {
        pending_barrier_version: 8,
        pending_we_epoch_id: [0x81; 32],
        current_barrier_version: 9,
        lookup_status: BarrierPendingLookupTraceStatus::Accepted,
        accepted_barrier_version: Some(9),
        accepted_fs_ec: Some(31),
        accepted_reason: Some(2),
        accepted_digest: Some([0x91; 32]),
        decision: BarrierPendingTraceDecision::RecoveryRequired,
        recovery_issue: Some(BarrierRecoveryIssue::ContradictoryAuthenticatedHistory),
        detail: Some("accepted merge contradicted local pending source".to_string()),
    };

    let summary = trace.technical_summary();
    assert!(summary.contains("pending_version=8"));
    assert!(summary.contains("current_version=9"));
    assert!(summary.contains("lookup=Accepted"));
    assert!(summary.contains("decision=RecoveryRequired"));
    assert!(summary.contains("accepted_version=9"));
    assert!(summary.contains("accepted_fs_ec=31"));
    assert!(summary.contains("accepted_reason=2"));
    assert!(summary.contains("recovery_issue=ContradictoryAuthenticatedHistory"));
    assert!(summary.contains("contradicted"));
    Ok(())
}

#[test]
fn persisted_barrier_state_roundtrip_drops_current_public_tree_cache()
-> Result<(), Box<dyn std::error::Error>> {
    let mut runtime = BarrierSecretState {
        barrier_initialized: true,
        barrier_version: 7,
        barrier_roots_hash: [0x11; 32],
        current_history_view_id: [0x22; 32],
        current_history_commitment: Some(HistoryCommitment {
            history_view_id: [0x22; 32],
            history_commitment_id: [0x23; 32],
            prev_history_commitment_id: [0x21; 32],
            history_seq: 9,
        }),
        current_history_authority_extension: Some(
            HistoryAuthorityExtension::LocalHistoryAuthorityV1,
        ),
        kem_tree_hash_after: [0x33; 32],
        max_barrier_update_bytes: DEFAULT_MAX_BARRIER_UPDATE_BYTES,
        n_max: 8,
        ..BarrierSecretState::default()
    };
    let snapshot = sample_current_public_tree(8, 0x55)?;
    runtime.kem_tree_hash_after = snapshot.kem_tree_hash_after;
    runtime.current_public_tree = Some(Arc::new(snapshot));
    runtime
        .retained_public_trees
        .push(RetainedBarrierPublicTree {
            barrier_version: runtime.barrier_version,
            history_commitment: runtime.current_history_commitment,
            snapshot: Arc::new(sample_current_public_tree(8, 0x56)?),
        });

    let roundtrip = PersistedBarrierState::from_runtime(&runtime).into_runtime()?;
    assert!(
        roundtrip.current_public_tree.is_none(),
        "persisted barrier state must not retain the large current public-tree cache"
    );
    assert!(
        roundtrip.retained_public_trees.is_empty(),
        "persisted barrier state must not retain recent public-tree snapshots"
    );
    Ok(())
}

#[test]
fn install_current_public_tree_cache_requires_matching_authenticated_hash()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xA14, "http://127.0.0.1:9", "room-a4", "alice")?;
    let snapshot = sample_current_public_tree(session.barrier_state.n_max, 0x44)?;
    session.barrier_state.kem_tree_hash_after = snapshot.kem_tree_hash_after;
    install_current_public_tree_cache(&mut session, snapshot)?;
    assert!(session.barrier_state.current_public_tree.is_some());

    let mut bad_snapshot = sample_current_public_tree(session.barrier_state.n_max, 0x45)?;
    bad_snapshot.kem_tree_hash_after = [0xEE; 32];
    let err = install_current_public_tree_cache(&mut session, bad_snapshot)
        .expect_err("mismatched current public-tree cache must fail");
    assert!(
        err.to_string()
            .contains("barrier tree snapshot auth failure"),
        "expected explicit snapshot auth failure: {err}"
    );
    Ok(())
}

#[test]
fn retained_authenticated_current_public_tree_survives_current_cache_clear()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xA15, "http://127.0.0.1:9", "room-a5", "alice")?;
    let snapshot = sample_current_public_tree(session.barrier_state.n_max, 0x46)?;
    session.barrier_state.kem_tree_hash_after = snapshot.kem_tree_hash_after;
    install_current_public_tree_cache(&mut session, snapshot)?;
    retain_authenticated_current_public_tree(&mut session)?;
    clear_current_public_tree_cache(&mut session.barrier_state);

    let (retained, commitment) = retained_authenticated_current_public_tree_cache(&session)
        .expect("retained cache should satisfy current-state lookup");
    assert_eq!(
        retained.kem_tree_hash_after,
        session.barrier_state.kem_tree_hash_after
    );
    assert_eq!(
        commitment,
        session.barrier_state.current_history_commitment.unwrap()
    );
    Ok(())
}

#[test]
fn retained_public_tree_cache_matches_historical_predecessor_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xA16, "http://127.0.0.1:9", "room-a6", "alice")?;
    let predecessor = Arc::new(sample_current_public_tree(
        session.barrier_state.n_max,
        0x57,
    )?);
    let predecessor_version = session.barrier_state.barrier_version.saturating_sub(1);
    retain_tree_hash_authenticated_public_tree(
        &mut session.barrier_state,
        predecessor_version,
        predecessor.clone(),
    );

    let retained = retained_public_tree_cache(
        &session,
        &predecessor.kem_tree_hash_after,
        predecessor.n_max,
    )
    .expect("historical predecessor cache should match retained snapshot");
    assert_eq!(retained.as_ref(), predecessor.as_ref());
    Ok(())
}

#[test]
fn retained_public_tree_cache_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xA17, "http://127.0.0.1:9", "room-a7", "alice")?;
    for offset in 0..16u8 {
        let snapshot = Arc::new(sample_current_public_tree(
            session.barrier_state.n_max,
            offset,
        )?);
        retain_tree_hash_authenticated_public_tree(
            &mut session.barrier_state,
            u64::from(offset),
            snapshot,
        );
    }
    assert!(
        session.barrier_state.retained_public_trees.len() <= 8,
        "retained public-tree cache must stay bounded"
    );
    Ok(())
}

#[test]
fn persisted_session_roundtrip_preserves_fs_forward_leap_policy_and_last_accepted_ec()
-> Result<(), Box<dyn std::error::Error>> {
    let session = build_test_session(0xA13, "http://127.0.0.1:9", "room-a3", "alice")?;
    let roundtrip = PersistedSession::from_session(&session).into_app_session()?;
    assert_eq!(
        roundtrip.fs_forward_leap_policy,
        session.fs_forward_leap_policy
    );
    assert_eq!(roundtrip.last_accepted_ec, session.last_accepted_ec);
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
        activation_source: current_pending_activation_source(&session),
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
        activation_source: current_pending_activation_source(&session),
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
        activation_source: current_pending_activation_source(&session),
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
        activation_source: current_pending_activation_source(&session),
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
        activation_source: current_pending_activation_source(&session),
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
fn pending_barrier_activation_requires_matching_persisted_source_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(0xB6, "http://127.0.0.1:9", "room-b5", "bob")?;
    let digest = [0x51; 32];
    session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 7,
        we_epoch_id: [0x46; 32],
        fs_ec: 31,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash: [0x61; 32],
        kem_tree_hash_after: [0x71; 32],
        k_barrier_new: Zeroizing::new([0x81; 32]),
        k_fs_after_pcs: Some(Zeroizing::new([0x91; 32])),
        barrier_update_reason: Some(1),
        barrier_update_digest: digest,
        on_path_key_material: BTreeMap::new(),
        activation_source: current_pending_activation_source(&session),
    });

    session.fs_dev_prev_commit = [0xEE; 32];
    let err = apply_pending_barrier_activation(&mut session, 7, Some(31), Some(1), Some(digest))
        .expect_err("mismatched persisted activation source must fail closed");
    assert!(
        err.to_string().contains("960.9"),
        "unexpected activation-source mismatch error: {err}"
    );
    assert!(
        session.barrier_state.pending.is_some(),
        "failed activation must retain pending state for recovery"
    );
    Ok(())
}

#[test]
fn epoch_sync_pending_bundle_allows_authority_headers_with_authenticated_source()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(
        0xB973,
        "http://127.0.0.1:9",
        "room-b87g-pending-seed",
        "bob",
    )?;
    let header = build_authority_activation_guard_header(
        &mut session,
        HistoryAuthorityExtension::GlobalHistoryAuthorityV1,
        vec![0xA1, 0xB2, 0xC3, 0xD4],
    )?;
    ensure_epoch_sync_pending_bundle_has_authenticated_source(&session, true, true, &header)?;
    Ok(())
}

#[test]
fn epoch_sync_pending_bundle_rejects_authority_headers_without_authenticated_source()
-> Result<(), Box<dyn std::error::Error>> {
    let mut session = build_test_session(
        0xB974,
        "http://127.0.0.1:9",
        "room-b87g-pending-missing",
        "bob",
    )?;
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
    let err = ensure_epoch_sync_pending_bundle_has_authenticated_source(
        &session, true, true, &header,
    )
    .expect_err(
        "local pending authority-bound bundle without authenticated pre-publish state must fail",
    );
    assert!(
        err.to_string()
            .contains("without authenticated pre-publish authority state"),
        "unexpected pending-source authority error: {err}"
    );
    Ok(())
}
