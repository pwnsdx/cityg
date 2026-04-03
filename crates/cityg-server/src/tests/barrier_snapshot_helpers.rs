use super::*;

#[test]
fn resolve_joins_since_reports_join_metadata() -> Result<(), CityGError> {
    let mut server = crate::demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let records = server.resolve_joins_since(&cityg_client::demo::DEMO_GID, 0)?;
    assert!(
        !records.records.is_empty(),
        "expected at least one join record"
    );
    let record = &records.records[0];
    assert!(record.leaf_index > 0);
    assert!(!record.device_pk.is_empty());
    assert!(
        record.ek_leaf.len() == 1184,
        "ek_leaf must be present and ML-KEM-768 size"
    );
    Ok(())
}

#[test]
fn resolve_joins_since_filters_post_genesis_join_history() -> Result<(), CityGError> {
    let gid = [0x82; 32];
    let mut server = CityGServer::new(ServerConfig::new());
    let state = server.roster.groups.entry(gid.to_vec()).or_default();
    state.barrier_version = 3;
    let leaf_v2 = colliding_cover_leaf(8);
    let leaf_v3a = colliding_cover_leaf(10);
    let leaf_v3b = colliding_cover_leaf(9);
    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![leaf_v2, leaf_v3a, leaf_v3b],
        revoked: Vec::new(),
    });
    let latest_root = [0xA1; 32];
    state.latest_root = Some(latest_root);
    state.snapshots.insert(latest_root, membership);
    state.join_history = vec![
        crate::JoinLeafHistoryRecord {
            leaf_id: colliding_cover_leaf(7),
            barrier_version: 1,
            leaf_index: 7,
            slot_generation: 0,
            device_pk: vec![0x11; 4],
            ek_leaf: vec![0x21; 1184],
        },
        crate::JoinLeafHistoryRecord {
            leaf_id: leaf_v2,
            barrier_version: 2,
            leaf_index: 8,
            slot_generation: 0,
            device_pk: vec![0x12; 4],
            ek_leaf: vec![0x22; 1184],
        },
        crate::JoinLeafHistoryRecord {
            leaf_id: leaf_v3a,
            barrier_version: 3,
            leaf_index: 10,
            slot_generation: 0,
            device_pk: vec![0x13; 4],
            ek_leaf: vec![0x23; 1184],
        },
        crate::JoinLeafHistoryRecord {
            leaf_id: leaf_v3b,
            barrier_version: 3,
            leaf_index: 9,
            slot_generation: 0,
            device_pk: vec![0x14; 4],
            ek_leaf: vec![0x24; 1184],
        },
    ];

    let records = server.resolve_joins_since(&gid, 1)?;
    assert_eq!(records.records.len(), 3);
    assert_eq!(records.records[0].leaf_index, 8);
    assert_eq!(records.records[0].device_pk, vec![0x12; 4]);
    assert_eq!(records.records[0].ek_leaf, vec![0x22; 1184]);
    assert_eq!(records.records[1].leaf_index, 9);
    assert_eq!(records.records[2].leaf_index, 10);
    Ok(())
}

#[test]
fn resolve_joins_since_prunes_resolved_and_revoked_join_history() -> Result<(), CityGError> {
    let gid = [0x85; 32];
    let mut server = CityGServer::new(ServerConfig::new());
    let leaf_active = colliding_cover_leaf(11);
    let leaf_revoked = colliding_cover_leaf(12);
    let latest_root = [0xB1; 32];

    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![leaf_active],
        revoked: Vec::new(),
    });
    let state = server.roster.groups.entry(gid.to_vec()).or_default();
    state.barrier_version = 5;
    state.latest_root = Some(latest_root);
    state.snapshots.insert(latest_root, membership);
    state.join_history = vec![
        crate::JoinLeafHistoryRecord {
            leaf_id: leaf_active,
            barrier_version: 2,
            leaf_index: 11,
            slot_generation: 0,
            device_pk: vec![0x11; 4],
            ek_leaf: vec![0x21; 1184],
        },
        crate::JoinLeafHistoryRecord {
            leaf_id: leaf_active,
            barrier_version: 5,
            leaf_index: 11,
            slot_generation: 0,
            device_pk: vec![0x15; 4],
            ek_leaf: vec![0x25; 1184],
        },
        crate::JoinLeafHistoryRecord {
            leaf_id: leaf_revoked,
            barrier_version: 4,
            leaf_index: 12,
            slot_generation: 0,
            device_pk: vec![0x12; 4],
            ek_leaf: vec![0x22; 1184],
        },
    ];

    let records = server.resolve_joins_since(&gid, 1)?;
    assert_eq!(records.records.len(), 1);
    assert_eq!(records.records[0].leaf_index, 11);
    assert_eq!(records.records[0].device_pk, vec![0x15; 4]);
    assert_eq!(records.records[0].ek_leaf, vec![0x25; 1184]);

    let pruned = &server
        .roster
        .groups
        .get(gid.as_slice())
        .ok_or(CityGError::InvalidInput("group not found"))?
        .join_history;
    assert_eq!(pruned.len(), 1);
    assert_eq!(pruned[0].leaf_id, leaf_active);
    assert_eq!(pruned[0].barrier_version, 5);
    Ok(())
}

#[test]
fn resolve_joins_since_rejects_duplicate_active_cover_allocations() -> Result<(), CityGError> {
    let gid = [0x84; 32];
    let mut server = CityGServer::new(ServerConfig::new());
    let leaf_a = colliding_cover_leaf(5);
    let leaf_b = colliding_cover_leaf(1029);
    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![leaf_a, leaf_b],
        revoked: Vec::new(),
    });
    let root = msphf_core::merkle::canonical_set_root(&[leaf_a, leaf_b])?;
    let state = server.roster.groups.entry(gid.to_vec()).or_default();
    state.snapshots.insert(root, membership);
    state.latest_root = Some(root);

    let err = server
        .resolve_joins_since(&gid, 0)
        .expect_err("duplicate active cover allocations must fail closed");
    assert!(matches!(
        err,
        CityGError::InvalidInput(crate::DUPLICATE_ACTIVE_COVER_LEAF_ALLOCATION_ERR)
    ));
    Ok(())
}

#[test]
fn resolve_joins_since_genesis_without_snapshot_rejects_missing_artifact() -> Result<(), CityGError>
{
    let gid = [0x81; 32];
    let mut server = CityGServer::new(ServerConfig::new());
    server
        .roster
        .groups
        .insert(gid.to_vec(), crate::GroupState::default());
    let err = server
        .resolve_joins_since(&gid, 0)
        .expect_err("missing genesis provisioning artifact must fail closed");
    assert!(matches!(
        err,
        CityGError::InvalidInput(crate::GENESIS_PROVISIONING_ARTIFACT_MISSING_ERR)
    ));
    Ok(())
}

#[test]
fn fetch_barrier_public_tree_enforces_snapshot_auth() -> Result<(), CityGError> {
    let mut server = crate::demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let group = server
        .roster
        .groups
        .get(cityg_client::demo::DEMO_GID.as_slice())
        .ok_or(CityGError::InvalidInput("group not found"))?;
    let expected_hash = group.kem_tree_hash_after;
    let n_max = group.n_max;

    let snapshot =
        server.fetch_barrier_public_tree(&cityg_client::demo::DEMO_GID, &expected_hash)?;
    assert_eq!(snapshot.n_max, n_max);
    assert_eq!(snapshot.kem_tree_hash_after, expected_hash);
    assert_eq!(
        snapshot.pk_entries.len() as u64,
        n_max.saturating_mul(2).saturating_sub(1)
    );

    let err = server
        .fetch_barrier_public_tree(&cityg_client::demo::DEMO_GID, &[0xFF; 32])
        .expect_err("mismatched hash must fail");
    assert!(matches!(
        err,
        CityGError::InvalidInput(crate::HISTORICAL_BARRIER_PUBLIC_TREE_SNAPSHOT_UNAVAILABLE_ERR)
    ));
    Ok(())
}

#[test]
fn fetch_barrier_public_tree_rejects_corrupted_history_snapshot() -> Result<(), CityGError> {
    let mut server = crate::demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let gid = cityg_client::demo::DEMO_GID;
    let (expected_hash, _current_hash) = {
        let historical_hash = server
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?
            .kem_tree_hash_after;
        let (current_hash, _entries) = advance_committed_tree_for_tests(&mut server, &gid, 0x55)?;
        (historical_hash, current_hash)
    };
    {
        let group = server
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        let historical_entries = crate::history_barrier_public_tree_entries(group, &expected_hash)
            .ok_or(CityGError::InvalidInput(
                "historical snapshot missing before corruption",
            ))?;
        let mut corrupted = historical_entries;
        corrupted[0] = vec![0x55; 1184];
        let snapshot_ref =
            crate::encode_barrier_public_tree_snapshot_ref(group, corrupted.as_slice())?;
        group
            .barrier_public_tree_history
            .insert(expected_hash, snapshot_ref);
    }

    let err = server
        .fetch_barrier_public_tree(&gid, &expected_hash)
        .expect_err("corrupted historical snapshot must fail auth");
    assert!(
        matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE.code
                    && freeze.reason
                        == msphf_orchestrator::FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE.reason
        ),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn fetch_barrier_public_tree_rejects_duplicate_active_cover_allocations() -> Result<(), CityGError>
{
    let gid = [0x85; 32];
    let mut server = CityGServer::new(ServerConfig::new());
    let leaf_a = colliding_cover_leaf(5);
    let leaf_b = colliding_cover_leaf(1029);
    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![leaf_a, leaf_b],
        revoked: Vec::new(),
    });
    let root = msphf_core::merkle::canonical_set_root(&[leaf_a, leaf_b])?;
    let state = server.roster.groups.entry(gid.to_vec()).or_default();
    state.snapshots.insert(root, membership);
    state.latest_root = Some(root);
    state.leaf_barrier_public.insert(leaf_a, vec![0x11; 1184]);
    state.leaf_barrier_public.insert(leaf_b, vec![0x22; 1184]);

    let err = server
        .fetch_barrier_public_tree(&gid, &[0u8; 32])
        .expect_err("duplicate active cover allocations must fail closed");
    assert!(matches!(
        err,
        CityGError::InvalidInput(crate::DUPLICATE_ACTIVE_COVER_LEAF_ALLOCATION_ERR)
    ));
    Ok(())
}

#[test]
fn fetch_barrier_public_tree_serves_historical_committed_snapshots() -> Result<(), CityGError> {
    let generated = build_genesis_member_bundle(0x72)?;
    let mut server = crate::demo::demo_server();
    server.accept_epoch(&generated.bundle)?;
    let gid = cityg_client::demo::DEMO_GID;
    let (historical_hash, historical_entries, n_max) = {
        let group = server
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        (
            group.kem_tree_hash_after,
            group.barrier_pk_entries.clone(),
            group.n_max,
        )
    };

    let (current_hash, current_entries) =
        advance_committed_tree_for_tests(&mut server, &gid, 0x72)?;
    assert_ne!(
        current_hash, historical_hash,
        "accepted refresh should advance the committed public tree hash"
    );

    let snapshot = server.fetch_barrier_public_tree(&gid, &historical_hash)?;
    assert_eq!(snapshot.n_max, n_max);
    assert_eq!(snapshot.kem_tree_hash_after, historical_hash);
    assert_eq!(snapshot.pk_entries, historical_entries);

    {
        let group =
            server
                .roster
                .groups
                .get_mut(gid.as_slice())
                .ok_or(CityGError::InvalidInput(
                    "group not found before recompute fetch",
                ))?;
        group.barrier_public_tree_history.remove(&current_hash);
        assert_eq!(group.barrier_pk_entries, current_entries);
    }
    let current_snapshot = server.fetch_barrier_public_tree(&gid, &current_hash)?;
    assert_eq!(current_snapshot.kem_tree_hash_after, current_hash);
    assert_ne!(current_snapshot.pk_entries, historical_entries);
    Ok(())
}

#[test]
fn history_commitment_advances_monotonically_and_preserves_historical_snapshots()
-> Result<(), CityGError> {
    let generated = build_genesis_member_bundle(0x74)?;
    let mut server = crate::demo::demo_server();
    server.accept_epoch(&generated.bundle)?;
    let gid = cityg_client::demo::DEMO_GID;

    let first_hash = {
        let group = server
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        group.kem_tree_hash_after
    };
    let first_snapshot = server.fetch_barrier_public_tree(&gid, &first_hash)?;
    let (second_hash, _) = advance_committed_tree_for_tests(&mut server, &gid, 0x74)?;
    let historical_hash = server
        .roster
        .groups
        .get(gid.as_slice())
        .and_then(|group| {
            group
                .barrier_public_tree_history
                .keys()
                .copied()
                .find(|hash| *hash != second_hash)
        })
        .ok_or(CityGError::InvalidInput(
            "missing historical barrier snapshot",
        ))?;
    let second_snapshot = server.fetch_barrier_public_tree(&gid, &second_hash)?;
    let historical_snapshot = server.fetch_barrier_public_tree(&gid, &historical_hash)?;

    assert_ne!(
        first_snapshot.history_commitment.history_commitment_id,
        [0u8; 32]
    );
    assert_ne!(
        historical_snapshot.history_commitment.history_commitment_id,
        [0u8; 32]
    );
    assert!(
        second_snapshot.history_commitment.history_seq
            > historical_snapshot.history_commitment.history_seq
    );
    assert_eq!(
        second_snapshot
            .history_commitment
            .prev_history_commitment_id,
        historical_snapshot.history_commitment.history_commitment_id
    );
    Ok(())
}

#[test]
fn barrier_public_tree_history_prunes_retired_snapshots() -> Result<(), CityGError> {
    let gid = [0x91; 32];
    let mut state = crate::GroupState::default();
    state.n_max = crate::DEFAULT_BARRIER_N_MAX;
    state.barrier_pk_entries = crate::build_all_blank_pk_entries(state.n_max)?;
    let mut historical_hashes = Vec::new();

    for seq in 0..(crate::MAX_RETAINED_BARRIER_PUBLIC_TREE_SNAPSHOTS + 8) {
        state.barrier_version = u64::try_from(seq).unwrap_or(u64::MAX);
        state.barrier_pk_entries[0] = (seq as u64).to_le_bytes().to_vec();
        state.kem_tree_hash_after = crate::compute_group_barrier_tree_hash(&state)?;
        historical_hashes.push(state.kem_tree_hash_after);
        crate::record_barrier_public_tree_snapshot(&gid, &mut state)?;
    }

    assert_eq!(
        state.barrier_public_tree_history.len(),
        crate::MAX_RETAINED_BARRIER_PUBLIC_TREE_SNAPSHOTS
    );
    let retired_hash = historical_hashes[0];
    assert!(
        !state
            .barrier_public_tree_history
            .contains_key(&retired_hash),
        "oldest committed snapshot should be retired once retention window is exceeded"
    );
    let current_hash = *historical_hashes
        .last()
        .ok_or(CityGError::InvalidInput("missing current hash"))?;
    assert!(
        state
            .barrier_public_tree_history
            .contains_key(&current_hash),
        "current committed snapshot must remain retained"
    );

    let mut server = CityGServer::new(ServerConfig::new());
    server.roster.groups.insert(gid.to_vec(), state);

    let err = server
        .fetch_barrier_public_tree(&gid, &retired_hash)
        .expect_err("retired historical snapshot should fail closed");
    assert!(matches!(
        err,
        CityGError::InvalidInput(crate::HISTORICAL_BARRIER_PUBLIC_TREE_SNAPSHOT_UNAVAILABLE_ERR)
    ));

    let current = server.fetch_barrier_public_tree(&gid, &current_hash)?;
    assert_eq!(current.kem_tree_hash_after, current_hash);
    Ok(())
}

#[test]
fn merge_ticket_hash_matches_fetchable_tree_snapshot() -> Result<(), CityGError> {
    let mut server = crate::demo::demo_server();
    let alice = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&alice)?;

    let ticket = server.build_merge_ticket(
        &cityg_client::demo::DEMO_GID,
        &cityg_client::demo::demo_member_leaf("alice"),
    )?;
    let snapshot = server
        .fetch_barrier_public_tree(&cityg_client::demo::DEMO_GID, &ticket.kem_tree_hash_after)?;
    assert_eq!(snapshot.kem_tree_hash_after, ticket.kem_tree_hash_after);
    assert_eq!(snapshot.n_max, ticket.n_max);
    Ok(())
}

#[test]
fn fetch_barrier_public_tree_prefers_current_commitment_for_current_hash() -> Result<(), CityGError>
{
    let mut server = crate::demo::demo_server();
    let alice = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&alice)?;

    let gid = cityg_client::demo::DEMO_GID;
    let ticket = server.build_merge_ticket(&gid, &cityg_client::demo::demo_member_leaf("alice"))?;
    let current = server.current_history_commitment(&gid)?;
    {
        let group = server
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group missing"))?;
        group.barrier_public_tree_history.insert(
            ticket.kem_tree_hash_after,
            crate::BarrierPublicTreeSnapshotRef {
                blob_indices: Vec::new(),
                barrier_version: ticket.barrier_version,
                history_view_id: [0xA1; 32],
                history_commitment: crate::HistoryCommitment {
                    history_view_id: [0xA1; 32],
                    history_commitment_id: [0xB2; 32],
                    prev_history_commitment_id: [0xC3; 32],
                    history_seq: current.history_seq.saturating_sub(1),
                },
            },
        );
    }

    let snapshot = server.fetch_barrier_public_tree(&gid, &ticket.kem_tree_hash_after)?;
    assert_eq!(snapshot.kem_tree_hash_after, ticket.kem_tree_hash_after);
    assert_eq!(snapshot.history_commitment, current);
    Ok(())
}

#[test]
fn fetch_barrier_public_tree_prefers_current_commitment_for_current_predecessor_hash()
-> Result<(), CityGError> {
    let mut server = crate::demo::demo_server();
    let gid = cityg_client::demo::DEMO_GID;
    let alice = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&alice)?;
    let predecessor_hash = {
        let group = server
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group missing"))?;
        group.kem_tree_hash_after
    };
    let bob = cityg_client::demo::demo_bundle("bob")?;
    server.accept_epoch(&bob)?;

    let current = server.current_history_commitment(&gid)?;
    {
        let group = server
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group missing"))?;
        group.current_accepted_barrier_predecessor_hash = predecessor_hash;
    }

    let snapshot = server.fetch_barrier_public_tree(&gid, &predecessor_hash)?;
    assert_eq!(snapshot.kem_tree_hash_after, predecessor_hash);
    assert_eq!(snapshot.history_commitment, current);
    Ok(())
}

#[test]
fn resolve_revoked_leaf_indices_requires_matching_roots_hash() -> Result<(), CityGError> {
    let mut server = crate::demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let (leaf, roots_hash) = {
        let group = server
            .roster
            .groups
            .get_mut(cityg_client::demo::DEMO_GID.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        let root = group.barrier_roots_hash;
        let leaf = group
            .latest_snapshot()
            .and_then(|snapshot| snapshot.members().next().copied())
            .ok_or(CityGError::InvalidInput("missing membership snapshot"))?;
        group.revoked.insert(leaf);
        (leaf, root)
    };

    let indices =
        server.resolve_revoked_leaf_indices(&cityg_client::demo::DEMO_GID, &roots_hash)?;
    let n_max = server
        .roster
        .groups
        .get(cityg_client::demo::DEMO_GID.as_slice())
        .map(|group| group.n_max)
        .unwrap_or(crate::DEFAULT_BARRIER_N_MAX);
    assert_eq!(
        indices.leaf_indices,
        vec![crate::cover_leaf_index(&leaf, n_max)]
    );

    let err = server
        .resolve_revoked_leaf_indices(&cityg_client::demo::DEMO_GID, &[0x42; 32])
        .expect_err("mismatched roots hash must fail");
    assert!(matches!(
        err,
        CityGError::InvalidInput("revocation_roots_hash does not match committed barrier roots")
    ));
    Ok(())
}

#[test]
fn barrier_helpers_report_missing_group_state() {
    let mut server = crate::demo::demo_server();
    let gid = [0xE1; 32];

    assert!(matches!(
        server.resolve_revoked_leaf_indices(&gid, &[0u8; 32]),
        Err(CityGError::InvalidInput("group not found"))
    ));
    assert!(matches!(
        server.resolve_joins_since(&gid, 0),
        Err(CityGError::InvalidInput("group not found"))
    ));
    assert!(matches!(
        server.fetch_barrier_public_tree(&gid, &[0u8; 32]),
        Err(CityGError::InvalidInput("group not found"))
    ));

    assert_eq!(server.barrier_roots_hash(gid.as_slice()), None);
    assert_eq!(server.barrier_kem_tree_hash_after(gid.as_slice()), None);
    assert_eq!(server.barrier_n_max(gid.as_slice()), None);
}
