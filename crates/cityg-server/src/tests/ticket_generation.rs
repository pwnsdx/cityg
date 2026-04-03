use super::*;
use crate::{
    BARRIER_LEAF_CAPACITY_EXHAUSTED_ERR, BARRIER_LEAF_CAPACITY_REFUSAL_THRESHOLD_REACHED_ERR,
    COVER_LEAF_INDEX_ALREADY_ALLOCATED_ERR, GroupState, demo, leaf_index,
};

#[test]
fn build_join_ticket_requires_kbroad_and_advances_leaf_index() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x42; 32];

    let err = server
        .build_join_ticket(&gid)
        .expect_err("missing kbroad should fail");
    assert!(matches!(
        err,
        CityGError::InvalidInput("kbroad key missing")
    ));

    server.register_group(&gid, vec![0x55; 16])?;
    let first = server.build_join_ticket(&gid)?;
    let second = server.build_join_ticket(&gid)?;
    assert!(leaf_index(&second.leaf_id) > leaf_index(&first.leaf_id));

    let mut demo_server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    demo_server.accept_epoch(&bundle)?;
    let err = demo_server
        .build_join_ticket(&cityg_client::demo::DEMO_GID)
        .expect_err("join ticket must fail closed until current barrier_update is accepted");
    assert!(matches!(
        err,
        CityGError::InvalidInput("current barrier_update missing for join provisioning")
    ));
    Ok(())
}

#[test]
fn build_join_ticket_with_leaf_uses_requested_leaf_and_rejects_duplicates() -> Result<(), CityGError>
{
    let mut server = demo::demo_server();
    let gid = cityg_client::demo::DEMO_GID;
    let requested_leaf = cityg_client::demo::demo_member_leaf("bound-leaf");

    let ticket = server.build_join_ticket_with_leaf(&gid, Some(requested_leaf))?;
    assert_eq!(ticket.leaf_id, requested_leaf);

    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![requested_leaf],
        revoked: Vec::new(),
    });
    let root = msphf_core::merkle::canonical_set_root(&[requested_leaf])?;
    let mut state = GroupState::default();
    state.snapshots.insert(root, membership);
    state.latest_root = Some(root);
    server.roster.groups.insert(gid.to_vec(), state);

    let err = server
        .build_join_ticket_with_leaf(&gid, Some(requested_leaf))
        .expect_err("duplicate requested leaf must fail");
    assert!(matches!(
        err,
        CityGError::InvalidInput("leaf already present in roster")
    ));
    Ok(())
}

#[test]
fn build_join_ticket_with_leaf_rejects_cover_index_collisions() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let gid = cityg_client::demo::DEMO_GID;
    let active_leaf = colliding_cover_leaf(5);
    let colliding_leaf = colliding_cover_leaf(1029);

    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![active_leaf],
        revoked: Vec::new(),
    });
    let root = msphf_core::merkle::canonical_set_root(&[active_leaf])?;
    let mut state = GroupState::default();
    state.snapshots.insert(root, membership);
    state.latest_root = Some(root);
    server.roster.groups.insert(gid.to_vec(), state);

    let err = server
        .build_join_ticket_with_leaf(&gid, Some(colliding_leaf))
        .expect_err("colliding cover index must be rejected");
    assert!(matches!(
        err,
        CityGError::InvalidInput(COVER_LEAF_INDEX_ALREADY_ALLOCATED_ERR)
    ));
    Ok(())
}

#[test]
fn build_join_ticket_rejects_when_barrier_leaf_capacity_is_exhausted() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x24; 32];
    server.register_group(&gid, vec![0x55; 16])?;

    {
        let state = server.roster.groups.entry(gid.to_vec()).or_default();
        state.n_max = 4;
        state.revoked = (0..4).map(colliding_cover_leaf).collect();
    }
    {
        let ctx_state = server.context_mut().barrier_group_state_entry_mut(&gid);
        ctx_state.n_max = 4;
    }

    let capacity = server
        .barrier_leaf_capacity(&gid)
        .expect("registered group should expose barrier capacity");
    assert_eq!(capacity.n_max, 4);
    assert_eq!(capacity.revoked_leaf_count, 4);
    assert_eq!(capacity.reserved_cover_leaf_count, 4);
    assert_eq!(capacity.remaining_cover_leaf_slots, 0);

    let err = server
        .build_join_ticket(&gid)
        .expect_err("exhausted barrier leaf capacity must reject new join tickets");
    assert!(matches!(
        err,
        CityGError::InvalidInput(BARRIER_LEAF_CAPACITY_EXHAUSTED_ERR)
    ));
    Ok(())
}

#[test]
fn pending_join_tickets_consume_cover_slots_until_exhaustion() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x39; 32];
    server.register_group(&gid, vec![0x77; 16])?;

    {
        let state = server.roster.groups.entry(gid.to_vec()).or_default();
        state.n_max = 4;
    }
    {
        let ctx_state = server.context_mut().barrier_group_state_entry_mut(&gid);
        ctx_state.n_max = 4;
    }

    for expected_pending in 1..=4u64 {
        let _ticket = server.build_join_ticket(&gid)?;
        let capacity = server
            .barrier_leaf_capacity(&gid)
            .expect("registered group should expose barrier capacity");
        assert_eq!(capacity.pending_join_ticket_count, expected_pending);
        assert_eq!(capacity.reserved_cover_leaf_count, expected_pending);
        assert_eq!(
            capacity.remaining_cover_leaf_slots,
            capacity.n_max.saturating_sub(expected_pending)
        );
    }

    let err = server
        .build_join_ticket(&gid)
        .expect_err("pending join tickets should eventually exhaust barrier capacity");
    assert!(matches!(
        err,
        CityGError::InvalidInput(BARRIER_LEAF_CAPACITY_EXHAUSTED_ERR)
    ));
    Ok(())
}

#[test]
fn build_join_ticket_rejects_new_reservations_at_refusal_threshold() -> Result<(), CityGError> {
    let mut config = ServerConfig::new();
    config.barrier_leaf_capacity_refusal_percent = Some(75);
    let mut server = CityGServer::new(config);
    let gid = [0x5A; 32];
    server.register_group(&gid, vec![0x88; 16])?;

    {
        let state = server.roster.groups.entry(gid.to_vec()).or_default();
        state.n_max = 4;
    }
    {
        let ctx_state = server.context_mut().barrier_group_state_entry_mut(&gid);
        ctx_state.n_max = 4;
    }

    for _ in 0..3 {
        let _ticket = server.build_join_ticket(&gid)?;
    }

    let err = server
        .build_join_ticket(&gid)
        .expect_err("refusal threshold should reject new reservations before full exhaustion");
    assert!(matches!(
        err,
        CityGError::InvalidInput(BARRIER_LEAF_CAPACITY_REFUSAL_THRESHOLD_REACHED_ERR)
    ));
    Ok(())
}

#[test]
fn build_join_ticket_with_existing_pending_leaf_remains_idempotent_at_refusal_threshold()
-> Result<(), CityGError> {
    let mut config = ServerConfig::new();
    config.barrier_leaf_capacity_refusal_percent = Some(50);
    let mut server = CityGServer::new(config);
    let gid = [0x5B; 32];
    server.register_group(&gid, vec![0x99; 16])?;

    {
        let state = server.roster.groups.entry(gid.to_vec()).or_default();
        state.n_max = 4;
    }
    {
        let ctx_state = server.context_mut().barrier_group_state_entry_mut(&gid);
        ctx_state.n_max = 4;
    }

    let first = server.build_join_ticket(&gid)?;
    let _second = server.build_join_ticket(&gid)?;

    let err = server
        .build_join_ticket(&gid)
        .expect_err("fresh reservation above threshold must fail");
    assert!(matches!(
        err,
        CityGError::InvalidInput(BARRIER_LEAF_CAPACITY_REFUSAL_THRESHOLD_REACHED_ERR)
    ));

    let retried = server.build_join_ticket_with_leaf(&gid, Some(first.leaf_id))?;
    assert_eq!(retried.leaf_id, first.leaf_id);

    let capacity = server
        .barrier_leaf_capacity(&gid)
        .expect("registered group should expose barrier capacity");
    assert_eq!(capacity.pending_join_ticket_count, 2);
    assert_eq!(capacity.reserved_cover_leaf_count, 2);
    Ok(())
}

#[test]
fn stale_group_second_join_accepts_without_autonomic_evolve() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let gid = cityg_client::demo::DEMO_GID;

    let first_member = build_genesis_member_bundle(0x75)?;
    server.accept_epoch(&first_member.bundle)?;
    let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;

    // Force the canonical FS base far enough behind wall clock that a fresh
    // client's autonomic catch-up overshoots the group's time-blind cap.
    server.context_mut().set_fs_base_ts(Some(1));

    let forward_jumping = build_join_bundle_from_server_ticket(&mut server, &gid, 0x76, false)?;
    let err = server
        .accept_epoch(&forward_jumping)
        .expect_err("autonomic-evolved second join should exceed the stale group cap");
    match err {
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze)) => {
            assert_eq!(freeze.code, 9476);
            assert_eq!(freeze.reason, "fs_forward_jump_group");
        }
        _ => {
            return Err(CityGError::InvalidInput(
                "unexpected stale-group join error",
            ));
        }
    }

    let recovered = build_join_bundle_from_server_ticket(&mut server, &gid, 0x77, true)?;
    assert_eq!(u64_from_header(&recovered.header_map, hdr::HDR_FS_EC)?, 0);
    server.accept_epoch(&recovered)?;

    let latest_root = server
        .latest_parent_root(gid.as_slice())
        .ok_or(CityGError::InvalidInput(
            "latest root missing after stale-group retry",
        ))?;
    let members = server
        .members_for_root(gid.as_slice(), &latest_root)
        .ok_or(CityGError::InvalidInput(
            "members missing after stale-group retry",
        ))?;
    assert_eq!(members.len(), 2);
    Ok(())
}

#[test]
fn build_merge_ticket_reports_missing_anchor_leaf_and_parity() -> Result<(), CityGError> {
    let gid = [0x24; 32];
    let leaf = cityg_client::demo::demo_member_leaf("merge");

    let mut empty = CityGServer::new(ServerConfig::new());
    let err = empty
        .build_merge_ticket(&gid, &leaf)
        .err()
        .expect("empty server should reject merge ticket");
    assert!(matches!(
        err,
        CityGError::InvalidInput("no anchors accepted for group")
    ));

    let mut server = CityGServer::new(ServerConfig::new());
    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![leaf],
        revoked: Vec::new(),
    });
    let root = msphf_core::merkle::canonical_set_root(&[leaf])?;
    let mut state = GroupState::default();
    state.snapshots.insert(root, membership);
    state.latest_root = Some(root);
    server.roster.groups.insert(gid.to_vec(), state);
    let mut registry = BTreeMap::new();
    registry.insert(gid.to_vec(), vec![0x77; 16]);
    server.context_mut().set_kbroad_registry(Some(registry));

    let missing_leaf_err = server
        .build_merge_ticket(&gid, &[0xFF; 32])
        .err()
        .expect("unknown leaf should fail before parity lookup");
    assert!(matches!(
        missing_leaf_err,
        CityGError::InvalidInput("leaf not present in roster")
    ));

    let no_parity_err = server
        .build_merge_ticket(&gid, &leaf)
        .err()
        .expect("missing parity should fail");
    assert!(matches!(
        no_parity_err,
        CityGError::InvalidInput("no pivot parity available")
    ));
    Ok(())
}

#[test]
fn build_merge_ticket_rejects_unknown_membership_root() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0x25; 32];
    let leaf = cityg_client::demo::demo_member_leaf("merge-root");
    let state = GroupState {
        latest_root: Some([0xAB; 32]),
        ..GroupState::default()
    };
    server.roster.groups.insert(gid.to_vec(), state);

    let err = match server.build_merge_ticket(&gid, &leaf) {
        Ok(_) => return Err(CityGError::InvalidInput("missing snapshot for latest root")),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        CityGError::InvalidInput("unknown membership root")
    ));
    Ok(())
}

#[test]
fn build_merge_ticket_preserves_existing_revoked_membership() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let gid = cityg_client::demo::DEMO_GID;
    let leaf_id = cityg_client::demo::demo_member_leaf("alice");
    let group = server
        .roster
        .groups
        .get_mut(gid.as_slice())
        .ok_or(CityGError::InvalidInput("missing group state"))?;
    group.revoked.insert(leaf_id);

    let ticket = server.build_merge_ticket(&gid, &leaf_id)?;
    let expected_root = msphf_core::merkle::canonical_set_root(&[leaf_id])?;
    assert_eq!(ticket.revoked_since_root, expected_root);
    assert_eq!(ticket.revoked_root, expected_root);
    Ok(())
}

#[test]
fn build_merge_ticket_requires_kbroad_even_with_live_roster_and_parity() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;
    server.context_mut().set_kbroad_registry(None);

    let err = match server.build_merge_ticket(
        &cityg_client::demo::DEMO_GID,
        &cityg_client::demo::demo_member_leaf("alice"),
    ) {
        Ok(_) => return Err(CityGError::InvalidInput("expected kbroad key miss")),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        CityGError::InvalidInput("kbroad key missing")
    ));
    Ok(())
}

#[test]
fn build_merge_ticket_falls_back_on_invalid_utf8_ids() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let gid = cityg_client::demo::DEMO_GID;
    let parent_root = server
        .latest_parent_root(gid.as_slice())
        .ok_or(CityGError::InvalidInput("latest root missing"))?;
    let leaf_id = cityg_client::demo::demo_member_leaf("alice");
    let mut parity = server
        .context_mut()
        .pivot_parities_for(gid.as_slice(), &parent_root)
        .into_iter()
        .next()
        .ok_or(CityGError::InvalidInput("pivot parity missing"))?;
    parity.we_epoch_id = [0u8; 32];
    parity.crs_id = vec![0xFF];
    parity.params_id = vec![0xFE];
    let now = server.context().current_time();
    server.context_mut().insert_pivot_parity(parity, now);

    let ticket = server.build_merge_ticket(&gid, &leaf_id)?;
    assert_eq!(ticket.msphf_crs_id, msphf_core::params::RLWE_CRS_ID_DEFAULT);
    assert_eq!(
        ticket.msphf_params_id,
        msphf_core::params::RLWE_PARAMS_ID_MOCK
    );
    Ok(())
}

#[test]
fn build_merge_ticket_prefers_highest_accept_seq_and_tie_breaks_on_weid() -> Result<(), CityGError>
{
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let gid = cityg_client::demo::DEMO_GID;
    let parent_root = server
        .latest_parent_root(gid.as_slice())
        .ok_or(CityGError::InvalidInput("latest root missing"))?;
    let leaf_id = cityg_client::demo::demo_member_leaf("alice");
    let base_parity = server
        .context_mut()
        .pivot_parities_for(gid.as_slice(), &parent_root)
        .into_iter()
        .next()
        .ok_or(CityGError::InvalidInput("pivot parity missing"))?;
    let now = server.context().current_time();
    let wid = server
        .context()
        .mh_window
        .find_head_window(&base_parity.we_epoch_id)
        .ok_or(CityGError::InvalidInput("pivot head missing"))?;

    let mut higher_seq = base_parity.clone();
    higher_seq.accept_seq = base_parity.accept_seq.saturating_add(5);
    higher_seq.we_epoch_id = [0xEE; 32];
    higher_seq.proof_mode = "higher-seq".to_string();
    higher_seq.vrf_id = "higher-seq".to_string();
    higher_seq.policy_version = "41".to_string();
    server
        .context_mut()
        .mh_window
        .accept_head(
            wid.as_slice(),
            HeadRecord::new(
                higher_seq.we_epoch_id,
                higher_seq.hp_commit,
                higher_seq.seed_ctx_hash,
                higher_seq.rho_commit,
                higher_seq.seed_commit,
                higher_seq.xk_hash,
                higher_seq.join_delta_root,
                higher_seq.revoked_since_root,
                higher_seq.revoked_root,
                higher_seq.accept_seq,
                now,
            ),
            now,
        )
        .map_err(|err| CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(err)))?;
    server.context_mut().insert_pivot_parity(higher_seq, now);

    let mut tie_winner = base_parity.clone();
    tie_winner.accept_seq = base_parity.accept_seq.saturating_add(5);
    tie_winner.we_epoch_id = [0x11; 32];
    tie_winner.proof_mode = "tie-winner".to_string();
    tie_winner.vrf_id = "tie-winner".to_string();
    tie_winner.policy_version = "42".to_string();
    server
        .context_mut()
        .mh_window
        .accept_head(
            wid.as_slice(),
            HeadRecord::new(
                tie_winner.we_epoch_id,
                tie_winner.hp_commit,
                tie_winner.seed_ctx_hash,
                tie_winner.rho_commit,
                tie_winner.seed_commit,
                tie_winner.xk_hash,
                tie_winner.join_delta_root,
                tie_winner.revoked_since_root,
                tie_winner.revoked_root,
                tie_winner.accept_seq,
                now,
            ),
            now,
        )
        .map_err(|err| CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(err)))?;
    server.context_mut().insert_pivot_parity(tie_winner, now);

    let ticket = server.build_merge_ticket(&gid, &leaf_id)?;
    assert_eq!(ticket.pivot_we_epoch_id, [0x11; 32]);
    assert_eq!(ticket.proof_mode, "tie-winner");
    assert_eq!(ticket.vrf_id, "tie-winner");
    assert_eq!(ticket.policy_version, "42");
    Ok(())
}

#[test]
fn build_merge_ticket_ignores_stale_parity_without_live_head() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let gid = cityg_client::demo::DEMO_GID;
    let parent_root = server
        .latest_parent_root(gid.as_slice())
        .ok_or(CityGError::InvalidInput("latest root missing"))?;
    let leaf_id = cityg_client::demo::demo_member_leaf("alice");
    let base_parity = server
        .context_mut()
        .pivot_parities_for(gid.as_slice(), &parent_root)
        .into_iter()
        .next()
        .ok_or(CityGError::InvalidInput("pivot parity missing"))?;
    let now = server.context().current_time();

    let mut stale = base_parity.clone();
    stale.accept_seq = base_parity.accept_seq.saturating_add(9);
    stale.we_epoch_id = [0xEE; 32];
    stale.proof_mode = "stale".to_string();
    stale.vrf_id = "stale".to_string();
    stale.policy_version = "99".to_string();
    server.context_mut().insert_pivot_parity(stale, now);

    let ticket = server.build_merge_ticket(&gid, &leaf_id)?;
    assert_eq!(
        ticket.pivot_we_epoch_id, base_parity.we_epoch_id,
        "merge ticket must ignore parity entries whose heads are no longer live in mh_window"
    );
    Ok(())
}

#[test]
fn join_root_carries_forward_live_checkpoint_parity() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let alice = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&alice)?;

    let gid = cityg_client::demo::DEMO_GID;
    let alice_root = server
        .latest_parent_root(gid.as_slice())
        .ok_or(CityGError::InvalidInput("latest root missing"))?;
    let now = server.context().current_time();
    let mut carried = server
        .context_mut()
        .pivot_parities_for(gid.as_slice(), &alice_root)
        .into_iter()
        .next()
        .ok_or(CityGError::InvalidInput("pivot parity missing"))?;
    carried.fs_ec = Some(carried.fs_ec.unwrap_or(0).saturating_add(50));
    server
        .context_mut()
        .insert_pivot_parity(carried.clone(), now);

    let bob = cityg_client::demo::demo_bundle("bob")?;
    server.accept_epoch(&bob)?;

    let new_root = server
        .latest_parent_root(gid.as_slice())
        .ok_or(CityGError::InvalidInput("latest root missing after bob"))?;
    let bob_leaf = cityg_client::demo::demo_member_leaf("bob");
    let ticket = server.build_merge_ticket(&gid, &bob_leaf)?;
    let max_ticket_fs = ticket
        .parities
        .iter()
        .filter_map(|parity| parity.fs_ec)
        .max()
        .ok_or(CityGError::InvalidInput("ticket missing fs_ec"))?;
    assert_eq!(
        max_ticket_fs,
        carried.fs_ec.unwrap_or(0),
        "new roots must keep a live parity at least as fresh as the prior checkpoint window"
    );
    assert_eq!(ticket.parent_root, new_root);
    Ok(())
}

#[test]
fn build_merge_ticket_defaults_fs_policy_and_base_ts_when_context_unset() -> Result<(), CityGError>
{
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;
    server.context_mut().set_fs_policy_version(None);
    server.context_mut().set_fs_base_ts(None);

    let ticket = server.build_merge_ticket(
        &cityg_client::demo::DEMO_GID,
        &cityg_client::demo::demo_member_leaf("alice"),
    )?;
    assert_eq!(ticket.fs_policy_version, "7");
    assert_eq!(ticket.fs_epoch_base_ts, 0);
    Ok(())
}

#[test]
fn build_merge_ticket_for_refresh_preserves_existing_revoked_roots() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let gid = cityg_client::demo::DEMO_GID;
    let leaf_id = cityg_client::demo::demo_member_leaf("alice");
    let extra_revoked = cityg_client::demo::demo_member_leaf("retired-bob");
    let group = server
        .roster
        .groups
        .get_mut(gid.as_slice())
        .ok_or(CityGError::InvalidInput("missing group state"))?;
    group.revoked.insert(leaf_id);
    group.revoked.insert(extra_revoked);

    let ticket = server.build_merge_ticket_for_refresh(&gid, &leaf_id)?;
    let mut expected_revoked = vec![extra_revoked, leaf_id];
    expected_revoked.sort();
    let expected_root = msphf_core::merkle::canonical_set_root(&expected_revoked)?;
    assert_eq!(ticket.revoked_since_root, expected_root);
    assert_eq!(ticket.revoked_root, expected_root);
    assert!(ticket.srx_cbor.is_empty());
    Ok(())
}

#[test]
fn build_merge_ticket_for_refresh_keeps_revocation_roots_stable() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let gid = cityg_client::demo::DEMO_GID;
    let leaf_id = cityg_client::demo::demo_member_leaf("alice");
    let leave_ticket = server.build_merge_ticket(&gid, &leaf_id)?;
    let refresh_ticket = server.build_merge_ticket_for_refresh(&gid, &leaf_id)?;

    assert_eq!(
        refresh_ticket.join_delta_root,
        cityg_client::witness::join_delta_root(&[])?
    );
    assert_eq!(
        refresh_ticket.revoked_since_root,
        refresh_ticket.revoked_root
    );
    assert_eq!(refresh_ticket.srx_cbor, Vec::<u8>::new());

    assert_ne!(
        leave_ticket.revoked_root, refresh_ticket.revoked_root,
        "leave ticket should stage self-revocation while refresh ticket must not"
    );
    Ok(())
}

#[test]
fn merge_ticket_after_single_join_has_parity() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let leaf_id = cityg_client::demo::demo_member_leaf("alice");
    let ticket = server.build_merge_ticket(&cityg_client::demo::DEMO_GID, &leaf_id)?;

    assert!(
        !ticket.parities.is_empty(),
        "expected pivot parity snapshot for current parent root"
    );
    assert_eq!(ticket.parent_root, ticket.parities[0].parent_root);
    Ok(())
}

#[test]
fn merge_ticket_encodes_requester_self_revocation_delta() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let leaf_id = cityg_client::demo::demo_member_leaf("alice");
    let ticket = server.build_merge_ticket(&cityg_client::demo::DEMO_GID, &leaf_id)?;
    let srx = cityg_client::witness::SrxInputsOwned::from_cbor(ticket.srx_cbor.as_slice())
        .map_err(|_| CityGError::InvalidInput("merge srx decode failed"))?;

    assert!(
        srx.join_leaf_ids.is_empty(),
        "merge must not add join leaves"
    );
    assert_eq!(
        srx.since_leaf_ids,
        vec![leaf_id],
        "merge ticket should include requester in revoked_since delta"
    );
    let expected_since_root = msphf_core::merkle::canonical_set_root(&[leaf_id])?;
    assert_eq!(ticket.revoked_since_root, expected_since_root);
    assert_eq!(ticket.revoked_root, expected_since_root);
    Ok(())
}

#[test]
fn bootstrapped_room_keeps_kbroad_registry_after_first_join() -> Result<(), CityGError> {
    let mut config = ServerConfig::new();
    config.enable_global_history_authority();
    let mut server = CityGServer::new(config);
    let gid = [0x91u8; 32];
    server.register_group_with_admin(
        &gid,
        cityg_client::demo::kbroad_public().to_vec(),
        vec![0xA5; 32],
    )?;

    let joined = build_join_member_from_server_ticket(&mut server, &gid, 0x91, false)?;
    server.accept_epoch(&joined.bundle)?;

    assert!(
        server
            .context()
            .kbroad_registry()
            .and_then(|registry| registry.get(gid.as_slice()))
            .is_some(),
        "first accepted join must not drop the room kbroad registry",
    );

    let refresh = server.build_merge_ticket_for_refresh(&gid, &joined.leaf_id)?;
    assert_eq!(
        refresh.kbroad_public,
        cityg_client::demo::kbroad_public().to_vec(),
        "refresh ticket must still expose the registered room kbroad key"
    );
    Ok(())
}
