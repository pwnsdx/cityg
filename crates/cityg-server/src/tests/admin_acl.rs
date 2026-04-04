use super::*;

#[test]
fn room_admin_rotation_requires_authorized_identity() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0xB3; 32];
    let initial_kbroad = vec![0x41; 16];
    let rotated_kbroad = vec![0x42; 16];
    let admin_pop_key = vec![0xAA; 48];
    let other_pop_key = vec![0xBB; 48];

    server.register_group_with_admin(&gid, initial_kbroad, admin_pop_key.clone())?;

    let err = server
        .rotate_group_kbroad_with_actor(
            &gid,
            rotated_kbroad.clone(),
            &other_pop_key,
            test_room_admin_replay_key(1),
        )
        .expect_err("non-admin identity must be rejected");
    assert!(matches!(
        err,
        CityGError::InvalidInput("room admin proof is not authorized")
    ));

    assert_eq!(
        server.rotate_group_kbroad_with_actor(
            &gid,
            rotated_kbroad.clone(),
            &admin_pop_key,
            test_room_admin_replay_key(2),
        )?,
        1
    );
    assert_eq!(
        server.build_join_ticket(&gid)?.kbroad_public,
        rotated_kbroad
    );
    Ok(())
}

#[test]
fn room_admin_rotation_requires_explicit_admin_acl() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0xB4; 32];
    server.register_group(&gid, vec![0x41; 16])?;

    let err = server
        .rotate_group_kbroad_with_actor(
            &gid,
            vec![0x42; 16],
            &[0xAB; 48],
            test_room_admin_replay_key(3),
        )
        .expect_err("legacy room without explicit admins must fail closed");
    assert!(matches!(
        err,
        CityGError::InvalidInput("room admin proof is not authorized")
    ));
    Ok(())
}

#[test]
fn grant_revoke_and_list_room_admins_enforce_authorization() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0xB5; 32];
    let kbroad_public = vec![0x51; 16];
    let creator_pop_key = vec![0xA1; 48];
    let delegate_pop_key = vec![0xB1; 48];
    let outsider_pop_key = vec![0xC1; 48];

    server.register_group_with_admin(&gid, kbroad_public, creator_pop_key.clone())?;

    let err = server
        .grant_room_admin(
            &gid,
            &outsider_pop_key,
            delegate_pop_key.clone(),
            test_room_admin_replay_key(4),
        )
        .expect_err("non-admin grant must fail");
    assert!(matches!(
        err,
        CityGError::InvalidInput("room admin proof is not authorized")
    ));

    let (granted, admin_count) = server.grant_room_admin(
        &gid,
        &creator_pop_key,
        delegate_pop_key.clone(),
        test_room_admin_replay_key(5),
    )?;
    assert!(granted);
    assert_eq!(admin_count, 2);
    assert_eq!(
        server.list_room_admins(&gid, &creator_pop_key)?,
        vec![creator_pop_key.clone(), delegate_pop_key.clone()]
    );

    let replay_err = server
        .grant_room_admin(
            &gid,
            &creator_pop_key,
            delegate_pop_key.clone(),
            test_room_admin_replay_key(5),
        )
        .expect_err("replayed grant proof must fail");
    assert!(matches!(
        replay_err,
        CityGError::InvalidInput(crate::ROOM_ADMIN_PROOF_REPLAYED_ERR)
    ));

    let (already_granted, admin_count) = server.grant_room_admin(
        &gid,
        &creator_pop_key,
        delegate_pop_key.clone(),
        test_room_admin_replay_key(6),
    )?;
    assert!(!already_granted);
    assert_eq!(admin_count, 2);

    assert_eq!(
        server.list_room_admins(&gid, &delegate_pop_key)?,
        vec![creator_pop_key.clone(), delegate_pop_key.clone()]
    );

    let err = server
        .revoke_room_admin(
            &gid,
            &outsider_pop_key,
            &delegate_pop_key,
            test_room_admin_replay_key(7),
        )
        .expect_err("non-admin revoke must fail");
    assert!(matches!(
        err,
        CityGError::InvalidInput("room admin proof is not authorized")
    ));

    let (revoked, admin_count) = server.revoke_room_admin(
        &gid,
        &creator_pop_key,
        &delegate_pop_key,
        test_room_admin_replay_key(8),
    )?;
    assert!(revoked);
    assert_eq!(admin_count, 1);
    assert_eq!(
        server.list_room_admins(&gid, &creator_pop_key)?,
        vec![creator_pop_key.clone()]
    );

    let (already_revoked, admin_count) = server.revoke_room_admin(
        &gid,
        &creator_pop_key,
        &delegate_pop_key,
        test_room_admin_replay_key(9),
    )?;
    assert!(!already_revoked);
    assert_eq!(admin_count, 1);
    Ok(())
}

#[test]
fn revoke_room_admin_rejects_last_admin_and_persists_grants() -> Result<(), CityGError> {
    let _serial = crate::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("room-admin-grants.journal");
    let gid = [0xB6; 32];
    let kbroad_public = vec![0x61; 16];
    let creator_pop_key = vec![0xD1; 48];
    let delegate_pop_key = vec![0xE1; 48];

    {
        let mut config = ServerConfig::new();
        config.state_path = Some(journal_path.clone());
        let mut server = CityGServer::new(config);
        server.register_group_with_admin(&gid, kbroad_public, creator_pop_key.clone())?;

        let err = server
            .revoke_room_admin(
                &gid,
                &creator_pop_key,
                &creator_pop_key,
                test_room_admin_replay_key(10),
            )
            .expect_err("last admin revoke must fail");
        assert!(matches!(
            err,
            CityGError::InvalidInput("cannot revoke the last room admin")
        ));

        let (granted, admin_count) = server.grant_room_admin(
            &gid,
            &creator_pop_key,
            delegate_pop_key.clone(),
            test_room_admin_replay_key(11),
        )?;
        assert!(granted);
        assert_eq!(admin_count, 2);
    }

    let mut config = ServerConfig::new();
    config.state_path = Some(journal_path);
    let restarted = CityGServer::new(config);
    assert_eq!(
        restarted.list_room_admins(&gid, &creator_pop_key)?,
        vec![creator_pop_key, delegate_pop_key]
    );
    Ok(())
}

#[test]
fn admin_expel_ticket_requires_authorized_admin_bound_to_author_leaf() -> Result<(), CityGError> {
    let mut server = crate::demo::demo_server();
    let alice = cityg_client::demo::demo_bundle("alice")?;
    let bob = cityg_client::demo::demo_bundle("bob")?;
    server.accept_epoch(&alice)?;
    server.accept_epoch(&bob)?;

    let gid = cityg_client::demo::DEMO_GID;
    let alice_leaf = cityg_client::demo::demo_member_leaf("alice");
    let bob_leaf = cityg_client::demo::demo_member_leaf("bob");
    let bound_admin_pop_key = vec![0xD1; 48];
    let unbound_admin_pop_key = vec![0xE1; 48];
    let outsider_pop_key = vec![0xF1; 48];

    {
        let group = server
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("missing demo group state"))?;
        group
            .room_admin_pop_keys
            .insert(bound_admin_pop_key.clone());
        group
            .room_admin_pop_keys
            .insert(unbound_admin_pop_key.clone());
        group
            .leaf_device_pk
            .insert(alice_leaf, bound_admin_pop_key.clone());
    }

    let err = match server.build_admin_expel_ticket(
        &gid,
        &outsider_pop_key,
        &alice_leaf,
        &bob_leaf,
        test_room_admin_replay_key(12),
    ) {
        Ok(_) => return Err(CityGError::InvalidInput("outsider expel must fail")),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        CityGError::InvalidInput("room admin proof is not authorized")
    ));

    let err = match server.build_admin_expel_ticket(
        &gid,
        &unbound_admin_pop_key,
        &alice_leaf,
        &bob_leaf,
        test_room_admin_replay_key(13),
    ) {
        Ok(_) => {
            return Err(CityGError::InvalidInput(
                "author leaf must match signer identity",
            ));
        }
        Err(err) => err,
    };
    assert!(matches!(
        err,
        CityGError::InvalidInput("author leaf is not bound to room admin identity")
    ));

    let err = match server.build_admin_expel_ticket(
        &gid,
        &bound_admin_pop_key,
        &alice_leaf,
        &alice_leaf,
        test_room_admin_replay_key(14),
    ) {
        Ok(_) => return Err(CityGError::InvalidInput("self-targeted expel must fail")),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        CityGError::InvalidInput(
            "author_leaf_id and target_leaf_id must differ; use controlled leave instead"
        )
    ));

    let ticket = server.build_admin_expel_ticket(
        &gid,
        &bound_admin_pop_key,
        &alice_leaf,
        &bob_leaf,
        test_room_admin_replay_key(15),
    )?;
    assert_eq!(ticket.leaf_id, alice_leaf);
    assert_eq!(
        ticket.slot_index,
        u64::from(crate::slot_index_for_leaf(&bob_leaf, ticket.n_max))
    );
    let srx = witness::SrxInputsOwned::from_cbor(&ticket.srx_cbor)?;
    assert_eq!(srx.since_leaf_ids, vec![bob_leaf]);
    let expected_revoked_root = msphf_core::merkle::canonical_set_root(&[bob_leaf])?;
    assert_eq!(ticket.revoked_since_root, expected_revoked_root);
    assert_eq!(ticket.revoked_root, expected_revoked_root);
    Ok(())
}

#[test]
fn explicit_room_admins_persist_across_restart() -> Result<(), CityGError> {
    let _serial = crate::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("room-admins.journal");
    let gid = [0xB4; 32];
    let kbroad_public = vec![0x44; 16];
    let admin_pop_key = vec![0xCC; 48];

    {
        let mut config = ServerConfig::new();
        config.state_path = Some(journal_path.clone());
        let mut server = CityGServer::new(config);
        server.register_group_with_admin(&gid, kbroad_public.clone(), admin_pop_key.clone())?;
    }

    let mut config = ServerConfig::new();
    config.state_path = Some(journal_path);
    let mut restarted = CityGServer::new(config);
    let rotated_kbroad = vec![0x55; 16];
    assert_eq!(
        restarted.rotate_group_kbroad_with_actor(
            &gid,
            rotated_kbroad,
            &admin_pop_key,
            test_room_admin_replay_key(16),
        )?,
        1
    );
    Ok(())
}

#[test]
fn room_admin_proof_replay_keys_persist_across_restart() -> Result<(), CityGError> {
    let _serial = crate::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("room-admin-proof-replay.journal");
    let gid = [0xB7; 32];
    let kbroad_public = vec![0x61; 16];
    let creator_pop_key = vec![0xD1; 48];
    let delegate_pop_key = vec![0xE1; 48];
    let replay_key = test_room_admin_replay_key(17);

    {
        let mut config = ServerConfig::new();
        config.state_path = Some(journal_path.clone());
        let mut server = CityGServer::new(config);
        server.register_group_with_admin(&gid, kbroad_public, creator_pop_key.clone())?;
        let (granted, admin_count) = server.grant_room_admin(
            &gid,
            &creator_pop_key,
            delegate_pop_key.clone(),
            replay_key,
        )?;
        assert!(granted);
        assert_eq!(admin_count, 2);
    }

    let mut config = ServerConfig::new();
    config.state_path = Some(journal_path);
    let mut restarted = CityGServer::new(config);
    let err = restarted
        .grant_room_admin(&gid, &creator_pop_key, delegate_pop_key, replay_key)
        .expect_err("replayed room-admin proof must remain rejected after restart");
    assert!(matches!(
        err,
        CityGError::InvalidInput(crate::ROOM_ADMIN_PROOF_REPLAYED_ERR)
    ));
    Ok(())
}
