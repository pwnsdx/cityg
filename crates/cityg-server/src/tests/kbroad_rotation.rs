use super::*;
use crate::{KBROAD_HISTORY_EXISTS_ERR, demo};

#[test]
fn register_group_rejects_duplicate_gid() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0xA1; 32];
    let key = vec![0x33; 16];

    server.register_group(&gid, key.clone())?;
    assert!(server.roster.groups.contains_key(gid.as_slice()));

    let err = server
        .register_group(&gid, key)
        .expect_err("duplicate gid should fail");
    assert!(matches!(
        err,
        CityGError::InvalidInput("kbroad key already registered")
    ));
    Ok(())
}

#[test]
fn register_group_rejects_gid_with_existing_history_even_if_registry_is_missing()
-> Result<(), CityGError> {
    let gid = [0xCA; 32];
    let leaf = cityg_client::demo::demo_member_leaf("history-owner");
    let mut server = CityGServer::new(ServerConfig::new());
    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![leaf],
        revoked: Vec::new(),
    });
    let root = msphf_core::merkle::canonical_set_root(&[leaf])?;
    let mut state = super::GroupState::default();
    state.snapshots.insert(root, membership);
    state.latest_root = Some(root);
    server.roster.groups.insert(gid.to_vec(), state);

    let err = server
        .register_group(&gid, vec![0x9A; 16])
        .expect_err("group with history must not be re-bootstrapped");
    assert!(matches!(
        err,
        CityGError::InvalidInput(KBROAD_HISTORY_EXISTS_ERR)
    ));
    Ok(())
}

#[test]
fn rotate_group_kbroad_rejects_missing_and_unchanged_keys() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0xB1; 32];
    let key = vec![0x44; 16];

    let missing = server
        .rotate_group_kbroad(&gid, key.clone())
        .expect_err("rotating an unknown group must fail");
    assert!(matches!(
        missing,
        CityGError::InvalidInput("kbroad key missing")
    ));

    server.register_group(&gid, key.clone())?;
    let unchanged = server
        .rotate_group_kbroad(&gid, key)
        .expect_err("rotating with the same key must fail");
    assert!(matches!(
        unchanged,
        CityGError::InvalidInput("kbroad key unchanged")
    ));
    Ok(())
}

#[test]
fn rotate_group_kbroad_allows_successive_unflagged_rotations() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0xB2; 32];
    let key_a = vec![0x41; 16];
    let key_b = vec![0x42; 16];
    let key_c = vec![0x43; 16];

    server.register_group(&gid, key_a)?;
    assert_eq!(server.rotate_group_kbroad(&gid, key_b.clone())?, 1);
    assert_eq!(server.rotate_group_kbroad(&gid, key_c.clone())?, 2);
    assert_eq!(server.kbroad_generation(&gid), 2);
    assert!(!server.kbroad_rotation_required(&gid));
    assert_eq!(server.build_join_ticket(&gid)?.kbroad_public, key_c);
    Ok(())
}

#[test]
fn accept_epoch_blocks_while_kbroad_rotation_is_pending() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let gid = cityg_client::demo::DEMO_GID;

    server.roster.mark_kbroad_rotation_required(gid.as_slice());

    let bundle = cityg_client::demo::demo_bundle("rotation-gate")?;
    let accept_err = server
        .accept_epoch(&bundle)
        .expect_err("acceptance must be blocked while rotation is required");
    assert!(matches!(
        accept_err,
        CityGError::InvalidInput("kbroad rotation required")
    ));
    Ok(())
}

#[test]
fn build_join_ticket_auto_rotates_kbroad_when_pending() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let gid = cityg_client::demo::DEMO_GID;
    let previous_key = server
        .ctx
        .kbroad_registry()
        .and_then(|registry| registry.get(gid.as_slice()).cloned())
        .expect("demo server should start with a KBROAD key");

    server.roster.mark_kbroad_rotation_required(gid.as_slice());

    let ticket = server.build_join_ticket(&gid)?;
    assert_eq!(server.kbroad_generation(&gid), 1);
    assert!(!server.kbroad_rotation_required(&gid));
    assert_ne!(ticket.kbroad_public, previous_key);
    assert_eq!(ticket.kbroad_generation, 1);
    Ok(())
}

#[test]
fn build_merge_ticket_auto_rotates_kbroad_when_pending() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let gid = cityg_client::demo::DEMO_GID;
    let previous_key = server
        .ctx
        .kbroad_registry()
        .and_then(|registry| registry.get(gid.as_slice()).cloned())
        .expect("demo server should start with a KBROAD key");
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;
    let leaf_id = cityg_client::demo::demo_member_leaf("alice");

    server.roster.mark_kbroad_rotation_required(gid.as_slice());

    let ticket = server.build_merge_ticket(&gid, &leaf_id)?;
    assert_eq!(server.kbroad_generation(&gid), 1);
    assert!(!server.kbroad_rotation_required(&gid));
    assert_ne!(ticket.kbroad_public, previous_key);
    assert_eq!(ticket.kbroad_generation, 1);
    Ok(())
}
