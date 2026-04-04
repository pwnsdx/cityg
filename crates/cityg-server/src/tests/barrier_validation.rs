use super::*;
use crate::{
    BarrierUpdateWire, COVER_LEAF_INDEX_ALREADY_ALLOCATED_ERR, GroupState, KemTreeCoverPayloadWire,
    build_all_blank_pk_entries, compute_barrier_tree_hash, compute_revocation_roots_hash, demo,
    ensure_join_cover_leaf_indices_available, to_cbor_vec, validate_barrier_update_against_roster,
};
use ciborium::value::{Integer, Value};

#[test]
fn validate_barrier_update_rejects_genesis_update_without_snapshot_artifact()
-> Result<(), CityGError> {
    let mut state = GroupState {
        n_max: 1,
        barrier_initialized: true,
        barrier_version: 0,
        ..GroupState::default()
    };
    state.barrier_pk_entries = build_all_blank_pk_entries(state.n_max)?;
    state.kem_tree_hash_after =
        compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;
    state.barrier_roots_hash = compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;

    let barrier_update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        0,
        0,
        state.n_max,
        state.barrier_roots_hash.to_vec(),
        state.kem_tree_hash_after.to_vec(),
        state.kem_tree_hash_after.to_vec(),
        to_cbor_vec(&KemTreeCoverPayloadWire(
            0,
            0,
            vec![0],
            None,
            Vec::new(),
            Vec::new(),
        ))?,
    );

    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(to_cbor_vec(&barrier_update)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );
    header.insert(112, Value::Bytes(vec![0u8; 32]));
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));

    let err = match validate_barrier_update_against_roster(
        &state,
        &header,
        &cityg_client::MembershipDelta::default(),
    ) {
        Ok(_) => {
            return Err(CityGError::InvalidInput(
                "genesis barrier update without snapshot artifact must freeze",
            ));
        }
        Err(err) => err,
    };
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_GENESIS_REQUIRED.code
                && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_GENESIS_REQUIRED.reason
    ));
    Ok(())
}

#[test]
fn accept_epoch_rejects_join_without_barrier_leaf_pk() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let mut bundle = cityg_client::demo::demo_bundle("alice")?;
    bundle.header_map.remove(&hdr::HDR_BARRIER_LEAF_PK);

    let err = server
        .accept_epoch(&bundle)
        .expect_err("join without barrier leaf key must be rejected");
    assert!(
        matches!(err, CityGError::InvalidInput(message) if message.contains("barrier_leaf_pk"))
            || matches!(
                err,
                CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Msphf(
                    msphf_core::MsphfError::InvalidInput(ref message)
                )) if message.contains("anchor_hdr_ctx mismatch")
            )
            || matches!(
                err,
                CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(code))
                    if code.code == 9071
            ),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn join_cover_leaf_index_guard_rejects_colliding_cover_index() -> Result<(), CityGError> {
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
    let err = ensure_join_cover_leaf_indices_available(&state, &[colliding_leaf])
        .expect_err("colliding join must be rejected");
    assert!(
        matches!(
            err,
            CityGError::InvalidInput(COVER_LEAF_INDEX_ALREADY_ALLOCATED_ERR)
        ),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn accepted_barrier_state_is_mirrored_to_roster() -> Result<(), CityGError> {
    let mut server = demo::demo_server();
    let bundle = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&bundle)?;

    let gid = cityg_client::demo::DEMO_GID.as_slice();
    let ctx_state = server
        .ctx
        .barrier_group_state(gid)
        .ok_or(CityGError::InvalidInput("context barrier state missing"))?
        .clone();
    let roster_state = server
        .roster
        .groups
        .get(gid)
        .ok_or(CityGError::InvalidInput("roster group missing"))?;

    assert_eq!(
        roster_state.barrier_initialized,
        ctx_state.barrier_initialized
    );
    assert_eq!(roster_state.barrier_version, ctx_state.barrier_version);
    assert_eq!(
        roster_state.barrier_roots_hash,
        ctx_state.barrier_roots_hash
    );
    assert_eq!(
        roster_state.kem_tree_hash_after,
        ctx_state.kem_tree_hash_after
    );
    assert_eq!(roster_state.n_max, ctx_state.n_max);
    assert_eq!(
        roster_state.last_pcs_refresh_ec,
        ctx_state.last_pcs_refresh_ec
    );
    assert_eq!(
        roster_state.pcs_refresh_min_delta_device_ec,
        ctx_state.pcs_refresh_min_delta_device_ec
    );
    assert_eq!(
        roster_state.pcs_refresh_min_delta_group_ec,
        ctx_state.pcs_refresh_min_delta_group_ec
    );
    assert_eq!(
        roster_state.pcs_refresh_slot_width_ec,
        ctx_state.pcs_refresh_slot_width_ec
    );
    Ok(())
}
