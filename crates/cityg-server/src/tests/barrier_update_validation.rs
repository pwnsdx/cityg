use super::*;

#[test]
fn validate_barrier_update_accepts_expected_pairs_and_pkhash_binding() -> Result<(), CityGError> {
    let mut state = super::GroupState {
        n_max: 4,
        ..super::GroupState::default()
    };
    state.barrier_initialized = true;
    state.barrier_version = 1;
    state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
    let leaf = cityg_client::demo::demo_member_leaf("barrier-expected-pairs");
    let pop_pk = vec![0xAB; 32];
    state.leaf_device_pk.insert(leaf, pop_pk.clone());
    let join_finalize_auth_token = install_pending_join_finalize_auth(&mut state, leaf)?;
    let join_ek = vec![0xA5; 1184];
    let delta = cityg_client::MembershipDelta {
        joined: vec![leaf],
        revoked: Vec::new(),
    };
    let updater_slot_index = super::slot_index_for_leaf(&leaf, state.n_max);
    let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
        .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
    let leaf_node = leaf_base
        + usize::try_from(updater_slot_index)
            .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
    let sibling_node = super::sibling_node(leaf_node)
        .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
    let parent_node = (leaf_node - 1) / 2;
    let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];

    let target_ek = vec![0x91; 1184];
    state.barrier_pk_entries[sibling_node] = target_ek.clone();
    state.kem_tree_hash_after =
        super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

    let mut snapshot_pre = state.barrier_pk_entries.clone();
    snapshot_pre[leaf_node] = join_ek.clone();
    super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
    let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

    let mut snapshot_post = snapshot_pre.clone();
    let ek_root = vec![0x11; 1184];
    let ek_parent = vec![0x22; 1184];
    snapshot_post[0] = ek_root.clone();
    snapshot_post[parent_node] = ek_parent.clone();
    let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

    let target_pkhash = super::compute_barrier_pkhash(target_ek.as_slice())?;
    let cover_payload = super::KemTreeCoverPayloadWire(
        u64::from(updater_slot_index),
        0,
        path_nodes,
        None,
        vec![super::NodeCiphertextWire(
            parent_node as u64,
            sibling_node as u64,
            target_pkhash[..16].to_vec(),
            vec![0x33; 1088],
            vec![0x44; 48],
        )],
        vec![
            super::NewPublicKeyWire(0, ek_root),
            super::NewPublicKeyWire(parent_node as u64, ek_parent),
        ],
    );
    let cover_payload_bytes = super::to_cbor_vec(&cover_payload)?;

    let revoked_since = [0u8; 32];
    let revoked_root = [0u8; 32];
    let revocation_roots_hash =
        super::compute_revocation_roots_hash(&revoked_since, &revoked_root)?;
    state.barrier_roots_hash = revocation_roots_hash;
    let barrier_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        2,
        1,
        state.n_max,
        revocation_roots_hash.to_vec(),
        kem_before.to_vec(),
        kem_after.to_vec(),
        cover_payload_bytes,
    );

    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&barrier_update)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(2u64)),
    );
    header.insert(112, Value::Bytes(revoked_since.to_vec()));
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));
    header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));
    header.insert(
        hdr::HDR_JOIN_FINALIZE_AUTH,
        Value::Bytes(join_finalize_auth_token.to_vec()),
    );

    let validation = super::validate_barrier_update_against_roster(&state, &header, &delta)?
        .ok_or(CityGError::InvalidInput("missing parsed barrier update"))?;
    assert_eq!(validation.parsed.tree_size, state.n_max);
    assert_eq!(validation.parsed.kem_tree_hash_before, kem_before);
    assert_eq!(validation.parsed.kem_tree_hash_after, kem_after);
    assert_eq!(validation.snapshot_post, snapshot_post);
    Ok(())
}

#[test]
fn validate_barrier_update_rejects_pcs_refresh_reason_for_unresolved_joiner()
-> Result<(), CityGError> {
    let mut state = super::GroupState {
        n_max: 4,
        ..super::GroupState::default()
    };
    state.barrier_initialized = true;
    state.barrier_version = 1;
    state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
    let leaf = cityg_client::demo::demo_member_leaf("barrier-join-finalize-must-use-reason2");
    let pop_pk = vec![0xAC; 32];
    state.leaf_device_pk.insert(leaf, pop_pk.clone());
    let _join_finalize_auth_token = install_pending_join_finalize_auth(&mut state, leaf)?;
    let join_ek = vec![0xA5; 1184];
    let delta = cityg_client::MembershipDelta {
        joined: vec![leaf],
        revoked: Vec::new(),
    };
    let updater_slot_index = super::slot_index_for_leaf(&leaf, state.n_max);
    let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
        .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
    let leaf_node = leaf_base
        + usize::try_from(updater_slot_index)
            .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
    let sibling_node = super::sibling_node(leaf_node)
        .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
    let parent_node = (leaf_node - 1) / 2;
    let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];

    let target_ek = vec![0x91; 1184];
    state.barrier_pk_entries[sibling_node] = target_ek.clone();
    state.kem_tree_hash_after =
        super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

    let mut snapshot_pre = state.barrier_pk_entries.clone();
    snapshot_pre[leaf_node] = join_ek.clone();
    super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
    let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

    let mut snapshot_post = snapshot_pre.clone();
    let ek_root = vec![0x11; 1184];
    let ek_parent = vec![0x22; 1184];
    snapshot_post[0] = ek_root.clone();
    snapshot_post[parent_node] = ek_parent.clone();
    let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

    let target_pkhash = super::compute_barrier_pkhash(target_ek.as_slice())?;
    let cover_payload = super::KemTreeCoverPayloadWire(
        u64::from(updater_slot_index),
        0,
        path_nodes,
        None,
        vec![super::NodeCiphertextWire(
            parent_node as u64,
            sibling_node as u64,
            target_pkhash[..16].to_vec(),
            vec![0x33; 1088],
            vec![0x44; 48],
        )],
        vec![
            super::NewPublicKeyWire(0, ek_root),
            super::NewPublicKeyWire(parent_node as u64, ek_parent),
        ],
    );
    let barrier_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        2,
        1,
        state.n_max,
        super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?.to_vec(),
        kem_before.to_vec(),
        kem_after.to_vec(),
        super::to_cbor_vec(&cover_payload)?,
    );
    state.barrier_roots_hash = super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;

    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&barrier_update)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );
    header.insert(112, Value::Bytes(vec![0u8; 32]));
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));
    header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));
    header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));

    let err = super::validate_barrier_update_against_roster(&state, &header, &delta)
        .err()
        .ok_or(CityGError::InvalidInput(
            "reason 1 must be rejected for an unresolved joiner",
        ))?;
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_PROACTIVE_FORBIDDEN.code
                && freeze.reason
                    == msphf_orchestrator::FREEZE_BARRIER_PROACTIVE_FORBIDDEN.reason
    ));
    Ok(())
}

#[test]
fn validate_barrier_update_rejects_join_finalize_reason_for_non_joiner() -> Result<(), CityGError> {
    let mut state = super::GroupState {
        n_max: 4,
        ..super::GroupState::default()
    };
    state.barrier_initialized = true;
    state.barrier_version = 1;
    state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
    let leaf = cityg_client::demo::demo_member_leaf("barrier-join-finalize-non-joiner");
    let pop_pk = vec![0xAE; 32];
    let leaf_ek = vec![0xA5; 1184];
    state.leaf_device_pk.insert(leaf, pop_pk.clone());
    install_active_fixture_lease(&mut state, leaf)?;

    let slot_index = super::slot_index_for_leaf(&leaf, state.n_max);
    let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
        .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
    let leaf_node = leaf_base
        + usize::try_from(slot_index)
            .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
    let sibling_node = super::sibling_node(leaf_node)
        .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
    let parent_node = (leaf_node - 1) / 2;
    let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];

    state.barrier_pk_entries[leaf_node] = leaf_ek.clone();
    let target_ek = vec![0x91; 1184];
    state.barrier_pk_entries[sibling_node] = target_ek.clone();
    state.kem_tree_hash_after =
        super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

    let mut snapshot_pre = state.barrier_pk_entries.clone();
    super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
    let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

    let mut snapshot_post = snapshot_pre.clone();
    let ek_root = vec![0x19; 1184];
    let ek_parent = vec![0x2A; 1184];
    snapshot_post[0] = ek_root.clone();
    snapshot_post[parent_node] = ek_parent.clone();
    let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

    let target_pkhash = super::compute_barrier_pkhash(target_ek.as_slice())?;
    let cover_payload = super::KemTreeCoverPayloadWire(
        u64::from(slot_index),
        0,
        path_nodes,
        None,
        vec![super::NodeCiphertextWire(
            parent_node as u64,
            sibling_node as u64,
            target_pkhash[..16].to_vec(),
            vec![0x33; 1088],
            vec![0x44; 48],
        )],
        vec![
            super::NewPublicKeyWire(0, ek_root),
            super::NewPublicKeyWire(parent_node as u64, ek_parent),
        ],
    );
    let barrier_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        2,
        1,
        state.n_max,
        super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?.to_vec(),
        kem_before.to_vec(),
        kem_after.to_vec(),
        super::to_cbor_vec(&cover_payload)?,
    );
    state.barrier_roots_hash = super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;

    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&barrier_update)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(2u64)),
    );
    header.insert(112, Value::Bytes(vec![0u8; 32]));
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));
    header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(leaf_ek));
    header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));

    let err = super::validate_barrier_update_against_roster(
        &state,
        &header,
        &cityg_client::MembershipDelta {
            joined: Vec::new(),
            revoked: Vec::new(),
        },
    )
    .err()
    .ok_or(CityGError::InvalidInput(
        "reason 2 must be rejected for an updater outside the unresolved JoinSet",
    ))?;
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_PROACTIVE_FORBIDDEN.code
                && freeze.reason
                    == msphf_orchestrator::FREEZE_BARRIER_PROACTIVE_FORBIDDEN.reason
    ));
    Ok(())
}

#[test]
fn validate_barrier_update_rejects_target_pkhash_mismatch() -> Result<(), CityGError> {
    let mut state = super::GroupState {
        n_max: 4,
        ..super::GroupState::default()
    };
    state.barrier_initialized = true;
    state.barrier_version = 1;
    state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
    let leaf = cityg_client::demo::demo_member_leaf("barrier-target-pkhash-mismatch");
    let pop_pk = vec![0xAD; 32];
    state.leaf_device_pk.insert(leaf, pop_pk.clone());
    let join_finalize_auth_token = install_pending_join_finalize_auth(&mut state, leaf)?;
    let join_ek = vec![0xA5; 1184];
    let delta = cityg_client::MembershipDelta {
        joined: vec![leaf],
        revoked: Vec::new(),
    };
    let updater_slot_index = super::slot_index_for_leaf(&leaf, state.n_max);
    let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
        .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
    let leaf_node = leaf_base
        + usize::try_from(updater_slot_index)
            .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
    let sibling_node = super::sibling_node(leaf_node)
        .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
    let parent_node = (leaf_node - 1) / 2;
    let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];

    let target_ek = vec![0x91; 1184];
    state.barrier_pk_entries[sibling_node] = target_ek;
    state.kem_tree_hash_after =
        super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

    let mut snapshot_pre = state.barrier_pk_entries.clone();
    snapshot_pre[leaf_node] = join_ek.clone();
    super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
    let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

    let mut snapshot_post = snapshot_pre.clone();
    snapshot_post[0] = vec![0x11; 1184];
    snapshot_post[parent_node] = vec![0x22; 1184];
    let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

    let cover_payload = super::KemTreeCoverPayloadWire(
        u64::from(updater_slot_index),
        0,
        path_nodes,
        None,
        vec![super::NodeCiphertextWire(
            parent_node as u64,
            sibling_node as u64,
            vec![0xFF; 16],
            vec![0x33; 1088],
            vec![0x44; 48],
        )],
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(parent_node as u64, vec![0x22; 1184]),
        ],
    );
    let barrier_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        2,
        1,
        state.n_max,
        super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?.to_vec(),
        kem_before.to_vec(),
        kem_after.to_vec(),
        super::to_cbor_vec(&cover_payload)?,
    );
    state.barrier_roots_hash = super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;

    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&barrier_update)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(2u64)),
    );
    header.insert(112, Value::Bytes(vec![0u8; 32]));
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));
    header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));
    header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));
    header.insert(
        hdr::HDR_JOIN_FINALIZE_AUTH,
        Value::Bytes(join_finalize_auth_token.to_vec()),
    );

    let err = match super::validate_barrier_update_against_roster(&state, &header, &delta) {
        Ok(_) => {
            return Err(CityGError::InvalidInput(
                "target pkhash mismatch must be rejected",
            ));
        }
        Err(err) => err,
    };
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_EXPECTEDPAIRS_FAILURE.code
                && freeze.reason
                    == msphf_orchestrator::FREEZE_BARRIER_EXPECTEDPAIRS_FAILURE.reason
    ));
    Ok(())
}

#[test]
fn validate_barrier_update_rejects_expected_pairs_mismatch() -> Result<(), CityGError> {
    let mut state = super::GroupState::default();
    state.n_max = 4;
    state.barrier_initialized = true;
    state.barrier_version = 1;
    state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;

    let leaf = cityg_client::demo::demo_member_leaf("barrier-pairs-mismatch");
    let pop_pk = vec![0xBC; 32];
    state.leaf_device_pk.insert(leaf, pop_pk.clone());
    let join_finalize_auth_token = install_pending_join_finalize_auth(&mut state, leaf)?;
    let join_ek = vec![0xA5; 1184];
    let delta = cityg_client::MembershipDelta {
        joined: vec![leaf],
        revoked: Vec::new(),
    };
    let updater_slot_index = super::slot_index_for_leaf(&leaf, state.n_max);
    let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
        .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
    let leaf_node = leaf_base
        + usize::try_from(updater_slot_index)
            .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
    let sibling_node = super::sibling_node(leaf_node)
        .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
    let parent_node = (leaf_node - 1) / 2;
    let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];
    state.barrier_pk_entries[sibling_node] = vec![0x91; 1184];

    let mut snapshot_pre = state.barrier_pk_entries.clone();
    snapshot_pre[leaf_node] = join_ek.clone();
    super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
    let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

    let mut snapshot_post = snapshot_pre.clone();
    snapshot_post[0] = vec![0x11; 1184];
    snapshot_post[parent_node] = vec![0x22; 1184];
    let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

    let revoked_since = [0u8; 32];
    let revoked_root = [0u8; 32];
    let revocation_roots_hash =
        super::compute_revocation_roots_hash(&revoked_since, &revoked_root)?;
    state.barrier_roots_hash = revocation_roots_hash;
    let cover_payload = super::KemTreeCoverPayloadWire(
        u64::from(updater_slot_index),
        0,
        path_nodes,
        None,
        vec![super::NodeCiphertextWire(
            parent_node as u64,
            leaf_node as u64,
            vec![0x55; 16],
            vec![0x66; 1088],
            vec![0x77; 48],
        )],
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(parent_node as u64, vec![0x22; 1184]),
        ],
    );
    let barrier_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        2,
        1,
        state.n_max,
        revocation_roots_hash.to_vec(),
        kem_before.to_vec(),
        kem_after.to_vec(),
        super::to_cbor_vec(&cover_payload)?,
    );

    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&barrier_update)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(2u64)),
    );
    header.insert(112, Value::Bytes(revoked_since.to_vec()));
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));
    header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));
    header.insert(
        hdr::HDR_JOIN_FINALIZE_AUTH,
        Value::Bytes(join_finalize_auth_token.to_vec()),
    );

    let err = match super::validate_barrier_update_against_roster(&state, &header, &delta) {
        Ok(_) => {
            return Err(CityGError::InvalidInput(
                "mismatched ExpectedPairs must be rejected",
            ));
        }
        Err(err) => err,
    };
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_EXPECTEDPAIRS_FAILURE.code
                && freeze.reason
                    == msphf_orchestrator::FREEZE_BARRIER_EXPECTEDPAIRS_FAILURE.reason
    ));
    Ok(())
}

#[test]
fn validate_barrier_update_rejects_updater_identity_mismatch() -> Result<(), CityGError> {
    let mut state = super::GroupState {
        n_max: 4,
        ..super::GroupState::default()
    };
    state.barrier_initialized = true;
    state.barrier_version = 1;
    state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
    let leaf = cityg_client::demo::demo_member_leaf("barrier-updater-mismatch");
    let mapped_pop_pk = vec![0xA1; 32];
    let header_pop_pk = vec![0xA2; 32];
    state.leaf_device_pk.insert(leaf, mapped_pop_pk);
    let _join_finalize_auth_token = install_pending_join_finalize_auth(&mut state, leaf)?;
    let join_ek = vec![0xA5; 1184];
    let delta = cityg_client::MembershipDelta {
        joined: vec![leaf],
        revoked: Vec::new(),
    };
    let updater_slot_index = super::slot_index_for_leaf(&leaf, state.n_max);
    let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
        .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
    let leaf_node = leaf_base
        + usize::try_from(updater_slot_index)
            .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
    let sibling_node = super::sibling_node(leaf_node)
        .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
    let parent_node = (leaf_node - 1) / 2;
    let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];

    let target_ek = vec![0x91; 1184];
    state.barrier_pk_entries[sibling_node] = target_ek.clone();
    state.kem_tree_hash_after =
        super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

    let mut snapshot_pre = state.barrier_pk_entries.clone();
    snapshot_pre[leaf_node] = join_ek.clone();
    super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
    let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

    let mut snapshot_post = snapshot_pre.clone();
    let ek_root = vec![0x11; 1184];
    let ek_parent = vec![0x22; 1184];
    snapshot_post[0] = ek_root.clone();
    snapshot_post[parent_node] = ek_parent.clone();
    let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

    let target_pkhash = super::compute_barrier_pkhash(target_ek.as_slice())?;
    let cover_payload = super::KemTreeCoverPayloadWire(
        u64::from(updater_slot_index),
        0,
        path_nodes,
        None,
        vec![super::NodeCiphertextWire(
            parent_node as u64,
            sibling_node as u64,
            target_pkhash[..16].to_vec(),
            vec![0x33; 1088],
            vec![0x44; 48],
        )],
        vec![
            super::NewPublicKeyWire(0, ek_root),
            super::NewPublicKeyWire(parent_node as u64, ek_parent),
        ],
    );
    let cover_payload_bytes = super::to_cbor_vec(&cover_payload)?;

    let revoked_since = [0u8; 32];
    let revoked_root = [0u8; 32];
    let revocation_roots_hash =
        super::compute_revocation_roots_hash(&revoked_since, &revoked_root)?;
    let barrier_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        2,
        1,
        state.n_max,
        revocation_roots_hash.to_vec(),
        kem_before.to_vec(),
        kem_after.to_vec(),
        cover_payload_bytes,
    );

    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&barrier_update)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(2u64)),
    );
    header.insert(112, Value::Bytes(revoked_since.to_vec()));
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));
    header.insert(hdr::HDR_POP_PK, Value::Bytes(header_pop_pk));

    let err = super::validate_barrier_update_against_roster(&state, &header, &delta)
        .err()
        .ok_or(CityGError::InvalidInput(
            "updater identity mismatch must be rejected",
        ))?;
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
    ));
    Ok(())
}

#[test]
fn validate_barrier_update_rejects_missing_author_pop_pk() -> Result<(), CityGError> {
    let mut state = super::GroupState {
        n_max: 4,
        ..super::GroupState::default()
    };
    state.barrier_initialized = true;
    state.barrier_version = 1;
    state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
    let leaf = cityg_client::demo::demo_member_leaf("barrier-missing-pop");
    let mapped_pop_pk = vec![0xA1; 32];
    state.leaf_device_pk.insert(leaf, mapped_pop_pk);
    let _join_finalize_auth_token = install_pending_join_finalize_auth(&mut state, leaf)?;
    let join_ek = vec![0xA5; 1184];
    let delta = cityg_client::MembershipDelta {
        joined: vec![leaf],
        revoked: Vec::new(),
    };
    let updater_slot_index = super::slot_index_for_leaf(&leaf, state.n_max);
    let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
        .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
    let leaf_node = leaf_base
        + usize::try_from(updater_slot_index)
            .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
    let sibling_node = super::sibling_node(leaf_node)
        .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
    let parent_node = (leaf_node - 1) / 2;
    let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];

    let target_ek = vec![0x91; 1184];
    state.barrier_pk_entries[sibling_node] = target_ek.clone();
    state.kem_tree_hash_after =
        super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

    let mut snapshot_pre = state.barrier_pk_entries.clone();
    snapshot_pre[leaf_node] = join_ek.clone();
    super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
    let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

    let mut snapshot_post = snapshot_pre.clone();
    let ek_root = vec![0x11; 1184];
    let ek_parent = vec![0x22; 1184];
    snapshot_post[0] = ek_root.clone();
    snapshot_post[parent_node] = ek_parent.clone();
    let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

    let target_pkhash = super::compute_barrier_pkhash(target_ek.as_slice())?;
    let cover_payload = super::KemTreeCoverPayloadWire(
        u64::from(updater_slot_index),
        0,
        path_nodes,
        None,
        vec![super::NodeCiphertextWire(
            parent_node as u64,
            sibling_node as u64,
            target_pkhash[..16].to_vec(),
            vec![0x33; 1088],
            vec![0x44; 48],
        )],
        vec![
            super::NewPublicKeyWire(0, ek_root),
            super::NewPublicKeyWire(parent_node as u64, ek_parent),
        ],
    );
    let barrier_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        2,
        1,
        state.n_max,
        super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?.to_vec(),
        kem_before.to_vec(),
        kem_after.to_vec(),
        super::to_cbor_vec(&cover_payload)?,
    );

    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&barrier_update)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(2u64)),
    );
    header.insert(112, Value::Bytes(vec![0u8; 32]));
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));
    header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));

    let err = match super::validate_barrier_update_against_roster(&state, &header, &delta) {
        Ok(_) => return Err(CityGError::InvalidInput("missing author pop key must fail")),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
    ));
    Ok(())
}

#[test]
fn validate_barrier_update_rejects_oversized_bytes() -> Result<(), CityGError> {
    let state = super::GroupState {
        max_barrier_update_bytes: 8,
        ..super::GroupState::default()
    };
    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(vec![0xAA; 9]));
    let delta = cityg_client::MembershipDelta {
        joined: Vec::new(),
        revoked: Vec::new(),
    };

    let err = super::validate_barrier_update_against_roster(&state, &header, &delta)
        .err()
        .ok_or(CityGError::InvalidInput(
            "oversized barrier_update must be rejected",
        ))?;
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.code
                && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.reason
    ));
    Ok(())
}

#[test]
fn validate_barrier_update_detects_hash_and_roots_mismatches() -> Result<(), CityGError> {
    let mut state = super::GroupState {
        n_max: 4,
        barrier_initialized: false,
        barrier_version: 0,
        ..super::GroupState::default()
    };

    let leaf = cityg_client::demo::demo_member_leaf("barrier-mismatch-matrix");
    let pop_pk = vec![0xDE; 32];
    state.leaf_device_pk.insert(leaf, pop_pk.clone());
    let leaf_ek = vec![0x33; 1184];
    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![leaf],
        revoked: Vec::new(),
    });
    let root = msphf_core::merkle::canonical_set_root(&[leaf])?;
    state.snapshots.insert(root, membership);
    state.latest_root = Some(root);
    state.leaf_barrier_public.insert(leaf, leaf_ek.clone());
    install_active_fixture_lease(&mut state, leaf)?;

    let updater_slot_index = u64::from(super::slot_index_for_leaf(&leaf, state.n_max));
    let leaf_node = state.n_max.saturating_sub(1) + updater_slot_index;
    let parent_node = (leaf_node - 1) / 2;
    let path_nodes = vec![leaf_node, parent_node, 0];
    let mut snapshot_pre = super::build_all_blank_pk_entries(state.n_max)?;
    snapshot_pre[usize::try_from(leaf_node).unwrap_or(0)] = leaf_ek;
    super::blank_internal_path_from_leaf(
        snapshot_pre.as_mut_slice(),
        usize::try_from(leaf_node).unwrap_or(0),
    );
    let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;
    let mut snapshot_post = snapshot_pre.clone();
    snapshot_post[0] = vec![0x11; 1184];
    snapshot_post[usize::try_from(parent_node).unwrap_or(0)] = vec![0x22; 1184];
    let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

    let revoked_since = [0u8; 32];
    let revoked_root = [0u8; 32];
    let rrh = super::compute_revocation_roots_hash(&revoked_since, &revoked_root)?;
    let cover_payload = super::KemTreeCoverPayloadWire(
        updater_slot_index,
        0,
        path_nodes,
        None,
        Vec::new(),
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(parent_node, vec![0x22; 1184]),
        ],
    );
    let cover_payload_bytes = super::to_cbor_vec(&cover_payload)?;

    let mut header = BTreeMap::new();
    header.insert(112, Value::Bytes(revoked_since.to_vec()));
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));

    let before_bad = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        0,
        0,
        state.n_max,
        rrh.to_vec(),
        vec![0x99; 32],
        kem_after.to_vec(),
        cover_payload_bytes.clone(),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&before_bad)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );
    let err = super::validate_barrier_update_against_roster(
        &state,
        &header,
        &cityg_client::MembershipDelta {
            joined: Vec::new(),
            revoked: Vec::new(),
        },
    )
    .err()
    .ok_or(CityGError::InvalidInput(
        "bad kem_tree_hash_before must fail",
    ))?;
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE.code
                && freeze.reason
                    == msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE.reason
    ));

    let roots_bad = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        0,
        0,
        state.n_max,
        vec![0x88; 32],
        kem_before.to_vec(),
        kem_after.to_vec(),
        cover_payload_bytes.clone(),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&roots_bad)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );
    let err = super::validate_barrier_update_against_roster(
        &state,
        &header,
        &cityg_client::MembershipDelta {
            joined: Vec::new(),
            revoked: Vec::new(),
        },
    )
    .err()
    .ok_or(CityGError::InvalidInput(
        "bad revocation_roots_hash must fail",
    ))?;
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.code
                && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.reason
    ));

    let valid_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        0,
        0,
        state.n_max,
        rrh.to_vec(),
        kem_before.to_vec(),
        kem_after.to_vec(),
        cover_payload_bytes.clone(),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&valid_update)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );
    let validation = super::validate_barrier_update_against_roster(
        &state,
        &header,
        &cityg_client::MembershipDelta {
            joined: Vec::new(),
            revoked: Vec::new(),
        },
    )?
    .ok_or(CityGError::InvalidInput(
        "valid barrier update should be accepted",
    ))?;
    assert_eq!(validation.snapshot_post, snapshot_post);
    assert!(
        validation.hash_cache_post.is_some(),
        "non-empty public-key updates should populate a hash cache"
    );
    header.insert(112, Value::Bytes(vec![0xAA; 31]));
    let err = super::validate_barrier_update_against_roster(
        &state,
        &header,
        &cityg_client::MembershipDelta {
            joined: Vec::new(),
            revoked: Vec::new(),
        },
    )
    .err()
    .ok_or(CityGError::InvalidInput(
        "invalid revocation roots header shape must fail",
    ))?;
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.code
                && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.reason
    ));
    header.insert(112, Value::Bytes(revoked_since.to_vec()));

    let after_bad = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        0,
        0,
        state.n_max,
        rrh.to_vec(),
        kem_before.to_vec(),
        vec![0x77; 32],
        cover_payload_bytes,
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&after_bad)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );
    let err = super::validate_barrier_update_against_roster(
        &state,
        &header,
        &cityg_client::MembershipDelta {
            joined: Vec::new(),
            revoked: Vec::new(),
        },
    )
    .err()
    .ok_or(CityGError::InvalidInput(
        "bad kem_tree_hash_after must fail",
    ))?;
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE.code
                && freeze.reason
                    == msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE.reason
    ));

    let mut singleton_state = super::GroupState {
        n_max: 1,
        barrier_initialized: false,
        barrier_version: 0,
        ..super::GroupState::default()
    };
    let singleton_leaf = cityg_client::demo::demo_member_leaf("barrier-singleton-empty");
    let singleton_pop_pk = vec![0xC4; 32];
    singleton_state
        .leaf_device_pk
        .insert(singleton_leaf, singleton_pop_pk.clone());
    let singleton_leaf_ek = vec![0x55; 1184];
    let mut singleton_membership = cityg_client::GroupMembership::default();
    singleton_membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![singleton_leaf],
        revoked: Vec::new(),
    });
    let singleton_root = msphf_core::merkle::canonical_set_root(&[singleton_leaf])?;
    singleton_state
        .snapshots
        .insert(singleton_root, singleton_membership);
    singleton_state.latest_root = Some(singleton_root);
    singleton_state
        .leaf_barrier_public
        .insert(singleton_leaf, singleton_leaf_ek.clone());
    install_active_fixture_lease(&mut singleton_state, singleton_leaf)?;

    let singleton_snapshot = vec![singleton_leaf_ek];
    let singleton_hash =
        super::compute_barrier_tree_hash(singleton_state.n_max, singleton_snapshot.as_slice())?;
    let singleton_rrh = super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;
    let singleton_cover =
        super::KemTreeCoverPayloadWire(0, 0, vec![0], None, Vec::new(), Vec::new());
    let singleton_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        0,
        0,
        singleton_state.n_max,
        singleton_rrh.to_vec(),
        singleton_hash.to_vec(),
        singleton_hash.to_vec(),
        super::to_cbor_vec(&singleton_cover)?,
    );
    let mut singleton_header = BTreeMap::new();
    singleton_header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&singleton_update)?),
    );
    singleton_header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );
    singleton_header.insert(112, Value::Bytes(vec![0u8; 32]));
    singleton_header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));
    singleton_header.insert(hdr::HDR_POP_PK, Value::Bytes(singleton_pop_pk));
    let singleton_validation = super::validate_barrier_update_against_roster(
        &singleton_state,
        &singleton_header,
        &cityg_client::MembershipDelta {
            joined: Vec::new(),
            revoked: Vec::new(),
        },
    )?
    .ok_or(CityGError::InvalidInput(
        "singleton barrier update without public-key changes should be accepted",
    ))?;
    assert!(singleton_validation.parsed.new_public_keys.is_empty());
    assert_eq!(singleton_validation.snapshot_post, singleton_snapshot);
    assert!(
        singleton_validation.hash_cache_post.is_none(),
        "empty update should reuse the prior cache instead of building a new one"
    );
    Ok(())
}

/// Two active members (A at slot 0, B at slot 1) in a 4-slot tree, and a
/// reason-0 barrier update authored by `author` that revokes `revoked`.
/// Only A's path is regenerated, so the update is valid whenever the policy
/// checks let it through.
struct RevocationFixture {
    state: super::GroupState,
    header: BTreeMap<u64, Value>,
    delta: cityg_client::MembershipDelta,
    alice: [u8; 32],
    bob: [u8; 32],
    alice_pop_pk: Vec<u8>,
    bob_pop_pk: Vec<u8>,
}

fn revocation_fixture(
    author_is_bob: bool,
    revoke_alice: bool,
) -> Result<RevocationFixture, CityGError> {
    let mut state = super::GroupState {
        n_max: 4,
        ..super::GroupState::default()
    };
    state.barrier_initialized = true;
    state.barrier_version = 3;
    let alice = [0xA1; 32];
    let bob = [0xB2; 32];
    let alice_pop_pk = vec![0xAA; 32];
    let bob_pop_pk = vec![0xBB; 32];
    let alice_lease = SlotLease {
        slot_index: 0,
        slot_generation: 0,
    };
    let bob_lease = SlotLease {
        slot_index: 1,
        slot_generation: 0,
    };
    state.ensure_slot_allocator_initialized();
    state.free_slots.remove(&0);
    state.free_slots.remove(&1);
    state.activate_slot_lease(alice, alice_lease)?;
    state.activate_slot_lease(bob, bob_lease)?;
    state.leaf_device_pk.insert(alice, alice_pop_pk.clone());
    state.leaf_device_pk.insert(bob, bob_pop_pk.clone());
    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![alice, bob],
        revoked: Vec::new(),
    });
    let root = msphf_core::merkle::canonical_set_root(&[alice, bob])?;
    state.snapshots.insert(root, membership);
    state.latest_root = Some(root);

    // Committed tree before the update: both leaves and their common path.
    let alice_ek = vec![0x31; 1184];
    let bob_ek = vec![0x32; 1184];
    let mut entries = super::build_all_blank_pk_entries(state.n_max)?;
    entries[3] = alice_ek.clone();
    entries[4] = bob_ek.clone();
    entries[1] = vec![0x41; 1184];
    entries[0] = vec![0x40; 1184];
    state.barrier_pk_entries = entries.clone();
    state.leaf_barrier_public.insert(alice, alice_ek);
    state.leaf_barrier_public.insert(bob, bob_ek);
    state.kem_tree_hash_after =
        super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;
    state.barrier_roots_hash = super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;

    let (author_leaf_node, revoked_leaf_node, author_pop_pk, revoked) = if author_is_bob {
        (
            4u64,
            3usize,
            bob_pop_pk.clone(),
            if revoke_alice { alice } else { bob },
        )
    } else {
        (
            3u64,
            4usize,
            alice_pop_pk.clone(),
            if revoke_alice { alice } else { bob },
        )
    };
    let revoked_node = if revoked == alice { 3usize } else { 4usize };
    let _ = revoked_leaf_node;

    // Snapshot the update is built against: revoked leaf and its path blanked.
    let mut snapshot_pre = entries;
    super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), revoked_node);
    snapshot_pre[revoked_node] = Vec::new();
    let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;
    let mut snapshot_post = snapshot_pre;
    snapshot_post[1] = vec![0x51; 1184];
    snapshot_post[0] = vec![0x50; 1184];
    let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

    let revoked_since = [0x5E; 32];
    let revoked_root = [0x5F; 32];
    let rrh = super::compute_revocation_roots_hash(&revoked_since, &revoked_root)?;
    let updater_slot_index = author_leaf_node - 3;
    let cover_payload = super::KemTreeCoverPayloadWire(
        updater_slot_index,
        0,
        vec![author_leaf_node, 1, 0],
        None,
        Vec::new(),
        vec![
            super::NewPublicKeyWire(0, vec![0x50; 1184]),
            super::NewPublicKeyWire(1, vec![0x51; 1184]),
        ],
    );
    let barrier_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        4,
        3,
        state.n_max,
        rrh.to_vec(),
        kem_before.to_vec(),
        kem_after.to_vec(),
        super::to_cbor_vec(&cover_payload)?,
    );
    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&barrier_update)?),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );
    header.insert(112, Value::Bytes(revoked_since.to_vec()));
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(hdr::HDR_POP_PK, Value::Bytes(author_pop_pk));
    Ok(RevocationFixture {
        state,
        header,
        delta: cityg_client::MembershipDelta {
            joined: Vec::new(),
            revoked: vec![revoked],
        },
        alice,
        bob,
        alice_pop_pk,
        bob_pop_pk,
    })
}

fn pending_removal_for(target: [u8; 32], lease: SlotLease) -> crate::PendingRemoval {
    let proposal = cityg_client::remove_proposal::RemoveProposal {
        gid: [0x47; 32],
        target_leaf_id: target,
        target_slot_index: lease.slot_index,
        target_slot_generation: lease.slot_generation,
        not_after_ms: u64::MAX,
    };
    // Validation only checks presence; the signature is verified on submission.
    let signed = cityg_client::remove_proposal::SignedRemoveProposal {
        proposal,
        signer_public_key: vec![0u8; cityg_pqc::ML_DSA_87_PUBLIC_KEY_BYTES],
        signature: vec![0u8; cityg_pqc::ML_DSA_87_SIGNATURE_BYTES],
    };
    let encoded = signed.to_cbor().unwrap_or_default();
    crate::PendingRemoval { signed, encoded }
}

fn expect_freeze(err: CityGError, expected: msphf_orchestrator::mhw::FreezeError) {
    assert!(
        matches!(
            &err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == expected.code && freeze.reason == expected.reason
        ),
        "expected {expected:?}, got {err:?}"
    );
}

#[test]
fn validate_barrier_update_rejects_updater_revoked_by_its_own_anchor() -> Result<(), CityGError> {
    // Audit C-03: a departing member must never pick the post-revocation key.
    let mut fixture = revocation_fixture(false, true)?;
    let alice_lease = fixture.state.leaf_slot_leases[&fixture.alice];
    fixture.state.pending_removals.insert(
        fixture.alice,
        pending_removal_for(fixture.alice, alice_lease),
    );
    let err = super::validate_barrier_update_against_roster(
        &fixture.state,
        &fixture.header,
        &fixture.delta,
    )
    .err()
    .ok_or(CityGError::InvalidInput("self-revocation must be rejected"))?;
    expect_freeze(err, msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID);
    Ok(())
}

#[test]
fn validate_barrier_update_rejects_unauthorized_revocation() -> Result<(), CityGError> {
    // Alice (not an admin) revokes Bob, who never asked to leave.
    let fixture = revocation_fixture(false, false)?;
    let err = super::validate_barrier_update_against_roster(
        &fixture.state,
        &fixture.header,
        &fixture.delta,
    )
    .err()
    .ok_or(CityGError::InvalidInput(
        "revocation without admin or proposal must be rejected",
    ))?;
    expect_freeze(
        err,
        msphf_orchestrator::FREEZE_BARRIER_REVOCATION_UNAUTHORIZED,
    );
    Ok(())
}

#[test]
fn validate_barrier_update_accepts_revocation_backed_by_pending_removal() -> Result<(), CityGError>
{
    let mut fixture = revocation_fixture(false, false)?;
    let bob_lease = fixture.state.leaf_slot_leases[&fixture.bob];
    fixture
        .state
        .pending_removals
        .insert(fixture.bob, pending_removal_for(fixture.bob, bob_lease));
    let validation = super::validate_barrier_update_against_roster(
        &fixture.state,
        &fixture.header,
        &fixture.delta,
    )?
    .ok_or(CityGError::InvalidInput("expected a validated update"))?;
    assert_eq!(validation.parsed.updater_slot_index, 0);
    assert!(
        validation.snapshot_post[4].is_empty(),
        "the revoked leaf stays blank after the update"
    );
    Ok(())
}

#[test]
fn validate_barrier_update_accepts_revocation_authored_by_room_admin() -> Result<(), CityGError> {
    let mut fixture = revocation_fixture(false, false)?;
    fixture
        .state
        .room_admin_pop_keys
        .insert(fixture.alice_pop_pk.clone());
    let _ = &fixture.bob_pop_pk;
    super::validate_barrier_update_against_roster(&fixture.state, &fixture.header, &fixture.delta)?
        .ok_or(CityGError::InvalidInput("expected a validated update"))?;
    Ok(())
}

#[test]
fn validate_barrier_update_rejects_updates_leaving_pending_removals_uncommitted()
-> Result<(), CityGError> {
    // Admin Alice expels Bob while a third member's removal is pending: the
    // update must also commit that removal.
    let mut fixture = revocation_fixture(false, false)?;
    fixture
        .state
        .room_admin_pop_keys
        .insert(fixture.alice_pop_pk.clone());
    let carol = [0xC3; 32];
    fixture.state.pending_removals.insert(
        carol,
        pending_removal_for(
            carol,
            SlotLease {
                slot_index: 2,
                slot_generation: 0,
            },
        ),
    );
    let err = super::validate_barrier_update_against_roster(
        &fixture.state,
        &fixture.header,
        &fixture.delta,
    )
    .err()
    .ok_or(CityGError::InvalidInput(
        "update must commit every pending removal",
    ))?;
    expect_freeze(
        err,
        msphf_orchestrator::FREEZE_BARRIER_PENDING_REMOVALS_UNCOMMITTED,
    );

    // Replay of historical bundles skips the removal policy.
    crate::validate_barrier_update_against_roster_with_policy(
        &fixture.state,
        &fixture.header,
        &fixture.delta,
        crate::RemovalPolicy::SkipForReplay,
    )?
    .ok_or(CityGError::InvalidInput(
        "replay should validate the update",
    ))?;
    Ok(())
}
