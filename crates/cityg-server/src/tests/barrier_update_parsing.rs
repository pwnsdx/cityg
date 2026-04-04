use super::*;

#[test]
fn barrier_snapshot_helpers_cover_fallback_and_parser_paths() -> Result<(), CityGError> {
    let mut state = super::GroupState {
        n_max: 4,
        ..super::GroupState::default()
    };
    let leaf = cityg_client::demo::demo_member_leaf("barrier-snapshot-fallback");
    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![leaf],
        revoked: Vec::new(),
    });
    let root = msphf_core::merkle::canonical_set_root(&[leaf])?;
    state.snapshots.insert(root, membership);
    state.latest_root = Some(root);
    let leaf_ek = vec![0x5A; 1184];
    state.leaf_barrier_public.insert(leaf, leaf_ek.clone());

    let pk_entries = super::build_pk_entries(&state)?;
    assert_eq!(pk_entries.len(), 7);
    let leaf_index = usize::try_from(super::cover_leaf_index(&leaf, state.n_max))
        .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
    assert_eq!(pk_entries[3 + leaf_index], leaf_ek);
    let group_hash = super::compute_group_barrier_tree_hash(&state)?;
    let direct_hash = super::compute_barrier_tree_hash(state.n_max, pk_entries.as_slice())?;
    assert_eq!(group_hash, direct_hash);

    let mut header = BTreeMap::new();
    assert!(super::parse_barrier_update(&header, 4)?.is_none());

    let cover_payload = super::KemTreeCoverPayloadWire(
        0,
        0,
        vec![3, 1, 0],
        Some(vec![2, 1]),
        Vec::new(),
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(1, vec![0x22; 1184]),
        ],
    );
    let barrier_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        1,
        0,
        4,
        vec![0u8; 32],
        vec![0u8; 32],
        vec![0u8; 32],
        super::to_cbor_vec(&cover_payload)?,
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&barrier_update)?),
    );

    assert!(matches!(
        super::parse_barrier_update(&header, 3),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));
    assert!(matches!(
        super::parse_barrier_update(&header, 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let blank_snapshot = super::build_all_blank_pk_entries(4)?;
    assert!(matches!(
        build_refresh_barrier_update_bytes(0, 0, 1, 0, [0u8; 32], [0u8; 32], &[],),
        Err(CityGError::InvalidInput(
            "invalid barrier update tree parameters"
        ))
    ));
    assert!(matches!(
        build_refresh_barrier_update_bytes(
            3,
            0,
            1,
            0,
            [0u8; 32],
            [0u8; 32],
            blank_snapshot.as_slice(),
        ),
        Err(CityGError::InvalidInput(
            "invalid barrier update tree parameters"
        ))
    ));
    assert!(matches!(
        build_refresh_barrier_update_bytes(
            4,
            4,
            1,
            0,
            [0u8; 32],
            [0u8; 32],
            blank_snapshot.as_slice(),
        ),
        Err(CityGError::InvalidInput(
            "invalid barrier update tree parameters"
        ))
    ));
    assert!(matches!(
        build_refresh_barrier_update_bytes(
            4,
            0,
            1,
            0,
            [0u8; 32],
            [0u8; 32],
            &blank_snapshot[..blank_snapshot.len() - 1],
        ),
        Err(CityGError::InvalidInput("barrier snapshot size mismatch"))
    ));
    Ok(())
}

#[test]
fn validate_barrier_update_uses_genesis_snapshot_joinset() -> Result<(), CityGError> {
    let mut state = super::GroupState {
        n_max: 4,
        barrier_initialized: false,
        barrier_version: 0,
        ..super::GroupState::default()
    };

    let leaf = cityg_client::demo::demo_member_leaf("barrier-genesis-joinset");
    let pop_pk = vec![0xCD; 32];
    state.leaf_device_pk.insert(leaf, pop_pk.clone());
    let leaf_ek = vec![0x73; 1184];
    let mut membership = cityg_client::GroupMembership::default();
    membership.apply_delta(&cityg_client::MembershipDelta {
        joined: vec![leaf],
        revoked: Vec::new(),
    });
    let root = msphf_core::merkle::canonical_set_root(&[leaf])?;
    state.snapshots.insert(root, membership);
    state.latest_root = Some(root);
    state.leaf_barrier_public.insert(leaf, leaf_ek.clone());

    let updater_leaf = u64::from(super::cover_leaf_index(&leaf, state.n_max));
    let leaf_node = state.n_max.saturating_sub(1) + updater_leaf;
    let parent_node = (leaf_node - 1) / 2;
    let path_nodes = vec![leaf_node, parent_node, 0];

    let mut snapshot_pre = super::build_all_blank_pk_entries(state.n_max)?;
    snapshot_pre[usize::try_from(leaf_node).unwrap_or(0)] = leaf_ek.clone();
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
    let revocation_roots_hash =
        super::compute_revocation_roots_hash(&revoked_since, &revoked_root)?;
    let cover_payload = super::KemTreeCoverPayloadWire(
        updater_leaf,
        0,
        path_nodes,
        None,
        Vec::new(),
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(parent_node, vec![0x22; 1184]),
        ],
    );
    let barrier_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        0,
        0,
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
        Value::Integer(Integer::from(0u64)),
    );
    header.insert(112, Value::Bytes(revoked_since.to_vec()));
    header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
    header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));

    let delta = cityg_client::MembershipDelta {
        joined: Vec::new(),
        revoked: Vec::new(),
    };
    let validation = super::validate_barrier_update_against_roster(&state, &header, &delta)?
        .ok_or(CityGError::InvalidInput(
            "expected validated barrier update",
        ))?;
    assert_eq!(validation.parsed.prev_barrier_version, 0);
    assert_eq!(validation.parsed.tree_size, state.n_max);
    assert_eq!(validation.snapshot_post, snapshot_post);
    Ok(())
}

#[test]
fn barrier_helpers_cover_remaining_error_paths() -> Result<(), CityGError> {
    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_BARRIER_UPDATE, Value::Integer(1.into()));
    assert!(matches!(super::parse_barrier_update(&header, 4), Ok(None)));

    let delta = cityg_client::MembershipDelta {
        joined: Vec::new(),
        revoked: Vec::new(),
    };
    let state = super::GroupState::default();
    assert!(
        super::validate_barrier_update_against_roster(&state, &BTreeMap::new(), &delta)?.is_none()
    );

    let empty_tree = super::build_all_blank_pk_entries(4)?;
    assert!(matches!(
        super::collect_expected_pairs(empty_tree.as_slice(), &[0, 0], 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));
    assert!(matches!(
        super::compute_barrier_tree_hash(4, &empty_tree[..6]),
        Err(CityGError::InvalidInput("barrier tree size mismatch"))
    ));
    assert!(matches!(
        super::build_all_blank_pk_entries(u64::MAX),
        Err(CityGError::InvalidInput(_))
    ));
    Ok(())
}

#[test]
fn parse_barrier_update_accepts_sorted_hint_and_ciphertexts() -> Result<(), CityGError> {
    let cover_payload = super::KemTreeCoverPayloadWire(
        0,
        0,
        vec![3, 1, 0],
        Some(vec![1, 2]),
        vec![super::NodeCiphertextWire(
            1,
            4,
            vec![0xAA; 16],
            vec![0xBB; 1088],
            vec![0xCC; 48],
        )],
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(1, vec![0x22; 1184]),
        ],
    );
    let barrier_update = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        7,
        6,
        4,
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 32],
        super::to_cbor_vec(&cover_payload)?,
    );
    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&barrier_update)?),
    );
    let parsed = super::parse_barrier_update(&header, 4)?
        .ok_or(CityGError::InvalidInput("expected parsed update"))?;
    assert_eq!(parsed.prev_barrier_version, 6);
    assert_eq!(parsed.path_nodes, vec![3, 1, 0]);
    assert_eq!(parsed.node_ciphertexts.len(), 1);
    assert_eq!(parsed.new_public_keys.len(), 2);
    Ok(())
}

#[test]
fn parse_barrier_update_rejects_new_public_keys_expected_set_mismatch() -> Result<(), CityGError> {
    let cover_missing = super::KemTreeCoverPayloadWire(
        0,
        0,
        vec![3, 1, 0],
        None,
        Vec::new(),
        vec![super::NewPublicKeyWire(0, vec![0x11; 1184])],
    );
    let update_missing = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        1,
        0,
        4,
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 32],
        super::to_cbor_vec(&cover_missing)?,
    );
    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&update_missing)?),
    );
    assert!(matches!(
        super::parse_barrier_update(&header, 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let cover_extra = super::KemTreeCoverPayloadWire(
        0,
        0,
        vec![3, 1, 0],
        None,
        Vec::new(),
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(1, vec![0x22; 1184]),
            super::NewPublicKeyWire(2, vec![0x33; 1184]),
        ],
    );
    let update_extra = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        1,
        0,
        4,
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 32],
        super::to_cbor_vec(&cover_extra)?,
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&update_extra)?),
    );
    assert!(matches!(
        super::parse_barrier_update(&header, 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));
    Ok(())
}

#[test]
fn parse_barrier_update_rejects_invalid_mode_and_path_shapes() -> Result<(), CityGError> {
    let valid_cover = super::KemTreeCoverPayloadWire(
        0,
        0,
        vec![3, 1, 0],
        None,
        Vec::new(),
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(1, vec![0x22; 1184]),
        ],
    );
    let mut header = BTreeMap::new();

    let wrong_mode = super::BarrierUpdateWire(
        "barrier-v0".to_string(),
        1,
        0,
        4,
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 32],
        super::to_cbor_vec(&valid_cover)?,
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&wrong_mode)?),
    );
    assert!(matches!(
        super::parse_barrier_update(&header, 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let empty_path = super::KemTreeCoverPayloadWire(
        0,
        0,
        Vec::new(),
        None,
        Vec::new(),
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(1, vec![0x22; 1184]),
        ],
    );
    let update_empty_path = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        1,
        0,
        4,
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 32],
        super::to_cbor_vec(&empty_path)?,
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&update_empty_path)?),
    );
    assert!(matches!(
        super::parse_barrier_update(&header, 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let wrong_leaf = super::KemTreeCoverPayloadWire(
        0,
        0,
        vec![4, 1, 0],
        None,
        Vec::new(),
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(1, vec![0x22; 1184]),
        ],
    );
    let update_wrong_leaf = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        1,
        0,
        4,
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 32],
        super::to_cbor_vec(&wrong_leaf)?,
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&update_wrong_leaf)?),
    );
    assert!(matches!(
        super::parse_barrier_update(&header, 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let duplicate_path = super::KemTreeCoverPayloadWire(
        0,
        0,
        vec![3, 1, 1, 0],
        None,
        Vec::new(),
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(1, vec![0x22; 1184]),
            super::NewPublicKeyWire(1, vec![0x33; 1184]),
        ],
    );
    let update_duplicate_path = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        1,
        0,
        4,
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 32],
        super::to_cbor_vec(&duplicate_path)?,
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&update_duplicate_path)?),
    );
    assert!(matches!(
        super::parse_barrier_update(&header, 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let non_parent_chain = super::KemTreeCoverPayloadWire(
        0,
        0,
        vec![3, 0],
        None,
        Vec::new(),
        vec![super::NewPublicKeyWire(0, vec![0x11; 1184])],
    );
    let update_non_parent_chain = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        1,
        0,
        4,
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 32],
        super::to_cbor_vec(&non_parent_chain)?,
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&update_non_parent_chain)?),
    );
    assert!(matches!(
        super::parse_barrier_update(&header, 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));
    Ok(())
}

#[test]
fn parse_barrier_update_rejects_invalid_key_and_ciphertext_shapes() -> Result<(), CityGError> {
    let mut header = BTreeMap::new();

    let wrong_key_len = super::KemTreeCoverPayloadWire(
        0,
        0,
        vec![3, 1, 0],
        None,
        Vec::new(),
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 64]),
            super::NewPublicKeyWire(1, vec![0x22; 1184]),
        ],
    );
    let update_wrong_key_len = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        1,
        0,
        4,
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 32],
        super::to_cbor_vec(&wrong_key_len)?,
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&update_wrong_key_len)?),
    );
    assert!(matches!(
        super::parse_barrier_update(&header, 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let unsorted_keys = super::KemTreeCoverPayloadWire(
        0,
        0,
        vec![3, 1, 0],
        None,
        Vec::new(),
        vec![
            super::NewPublicKeyWire(1, vec![0x22; 1184]),
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
        ],
    );
    let update_unsorted_keys = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        1,
        0,
        4,
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 32],
        super::to_cbor_vec(&unsorted_keys)?,
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&update_unsorted_keys)?),
    );
    assert!(matches!(
        super::parse_barrier_update(&header, 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let wrong_ciphertext_size = super::KemTreeCoverPayloadWire(
        0,
        0,
        vec![3, 1, 0],
        None,
        vec![super::NodeCiphertextWire(
            1,
            4,
            vec![0xAA; 16],
            vec![0xBB; 1088],
            vec![0xCC; 47],
        )],
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(1, vec![0x22; 1184]),
        ],
    );
    let update_wrong_ciphertext_size = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        1,
        0,
        4,
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 32],
        super::to_cbor_vec(&wrong_ciphertext_size)?,
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&update_wrong_ciphertext_size)?),
    );
    assert!(matches!(
        super::parse_barrier_update(&header, 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let unsorted_ciphertexts = super::KemTreeCoverPayloadWire(
        0,
        0,
        vec![3, 1, 0],
        None,
        vec![
            super::NodeCiphertextWire(1, 4, vec![0xAA; 16], vec![0xBB; 1088], vec![0xCC; 48]),
            super::NodeCiphertextWire(1, 3, vec![0xAA; 16], vec![0xBB; 1088], vec![0xCC; 48]),
        ],
        vec![
            super::NewPublicKeyWire(0, vec![0x11; 1184]),
            super::NewPublicKeyWire(1, vec![0x22; 1184]),
        ],
    );
    let update_unsorted_ciphertexts = super::BarrierUpdateWire(
        "barrier-v1".to_string(),
        1,
        0,
        4,
        vec![0x01; 32],
        vec![0x02; 32],
        vec![0x03; 32],
        super::to_cbor_vec(&unsorted_ciphertexts)?,
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(super::to_cbor_vec(&update_unsorted_ciphertexts)?),
    );
    assert!(matches!(
        super::parse_barrier_update(&header, 4),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));
    Ok(())
}
