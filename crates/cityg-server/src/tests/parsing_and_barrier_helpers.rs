use super::super::{
    GroupState, blank_internal_path_from_leaf_cow, blank_leaf_and_path_cow,
    build_all_blank_pk_entries, build_all_blank_pk_entries_cow, build_pk_entries_cow,
    collect_expected_pairs, collect_resolution_nodes, compute_barrier_tree_hash, direct_path_nodes,
    header_bytes, header_bytes_opt, header_bytes32, header_bytes32_opt, header_string,
    parse_barrier_update_reason, parse_deterministic_cbor, sibling_node,
};
use super::*;

#[test]
fn group_state_defaults_include_barrier_policy_bounds() -> Result<(), CityGError> {
    let mut server = CityGServer::new(ServerConfig::new());
    let gid = [0xD1; 32];
    server.register_group(&gid, vec![0x11; 16])?;
    let state = server
        .roster
        .groups
        .get(gid.as_slice())
        .expect("group should exist after registration");
    assert_eq!(state.n_max, super::super::DEFAULT_BARRIER_N_MAX);
    assert!(state.n_max.is_power_of_two());
    assert!(state.pcs_refresh_min_delta_device_ec >= 1);
    assert!(state.pcs_refresh_min_delta_group_ec >= 1);
    assert!(state.pcs_refresh_slot_width_ec >= 1);
    Ok(())
}

#[test]
fn header_helpers_cover_defaults_and_type_validation() {
    let mut map = BTreeMap::new();
    map.insert(1, Value::Bytes(vec![0x11; 32]));
    map.insert(2, Value::Bytes(vec![0x22]));
    map.insert(3, Value::Integer(7.into()));
    map.insert(4, Value::Null);
    map.insert(5, Value::Text("ok".to_string()));
    map.insert(6, Value::Bytes(vec![0x66, 0x67]));
    map.insert(7, Value::Bool(true));

    assert!(header_bytes32(&map, 1, "required").is_ok());
    assert!(matches!(
        header_bytes32(&map, 2, "required"),
        Err(CityGError::InvalidInput("pivot field wrong length"))
    ));
    assert!(matches!(
        header_bytes32(&map, 3, "required"),
        Err(CityGError::InvalidInput("pivot field wrong type"))
    ));
    assert!(matches!(
        header_bytes32(&map, 99, "required"),
        Err(CityGError::InvalidInput("required"))
    ));

    assert!(matches!(header_bytes32_opt(&map, 1), Ok(Some(_))));
    assert!(matches!(header_bytes32_opt(&map, 4), Ok(None)));
    assert!(matches!(
        header_bytes32_opt(&map, 2),
        Err(CityGError::InvalidInput("pivot field wrong length"))
    ));
    assert!(matches!(
        header_bytes32_opt(&map, 7),
        Err(CityGError::InvalidInput("pivot field wrong type"))
    ));

    assert!(matches!(
        header_bytes(&map, 3, "bytes"),
        Err(CityGError::InvalidInput("pivot field wrong type"))
    ));
    assert!(matches!(
        header_bytes(&map, 99, "bytes"),
        Err(CityGError::InvalidInput("bytes"))
    ));
    assert!(matches!(
        header_bytes_opt(&map, 3),
        Err(CityGError::InvalidInput("pivot field wrong type"))
    ));
    assert!(matches!(
        header_string(&map, 5, None),
        Ok(value) if value == "ok"
    ));
    assert!(matches!(
        header_string(&map, 6, None),
        Ok(value) if value == "fg"
    ));
    assert!(matches!(
        header_string(&map, 4, Some("fallback")),
        Ok(value) if value == "fallback"
    ));
    assert!(matches!(
        header_string(&map, 4, None),
        Err(CityGError::InvalidInput("pivot field missing"))
    ));
    assert!(matches!(
        header_string(&map, 7, None),
        Err(CityGError::InvalidInput("pivot field wrong type"))
    ));
    assert!(matches!(
        header_string(&map, 99, Some("fallback")),
        Ok(value) if value == "fallback"
    ));
}

#[test]
fn parse_barrier_update_reason_covers_presence_and_bounds() {
    let empty = BTreeMap::new();
    assert!(matches!(parse_barrier_update_reason(&empty), Ok(None)));

    let mut reason_without_update = BTreeMap::new();
    reason_without_update.insert(hdr::HDR_BARRIER_UPDATE_REASON, Value::Integer(1.into()));
    assert!(matches!(
        parse_barrier_update_reason(&reason_without_update),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let mut update_without_reason = BTreeMap::new();
    update_without_reason.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(vec![0xAA]));
    assert!(matches!(
        parse_barrier_update_reason(&update_without_reason),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let mut invalid_type = update_without_reason.clone();
    invalid_type.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Text("not-an-integer".to_string()),
    );
    assert!(matches!(
        parse_barrier_update_reason(&invalid_type),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let mut negative = update_without_reason.clone();
    negative.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(-1i64)),
    );
    assert!(matches!(
        parse_barrier_update_reason(&negative),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    let mut too_large = update_without_reason.clone();
    too_large.insert(hdr::HDR_BARRIER_UPDATE_REASON, Value::Integer(3.into()));
    assert!(matches!(
        parse_barrier_update_reason(&too_large),
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));

    for reason in 0u64..=2 {
        let mut header = update_without_reason.clone();
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(reason)),
        );
        assert_eq!(
            parse_barrier_update_reason(&header).expect("valid reason"),
            Some(reason)
        );
    }
}

#[test]
fn parse_deterministic_cbor_rejects_noncanonical_map_bytes() {
    let noncanonical = vec![0xA2, 0x01, 0x01, 0x00, 0x00];
    let parsed = parse_deterministic_cbor::<BTreeMap<u8, u8>>(&noncanonical);
    assert!(matches!(
        parsed,
        Err(CityGError::InvalidInput("barrier_update malformed"))
    ));
}

#[test]
fn barrier_tree_helpers_cover_resolution_and_size_errors() -> Result<(), CityGError> {
    let base = build_all_blank_pk_entries(4)?;
    assert_eq!(base.len(), 7);
    assert!(collect_expected_pairs(base.as_slice(), &[3, 1, 0], 4)?.is_empty());

    let mut with_target = base.clone();
    with_target[4] = vec![0x44; 1184];
    let pairs = collect_expected_pairs(with_target.as_slice(), &[3, 1, 0], 4)?;
    assert_eq!(pairs, vec![(1, 4)]);

    assert!(matches!(
        compute_barrier_tree_hash(0, &[] as &[&[u8]]),
        Err(CityGError::InvalidInput(_))
    ));
    Ok(())
}

#[test]
fn barrier_tree_path_and_cow_helpers_cover_mutation_paths() -> Result<(), CityGError> {
    assert_eq!(direct_path_nodes(5), vec![5, 2, 0]);
    assert_eq!(sibling_node(0), None);
    assert_eq!(sibling_node(5), Some(6));
    assert_eq!(sibling_node(6), Some(5));

    let mut borrowed = vec![
        Cow::Borrowed(&[0x00][..]),
        Cow::Borrowed(&[0x01][..]),
        Cow::Borrowed(&[0x02][..]),
        Cow::Borrowed(&[0x03][..]),
        Cow::Borrowed(&[0x04][..]),
        Cow::Borrowed(&[0x05][..]),
        Cow::Borrowed(&[0x06][..]),
    ];
    blank_internal_path_from_leaf_cow(&mut borrowed, 5);
    assert_eq!(borrowed[5].as_ref(), &[0x05]);
    assert!(borrowed[2].is_empty());
    assert!(borrowed[0].is_empty());
    assert_eq!(borrowed[1].as_ref(), &[0x01]);

    blank_leaf_and_path_cow(&mut borrowed, 4);
    assert!(borrowed[4].is_empty());
    assert!(borrowed[1].is_empty());
    assert!(borrowed[0].is_empty());
    assert_eq!(borrowed[6].as_ref(), &[0x06]);

    let blanks = build_all_blank_pk_entries_cow(4)?;
    assert_eq!(blanks.len(), 7);
    assert!(blanks.iter().all(|entry| entry.is_empty()));
    assert!(matches!(
        build_all_blank_pk_entries_cow(u64::MAX),
        Err(CityGError::InvalidInput(_))
    ));
    Ok(())
}

#[test]
fn barrier_resolution_and_pk_entries_cow_helpers_cover_branches() -> Result<(), CityGError> {
    let snapshot: Vec<Cow<'_, [u8]>> = vec![
        Cow::Borrowed(&[]),
        Cow::Borrowed(&[]),
        Cow::Borrowed(&[0xC2][..]),
        Cow::Borrowed(&[0xD3][..]),
        Cow::Borrowed(&[]),
        Cow::Borrowed(&[]),
        Cow::Borrowed(&[]),
    ];
    let mut targets = Vec::new();
    collect_resolution_nodes(snapshot.as_slice(), 0, 3, &mut targets);
    assert_eq!(targets, vec![3, 2]);

    let mut state = GroupState {
        n_max: 4,
        ..GroupState::default()
    };
    state.barrier_pk_entries = (0..7).map(|idx| vec![idx as u8]).collect();
    let borrowed = build_pk_entries_cow(&state)?;
    assert_eq!(borrowed.len(), 7);
    assert_eq!(borrowed[6].as_ref(), &[6]);
    Ok(())
}
