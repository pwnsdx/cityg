use super::*;
use proptest::test_runner::TestCaseError;

#[test]
fn malformed_join_rejection_does_not_poison_room_state() -> Result<(), CityGError> {
    let mut server = super::super::demo::demo_server();
    let alice = cityg_client::demo::demo_bundle("alice")?;
    server.accept_epoch(&alice)?;
    assert_eq!(
        server.members(&cityg_client::demo::DEMO_GID).len(),
        1,
        "room must be healthy after the first honest join"
    );

    let mut malformed_bob = cityg_client::demo::demo_bundle("bob")?;
    malformed_bob.header_map.remove(&hdr::HDR_BARRIER_LEAF_PK);
    let err = server
        .accept_epoch(&malformed_bob)
        .expect_err("malformed join must be rejected");
    assert!(
        matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
        "unexpected malformed join error: {err:?}"
    );

    let members_after_reject = server.members(&cityg_client::demo::DEMO_GID);
    assert_eq!(
        members_after_reject.len(),
        1,
        "rejected malformed join must not change membership"
    );
    assert_eq!(
        members_after_reject[0],
        cityg_client::demo::demo_member_leaf("alice"),
        "the healthy survivor roster must remain intact"
    );

    let honest_bob = cityg_client::demo::demo_bundle("bob")?;
    server.accept_epoch(&honest_bob)?;
    assert_eq!(
        server.members(&cityg_client::demo::DEMO_GID).len(),
        2,
        "a later honest join must still succeed"
    );
    Ok(())
}

#[test]
fn malformed_leave_rejection_does_not_poison_room_state() -> Result<(), CityGError> {
    let mut server = demo_server_with_global_history_authority();
    let gid = cityg_client::demo::DEMO_GID;
    let alice = build_genesis_member_bundle(0x86)?;
    server.accept_epoch(&alice.bundle)?;
    let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
    let mut malformed_leave = build_leave_bundle_for_member(&mut server, &alice, &alice.bundle)?;
    assert_eq!(
        u64_from_header(&malformed_leave.header_map, hdr::HDR_BARRIER_UPDATE_REASON)?,
        0,
        "leave bundle should use barrier_update reason 0"
    );
    malformed_leave.header_map.remove(&hdr::HDR_BARRIER_UPDATE);
    let err = server
        .accept_epoch(&malformed_leave)
        .expect_err("malformed leave must be rejected");
    assert!(
        matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
        "unexpected malformed leave error: {err:?}"
    );

    let members_after_reject = server.members(&gid);
    assert_eq!(
        members_after_reject,
        vec![alice.leaf_id],
        "rejected malformed leave must not poison the live roster"
    );

    let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x8A, true)?;
    server.accept_epoch(&bob.bundle)?;
    let members_after_honest_join = server.members(&gid);
    assert_eq!(
        members_after_honest_join.len(),
        2,
        "a later honest join must still succeed after malformed leave rejection"
    );
    Ok(())
}

#[test]
fn malformed_refresh_rejection_does_not_poison_room_state() -> Result<(), CityGError> {
    let mut server = demo_server_with_global_history_authority();
    let gid = cityg_client::demo::DEMO_GID;
    let alice = build_genesis_member_bundle(0x87)?;
    server.accept_epoch(&alice.bundle)?;
    let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;

    let (join_finalize, _) = build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;
    assert_eq!(
        u64_from_header(&join_finalize.header_map, hdr::HDR_BARRIER_UPDATE_REASON)?,
        2,
        "first post-join merge should be join_finalize"
    );
    let mut malformed_refresh = join_finalize.clone();
    malformed_refresh.header_map.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );
    assert_eq!(
        u64_from_header(&malformed_refresh.header_map, hdr::HDR_BARRIER_UPDATE_REASON)?,
        1,
        "mutated hostile bundle should masquerade as a refresh"
    );
    malformed_refresh
        .header_map
        .remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS);
    let err = server
        .accept_epoch(&malformed_refresh)
        .expect_err("malformed refresh must be rejected");
    assert!(
        matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
        "unexpected malformed refresh error: {err:?}"
    );

    let members_after_reject = server.members(&gid);
    assert_eq!(
        members_after_reject,
        vec![alice.leaf_id],
        "rejected malformed refresh must not poison membership state"
    );

    let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x8B, true)?;
    server.accept_epoch(&bob.bundle)?;
    assert_eq!(
        server.members(&gid).len(),
        2,
        "room must still accept an honest join after malformed refresh rejection"
    );
    Ok(())
}

#[test]
fn malformed_refresh_concurrent_with_honest_join_preserves_live_state() -> Result<(), CityGError> {
    let mut server = demo_server_with_global_history_authority();
    let gid = cityg_client::demo::DEMO_GID;
    let alice = build_genesis_member_bundle(0x91)?;
    server.accept_epoch(&alice.bundle)?;
    let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;

    let (join_finalize, _) = build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;
    let mut malformed_refresh = join_finalize.clone();
    malformed_refresh.header_map.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );
    malformed_refresh
        .header_map
        .remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS);

    let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x92, true)?;
    server.accept_epoch(&bob.bundle)?;

    let err = server
        .accept_epoch(&malformed_refresh)
        .expect_err("malformed refresh race must be rejected");
    assert!(
        matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
        "unexpected malformed refresh live-race error: {err:?}"
    );

    let members_after_race = server.members(&gid);
    assert_eq!(
        members_after_race.len(),
        2,
        "malformed refresh race must preserve the healthy live roster without restart"
    );
    assert!(
        members_after_race.contains(&alice.leaf_id) && members_after_race.contains(&bob.leaf_id),
        "alice and bob must remain present after the malformed refresh live race"
    );

    let followup_ticket = server.build_merge_ticket_for_refresh(&gid, &alice.leaf_id)?;
    assert_eq!(
        followup_ticket.barrier_version, 0,
        "live malformed refresh race must still allow a healthy survivor refresh ticket"
    );
    Ok(())
}

#[test]
fn malformed_refresh_concurrent_with_honest_join_does_not_poison_restart_recovery()
-> Result<(), CityGError> {
    let _guard = super::super::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("malformed-refresh-race.journal");
    let gid = cityg_client::demo::DEMO_GID;
    let alice = build_genesis_member_bundle(0x92)?;
    let bob_leaf_id;

    {
        let mut server = demo_server_with_journal_and_global_history_authority(&journal_path);
        server.accept_epoch(&alice.bundle)?;
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;

        let (join_finalize, _) =
            build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;
        let mut malformed_refresh = join_finalize.clone();
        malformed_refresh.header_map.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(1u64)),
        );
        malformed_refresh
            .header_map
            .remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS);

        let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x93, true)?;
        server.accept_epoch(&bob.bundle)?;
        bob_leaf_id = bob.leaf_id;

        let err = server
            .accept_epoch(&malformed_refresh)
            .expect_err("malformed refresh race must be rejected");
        assert!(
            matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
            "unexpected malformed refresh race error: {err:?}"
        );

        let members_before_restart = server.members(&gid);
        assert_eq!(
            members_before_restart.len(),
            2,
            "malformed refresh race must preserve the healthy live roster"
        );
        assert!(
            members_before_restart.contains(&alice.leaf_id)
                && members_before_restart.contains(&bob.leaf_id),
            "alice and bob must remain visible after the malformed refresh race"
        );
    }

    let mut reloaded = demo_server_with_journal_and_global_history_authority(&journal_path);
    let members_after_restart = reloaded.members(&gid);
    assert_eq!(
        members_after_restart.len(),
        2,
        "restart must preserve the healthy roster after malformed refresh race rejection"
    );
    assert!(
        members_after_restart.contains(&alice.leaf_id)
            && members_after_restart.contains(&bob_leaf_id),
        "alice and bob must remain visible after restart"
    );

    let followup_ticket = reloaded.build_merge_ticket_for_refresh(&gid, &alice.leaf_id)?;
    assert_eq!(
        followup_ticket.barrier_version, 0,
        "restart must still allow a healthy survivor refresh ticket after malformed refresh race"
    );
    Ok(())
}

#[test]
fn hostile_barrier_update_mutations_fail_closed_without_poisoning_restart_recovery()
-> Result<(), CityGError> {
    let _guard = super::super::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("hostile-barrier-mutations.journal");
    let gid = cityg_client::demo::DEMO_GID;
    let alice = build_genesis_member_bundle(0x95)?;

    {
        let mut server = demo_server_with_journal_and_global_history_authority(&journal_path);
        server.accept_epoch(&alice.bundle)?;
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
        let (pristine_bundle, _) =
            build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;

        for mutation in [
            "missing_witness",
            "corrupt_receipt",
            "corrupt_attestation",
            "corrupt_barrier_update",
            "mismatched_reason",
        ] {
            let mut mutated = pristine_bundle.clone();
            match mutation {
                "missing_witness" => {
                    mutated
                        .header_map
                        .remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS);
                }
                "corrupt_receipt" => {
                    let Value::Bytes(raw_receipt) = mutated
                        .header_map
                        .get_mut(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
                        .ok_or(CityGError::InvalidInput("missing full verification receipt"))?
                    else {
                        return Err(CityGError::InvalidInput(
                            "full verification receipt must be bytes",
                        ));
                    };
                    if raw_receipt.is_empty() {
                        raw_receipt.push(0x01);
                    } else {
                        raw_receipt[0] ^= 0x55;
                    }
                }
                "corrupt_attestation" => {
                    let Value::Bytes(raw_attestation) = mutated
                        .header_map
                        .get_mut(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION)
                        .ok_or(CityGError::InvalidInput(
                            "missing global history attestation",
                        ))?
                    else {
                        return Err(CityGError::InvalidInput(
                            "global history attestation must be bytes",
                        ));
                    };
                    if raw_attestation.is_empty() {
                        raw_attestation.push(0x01);
                    } else {
                        raw_attestation[0] ^= 0xA5;
                    }
                }
                "corrupt_barrier_update" => {
                    let Value::Bytes(raw_update) = mutated
                        .header_map
                        .get_mut(&hdr::HDR_BARRIER_UPDATE)
                        .ok_or(CityGError::InvalidInput("missing barrier update"))?
                    else {
                        return Err(CityGError::InvalidInput("barrier update must be bytes"));
                    };
                    raw_update.truncate(raw_update.len().min(4));
                    if raw_update.is_empty() {
                        raw_update.push(0x01);
                    }
                }
                "mismatched_reason" => {
                    mutated.header_map.insert(
                        hdr::HDR_BARRIER_UPDATE_REASON,
                        Value::Integer(Integer::from(1u64)),
                    );
                }
                _ => unreachable!("unknown mutation"),
            }

            let err = server
                .accept_epoch(&mutated)
                .expect_err("hostile mutation must be rejected");
            assert!(
                matches!(err, CityGError::InvalidInput(_))
                    || matches!(err, CityGError::Acceptance(_)),
                "unexpected hostile mutation error for {mutation}: {err:?}"
            );
            assert_eq!(
                server.members(&gid),
                vec![alice.leaf_id],
                "mutation {mutation} must not poison the live roster",
            );
        }

        let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x96, true)?;
        server.accept_epoch(&bob.bundle)?;
        let members_after_honest_join = server.members(&gid);
        assert_eq!(
            members_after_honest_join.len(),
            2,
            "room must still accept an honest join after hostile barrier mutations"
        );
    }

    let mut reloaded = demo_server_with_journal_and_global_history_authority(&journal_path);
    let members_after_restart = reloaded.members(&gid);
    assert_eq!(
        members_after_restart.len(),
        2,
        "restart must preserve the healthy roster after hostile barrier mutations"
    );
    let followup_ticket = reloaded.build_merge_ticket_for_refresh(&gid, &alice.leaf_id)?;
    assert_eq!(
        followup_ticket.barrier_version, 0,
        "restart must still allow a healthy survivor refresh ticket after hostile barrier mutations"
    );
    Ok(())
}

#[test]
fn hostile_barrier_update_byte_flip_sweep_fail_closed_without_poisoning_restart_recovery()
-> Result<(), CityGError> {
    fn mutation_offsets(len: usize) -> Vec<usize> {
        if len == 0 {
            return Vec::new();
        }
        let mut offsets = vec![0, len / 3, (2 * len) / 3, len - 1];
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }

    let _guard = super::super::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("hostile-barrier-byte-flip-sweep.journal");
    let gid = cityg_client::demo::DEMO_GID;
    let alice = build_genesis_member_bundle(0x95)?;

    {
        let mut server = demo_server_with_journal_and_global_history_authority(&journal_path);
        server.accept_epoch(&alice.bundle)?;
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
        let (pristine_bundle, _) =
            build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;

        let byte_flip_headers = [
            ("witness", hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS, 0x11u8),
            ("receipt", hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT, 0x22u8),
            ("attestation", hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION, 0x44u8),
            ("barrier_update", hdr::HDR_BARRIER_UPDATE, 0x88u8),
        ];

        let mut exercised_cases = 0usize;
        for (label, header, mask) in byte_flip_headers {
            let Some(raw) = pristine_bundle.header_map.get(&header) else {
                continue;
            };
            let Value::Bytes(raw_bytes) = raw else {
                return Err(CityGError::InvalidInput(
                    "byte-flip mutation target must be bytes",
                ));
            };

            for offset in mutation_offsets(raw_bytes.len()) {
                let mut mutated = pristine_bundle.clone();
                let Value::Bytes(mutated_bytes) = mutated
                    .header_map
                    .get_mut(&header)
                    .ok_or(CityGError::InvalidInput(
                        "missing byte-flip mutation target",
                    ))?
                else {
                    return Err(CityGError::InvalidInput(
                        "byte-flip mutation target must stay bytes",
                    ));
                };
                mutated_bytes[offset] ^= mask;

                let err = server
                    .accept_epoch(&mutated)
                    .expect_err("byte-flipped hostile mutation must be rejected");
                assert!(
                    matches!(err, CityGError::InvalidInput(_))
                        || matches!(err, CityGError::Acceptance(_)),
                    "unexpected byte-flip mutation error for {label}@{offset}: {err:?}"
                );
                assert_eq!(
                    server.members(&gid),
                    vec![alice.leaf_id],
                    "mutation {label}@{offset} must not poison the live roster",
                );
                exercised_cases += 1;
            }
        }

        assert!(
            exercised_cases >= 10,
            "mutation sweep should exercise multiple hostile byte-flip cases"
        );

        for reason in [0u64, 2u64, 7u64, u16::MAX as u64] {
            let mut mutated = pristine_bundle.clone();
            mutated.header_map.insert(
                hdr::HDR_BARRIER_UPDATE_REASON,
                Value::Integer(Integer::from(reason)),
            );
            let err = server
                .accept_epoch(&mutated)
                .expect_err("mutated reason must be rejected");
            assert!(
                matches!(err, CityGError::InvalidInput(_))
                    || matches!(err, CityGError::Acceptance(_)),
                "unexpected mutated reason error for reason={reason}: {err:?}"
            );
            assert_eq!(
                server.members(&gid),
                vec![alice.leaf_id],
                "mutated reason {reason} must not poison the live roster",
            );
            exercised_cases += 1;
        }

        assert!(
            exercised_cases >= 14,
            "mutation sweep should exercise a meaningful hostile bundle set"
        );

        let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x98, true)?;
        server.accept_epoch(&bob.bundle)?;
        assert_eq!(
            server.members(&gid).len(),
            2,
            "room must still accept an honest join after the byte-flip mutation sweep"
        );
    }

    let mut reloaded = demo_server_with_journal_and_global_history_authority(&journal_path);
    assert_eq!(
        reloaded.members(&gid).len(),
        2,
        "restart must preserve the healthy roster after the byte-flip mutation sweep"
    );
    let followup_ticket = reloaded.build_merge_ticket_for_refresh(&gid, &alice.leaf_id)?;
    assert_eq!(
        followup_ticket.barrier_version, 0,
        "restart must still allow a healthy survivor refresh ticket after the byte-flip mutation sweep"
    );
    Ok(())
}

proptest::proptest! {
    #![proptest_config(ProptestConfig {
        cases: 24,
        max_shrink_iters: 0,
        .. ProptestConfig::default()
    })]

    #[test]
    fn prop_authority_bound_refresh_bundle_mutations_fail_closed_without_poisoning_live_state(
        mutation_target in 0u8..5,
        offset_seed in any::<usize>(),
        xor_mask in 1u8..=u8::MAX,
        alternate_reason in prop_oneof![Just(0u64), Just(2u64), 3u64..=32u64],
    ) {
        let gid = cityg_client::demo::DEMO_GID;
        let alice = build_genesis_member_bundle(0xA0).expect("build alice");
        let mut server = demo_server_with_global_history_authority();
        server.accept_epoch(&alice.bundle).expect("accept alice");
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)
            .expect("seed accepted barrier update");

        let (pristine_bundle, _) =
            build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)
                .expect("build refresh bundle");
        let baseline_reason = u64_from_header(
            &pristine_bundle.header_map,
            hdr::HDR_BARRIER_UPDATE_REASON,
        )
        .expect("baseline reason");

        let mut mutated = pristine_bundle.clone();
        match mutation_target {
            0 => {
                let raw = match mutated
                    .header_map
                    .get_mut(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
                {
                    Some(Value::Bytes(raw)) => raw,
                    _ => {
                        return Err(TestCaseError::fail(
                            "refresh receipt must exist as bytes under global authority",
                        ));
                    }
                };
                let idx = offset_seed % raw.len();
                raw[idx] ^= xor_mask;
            }
            1 => {
                let raw = match mutated
                    .header_map
                    .get_mut(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION)
                {
                    Some(Value::Bytes(raw)) => raw,
                    _ => {
                        return Err(TestCaseError::fail(
                            "refresh attestation must exist as bytes under global authority",
                        ));
                    }
                };
                let idx = offset_seed % raw.len();
                raw[idx] ^= xor_mask;
            }
            2 => {
                let raw = match mutated.header_map.get_mut(&hdr::HDR_BARRIER_UPDATE) {
                    Some(Value::Bytes(raw)) => raw,
                    _ => {
                        return Err(TestCaseError::fail(
                            "refresh barrier update must exist as bytes",
                        ));
                    }
                };
                let idx = offset_seed % raw.len();
                raw[idx] ^= xor_mask;
            }
            3 => {
                let replacement_reason = if alternate_reason == baseline_reason {
                    if baseline_reason == 0 { 2 } else { 0 }
                } else {
                    alternate_reason
                };
                mutated.header_map.insert(
                    hdr::HDR_BARRIER_UPDATE_REASON,
                    Value::Integer(Integer::from(replacement_reason)),
                );
            }
            4 => {
                if let Some(Value::Bytes(raw)) = mutated
                    .header_map
                    .get_mut(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS)
                {
                    let idx = offset_seed % raw.len();
                    raw[idx] ^= xor_mask;
                } else {
                    let raw = match mutated.header_map.get_mut(&hdr::HDR_BARRIER_UPDATE) {
                        Some(Value::Bytes(raw)) => raw,
                        _ => {
                            return Err(TestCaseError::fail(
                                "fallback refresh barrier update must exist as bytes",
                            ));
                        }
                    };
                    let idx = offset_seed % raw.len();
                    raw[idx] ^= xor_mask;
                }
            }
            _ => unreachable!("bounded mutation target"),
        }

        let err = server
            .accept_epoch(&mutated)
            .expect_err("mutated refresh bundle must be rejected");
        prop_assert!(
            matches!(err, CityGError::InvalidInput(_))
                || matches!(err, CityGError::Acceptance(_)),
            "unexpected property mutation error: {err:?}"
        );

        let members = server.members(&gid);
        prop_assert_eq!(
            members.len(),
            1,
            "mutated refresh bundle must not poison the live roster"
        );
        prop_assert!(members.contains(&alice.leaf_id));
    }
}

#[test]
fn malformed_admin_expel_rejection_does_not_poison_room_state() -> Result<(), CityGError> {
    let mut server = demo_server_with_global_history_authority();
    let gid = cityg_client::demo::DEMO_GID;
    let alice = build_genesis_member_bundle(0x81)?;
    server.accept_epoch(&alice.bundle)?;
    let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
    let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x82, true)?;
    server.accept_epoch(&bob.bundle)?;

    {
        let group = server
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("missing demo group state"))?;
        group.room_admin_pop_keys.insert(alice.pop_public_key.clone());
    }

    let mut malformed_expel =
        build_admin_expel_bundle_for_member(&mut server, &alice, &alice.bundle, &bob.leaf_id, 0x31)?;
    malformed_expel.header_map.remove(&hdr::HDR_BARRIER_UPDATE);
    let err = server
        .accept_epoch(&malformed_expel)
        .expect_err("malformed admin expel must be rejected");
    assert!(
        matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
        "unexpected malformed admin expel error: {err:?}"
    );

    let members_after_reject = server.members(&gid);
    assert_eq!(
        members_after_reject.len(),
        2,
        "rejected malformed admin expel must not evict or corrupt members"
    );
    assert!(
        members_after_reject.contains(&alice.leaf_id)
            && members_after_reject.contains(&bob.leaf_id),
        "the healthy room membership must remain intact after malformed admin expel"
    );

    let charlie = build_join_member_from_server_ticket(&mut server, &gid, 0x83, true)?;
    server.accept_epoch(&charlie.bundle)?;
    let members_after_honest_join = server.members(&gid);
    assert_eq!(
        members_after_honest_join.len(),
        3,
        "a later honest join must still succeed after malformed admin expel rejection"
    );
    assert!(
        members_after_honest_join.contains(&alice.leaf_id)
            && members_after_honest_join.contains(&bob.leaf_id)
            && members_after_honest_join.contains(&charlie.leaf_id),
        "the room must remain healthy after malformed admin expel rejection"
    );
    Ok(())
}

#[test]
fn malformed_admin_expel_rejection_does_not_poison_restart_recovery() -> Result<(), CityGError> {
    let _guard = super::super::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("malformed-admin-expel.journal");
    let gid = cityg_client::demo::DEMO_GID;

    {
        let mut server = demo_server_with_journal_and_global_history_authority(&journal_path);
        let alice = build_genesis_member_bundle(0x83)?;
        server.accept_epoch(&alice.bundle)?;
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
        let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x84, true)?;
        server.accept_epoch(&bob.bundle)?;

        {
            let group = server
                .roster
                .groups
                .get_mut(gid.as_slice())
                .ok_or(CityGError::InvalidInput("missing demo group state"))?;
            group.room_admin_pop_keys.insert(alice.pop_public_key.clone());
        }

        let mut malformed_expel =
            build_admin_expel_bundle_for_member(&mut server, &alice, &alice.bundle, &bob.leaf_id, 0x41)?;
        malformed_expel.header_map.remove(&hdr::HDR_BARRIER_UPDATE);
        let err = server
            .accept_epoch(&malformed_expel)
            .expect_err("malformed admin expel must be rejected before restart");
        assert!(
            matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
            "unexpected malformed admin expel error: {err:?}"
        );

        let members_before_restart = server.members(&gid);
        assert_eq!(members_before_restart.len(), 2);
    }

    let mut reloaded = demo_server_with_journal_and_global_history_authority(&journal_path);
    let members_after_restart = reloaded.members(&gid);
    assert_eq!(
        members_after_restart.len(),
        2,
        "restart must preserve the healthy roster after malformed admin expel rejection"
    );

    let charlie = build_join_member_from_server_ticket(&mut reloaded, &gid, 0x85, true)?;
    reloaded.accept_epoch(&charlie.bundle)?;
    let members_after_honest_join = reloaded.members(&gid);
    assert_eq!(
        members_after_honest_join.len(),
        3,
        "room must still accept later honest joins after restart"
    );
    Ok(())
}

#[test]
fn malformed_join_finalize_rejection_does_not_poison_restart_recovery() -> Result<(), CityGError> {
    let _guard = super::super::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("malformed-join-finalize.journal");
    let gid = cityg_client::demo::DEMO_GID;
    let alice = build_genesis_member_bundle(0x88)?;

    {
        let mut server = demo_server_with_journal_and_global_history_authority(&journal_path);
        server.accept_epoch(&alice.bundle)?;
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;

        let (pristine_join_finalize, _) =
            build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;
        let mut malformed_join_finalize = pristine_join_finalize.clone();
        assert_eq!(
            u64_from_header(&malformed_join_finalize.header_map, hdr::HDR_BARRIER_UPDATE_REASON)?,
            2,
            "first post-join merge should be join_finalize"
        );
        malformed_join_finalize
            .header_map
            .remove(&hdr::HDR_JOIN_FINALIZE_AUTH);
        let err = server
            .accept_epoch(&malformed_join_finalize)
            .expect_err("malformed join_finalize must be rejected");
        assert!(
            matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
            "unexpected malformed join_finalize error: {err:?}"
        );

        let members_before_restart = server.members(&gid);
        assert_eq!(
            members_before_restart,
            vec![alice.leaf_id],
            "rejected malformed join_finalize must not poison the live roster"
        );
    }

    let mut reloaded = demo_server_with_journal_and_global_history_authority(&journal_path);
    assert_eq!(
        reloaded.members(&gid),
        vec![alice.leaf_id],
        "restart must preserve healthy membership after malformed join_finalize rejection"
    );

    let followup_ticket = reloaded.build_merge_ticket_for_refresh(&gid, &alice.leaf_id)?;
    assert_eq!(
        followup_ticket.barrier_version, 0,
        "restart must still allow a fresh join_finalize/refresh ticket after malformed rejection"
    );
    let (fresh_join_finalize, _) =
        build_refresh_bundle_for_member(&mut reloaded, &alice, &alice.bundle)?;
    assert_eq!(
        u64_from_header(&fresh_join_finalize.header_map, hdr::HDR_BARRIER_UPDATE_REASON)?,
        2,
        "restart must still permit a valid join_finalize after malformed rejection"
    );
    Ok(())
}

#[test]
fn stale_leave_race_with_honest_join_does_not_poison_restart_recovery() -> Result<(), CityGError> {
    let _guard = super::super::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("stale-leave-race.journal");
    let gid = cityg_client::demo::DEMO_GID;
    let alice = build_genesis_member_bundle(0x8F)?;

    {
        let mut server = demo_server_with_journal_and_global_history_authority(&journal_path);
        server.accept_epoch(&alice.bundle)?;
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;

        let stale_leave = build_leave_bundle_for_member(&mut server, &alice, &alice.bundle)?;
        let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x90, true)?;
        server.accept_epoch(&bob.bundle)?;

        let err = server
            .accept_epoch(&stale_leave)
            .expect_err("stale leave race must be rejected");
        assert!(
            matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
            "unexpected stale leave race error: {err:?}"
        );

        let members_before_restart = server.members(&gid);
        assert_eq!(
            members_before_restart.len(),
            2,
            "stale leave rejection must preserve the healthy live roster"
        );
        assert!(
            members_before_restart.contains(&alice.leaf_id)
                && members_before_restart.contains(&bob.leaf_id),
            "alice and bob must remain visible after the stale leave race"
        );
    }

    let mut reloaded = demo_server_with_journal_and_global_history_authority(&journal_path);
    let members_after_restart = reloaded.members(&gid);
    assert_eq!(
        members_after_restart.len(),
        2,
        "restart must preserve the healthy roster after stale leave rejection"
    );
    assert!(
        members_after_restart.contains(&alice.leaf_id),
        "surviving author must remain visible after restart"
    );

    let followup_ticket = reloaded.build_merge_ticket_for_refresh(&gid, &alice.leaf_id)?;
    assert_eq!(
        followup_ticket.barrier_version, 0,
        "restart must still allow a healthy survivor refresh ticket after stale leave rejection"
    );
    Ok(())
}
