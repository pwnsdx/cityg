use super::*;

#[test]
fn accept_epoch_rejects_barrier_update_global_history_attestation_without_extension()
-> Result<(), CityGError> {
    let generated = build_genesis_member_bundle(0x78)?;
    let mut server = super::super::demo::demo_server();
    server.accept_epoch(&generated.bundle)?;
    let gid = cityg_client::demo::DEMO_GID;
    let _ = advance_committed_tree_for_tests(&mut server, &gid, 0x78)?;

    let (mut bundle, _pristine_bundle) =
        build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
    bundle.header_map.insert(
        hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
        Value::Bytes(vec![0xCD; 32]),
    );

    let err = server
        .accept_epoch(&bundle)
        .expect_err("base profile must reject unsupported global-history attestation header");
    assert!(
        matches!(err, CityGError::InvalidInput("barrier_update malformed"))
            || matches!(
                err,
                CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                    if freeze.code
                        == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                        && freeze.reason
                            == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
            ),
        "unexpected error: {err:?}"
    );
    Ok(())
}

#[test]
fn build_refresh_bundle_includes_local_history_authority_headers() -> Result<(), CityGError> {
    let generated = build_genesis_member_bundle(0x79)?;
    let mut server = demo_server_with_local_history_authority();
    server.accept_epoch(&generated.bundle)?;

    let (bundle, _pristine_bundle) =
        build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
    assert!(
        bundle
            .header_map
            .contains_key(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION)
    );
    assert!(
        bundle
            .header_map
            .contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
    );
    assert!(
        !bundle
            .header_map
            .contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS)
    );
    Ok(())
}

#[test]
fn build_refresh_bundle_includes_global_history_authority_headers() -> Result<(), CityGError> {
    let generated = build_genesis_member_bundle(0x7B)?;
    let mut server = demo_server_with_global_history_authority();
    server.accept_epoch(&generated.bundle)?;

    assert_eq!(
        server.history_authority_extension_id(),
        GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
    );
    let (bundle, _pristine_bundle) =
        build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
    assert!(
        bundle
            .header_map
            .contains_key(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION)
    );
    assert!(
        bundle
            .header_map
            .contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
    );
    let raw_attestation = bundle
        .header_map
        .get(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION)
        .and_then(Value::as_bytes)
        .ok_or(CityGError::InvalidInput("missing history attestation"))?;
    let (
        descriptor,
        gid,
        history_commitment,
        barrier_version,
        kem_tree_hash_after,
        _,
        finality_kind,
        signature,
    ) = parse_global_history_attestation(raw_attestation.as_slice())?;
    let payload = to_cbor_vec(&GlobalHistoryAttestationSignedPayload(
        "cityg/global-history-attestation-v1",
        &descriptor.scope_id,
        &gid,
        &history_commitment.history_view_id,
        &history_commitment.history_commitment_id,
        &history_commitment.prev_history_commitment_id,
        history_commitment.history_seq,
        barrier_version,
        &kem_tree_hash_after,
        &global_history_parent_attestation_id(
            &descriptor.scope_id,
            &gid,
            &history_commitment.prev_history_commitment_id,
        )?,
        finality_kind.as_str(),
    ))?;
    let stored_descriptor =
        server
            .history_authority_descriptor()
            .ok_or(CityGError::InvalidInput(
                "missing history authority descriptor",
            ))?;
    verify_history_authority_signature(&stored_descriptor, payload.as_slice(), &signature)?;
    assert_eq!(finality_kind, GLOBAL_HISTORY_ATTESTATION_FINALITY_KIND);
    Ok(())
}

#[test]
fn full_verification_witness_rejects_barrier_update_hash_mismatch() -> Result<(), CityGError> {
    let generated = build_genesis_member_bundle(0x7D)?;
    let mut server = demo_server_with_global_history_authority();
    server.accept_epoch(&generated.bundle)?;

    let ticket =
        server.build_merge_ticket_for_refresh(&cityg_client::demo::DEMO_GID, &generated.leaf_id)?;
    let join_records =
        server.resolve_joins_since(&cityg_client::demo::DEMO_GID, ticket.barrier_version)?;
    let committed_roots_hash = super::super::compute_revocation_roots_hash(
        &ticket.revoked_since_root,
        &ticket.revoked_root,
    )?;
    let committed_revoked = server
        .resolve_revoked_leaf_indices(&cityg_client::demo::DEMO_GID, &committed_roots_hash)?;
    let (bundle, _) = build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
    let raw_barrier_update = bundle
        .header_map
        .get(&hdr::HDR_BARRIER_UPDATE)
        .and_then(Value::as_bytes)
        .ok_or(CityGError::InvalidInput("missing barrier_update"))?;
    let super::super::BarrierUpdateWire(
        mode,
        barrier_version,
        prev_barrier_version,
        tree_size,
        revocation_roots_hash,
        kem_tree_hash_before,
        mut kem_tree_hash_after,
        cover_payload,
    ) = super::super::parse_deterministic_cbor(raw_barrier_update)?;
    kem_tree_hash_after[0] ^= 0xFF;
    let tampered_barrier_update = to_cbor_vec(&super::super::BarrierUpdateWire(
        mode,
        barrier_version,
        prev_barrier_version,
        tree_size,
        revocation_roots_hash,
        kem_tree_hash_before,
        kem_tree_hash_after,
        cover_payload,
    ))?;
    let deployment_profile_manifest = server.deployment_profile_manifest_bytes(
        &cityg_client::demo::DEMO_GID,
        "v0.1.4",
        server.history_authority_extension_id(),
        ticket.n_max,
        ticket.max_barrier_update_bytes,
        ticket.fs_forward_leap_policy,
    )?;

    let err = server
        .full_verification_witness_bytes(
            &cityg_client::demo::DEMO_GID,
            &ticket.current_history_commitment,
            ticket.barrier_version,
            &ticket.kem_tree_hash_after,
            &generated.leaf_id,
            1,
            ticket.slot_index,
            ticket.slot_generation,
            tampered_barrier_update.as_slice(),
            ticket.barrier_version,
            join_records.records.as_slice(),
            &committed_roots_hash,
            committed_revoked.records.as_slice(),
            deployment_profile_manifest.as_slice(),
        )
        .expect_err("tampered barrier_update must not receive a full verification witness");
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE.code
                && freeze.reason
                    == msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE.reason
    ));
    Ok(())
}

#[test]
fn full_verification_witness_rejects_updater_slot_generation_mismatch() -> Result<(), CityGError> {
    let generated = build_genesis_member_bundle(0x7E)?;
    let mut server = demo_server_with_global_history_authority();
    server.accept_epoch(&generated.bundle)?;

    let ticket =
        server.build_merge_ticket_for_refresh(&cityg_client::demo::DEMO_GID, &generated.leaf_id)?;
    let join_records =
        server.resolve_joins_since(&cityg_client::demo::DEMO_GID, ticket.barrier_version)?;
    let committed_roots_hash = super::super::compute_revocation_roots_hash(
        &ticket.revoked_since_root,
        &ticket.revoked_root,
    )?;
    let committed_revoked = server
        .resolve_revoked_leaf_indices(&cityg_client::demo::DEMO_GID, &committed_roots_hash)?;
    let (bundle, _) = build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
    let raw_barrier_update = bundle
        .header_map
        .get(&hdr::HDR_BARRIER_UPDATE)
        .and_then(Value::as_bytes)
        .ok_or(CityGError::InvalidInput("missing barrier_update"))?;
    let deployment_profile_manifest = server.deployment_profile_manifest_bytes(
        &cityg_client::demo::DEMO_GID,
        "v0.1.4",
        server.history_authority_extension_id(),
        ticket.n_max,
        ticket.max_barrier_update_bytes,
        ticket.fs_forward_leap_policy,
    )?;

    let err = server
        .full_verification_witness_bytes(
            &cityg_client::demo::DEMO_GID,
            &ticket.current_history_commitment,
            ticket.barrier_version,
            &ticket.kem_tree_hash_after,
            &generated.leaf_id,
            1,
            ticket.slot_index,
            ticket.slot_generation + 1,
            raw_barrier_update,
            ticket.barrier_version,
            join_records.records.as_slice(),
            &committed_roots_hash,
            committed_revoked.records.as_slice(),
            deployment_profile_manifest.as_slice(),
        )
        .expect_err(
            "mismatched updater_slot_generation must not receive a full verification witness",
        );
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                && freeze.reason
                    == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
    ));
    Ok(())
}

#[test]
fn accept_epoch_rejects_barrier_update_missing_receipt_under_local_history_authority()
-> Result<(), CityGError> {
    let generated = build_genesis_member_bundle(0x7A)?;
    let mut server = demo_server_with_local_history_authority();
    server.accept_epoch(&generated.bundle)?;

    let (mut bundle, _pristine_bundle) =
        build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
    bundle
        .header_map
        .remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT);

    let err = server
        .accept_epoch(&bundle)
        .expect_err("local history authority must require full verification receipt");
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
    ));
    Ok(())
}

#[test]
fn accept_epoch_rejects_barrier_update_receipt_slot_generation_mismatch_under_local_history_authority()
-> Result<(), CityGError> {
    let generated = build_genesis_member_bundle(0x7F)?;
    let mut server = demo_server_with_local_history_authority();
    server.accept_epoch(&generated.bundle)?;

    let (mut bundle, _pristine_bundle) =
        build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
    let raw_receipt = bundle
        .header_map
        .get(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
        .and_then(Value::as_bytes)
        .ok_or(CityGError::InvalidInput(
            "missing full verification receipt",
        ))?;
    let mut receipt: super::super::FullVerificationReceiptWire =
        super::super::parse_deterministic_cbor(raw_receipt)?;
    receipt.updater_slot_generation += 1;
    bundle.header_map.insert(
        hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
        Value::Bytes(to_cbor_vec(&receipt)?),
    );

    let err = server.accept_epoch(&bundle).expect_err(
        "local history authority must reject mismatched receipt updater_slot_generation",
    );
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
    ));
    Ok(())
}

#[test]
fn accept_epoch_rejects_barrier_update_missing_receipt_under_global_history_authority()
-> Result<(), CityGError> {
    let generated = build_genesis_member_bundle(0x7C)?;
    let mut server = demo_server_with_global_history_authority();
    server.accept_epoch(&generated.bundle)?;

    let (mut bundle, _pristine_bundle) =
        build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
    bundle
        .header_map
        .remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT);

    let err = server
        .accept_epoch(&bundle)
        .expect_err("global history authority must require full verification receipt");
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
    ));
    Ok(())
}

#[test]
fn accept_epoch_rejects_barrier_update_witness_slot_generation_mismatch_under_global_history_authority()
-> Result<(), CityGError> {
    let generated = build_genesis_member_bundle(0x80)?;
    let mut server = demo_server_with_global_history_authority();
    server.accept_epoch(&generated.bundle)?;

    let (mut bundle, _pristine_bundle) =
        build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
    let ticket =
        server.build_merge_ticket_for_refresh(&cityg_client::demo::DEMO_GID, &generated.leaf_id)?;
    let join_records =
        server.resolve_joins_since(&cityg_client::demo::DEMO_GID, ticket.barrier_version)?;
    let committed_roots_hash = super::super::compute_revocation_roots_hash(
        &ticket.revoked_since_root,
        &ticket.revoked_root,
    )?;
    let committed_revoked = server
        .resolve_revoked_leaf_indices(&cityg_client::demo::DEMO_GID, &committed_roots_hash)?;
    let raw_barrier_update = bundle
        .header_map
        .get(&hdr::HDR_BARRIER_UPDATE)
        .and_then(Value::as_bytes)
        .ok_or(CityGError::InvalidInput("missing barrier_update"))?;
    let deployment_profile_manifest = server.deployment_profile_manifest_bytes(
        &cityg_client::demo::DEMO_GID,
        "v0.1.4",
        server.history_authority_extension_id(),
        ticket.n_max,
        ticket.max_barrier_update_bytes,
        ticket.fs_forward_leap_policy,
    )?;
    let raw_witness = server.full_verification_witness_bytes(
        &cityg_client::demo::DEMO_GID,
        &ticket.current_history_commitment,
        ticket.barrier_version,
        &ticket.kem_tree_hash_after,
        &generated.leaf_id,
        1,
        ticket.slot_index,
        ticket.slot_generation,
        raw_barrier_update,
        ticket.barrier_version,
        join_records.records.as_slice(),
        &committed_roots_hash,
        committed_revoked.records.as_slice(),
        deployment_profile_manifest.as_slice(),
    )?;
    let mut witness: super::super::FullVerificationWitnessWire =
        super::super::parse_deterministic_cbor(raw_witness.as_slice())?;
    witness.updater_slot_generation += 1;
    bundle.header_map.insert(
        hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS,
        Value::Bytes(to_cbor_vec(&witness)?),
    );

    let err = server.accept_epoch(&bundle).expect_err(
        "global history authority must reject mismatched witness updater_slot_generation",
    );
    assert!(matches!(
        err,
        CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
    ));
    Ok(())
}
