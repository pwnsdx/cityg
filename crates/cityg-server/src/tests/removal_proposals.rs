//! Signed removal proposals and the removal policy (audit C-03).

use super::*;
use crate::RemoveProposalSubmission;

/// Alice (genesis) and Bob (joined and finalized); returns their bundles.
fn two_member_room() -> Result<
    (
        CityGServer,
        GeneratedMemberBundle,
        GeneratedMemberBundle,
        ClientEpochBundle,
    ),
    CityGError,
> {
    let gid = cityg_client::demo::DEMO_GID;
    let mut server = super::super::demo::demo_server();
    let alice = build_genesis_member_bundle(0x61)?;
    server.accept_epoch(&alice.bundle)?;
    let _ = advance_committed_tree_for_tests(&mut server, &gid, 0x61)?;
    let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
    let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x62, false)?;
    server.accept_epoch(&bob.bundle)?;
    let (bob_finalize, _) = build_refresh_bundle_for_member(&mut server, &bob, &bob.bundle)?;
    server.accept_epoch(&bob_finalize)?;
    Ok((server, alice, bob, bob_finalize))
}

fn signed_proposal(
    target: [u8; 32],
    lease: SlotLease,
    not_after_ms: u64,
    signer_public_key: &[u8],
    signer_secret_key: &MlDsaSecretKey,
) -> Result<Vec<u8>, CityGError> {
    let proposal = cityg_client::remove_proposal::RemoveProposal {
        gid: cityg_client::demo::DEMO_GID,
        target_leaf_id: target,
        target_slot_index: lease.slot_index,
        target_slot_generation: lease.slot_generation,
        not_after_ms,
    };
    cityg_client::remove_proposal::SignedRemoveProposal::sign(
        proposal,
        signer_public_key,
        signer_secret_key.as_bytes(),
    )
    .and_then(|signed| signed.to_cbor())
    .map_err(|_| CityGError::InvalidInput("build remove proposal"))
}

fn active_lease(server: &CityGServer, leaf: &[u8; 32]) -> Result<SlotLease, CityGError> {
    server
        .roster
        .groups
        .get(cityg_client::demo::DEMO_GID.as_slice())
        .and_then(|state| state.leaf_slot_leases.get(leaf).copied())
        .ok_or(CityGError::InvalidInput("missing active lease"))
}

fn expect_invalid_input<T: std::fmt::Debug>(result: Result<T, CityGError>, expected: &str) {
    assert!(
        matches!(&result, Err(CityGError::InvalidInput(message)) if *message == expected),
        "expected InvalidInput({expected}), got {result:?}"
    );
}

#[test]
fn submit_remove_proposal_validates_signer_target_and_lifetime() -> Result<(), CityGError> {
    let (mut server, alice, bob, _) = two_member_room()?;
    let gid = cityg_client::demo::DEMO_GID;
    let now = super::super::current_timestamp_ms();
    let bob_lease = active_lease(&server, &bob.leaf_id)?;

    // Malformed bytes and foreign group.
    expect_invalid_input(
        server.submit_remove_proposal(&gid, &[0x01, 0x02]),
        "malformed remove proposal",
    );
    let valid = signed_proposal(
        bob.leaf_id,
        bob_lease,
        now + 60_000,
        &bob.pop_public_key,
        &bob.pop_secret_key,
    )?;
    expect_invalid_input(
        server.submit_remove_proposal(&[0x99; 32], &valid),
        "remove proposal gid mismatch",
    );

    // Tampered signature.
    let mut tampered = valid.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    expect_invalid_input(
        server.submit_remove_proposal(&gid, &tampered),
        "remove proposal signature rejected",
    );

    // Expired and over-long lifetimes.
    let expired = signed_proposal(
        bob.leaf_id,
        bob_lease,
        now.saturating_sub(1),
        &bob.pop_public_key,
        &bob.pop_secret_key,
    )?;
    expect_invalid_input(
        server.submit_remove_proposal(&gid, &expired),
        "remove proposal expired",
    );
    let too_long = signed_proposal(
        bob.leaf_id,
        bob_lease,
        now + cityg_client::remove_proposal::MAX_REMOVE_PROPOSAL_LIFETIME_MS + 60_000,
        &bob.pop_public_key,
        &bob.pop_secret_key,
    )?;
    expect_invalid_input(
        server.submit_remove_proposal(&gid, &too_long),
        "remove proposal lifetime too long",
    );

    // Stale lease and unknown target.
    let stale = signed_proposal(
        bob.leaf_id,
        SlotLease {
            slot_index: bob_lease.slot_index,
            slot_generation: bob_lease.slot_generation + 1,
        },
        now + 60_000,
        &bob.pop_public_key,
        &bob.pop_secret_key,
    )?;
    expect_invalid_input(
        server.submit_remove_proposal(&gid, &stale),
        "remove proposal target slot lease mismatch",
    );
    let unknown = signed_proposal(
        [0x77; 32],
        bob_lease,
        now + 60_000,
        &bob.pop_public_key,
        &bob.pop_secret_key,
    )?;
    expect_invalid_input(
        server.submit_remove_proposal(&gid, &unknown),
        "remove proposal target is not an active member",
    );

    // Alice may not ask for Bob's removal: she is neither Bob nor an admin.
    let by_alice = signed_proposal(
        bob.leaf_id,
        bob_lease,
        now + 60_000,
        &alice.pop_public_key,
        &alice.pop_secret_key,
    )?;
    expect_invalid_input(
        server.submit_remove_proposal(&gid, &by_alice),
        "remove proposal must be signed by its target or by a room admin",
    );
    assert!(server.pending_removal_proposals(&gid).is_empty());
    assert!(!server.has_pending_removal(&gid, &bob.leaf_id));

    // Bob's own proposal is recorded, idempotently.
    assert_eq!(
        server.submit_remove_proposal(&gid, &valid)?,
        RemoveProposalSubmission::Pending,
        "another member remains to commit Bob's removal"
    );
    assert_eq!(
        server.submit_remove_proposal(&gid, &valid)?,
        RemoveProposalSubmission::Pending
    );
    assert_eq!(server.pending_removal_proposals(&gid), vec![valid.clone()]);
    assert!(server.has_pending_removal(&gid, &bob.leaf_id));
    assert!(!server.has_pending_removal(&gid, &alice.leaf_id));
    Ok(())
}

#[test]
fn room_admin_may_propose_another_members_removal() -> Result<(), CityGError> {
    let (mut server, alice, bob, _) = two_member_room()?;
    let gid = cityg_client::demo::DEMO_GID;
    server
        .roster
        .groups
        .get_mut(gid.as_slice())
        .ok_or(CityGError::InvalidInput("missing group"))?
        .room_admin_pop_keys
        .insert(alice.pop_public_key.clone());
    let bob_lease = active_lease(&server, &bob.leaf_id)?;
    let by_admin = signed_proposal(
        bob.leaf_id,
        bob_lease,
        super::super::current_timestamp_ms() + 60_000,
        &alice.pop_public_key,
        &alice.pop_secret_key,
    )?;
    server.submit_remove_proposal(&gid, &by_admin)?;
    assert!(server.has_pending_removal(&gid, &bob.leaf_id));
    Ok(())
}

#[test]
fn pending_removal_blocks_refresh_and_self_revocation_until_committed() -> Result<(), CityGError> {
    let (mut server, alice, bob, bob_finalize) = two_member_room()?;
    let gid = cityg_client::demo::DEMO_GID;
    let bob_lease = submit_leave_proposal(&mut server, &bob)?;

    // The refresh ticket stays available (clients sync from it), but a
    // refresh update would leave Bob's removal uncommitted.
    let (refresh, _) = build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;
    let refresh_err = server
        .accept_epoch(&refresh)
        .err()
        .ok_or(CityGError::InvalidInput("refresh must be refused"))?;
    assert!(
        matches!(
            &refresh_err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code
                    == msphf_orchestrator::FREEZE_BARRIER_PENDING_REMOVALS_UNCOMMITTED.code
        ),
        "unexpected refresh error: {refresh_err:?}"
    );
    // Bob cannot commit his own removal.
    let self_err = server
        .build_merge_ticket(&gid, &bob.leaf_id)
        .err()
        .ok_or(CityGError::InvalidInput("self commit must be refused"))?;
    assert!(matches!(
        self_err,
        CityGError::InvalidInput(message) if message.starts_with("a member cannot author its own revocation")
    ));

    // A hostile self-revocation bundle from Bob is rejected at acceptance.
    let hostile = build_leave_bundle_for_member(&mut server, &bob, &bob_finalize)?;
    let err = server
        .accept_epoch(&hostile)
        .err()
        .ok_or(CityGError::InvalidInput(
            "hostile self-revocation must fail",
        ))?;
    assert!(
        matches!(
            &err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
        ),
        "unexpected error: {err:?}"
    );
    assert_eq!(
        server.members(&gid).len(),
        2,
        "rejection leaves the roster intact"
    );

    // Alice commits the removal: Bob is gone and the proposal is consumed.
    let removal =
        build_removal_commit_bundle_for_member(&mut server, &alice, &alice.bundle, bob_lease)?;
    server.accept_epoch(&removal)?;
    assert_eq!(server.members(&gid), vec![alice.leaf_id]);
    assert!(server.pending_removal_proposals(&gid).is_empty());
    assert!(!server.has_pending_removal(&gid, &bob.leaf_id));
    Ok(())
}

#[test]
fn pending_removals_survive_restart() -> Result<(), CityGError> {
    let _guard = super::super::journal_serial_guard();
    let dir = tempdir()?;
    let journal_path = dir.path().join("cityg-server.journal");
    let gid = cityg_client::demo::DEMO_GID;
    let expected = {
        let mut server = demo_server_with_journal(&journal_path);
        let alice = build_genesis_member_bundle(0x63)?;
        server.accept_epoch(&alice.bundle)?;
        let _ = advance_committed_tree_for_tests(&mut server, &gid, 0x63)?;
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
        let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x64, false)?;
        server.accept_epoch(&bob.bundle)?;
        let (bob_finalize, _) = build_refresh_bundle_for_member(&mut server, &bob, &bob.bundle)?;
        server.accept_epoch(&bob_finalize)?;
        submit_leave_proposal(&mut server, &bob)?;
        server.pending_removal_proposals(&gid)
    };
    assert_eq!(expected.len(), 1);
    let mut restarted = demo_server_with_journal(&journal_path);
    assert_eq!(restarted.pending_removal_proposals(&gid), expected);
    Ok(())
}
