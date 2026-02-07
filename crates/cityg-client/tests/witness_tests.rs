use cityg_client::witness::*;

#[test]
fn test_sequential_leaf_deterministic() {
    let leaf1 = sequential_leaf(1);
    let leaf2 = sequential_leaf(1);
    assert_eq!(leaf1, leaf2, "Same index should produce same leaf");
}

#[test]
fn test_sequential_leaf_different_indices() {
    let leaf1 = sequential_leaf(1);
    let leaf2 = sequential_leaf(2);
    assert_ne!(
        leaf1, leaf2,
        "Different indices should produce different leaves"
    );
}

#[test]
fn test_sequential_leaf_structure() {
    let leaf = sequential_leaf(42);

    // The last 4 bytes should be the index in big-endian
    let index_bytes = &leaf[28..32];
    let decoded_index = u32::from_be_bytes([
        index_bytes[0],
        index_bytes[1],
        index_bytes[2],
        index_bytes[3],
    ]);
    assert_eq!(decoded_index, 42);
}

#[test]
fn test_join_delta_root_single_leaf() -> Result<(), Box<dyn std::error::Error>> {
    let leaves = vec![[1u8; 32]];
    let result = join_delta_root(&leaves);
    assert!(result.is_ok(), "Should compute root for single leaf");

    let root = result?;
    assert_ne!(root, [0u8; 32], "Root should not be all zeros");
    Ok(())
}

#[test]
fn test_join_delta_root_multiple_leaves() {
    let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let result = join_delta_root(&leaves);
    assert!(result.is_ok(), "Should compute root for multiple leaves");
}

#[test]
fn test_join_delta_root_empty() {
    let leaves: Vec<[u8; 32]> = vec![];
    let _result = join_delta_root(&leaves);
    // Empty should fail or return a sentinel value
    // The behavior depends on canonical_set_root implementation
}

#[test]
fn test_witness_cbor_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    use msphf_core::witness::{CanonicalWitness, RawMembershipWitness, WitnessVariants};

    let witness = CanonicalWitness {
        inner: WitnessVariants::A {
            witness: RawMembershipWitness {
                leaf_id: vec![0x22; 32],
                root: vec![0x11; 32],
                path: vec![],
            },
            pop: None,
        },
    };

    let bytes = witness_to_cbor(&witness)?;
    let decoded = witness_from_cbor(&bytes)?;

    // Verify the witness mode is preserved
    use msphf_core::witness::WitnessMode;
    assert_eq!(decoded.mode(), WitnessMode::A);
    Ok(())
}

#[test]
fn test_witness_from_cbor_invalid() {
    let invalid_bytes = vec![0xFF, 0xFF, 0xFF];
    let result = witness_from_cbor(&invalid_bytes);
    assert!(result.is_err(), "Should fail with invalid CBOR");
}

#[test]
fn test_witness_from_cbor_empty() {
    let empty_bytes = vec![];
    let result = witness_from_cbor(&empty_bytes);
    assert!(result.is_err(), "Should fail with empty input");
}

#[test]
fn test_demo_pox_commit() {
    let commit = demo_pox_commit();
    assert_ne!(commit, [0u8; 32], "POX commit should not be all zeros");
}

#[test]
fn test_build_branch_b_artifacts_produces_valid_data() -> Result<(), Box<dyn std::error::Error>> {
    let join_leaves = vec![[1u8; 32], [2u8; 32]];
    let parent_leaves: Vec<[u8; 32]> = vec![];
    let parent_root = [0u8; 32];
    let revoked_since_root = [0u8; 32];

    let result = build_branch_b_artifacts(
        &parent_leaves,
        &join_leaves,
        parent_root,
        revoked_since_root,
    );
    assert!(result.is_ok(), "Should succeed with valid inputs");

    let (_witness, srx_owned) = result?;
    assert_eq!(srx_owned.join_leaf_ids, join_leaves);
    Ok(())
}

#[test]
fn test_build_branch_b_with_parent() -> Result<(), Box<dyn std::error::Error>> {
    use msphf_core::merkle::canonical_set_root;

    let parent_leaves = vec![[0x10; 32], [0x20; 32]];
    let join_leaves = vec![[0x30; 32]];
    let parent_root = canonical_set_root(&parent_leaves)?;
    let revoked_since_root = [0u8; 32];

    let result = build_branch_b_artifacts(
        &parent_leaves,
        &join_leaves,
        parent_root,
        revoked_since_root,
    );
    assert!(result.is_ok(), "Should handle parent leaves");
    Ok(())
}

#[test]
fn test_srx_inputs_cbor_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    use msphf_core::merkle::canonical_set_root;

    let parent_leaves = vec![[0x10; 32]];
    let join_leaves = vec![[0x30; 32]];
    let parent_root = canonical_set_root(&parent_leaves)?;
    let revoked_since_root = [0u8; 32];

    let (_witness, srx_owned) = build_branch_b_artifacts(
        &parent_leaves,
        &join_leaves,
        parent_root,
        revoked_since_root,
    )?;

    let bytes = srx_owned.to_cbor()?;
    let decoded = SrxInputsOwned::from_cbor(&bytes)?;

    assert_eq!(decoded.join_leaf_ids, srx_owned.join_leaf_ids);
    Ok(())
}

#[test]
fn test_build_branch_b_artifacts_rejects_parent_root_mismatch() {
    let parent_leaves = vec![[0x10; 32], [0x20; 32]];
    let join_leaves = vec![[0x30; 32]];
    let bad_parent_root = [0xFF; 32];

    let err = build_branch_b_artifacts(&parent_leaves, &join_leaves, bad_parent_root, [0u8; 32])
        .expect_err("mismatched parent root must fail");
    assert!(err.to_string().contains("parent root mismatch"));
}

#[test]
fn test_build_merge_srx_inputs_rejects_nonzero_revoked_root_when_empty() {
    let parent_leaves = vec![[0x10; 32]];
    let join_leaves = vec![[0x20; 32]];
    let parent_root =
        msphf_core::merkle::canonical_set_root(&parent_leaves).expect("parent root should compute");
    let revoked_since_leaves: Vec<[u8; 32]> = Vec::new();
    let revoked_leaves: Vec<[u8; 32]> = Vec::new();

    let err = build_merge_srx_inputs(
        &parent_leaves,
        &join_leaves,
        parent_root,
        &revoked_since_leaves,
        &revoked_leaves,
        [0x99; 32],
    )
    .expect_err("non-zero revoked root with empty revoked set must fail");

    assert!(err.to_string().contains("revoked_root mismatch"));
}

#[test]
fn test_build_merge_srx_inputs_rejects_revoked_since_not_in_revoked_set() {
    let parent_leaves = vec![[0x10; 32]];
    let join_leaves = vec![[0x20; 32]];
    let parent_root =
        msphf_core::merkle::canonical_set_root(&parent_leaves).expect("parent root should compute");
    let revoked_since_leaves = vec![[0xA5; 32]];
    let revoked_leaves: Vec<[u8; 32]> = Vec::new();

    let err = build_merge_srx_inputs(
        &parent_leaves,
        &join_leaves,
        parent_root,
        &revoked_since_leaves,
        &revoked_leaves,
        [0u8; 32],
    )
    .expect_err("revoked_since entries must belong to revoked set");

    assert!(
        err.to_string()
            .contains("revoked leaf missing from revoked set")
    );
}

#[test]
fn test_build_branch_b_artifacts_interval_nonmembership_includes_anchors()
-> Result<(), Box<dyn std::error::Error>> {
    let parent_leaves = vec![[0x10; 32], [0x30; 32], [0x50; 32]];
    let parent_root = msphf_core::merkle::canonical_set_root(&parent_leaves)?;
    let join_leaves = vec![[0x40; 32]];

    let (_witness, srx) =
        build_branch_b_artifacts(&parent_leaves, &join_leaves, parent_root, [0u8; 32])?;
    assert_eq!(srx.join_nonmem_parent.len(), 1);
    let interval = &srx.join_nonmem_parent[0];
    assert!(interval.witness.left.is_some());
    assert!(interval.witness.right.is_some());
    assert!(interval.left_ref.is_some());
    assert!(interval.right_ref.is_some());
    assert!(interval.witness.nmint.is_some());
    Ok(())
}

#[test]
fn test_build_branch_b_artifacts_left_boundary_nonmembership()
-> Result<(), Box<dyn std::error::Error>> {
    let parent_leaves = vec![[0x20; 32], [0x30; 32]];
    let parent_root = msphf_core::merkle::canonical_set_root(&parent_leaves)?;
    let join_leaves = vec![[0x10; 32]];

    let (_witness, srx) =
        build_branch_b_artifacts(&parent_leaves, &join_leaves, parent_root, [0u8; 32])?;
    let nm = &srx.join_nonmem_parent[0].witness;
    assert!(nm.left.is_none());
    assert!(nm.right.is_some());
    assert!(!nm.path.is_empty());
    Ok(())
}

#[test]
fn test_build_branch_b_artifacts_right_boundary_nonmembership()
-> Result<(), Box<dyn std::error::Error>> {
    let parent_leaves = vec![[0x20; 32], [0x30; 32]];
    let parent_root = msphf_core::merkle::canonical_set_root(&parent_leaves)?;
    let join_leaves = vec![[0x40; 32]];

    let (_witness, srx) =
        build_branch_b_artifacts(&parent_leaves, &join_leaves, parent_root, [0u8; 32])?;
    let nm = &srx.join_nonmem_parent[0].witness;
    assert!(nm.left.is_some());
    assert!(nm.right.is_none());
    assert!(!nm.path.is_empty());
    Ok(())
}

#[test]
fn test_srx_inputs_from_cbor_invalid() {
    let err = SrxInputsOwned::from_cbor(&[0xFF, 0x00]).expect_err("invalid cbor should fail");
    assert!(err.to_string().contains("unable to parse SRX inputs"));
}
