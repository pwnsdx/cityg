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
fn test_join_delta_root_single_leaf() {
    let leaves = vec![[1u8; 32]];
    let result = join_delta_root(&leaves);
    assert!(result.is_ok(), "Should compute root for single leaf");

    let root = result.expect("single leaf should have a root");
    assert_ne!(root, [0u8; 32], "Root should not be all zeros");
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
fn test_witness_cbor_roundtrip() {
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

    let bytes = witness_to_cbor(&witness).expect("encode");
    let decoded = witness_from_cbor(&bytes).expect("decode");

    // Verify the witness mode is preserved
    use msphf_core::witness::WitnessMode;
    assert_eq!(decoded.mode(), WitnessMode::A);
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
fn test_build_branch_b_artifacts_produces_valid_data() {
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

    let (_witness, srx_owned) = result.expect("branch B artifacts");
    assert_eq!(srx_owned.join_leaf_ids, join_leaves);
}

#[test]
fn test_build_branch_b_with_parent() {
    use msphf_core::merkle::canonical_set_root;

    let parent_leaves = vec![[0x10; 32], [0x20; 32]];
    let join_leaves = vec![[0x30; 32]];
    let parent_root = canonical_set_root(&parent_leaves).expect("parent root");
    let revoked_since_root = [0u8; 32];

    let result = build_branch_b_artifacts(
        &parent_leaves,
        &join_leaves,
        parent_root,
        revoked_since_root,
    );
    assert!(result.is_ok(), "Should handle parent leaves");
}

#[test]
fn test_srx_inputs_cbor_roundtrip() {
    use msphf_core::merkle::canonical_set_root;

    let parent_leaves = vec![[0x10; 32]];
    let join_leaves = vec![[0x30; 32]];
    let parent_root = canonical_set_root(&parent_leaves).expect("parent root");
    let revoked_since_root = [0u8; 32];

    let (_witness, srx_owned) = build_branch_b_artifacts(
        &parent_leaves,
        &join_leaves,
        parent_root,
        revoked_since_root,
    )
    .expect("build artifacts");

    let bytes = srx_owned.to_cbor().expect("serialize");
    let decoded = SrxInputsOwned::from_cbor(&bytes).expect("deserialize");

    assert_eq!(decoded.join_leaf_ids, srx_owned.join_leaf_ids);
}
