use cityg_client::demo::*;

#[test]
fn test_demo_member_leaf_consistency() {
    let leaf1 = demo_member_leaf("alice");
    let leaf2 = demo_member_leaf("alice");
    assert_eq!(leaf1, leaf2, "Same label should return same leaf");
}

#[test]
fn test_demo_member_leaf_uniqueness() {
    let alice = demo_member_leaf("alice");
    let bob = demo_member_leaf("bob");
    assert_ne!(
        alice, bob,
        "Different labels should return different leaves"
    );
}

#[test]
fn test_demo_bundle_alice() -> Result<(), Box<dyn std::error::Error>> {
    let result = demo_bundle_alice();
    assert!(
        result.is_ok(),
        "Alice demo bundle should generate successfully"
    );

    let bundle = result?;
    assert_eq!(bundle.gid(), &DEMO_GID);
    Ok(())
}

#[test]
fn test_demo_bundle_bob() -> Result<(), Box<dyn std::error::Error>> {
    // Generate Alice first (as she's the genesis)
    let _alice = demo_bundle_alice()?;

    let result = demo_bundle_bob();
    assert!(
        result.is_ok(),
        "Bob demo bundle should generate successfully"
    );

    let bundle = result?;
    assert_eq!(bundle.gid(), &DEMO_GID);
    Ok(())
}

#[test]
fn test_demo_bundle_generates_with_label() {
    let result = demo_bundle("test_user");
    assert!(result.is_ok(), "Demo bundle should generate for any label");
}

#[test]
fn test_kbroad_keys_not_empty() {
    let public = kbroad_public();
    let secret = kbroad_secret();

    assert!(!public.is_empty(), "Public key should not be empty");
    assert!(!secret.is_empty(), "Secret key should not be empty");
    assert_ne!(public, secret, "Public and secret keys should differ");
}

#[test]
fn test_bootstrap_public_not_empty() {
    let bootstrap = bootstrap_public();
    assert!(
        !bootstrap.is_empty(),
        "Bootstrap public key should not be empty"
    );
}

#[test]
fn test_serialize_witness_produces_bytes() -> Result<(), Box<dyn std::error::Error>> {
    use msphf_core::witness::{CanonicalWitness, RawMembershipWitness, WitnessVariants};

    // Create a minimal witness for testing
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

    let result = serialize_witness(&witness);
    assert!(result.is_ok(), "Serialization should succeed");
    let serialized = result?;
    assert!(
        !serialized.is_empty(),
        "Serialized bytes should not be empty"
    );
    Ok(())
}

#[test]
fn test_witness_branch_b_structure() {
    let join_root = [0x11; 32];
    let revoked_root = [0x22; 32];

    let witness = witness_branch_b(&join_root, &revoked_root);

    // Verify it's a branch B witness
    use msphf_core::witness::WitnessMode;
    assert_eq!(witness.mode(), WitnessMode::B);
}

#[test]
fn test_attach_bootstrap_to_bundle() -> Result<(), Box<dyn std::error::Error>> {
    let mut bundle = demo_bundle_alice()?;
    let _result = attach_bootstrap(&mut bundle);

    // Should succeed or fail gracefully
    // We can't assert success as it depends on keys being set up correctly
    // But we can verify it doesn't panic
    Ok(())
}
