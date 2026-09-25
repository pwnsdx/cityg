use super::*;
use crate::join::JoinSecrets;
use crate::kem::KemSecret;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn content(author: &DeviceIdentity, kind: CommitKind, rng: &mut ChaCha20Rng) -> CommitContent {
    CommitContent {
        gid: [3; 32],
        epoch: 4,
        kind,
        prev_interim_transcript_hash: [5; 32],
        author_leaf: 0,
        author_device_pk: author.public_key().to_vec(),
        tree_hash: [7; 32],
        registry_hash: [6; 32],
        update_path: UpdatePath {
            leaf_public_key: KemSecret::generate(rng).public_key(),
            nodes: Vec::new(),
        },
        removals: Vec::new(),
        joins: Vec::new(),
        admin_changes: Vec::new(),
        admission: None,
        external_init: None,
        group_nonce: None,
        capacity: None,
        new_device_pk: None,
    }
}

fn signed(
    content: CommitContent,
    author: &DeviceIdentity,
    rotation: Option<&DeviceIdentity>,
    rng: &mut ChaCha20Rng,
) -> Vec<u8> {
    let signature = content.sign(author, rng).unwrap();
    let rotation_signature = rotation.map(|new| content.sign_rotation(new, rng).unwrap());
    Commit {
        content,
        signature,
        rotation_signature,
        confirmation_tag: [8; 32],
    }
    .encode()
    .unwrap()
}

fn admission(gid: &Digest, admin: &DeviceIdentity, joiner: &DeviceIdentity) -> SignedAdmission {
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    SignedAdmission::by_admin(gid, &joiner.device_id(gid).unwrap(), 9, admin, &mut rng).unwrap()
}

#[test]
fn commits_round_trip_and_verify() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let alice = DeviceIdentity::from_seed(&[1; 32]);
    let bob = DeviceIdentity::from_seed(&[2; 32]);
    let carol = DeviceIdentity::from_seed(&[3; 32]);
    let rotated = DeviceIdentity::from_seed(&[4; 32]);

    let mut member = content(&alice, CommitKind::Member, &mut rng);
    member.admin_changes = vec![AdminChange::Grant { leaf: 1, since: 2 }];
    member.joins = vec![
        SignedJoinRequest::create(
            &bob,
            &JoinSecrets::generate(&mut rng),
            &admission(&member.gid, &alice, &bob),
            &mut rng,
        )
        .unwrap(),
    ];
    member.new_device_pk = Some(rotated.public_key().to_vec());
    let encoded = signed(member.clone(), &alice, Some(&rotated), &mut rng);
    let (decoded, tbs) = Commit::decode(&encoded, 1 << 20).unwrap();
    assert_eq!(decoded.content, member);
    assert_eq!(tbs, member.tbs().unwrap());
    assert!(decoded.rotation_signature.is_some());
    assert_eq!(decoded.encode().unwrap(), encoded);

    let mut genesis = content(&alice, CommitKind::Genesis, &mut rng);
    genesis.group_nonce = Some([1; 32]);
    genesis.capacity = Some(8);
    let encoded = signed(genesis.clone(), &alice, None, &mut rng);
    assert_eq!(
        Commit::decode(&encoded, 1 << 20).unwrap().0.content,
        genesis
    );

    let mut resync = content(&alice, CommitKind::Resync, &mut rng);
    resync.author_leaf = 1;
    resync.external_init = Some(vec![1, 2, 3]);
    let encoded = signed(resync.clone(), &alice, None, &mut rng);
    assert_eq!(Commit::decode(&encoded, 1 << 20).unwrap().0.content, resync);

    let mut join = content(&carol, CommitKind::ExternalJoin, &mut rng);
    join.admission = Some(admission(&join.gid, &alice, &carol));
    join.external_init = Some(vec![4]);
    let encoded = signed(join.clone(), &carol, None, &mut rng);
    assert_eq!(Commit::decode(&encoded, 1 << 20).unwrap().0.content, join);
    assert!(CommitKind::Resync.is_external() && !CommitKind::Member.is_external());
    assert!(commit_bound(Some(4)) < commit_bound(None));
}

#[test]
fn registry_and_signatures_are_enforced() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let alice = DeviceIdentity::from_seed(&[1; 32]);
    let bob = DeviceIdentity::from_seed(&[2; 32]);
    let member = content(&alice, CommitKind::Member, &mut rng);
    assert!(member.sign(&bob, &mut rng).is_err());
    assert!(member.sign_rotation(&bob, &mut rng).is_err());

    // Genesis fields on a member commit are rejected.
    let mut wrong = member.clone();
    wrong.capacity = Some(8);
    assert!(wrong.tbs().is_err());
    let mut rotating_resync = content(&alice, CommitKind::Resync, &mut rng);
    rotating_resync.external_init = Some(vec![1]);
    rotating_resync.new_device_pk = Some(bob.public_key().to_vec());
    assert!(rotating_resync.tbs().is_err(), "only member commits rotate");
    // An external join without admission is rejected.
    let mut join = content(&alice, CommitKind::ExternalJoin, &mut rng);
    join.external_init = Some(vec![0]);
    assert!(join.tbs().is_err());
    // A genesis away from leaf 0 is rejected.
    let mut genesis = content(&alice, CommitKind::Genesis, &mut rng);
    genesis.group_nonce = Some([1; 32]);
    genesis.capacity = Some(8);
    genesis.author_leaf = 1;
    assert!(genesis.tbs().is_err());
    genesis.author_leaf = 0;
    genesis.capacity = Some(6);
    assert_eq!(genesis.tbs(), Err(CoreError::Invalid("capacity")));

    // Duplicate admin changes and oversized lists are rejected.
    let mut duplicate = member.clone();
    duplicate.admin_changes = vec![
        AdminChange::Grant { leaf: 1, since: 0 },
        AdminChange::Revoke { leaf: 1, since: 0 },
    ];
    assert_eq!(
        duplicate.tbs(),
        Err(CoreError::Malformed("duplicate admin change"))
    );

    // A rotation needs both the new key and its signature.
    let mut rotating = member.clone();
    rotating.new_device_pk = Some(bob.public_key().to_vec());
    let signature = rotating.sign(&alice, &mut rng).unwrap();
    let unsigned = Commit {
        content: rotating.clone(),
        signature: signature.clone(),
        rotation_signature: None,
        confirmation_tag: [0; 32],
    };
    assert!(unsigned.encode().is_err());
    let forged = Commit {
        content: rotating.clone(),
        signature,
        rotation_signature: Some(rotating.sign(&alice, &mut rng).unwrap()),
        confirmation_tag: [0; 32],
    };
    assert_eq!(
        Commit::decode(&forged.encode().unwrap(), 1 << 20).err(),
        Some(CoreError::BadSignature("commit key rotation"))
    );

    // A signature over other content does not verify.
    let encoded = signed(member.clone(), &alice, None, &mut rng);
    let Value::Map(mut entries) = decode(&encoded, 1 << 20, "t").unwrap() else {
        panic!("map")
    };
    for (key, value) in &mut entries {
        if *key == uint(key::EPOCH) {
            *value = uint(5);
        }
    }
    let forged = encode(&Value::Map(entries.clone())).unwrap();
    assert_eq!(
        Commit::decode(&forged, 1 << 20).err(),
        Some(CoreError::BadSignature("commit"))
    );
    // Unknown keys are rejected.
    let mut unknown = entries.clone();
    unknown.push((uint(99), uint(1)));
    assert_eq!(
        Commit::decode(&encode(&Value::Map(unknown)).unwrap(), 1 << 20).err(),
        Some(CoreError::Malformed("unknown commit key"))
    );
    // A member commit without its join list is malformed.
    let missing: Vec<_> = entries
        .iter()
        .filter(|(key, _)| *key != uint(key::JOINS))
        .cloned()
        .collect();
    assert_eq!(
        Commit::decode(&encode(&Value::Map(missing)).unwrap(), 1 << 20).err(),
        Some(CoreError::Malformed("commit fields for its kind"))
    );
    assert!(Commit::decode(&encoded, 100).is_err(), "size bound");
    assert!(Commit::decode(&[0x80], 100).is_err());
    assert!(
        max_commit_bytes(MAX_CAPACITY) < 16 << 20,
        "fits a DS request"
    );
}

#[test]
fn admin_change_encoding() {
    for change in [
        AdminChange::Grant { leaf: 3, since: 7 },
        AdminChange::Revoke { leaf: 3, since: 7 },
    ] {
        assert_eq!(AdminChange::from_value(change.to_value()).unwrap(), change);
        assert_eq!(change.target(), (3, 7));
    }
    assert!(AdminChange::from_value(array(vec![uint(2), uint(1), uint(1)])).is_err());
    assert!(AdminChange::from_value(array(vec![uint(0), uint(1)])).is_err());
}
