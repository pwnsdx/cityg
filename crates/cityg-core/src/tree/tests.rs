use super::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

struct Member {
    leaf: u32,
    private: PrivatePath,
}

fn device_pk(tag: u32) -> Vec<u8> {
    let mut key = vec![0u8; cityg_pqc::PUBLIC_KEY_BYTES];
    key[..4].copy_from_slice(&tag.to_be_bytes());
    key
}

fn member_node(tag: u32, since: u64, encryption_key: Vec<u8>) -> LeafNode {
    LeafNode {
        device_pk: device_pk(tag),
        since,
        encryption_key,
        admission_hash: [tag as u8; 32],
    }
}

/// Add a member in the entry leaf; it holds only its leaf key.
fn join(tree: &mut PublicTree, tag: u32, rng: &mut ChaCha20Rng) -> Member {
    let key = KemSecret::generate(rng);
    let leaf = tree.entry_leaf().unwrap();
    tree.add_leaf(leaf, member_node(tag, 0, key.public_key()))
        .unwrap();
    Member {
        leaf,
        private: PrivatePath {
            leaf: Some(key),
            nodes: BTreeMap::new(),
        },
    }
}

/// The author re-keys its path; every other member decrypts it, in the
/// tree the commit starts from and in the tree it produces. Returns the
/// commit secret everyone agrees on.
fn commit(
    tree: &mut PublicTree,
    members: &mut [Member],
    author: usize,
    epoch: u64,
    rng: &mut ChaCha20Rng,
) -> [u8; 32] {
    let context = PathContext {
        gid: [0x42; 32],
        epoch,
        author_leaf: members[author].leaf,
    };
    let (path, secrets) = generate_update_path(tree, &context, rng).unwrap();
    validate_update_path(tree, context.author_leaf, &path).unwrap();
    let mut after = tree.clone();
    after.apply_update_path(context.author_leaf, &path).unwrap();
    let mut secrets_seen = vec![*secrets.commit_secret];
    for (index, member) in members.iter_mut().enumerate() {
        if index == author {
            continue;
        }
        let received =
            decrypt_update_path(tree, &context, &path, member.leaf, &member.private).unwrap();
        let from_result =
            decrypt_update_path(&after, &context, &path, member.leaf, &member.private).unwrap();
        assert_eq!(*received.commit_secret, *from_result.commit_secret);
        secrets_seen.push(*received.commit_secret);
        member.private.nodes.extend(received.node_keys);
    }
    *tree = after;
    let author_member = &mut members[author];
    author_member.private.leaf = secrets.leaf_key;
    author_member.private.nodes = secrets.node_keys;
    assert!(secrets_seen.windows(2).all(|pair| pair[0] == pair[1]));
    for member in members.iter_mut() {
        member.private.retain_live(tree);
    }
    secrets_seen[0]
}

#[test]
fn array_layout_matches_rfc_9420() {
    // Tree of 8 leaves (RFC 9420, appendix C).
    assert_eq!(root(8), 7);
    assert_eq!(root(1), 0);
    assert_eq!((level(0), level(1), level(3), level(7)), (0, 1, 2, 3));
    assert_eq!((left(7), right(7), left(3), right(3)), (3, 11, 1, 5));
    assert_eq!((left(1), right(1), left(11), right(11)), (0, 2, 9, 13));
    assert_eq!((parent(0), parent(2), parent(1), parent(5)), (1, 1, 3, 3));
    assert_eq!(
        (parent(3), parent(11), parent(14), parent(13)),
        (7, 7, 13, 11)
    );
    assert_eq!(
        (sibling(0), sibling(1), sibling(3), sibling(12)),
        (2, 5, 11, 14)
    );
    assert!(is_ancestor_or_self(7, 14) && is_ancestor_or_self(3, 6));
    assert!(!is_ancestor_or_self(3, 8) && !is_ancestor_or_self(9, 12));
    assert!(is_ancestor_or_self(4, 4) && !is_ancestor_or_self(4, 6));
    assert_eq!(leaf_node(5), 10);

    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let mut tree = PublicTree::new(8).unwrap();
    for tag in 0..8 {
        join(&mut tree, tag, &mut rng);
    }
    assert_eq!(tree.width(), 8);
    assert_eq!(tree.direct_path(0).unwrap(), vec![1, 3, 7]);
    assert_eq!(tree.copath(0).unwrap(), vec![2, 5, 11]);
    assert_eq!(tree.direct_path(7).unwrap(), vec![13, 11, 7]);
    assert_eq!(tree.copath(7).unwrap(), vec![12, 9, 3]);
    assert_eq!(tree.copath(5).unwrap(), vec![8, 13, 3]);
    assert!(tree.direct_path(8).is_err());
    assert_eq!(tree.entry_leaf(), None, "full at its capacity");
    assert_eq!(
        tree.add_leaf(
            8,
            member_node(9, 0, KemSecret::generate(&mut rng).public_key())
        ),
        Err(CoreError::Invalid("the group is full"))
    );
}

#[test]
fn capacities_and_bounds() {
    assert!(PublicTree::new(3).is_err());
    assert!(PublicTree::new(1).is_err());
    assert!(PublicTree::new(MAX_CAPACITY * 2).is_err());
    validate_capacity(MAX_CAPACITY).unwrap();
    assert!(max_update_path_bytes(MAX_CAPACITY) < 10_000_000);
    assert!(max_update_path_bytes(2) > 2 * KEM_PUBLIC_KEY_BYTES);
}

#[test]
fn the_tree_grows_by_doubling_and_truncates() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let mut tree = PublicTree::new(16).unwrap();
    let mut widths = Vec::new();
    for tag in 0..5 {
        let member = join(&mut tree, tag, &mut rng);
        assert_eq!(member.leaf, tag);
        widths.push(tree.width());
    }
    assert_eq!(widths, vec![1, 2, 4, 4, 8]);
    assert_eq!(tree.member_count(), 5);
    assert_eq!(tree.find_device(&device_pk(3)), Some(3));
    assert_eq!(tree.member(3, 0).map(|m| m.admission_hash), Some([3; 32]));
    assert!(tree.member(3, 1).is_none());

    // A blank leaf is reused before the tree grows.
    tree.remove_leaf(1).unwrap();
    assert_eq!(tree.entry_leaf(), Some(1));
    // Removing the rightmost members halves the tree.
    tree.remove_leaf(4).unwrap();
    tree.truncate();
    assert_eq!(tree.width(), 4);
    tree.remove_leaf(3).unwrap();
    tree.remove_leaf(2).unwrap();
    tree.truncate();
    assert_eq!(tree.width(), 1, "only leaf 0 remains");
    assert_eq!(tree.direct_path(0).unwrap(), Vec::<u32>::new());
    assert_eq!(tree.root(), 0);
    let decoded = PublicTree::from_cbor(&tree.to_cbor().unwrap()).unwrap();
    assert_eq!(decoded, tree);
}

#[test]
fn entering_leaves_are_unmerged_under_keyed_parents() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let mut tree = PublicTree::new(8).unwrap();
    let mut members = vec![join(&mut tree, 0, &mut rng), join(&mut tree, 1, &mut rng)];
    commit(&mut tree, &mut members, 0, 1, &mut rng);
    assert!(tree.parent_node(1).is_some());

    // The tree grows: the new root is blank, the old root keeps its key.
    members.push(join(&mut tree, 2, &mut rng));
    assert_eq!(tree.width(), 4);
    assert_eq!(tree.root(), 3);
    assert!(tree.parent_node(3).is_none());
    assert_eq!(tree.resolution(5), vec![4]);
    commit(&mut tree, &mut members, 1, 2, &mut rng);
    assert_eq!(tree.parent_node(3).unwrap().unmerged, Vec::<u32>::new());

    // A member entering below keyed parents is unmerged at each of them.
    members.push(join(&mut tree, 3, &mut rng));
    assert_eq!(members[3].leaf, 3);
    assert_eq!(tree.parent_node(3).unwrap().unmerged, vec![3]);
    assert!(tree.parent_node(5).is_none(), "leaf 2's parent is blank");
    assert_eq!(tree.resolution(3), vec![3, 6]);
    assert_eq!(tree.resolution(5), vec![4, 6]);
    // Leaf 3 decrypts the next path with its leaf key (W1) and is merged.
    let before = tree.tree_hash().unwrap();
    commit(&mut tree, &mut members, 0, 3, &mut rng);
    assert_ne!(before, tree.tree_hash().unwrap());
    assert!(tree.parent_node(3).unwrap().unmerged.is_empty());
    assert!(members[3].private.nodes.contains_key(&3));
    // Resync: the same leaf gets a new occupancy and is unmerged again
    // until its path is re-keyed.
    let key = KemSecret::generate(&mut rng);
    tree.replace_leaf(3, member_node(3, 4, key.public_key()))
        .unwrap();
    assert_eq!(tree.parent_node(3).unwrap().unmerged, vec![3]);
    assert!(
        tree.replace_leaf(3, member_node(3, 4, key.public_key()))
            .is_ok()
    );
    assert_eq!(
        tree.parent_node(3).unwrap().unmerged,
        vec![3],
        "no duplicate"
    );
    tree.set_device_key(3, &device_pk(30)).unwrap();
    assert_eq!(tree.find_device(&device_pk(30)), Some(3));
    assert!(tree.set_device_key(9, &device_pk(31)).is_err());
    let decoded = PublicTree::from_cbor(&tree.to_cbor().unwrap()).unwrap();
    assert_eq!(decoded.tree_hash().unwrap(), tree.tree_hash().unwrap());
}

#[test]
fn members_agree_on_commit_secrets_across_joins_and_removals() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let mut tree = PublicTree::new(16).unwrap();
    let mut members: Vec<Member> = (0..5).map(|tag| join(&mut tree, tag, &mut rng)).collect();
    let first = commit(&mut tree, &mut members, 0, 1, &mut rng);
    let second = commit(&mut tree, &mut members, 3, 2, &mut rng);
    assert_ne!(first, second);

    // Remove leaf 1: its path is blanked; members forget the blanked keys.
    let removed = members.remove(1);
    tree.remove_leaf(removed.leaf).unwrap();
    for member in &mut members {
        member.private.retain_live(&tree);
    }
    // Two members join without committing, then leaf 4 commits.
    members.push(join(&mut tree, 10, &mut rng));
    members.push(join(&mut tree, 11, &mut rng));
    let third = commit(&mut tree, &mut members, 3, 3, &mut rng);
    let fourth = commit(&mut tree, &mut members, 5, 4, &mut rng);
    assert_ne!(third, fourth);

    // The removed member is not covered by later paths.
    let context = PathContext {
        gid: [0x42; 32],
        epoch: 5,
        author_leaf: 0,
    };
    let (path, _) = generate_update_path(&tree, &context, &mut rng).unwrap();
    let stale = decrypt_update_path(&tree, &context, &path, removed.leaf, &removed.private);
    assert!(stale.is_err(), "a removed member cannot decrypt");
}

#[test]
fn a_single_member_tree_still_yields_fresh_commit_secrets() {
    let mut rng = ChaCha20Rng::seed_from_u64(8);
    let mut tree = PublicTree::new(4).unwrap();
    let mut members = vec![join(&mut tree, 0, &mut rng)];
    let first = commit(&mut tree, &mut members, 0, 1, &mut rng);
    let second = commit(&mut tree, &mut members, 0, 2, &mut rng);
    assert_ne!(first, second);
    assert!(members[0].private.nodes.is_empty());
}

#[test]
fn tampered_paths_are_rejected() {
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let mut tree = PublicTree::new(4).unwrap();
    let members: Vec<Member> = (0..3).map(|tag| join(&mut tree, tag, &mut rng)).collect();
    let context = PathContext {
        gid: [1; 32],
        epoch: 1,
        author_leaf: 0,
    };
    let (path, _) = generate_update_path(&tree, &context, &mut rng).unwrap();

    let mut missing = path.clone();
    missing.nodes[0].targets.clear();
    assert_eq!(
        validate_update_path(&tree, 0, &missing),
        Err(CoreError::Invalid("update path targets"))
    );
    let mut wrong_node = path.clone();
    wrong_node.nodes[0].node = 5;
    assert!(validate_update_path(&tree, 0, &wrong_node).is_err());
    let mut short = path.clone();
    short.nodes.pop();
    assert!(validate_update_path(&tree, 0, &short).is_err());
    assert!(validate_update_path(&tree, 3, &path).is_err(), "blank leaf");
    let mut truncated = path.clone();
    truncated.nodes[0].targets[0].wrapped_secret.pop();
    assert_eq!(
        validate_update_path(&tree, 0, &truncated),
        Err(CoreError::Malformed("update path ciphertext"))
    );

    // A wrong public key is detected by the members that can derive it.
    let mut forged = path.clone();
    forged.nodes[1].public_key = KemSecret::generate(&mut rng).public_key();
    let err = decrypt_update_path(&tree, &context, &forged, 1, &members[1].private);
    assert_eq!(
        err.err(),
        Some(CoreError::Invalid("update path public key mismatch"))
    );
    // A wrong context fails authentication.
    let other = PathContext {
        epoch: 2,
        ..context
    };
    assert!(decrypt_update_path(&tree, &other, &path, 1, &members[1].private).is_err());
    assert!(decrypt_update_path(&tree, &context, &path, 0, &members[0].private).is_err());
    // A member without the matching key cannot decrypt.
    let stranger = PrivatePath {
        leaf: Some(KemSecret::generate(&mut rng)),
        nodes: BTreeMap::new(),
    };
    assert!(decrypt_update_path(&tree, &context, &path, 1, &stranger).is_err());
    let keyless = PrivatePath::default();
    assert_eq!(
        decrypt_update_path(&tree, &context, &path, 1, &keyless).err(),
        Some(CoreError::Decrypt("no path secret for this member"))
    );
}

#[test]
fn encodings_round_trip_and_reject_non_canonical_trees() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let mut tree = PublicTree::new(4).unwrap();
    let mut members: Vec<Member> = (0..3).map(|tag| join(&mut tree, tag, &mut rng)).collect();
    commit(&mut tree, &mut members, 2, 1, &mut rng);
    let decoded = PublicTree::from_cbor(&tree.to_cbor().unwrap()).unwrap();
    assert_eq!(decoded, tree);
    assert_eq!(decoded.tree_hash().unwrap(), tree.tree_hash().unwrap());
    let context = PathContext {
        gid: [2; 32],
        epoch: 2,
        author_leaf: 1,
    };
    let (path, _) = generate_update_path(&tree, &context, &mut rng).unwrap();
    let value = update_path_to_value(&path);
    assert_eq!(update_path_from_value(value).unwrap(), path);
    assert!(update_path_from_value(uint(1)).is_err());
    assert!(PublicTree::from_cbor(&[0x80]).is_err());
    assert!(tree.add_leaf(0, tree.leaf(0).unwrap().clone()).is_err());
    assert!(tree.remove_leaf(3).is_err());
    assert!(tree.remove_leaf(7).is_err());
    assert!(tree.replace_leaf(3, tree.leaf(0).unwrap().clone()).is_err());
    let mut bad = tree.clone();
    bad.apply_update_path(3, &path).unwrap_err();

    let reencode = |tree: &PublicTree| PublicTree::from_cbor(&tree.to_cbor().unwrap());
    // Not truncated: the right half holds no member.
    let mut wide = tree.clone();
    wide.capacity = 8;
    wide.leaves.resize(8, None);
    wide.parents.resize(7, None);
    assert_eq!(
        reencode(&wide),
        Err(CoreError::Malformed("tree is not truncated"))
    );
    // Wider than the capacity.
    let mut over = tree.clone();
    over.capacity = 2;
    assert_eq!(reencode(&over), Err(CoreError::Malformed("tree size")));
    // Two leaves with one device key.
    let mut duplicate = tree.clone();
    duplicate.leaves[1] = duplicate.leaves[0].clone();
    assert_eq!(
        reencode(&duplicate),
        Err(CoreError::Malformed("duplicate device key in the tree"))
    );
    // Unmerged leaves must be members below their node, in order.
    let mut stray = tree.clone();
    stray.parents[1].as_mut().unwrap().unmerged = vec![1, 0];
    assert_eq!(
        reencode(&stray),
        Err(CoreError::Malformed("tree unmerged leaves"))
    );
    let mut outside = tree.clone();
    outside.parents[0] = outside.parents[1].clone();
    outside.parents[0].as_mut().unwrap().unmerged = vec![2];
    assert_eq!(
        reencode(&outside),
        Err(CoreError::Malformed("tree unmerged leaves"))
    );
    let mut empty = PublicTree::new(4).unwrap();
    assert_eq!(
        reencode(&empty),
        Err(CoreError::Malformed("tree without members"))
    );
    empty.leaves.clear();
    assert_eq!(reencode(&empty), Err(CoreError::Malformed("tree size")));
}

#[test]
fn worst_case_update_paths_fit_the_bound() {
    // A full tree without parent keys maximizes the copath resolutions: the
    // author encrypts to every other leaf.
    let mut rng = ChaCha20Rng::seed_from_u64(13);
    for capacity in [2u32, 4, 16, 64] {
        let mut tree = PublicTree::new(capacity).unwrap();
        for tag in 0..capacity {
            join(&mut tree, tag, &mut rng);
        }
        let context = PathContext {
            gid: [3; 32],
            epoch: 1,
            author_leaf: capacity - 1,
        };
        let (path, _) = generate_update_path(&tree, &context, &mut rng).unwrap();
        validate_update_path(&tree, context.author_leaf, &path).unwrap();
        let targets: usize = path.nodes.iter().map(|node| node.targets.len()).sum();
        assert_eq!(targets, capacity as usize - 1);
        let encoded = encode(&update_path_to_value(&path)).unwrap();
        assert!(
            encoded.len() <= max_update_path_bytes(capacity),
            "capacity {capacity}: {} > {}",
            encoded.len(),
            max_update_path_bytes(capacity)
        );
    }
}

#[test]
fn leaf_proofs_verify_against_the_tree_hash() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let mut tree = PublicTree::new(16).unwrap();
    let mut members: Vec<Member> = (0..7).map(|tag| join(&mut tree, tag, &mut rng)).collect();
    commit(&mut tree, &mut members, 2, 1, &mut rng);
    // A blank leaf and an unmerged leaf below keyed parents.
    tree.remove_leaf(5).unwrap();
    join(&mut tree, 20, &mut rng);
    tree.remove_leaf(6).unwrap();
    let tree_hash = tree.tree_hash().unwrap();
    let hashes = tree.node_hashes().unwrap();
    assert_eq!(hashes.len(), 2 * tree.width() as usize - 1);
    assert_eq!(hashes[tree.root() as usize], tree_hash);

    let proofs = tree.leaf_proofs(0..tree.width()).unwrap();
    for proof in &proofs {
        proof.verify(&tree_hash).unwrap();
        assert_eq!(proof.node.as_ref(), tree.leaf(proof.leaf));
        assert_eq!(proof.path.len(), tree.width().trailing_zeros() as usize);
        let decoded = LeafProof::decode(&proof.encode().unwrap()).unwrap();
        assert_eq!(&decoded, proof);
        assert!(proof.encode().unwrap().len() < MAX_LEAF_PROOF_BYTES);
        match proof.member() {
            Some((member, record)) => {
                assert_eq!(member.since, record.since);
                assert_eq!(tree.member_by_ref(member), Some(record));
            }
            None => assert!(tree.leaf(proof.leaf).is_none()),
        }
    }
    assert!(proofs.iter().any(|proof| proof.node.is_none()));
    assert_eq!(tree.leaf_proof(3).unwrap(), proofs[3]);
    assert!(tree.leaf_proof(tree.width()).is_err());

    // Any change breaks the proof.
    let proof = &proofs[3];
    let mut forged = proof.clone();
    forged.node.as_mut().unwrap().since = 9;
    assert!(forged.verify(&tree_hash).is_err());
    let mut forged = proof.clone();
    forged.node = None;
    assert!(forged.verify(&tree_hash).is_err());
    let mut forged = proof.clone();
    forged.path[1].sibling[5] ^= 1;
    assert!(forged.verify(&tree_hash).is_err());
    let mut forged = proof.clone();
    forged.path[0].parent = match forged.path[0].parent {
        Some(_) => None,
        None => Some([0; 32]),
    };
    assert!(forged.verify(&tree_hash).is_err());
    let mut forged = proof.clone();
    forged.leaf = 2;
    assert!(forged.verify(&tree_hash).is_err());
    for width in [3, 4, 32, MAX_CAPACITY * 2] {
        let mut forged = proof.clone();
        forged.width = width;
        assert!(forged.verify(&tree_hash).is_err());
    }
    let mut forged = proof.clone();
    forged.path.pop();
    assert!(forged.verify(&tree_hash).is_err());
    let mut forged = proof.clone();
    forged.leaf = 99;
    assert!(forged.verify(&tree_hash).is_err());
    assert!(LeafProof::decode(&[0x80]).is_err());
    assert!(LeafProof::decode(&[0u8; MAX_LEAF_PROOF_BYTES + 1]).is_err());

    // A single-leaf tree: the proof is the leaf itself.
    let mut single = PublicTree::new(2).unwrap();
    join(&mut single, 0, &mut rng);
    let proof = single.leaf_proof(0).unwrap();
    assert!(proof.path.is_empty());
    proof.verify(&single.tree_hash().unwrap()).unwrap();
}

#[test]
fn index_helpers_match_the_tree() {
    let mut rng = ChaCha20Rng::seed_from_u64(12);
    let mut tree = PublicTree::new(32).unwrap();
    for tag in 0..11 {
        join(&mut tree, tag, &mut rng);
    }
    for leaf in [0u32, 1, 5, 10] {
        let path = tree.direct_path(leaf).unwrap();
        for (index, node) in path.iter().enumerate() {
            assert_eq!(ancestor(leaf, index as u32 + 1), *node);
        }
        assert_eq!(ancestor(leaf, 0), leaf_node(leaf));
        for other in [0u32, 3, 7, 10] {
            if other == leaf {
                continue;
            }
            let level = common_ancestor_level(leaf, other);
            let lca = ancestor(leaf, level);
            assert_eq!(lca, ancestor(other, level));
            assert!(level == 1 || ancestor(leaf, level - 1) != ancestor(other, level - 1));
            assert!(is_ancestor_or_self(lca, leaf_node(other)));
        }
    }
    let occupied = |tree: &PublicTree| tree.members().map(|(leaf, _)| leaf).collect::<Vec<_>>();
    for removed in [3u32, 0, 10, 9, 8] {
        tree.remove_leaf(removed).unwrap();
        assert_eq!(entry_leaf_of(occupied(&tree), 32), tree.entry_leaf());
        let mut truncated = tree.clone();
        truncated.truncate();
        assert_eq!(canonical_width(occupied(&tree)), truncated.width());
    }
    assert_eq!(canonical_width([]), 1);
    assert_eq!(canonical_width([0]), 1);
    assert_eq!(canonical_width([4, 1]), 8);
    assert_eq!(entry_leaf_of([0, 1], 2), None);
    assert_eq!(entry_leaf_of([0, 1], 4), Some(2));
    assert_eq!(entry_leaf_of([1, 2], 4), Some(0));
}
