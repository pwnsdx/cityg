#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::todo,
    clippy::unimplemented
)]

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anchor_seed::{build_anchor_seed_ctx, compute_seed_ctx_hash};
use blake3::Hasher;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ciborium::value::{Integer, Value};
use msphf_core::params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_A1};
use msphf_core::{
    ds,
    hash::h_l,
    instance, merkle,
    witness::{
        CanonicalWitness, RawMembershipWitness, RawNonMembershipWitness, RawPathEntry,
        WitnessVariants,
    },
};
use msphf_orchestrator::HpBindingInputs;
use msphf_orchestrator::hdr::{HDR_BOOTSTRAP_ALG, HDR_BOOTSTRAP_PK, HDR_BOOTSTRAP_SIG, HDR_CRS_ID};
use msphf_orchestrator::mhw::{DEFAULT_H_MAX, DEFAULT_T_WINDOW};
use msphf_orchestrator::{
    AcceptanceContext, AcceptanceError, AcceptanceKind, AcceptanceOptions, AnchorInstanceParts,
    BootstrapPolicy, DEFAULT_POLICY_VERSION, DEFAULT_PROOF_MODE, DEFAULT_VRF_ID, FsJoinInputs,
    FsMergeInputs, LeafIdMode, OrchestrationParams, PopKeypair, SrxInputs, SrxMode,
    SrxNonMembershipAnchor, build_bootstrap_digest, extract_epoch_msphf_or, joiner_kgen_merge_or,
    joiner_kgen_or,
};
use pqcrypto_dilithium::dilithium5::{
    SecretKey as MlDsaSecretKey, detached_sign, keypair as dsa_keypair,
};
use pqcrypto_kyber::kyber768::keypair as kyber_keypair;
use pqcrypto_kyber::kyber768::{
    Ciphertext as MlKemCiphertext, SecretKey as MlKemSecretKey, decapsulate as ml_kem_decapsulate,
};
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait,
    SecretKey as KemSecretKeyTrait, SharedSecret as KemSharedSecretTrait,
};
use pqcrypto_traits::sign::{
    DetachedSignature as SignDetachedSignatureTrait, PublicKey as SignPublicKeyTrait,
};
use serde::Serialize;

fn fixture_pop_keys() -> (&'static [u8], &'static MlDsaSecretKey) {
    static POP_KEYS: OnceLock<(&'static [u8], &'static MlDsaSecretKey)> = OnceLock::new();
    *POP_KEYS.get_or_init(|| {
        let (pk, sk) = dsa_keypair();
        let pk_static: &'static [u8] = Box::leak(pk.as_bytes().to_vec().into_boxed_slice());
        let sk_static: &'static MlDsaSecretKey = Box::leak(Box::new(sk));
        (pk_static, sk_static)
    })
}

#[cfg(feature = "zkvrf-pq")]
fn fixture_vrf_keys() -> (&'static [u8], &'static [u8]) {
    static VRF_KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    let pair = VRF_KEYS.get_or_init(|| {
        let params = match msphf_orchestrator::lb::generate_parameters([0u8; 32]) {
            Ok(params) => params,
            Err(_) => unreachable!("deterministic test VRF params must be derivable"),
        };
        match msphf_orchestrator::lb::generate_keypair(&params, [1u8; 32]) {
            Ok(pair) => pair,
            Err(_) => unreachable!("deterministic test VRF keypair must be derivable"),
        }
    });
    (&pair.0, &pair.1)
}

fn witness_branch_a(root: &[u8; 32]) -> CanonicalWitness {
    CanonicalWitness {
        inner: WitnessVariants::A {
            witness: RawMembershipWitness {
                leaf_id: root.to_vec(),
                root: root.to_vec(),
                path: Vec::new(),
            },
            pop: None,
        },
    }
}

fn witness_branch_b(
    join_root: &[u8; 32],
    _parent_root: &[u8; 32],
    revoked_root: &[u8; 32],
) -> CanonicalWitness {
    CanonicalWitness {
        inner: WitnessVariants::B {
            witness: RawMembershipWitness {
                leaf_id: join_root.to_vec(),
                root: join_root.to_vec(),
                path: Vec::new(),
            },
            nonmem: Some(RawNonMembershipWitness {
                query: join_root.to_vec(),
                root: revoked_root.to_vec(),
                left: None,
                right: None,
                path: Vec::new(),
                left_below: Vec::new(),
                right_below: Vec::new(),
                above: Vec::new(),
                nmint: None,
                lca_left_height: None,
                lca_right_height: None,
            }),
            pop: None,
        },
    }
}

fn serialize_witness(witness: &CanonicalWitness) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    into_writer(witness, &mut buf)?;
    Ok(buf)
}

fn build_noncanonical_witness(membership_root: &[u8; 32], _revoked_root: &[u8; 32]) -> Vec<u8> {
    let invalid = CanonicalWitness {
        inner: WitnessVariants::B {
            witness: RawMembershipWitness {
                leaf_id: membership_root.to_vec(),
                root: vec![0xFF; 32],
                path: Vec::new(),
            },
            nonmem: None,
            pop: None,
        },
    };
    serialize_witness(&invalid).unwrap()
}

fn sentinel_nonmem(root: [u8; 32], query: [u8; 32]) -> RawNonMembershipWitness {
    RawNonMembershipWitness {
        query: query.to_vec(),
        root: root.to_vec(),
        left: None,
        right: None,
        path: Vec::new(),
        left_below: Vec::new(),
        right_below: Vec::new(),
        above: Vec::new(),
        nmint: None,
        lca_left_height: None,
        lca_right_height: None,
    }
}

fn leak_bytes32(bytes: [u8; 32]) -> &'static [u8] {
    Box::leak(Box::new(bytes)).as_slice()
}

fn default_join_leaves() -> Vec<[u8; 32]> {
    let mut leaves = vec![
        merkle::hash_leaf(b"join-leaf-0"),
        merkle::hash_leaf(b"join-leaf-1"),
        merkle::hash_leaf(b"join-leaf-2"),
    ];
    leaves.sort();
    leaves
}

fn slice_to_array32(slice: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(slice);
    arr
}

fn canonical_membership_path(leaves: &[[u8; 32]], target: &[u8; 32]) -> Option<Vec<RawPathEntry>> {
    if leaves.len() <= 1 {
        return Some(Vec::new());
    }

    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut index = level.iter().position(|leaf| leaf == target)?;
    let mut path = Vec::new();

    while level.len() > 1 {
        let len = level.len();
        if index % 2 == 0 {
            if index + 1 < len {
                path.push(RawPathEntry {
                    dir: 0,
                    sibling: level[index + 1].to_vec(),
                });
            }
        } else {
            path.push(RawPathEntry {
                dir: 1,
                sibling: level[index - 1].to_vec(),
            });
        }

        let mut next = Vec::with_capacity(len.div_ceil(2));
        for chunk in level.chunks_exact(2) {
            next.push(merkle::hash_node(&chunk[0], &chunk[1]));
        }
        let mut new_index = index / 2;
        if len % 2 == 1 {
            let carry = *level.last()?;
            next.push(carry);
            if index == len - 1 {
                new_index = next.len() - 1;
            }
        }
        level = next;
        index = new_index;
    }

    Some(path)
}

fn fold_step_into(acc: &mut [u8; 32], entry: &RawPathEntry) -> Option<()> {
    if entry.sibling.len() != 32 {
        return None;
    }
    let sibling: [u8; 32] = entry.sibling.as_slice().try_into().ok()?;
    match entry.dir {
        0 => {
            *acc = merkle::hash_node(acc, &sibling);
            Some(())
        }
        1 => {
            *acc = merkle::hash_node(&sibling, acc);
            Some(())
        }
        _ => None,
    }
}

fn build_chain(leaf: [u8; 32], path: &[RawPathEntry]) -> Option<Vec<[u8; 32]>> {
    let mut chain = Vec::with_capacity(path.len() + 1);
    let mut acc = leaf;
    chain.push(acc);
    for entry in path {
        fold_step_into(&mut acc, entry)?;
        chain.push(acc);
    }
    Some(chain)
}

type SplitIntervalPaths = (Vec<RawPathEntry>, Vec<RawPathEntry>, Vec<RawPathEntry>, u8, u8);

fn split_interval_paths(
    left_leaf: [u8; 32],
    left_path: &[RawPathEntry],
    right_leaf: [u8; 32],
    right_path: &[RawPathEntry],
    parent_root: [u8; 32],
) -> Option<SplitIntervalPaths> {
    let left_chain = build_chain(left_leaf, left_path)?;
    let right_chain = build_chain(right_leaf, right_path)?;
    if *left_chain.last()? != parent_root || *right_chain.last()? != parent_root {
        return None;
    }

    let mut common = 0usize;
    while common < left_chain.len() && common < right_chain.len() {
        let l = left_chain[left_chain.len() - 1 - common];
        let r = right_chain[right_chain.len() - 1 - common];
        if l == r {
            common += 1;
        } else {
            break;
        }
    }
    if common == 0 {
        return None;
    }

    let left_len = left_path.len();
    let right_len = right_path.len();
    if common > left_len || common > right_len {
        return None;
    }
    let lca_step_left = left_len - common;
    let lca_step_right = right_len - common;
    let left_below = left_path[..lca_step_left].to_vec();
    let right_below = right_path[..lca_step_right].to_vec();

    let shared_suffix_len = common.saturating_sub(1);
    let above = if shared_suffix_len > 0 {
        let start_left = left_len - shared_suffix_len;
        let start_right = right_len - shared_suffix_len;
        let suffix_left = &left_path[start_left..];
        let suffix_right = &right_path[start_right..];
        if suffix_left.len() != suffix_right.len() {
            return None;
        }
        for (l_entry, r_entry) in suffix_left.iter().zip(suffix_right.iter()) {
            if l_entry.dir != r_entry.dir || l_entry.sibling != r_entry.sibling {
                return None;
            }
        }
        suffix_left.to_vec()
    } else {
        Vec::new()
    };

    let l_h = u8::try_from(left_below.len() + 1).ok()?;
    let r_h = u8::try_from(right_below.len() + 1).ok()?;
    Some((left_below, right_below, above, l_h, r_h))
}

fn parent_nonmem_witness(
    parent_leaves: &[[u8; 32]],
    parent_root: [u8; 32],
    query: [u8; 32],
) -> (RawNonMembershipWitness, Option<[u8; 32]>, Option<[u8; 32]>) {
    if parent_leaves.is_empty() {
        let witness = RawNonMembershipWitness {
            query: query.to_vec(),
            root: parent_root.to_vec(),
            left: None,
            right: None,
            path: Vec::new(),
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: None,
            lca_left_height: None,
            lca_right_height: None,
        };
        return (witness, None, None);
    }

    let mut pos = 0;
    while pos < parent_leaves.len() && parent_leaves[pos] < query {
        pos += 1;
    }

    let left = if pos > 0 {
        Some(parent_leaves[pos - 1])
    } else {
        None
    };
    let right = if pos < parent_leaves.len() {
        Some(parent_leaves[pos])
    } else {
        None
    };

    match (left, right) {
        (Some(l), Some(r)) => {
            let left_path = canonical_membership_path(parent_leaves, &l).unwrap();
            let right_path = canonical_membership_path(parent_leaves, &r).unwrap();
            let (left_below, right_below, above, lca_left_h, lca_right_h) =
                split_interval_paths(l, &left_path, r, &right_path, parent_root).unwrap();
            let witness = RawNonMembershipWitness {
                query: query.to_vec(),
                root: parent_root.to_vec(),
                left: Some(l.to_vec()),
                right: Some(r.to_vec()),
                path: Vec::new(),
                left_below,
                right_below,
                above,
                nmint: Some(
                    merkle::hash_interval_binding(&l, &l, &r, &r, lca_left_h, lca_right_h)
                        .to_vec(),
                ),
                lca_left_height: Some(lca_left_h),
                lca_right_height: Some(lca_right_h),
            };
            (witness, Some(l), Some(r))
        }
        (Some(l), None) => {
            let witness = RawNonMembershipWitness {
                query: query.to_vec(),
                root: parent_root.to_vec(),
                left: Some(l.to_vec()),
                right: None,
                path: canonical_membership_path(parent_leaves, &l).unwrap(),
                left_below: Vec::new(),
                right_below: Vec::new(),
                above: Vec::new(),
                nmint: None,
                lca_left_height: None,
                lca_right_height: None,
            };
            (witness, Some(l), None)
        }
        (None, Some(r)) => {
            let witness = RawNonMembershipWitness {
                query: query.to_vec(),
                root: parent_root.to_vec(),
                left: None,
                right: Some(r.to_vec()),
                path: canonical_membership_path(parent_leaves, &r).unwrap(),
                left_below: Vec::new(),
                right_below: Vec::new(),
                above: Vec::new(),
                nmint: None,
                lca_left_height: None,
                lca_right_height: None,
            };
            (witness, None, Some(r))
        }
        (None, None) => {
            let witness = RawNonMembershipWitness {
                query: query.to_vec(),
                root: parent_root.to_vec(),
                left: None,
                right: None,
                path: Vec::new(),
                left_below: Vec::new(),
                right_below: Vec::new(),
                above: Vec::new(),
                nmint: None,
                lca_left_height: None,
                lca_right_height: None,
            };
            (witness, None, None)
        }
    }
}

fn build_srx_inputs(
    join_leaves: &[[u8; 32]],
    parent_leaves: &[[u8; 32]],
    parent_root: [u8; 32],
    revoked_since_root: [u8; 32],
    revoked_since_leaves: &[[u8; 32]],
    revoked_leaves: &[[u8; 32]],
    revoked_root: [u8; 32],
) -> Option<SrxInputs<'static>> {
    use std::collections::{BTreeMap, HashMap};

    let mut parent_sorted = parent_leaves.to_vec();
    parent_sorted.sort();
    let expected_parent_root = merkle::canonical_set_root(&parent_sorted).ok()?;
    assert_eq!(
        expected_parent_root, parent_root,
        "parent root must match canonical set root"
    );

    let mut anchor_map: BTreeMap<([u8; 32], [u8; 32]), RawMembershipWitness> = BTreeMap::new();
    let mut join_nonmem_parent_temp = Vec::new();

    for leaf in join_leaves.iter().copied() {
        let (witness, left_anchor, right_anchor) =
            parent_nonmem_witness(&parent_sorted, parent_root, leaf);
        let left_key = left_anchor.map(|anchor_leaf| (parent_root, anchor_leaf));
        let right_key = right_anchor.map(|anchor_leaf| (parent_root, anchor_leaf));

        if let Some((root, leaf_id)) = left_key {
            anchor_map
                .entry((root, leaf_id))
                .or_insert_with(|| RawMembershipWitness {
                    leaf_id: leaf_id.to_vec(),
                    root: root.to_vec(),
                    path: canonical_membership_path(&parent_sorted, &leaf_id).unwrap(),
                });
        }
        if let Some((root, leaf_id)) = right_key {
            anchor_map
                .entry((root, leaf_id))
                .or_insert_with(|| RawMembershipWitness {
                    leaf_id: leaf_id.to_vec(),
                    root: root.to_vec(),
                    path: canonical_membership_path(&parent_sorted, &leaf_id).unwrap(),
                });
        }

        join_nonmem_parent_temp.push((witness, left_key, right_key));
    }

    let mut anchor_mem_pool = Vec::new();
    let mut anchor_lookup: HashMap<([u8; 32], [u8; 32]), u32> = HashMap::new();
    for (idx, (key, witness)) in anchor_map.into_iter().enumerate() {
        anchor_mem_pool.push(witness);
        anchor_lookup.insert(key, idx as u32);
    }

    let join_nonmem_parent = join_nonmem_parent_temp
        .into_iter()
        .map(|(witness, left_key, right_key)| SrxNonMembershipAnchor {
            left_ref: left_key.map(|key| anchor_lookup[&key]),
            right_ref: right_key.map(|key| anchor_lookup[&key]),
            witness,
        })
        .collect();

    let join_nonmem_revoked_since = join_leaves
        .iter()
        .map(|leaf| SrxNonMembershipAnchor {
            witness: sentinel_nonmem(revoked_since_root, *leaf),
            left_ref: None,
            right_ref: None,
        })
        .collect();

    let mut revoked_since_sorted = revoked_since_leaves.to_vec();
    revoked_since_sorted.sort();
    let expected_since_root = merkle::canonical_set_root(&revoked_since_sorted).ok()?;
    assert_eq!(
        expected_since_root, revoked_since_root,
        "revoked_since_root must match canonical root of revoked_since_leaves"
    );

    let mut revoked_sorted = revoked_leaves.to_vec();
    revoked_sorted.sort();
    let expected_revoked_root = merkle::canonical_set_root(&revoked_sorted).ok()?;
    assert_eq!(
        expected_revoked_root, revoked_root,
        "revoked_root must match canonical root of revoked_leaves"
    );

    let since_mem_revoked: Vec<RawMembershipWitness> = revoked_since_sorted
        .iter()
        .map(|leaf| {
            assert!(
                revoked_sorted.contains(leaf),
                "revoked leaf must appear in revoked set"
            );
            RawMembershipWitness {
                leaf_id: leaf.to_vec(),
                root: revoked_root.to_vec(),
                path: canonical_membership_path(&revoked_sorted, leaf).unwrap(),
            }
        })
        .collect();

    Some(SrxInputs {
        join_leaf_ids: Cow::Owned(join_leaves.to_vec()),
        join_nonmem_parent,
        join_nonmem_revoked_since,
        since_leaf_ids: Cow::Owned(revoked_since_sorted),
        since_mem_revoked: Cow::Owned(since_mem_revoked),
        anchor_mem_pool,
        join_frontier: None,
        since_frontier: None,
    })
}

fn make_anchor_fixture(
    config: AnchorFixtureConfig,
) -> Option<(
    AnchorInstanceParts<'static>,
    OrchestrationParams<'static>,
    Vec<[u8; 32]>,
)> {
    let (pop_pk, pop_sk) = fixture_pop_keys();
    let mut join_leaves = config.join_leaves.clone();
    if let Ok(pop_leaf) =
        msphf_orchestrator::compute_leaf_id(LeafIdMode::PerGroup, &config.gid, "ML-DSA-65", pop_pk)
    {
        join_leaves.push(pop_leaf);
    }
    join_leaves.sort();
    join_leaves.dedup();
    let join_root = merkle::canonical_set_root(&join_leaves).ok()?;

    let mut parent_leaves = config.parent_leaves.clone();
    parent_leaves.sort();
    let parent_root_canonical = merkle::canonical_set_root(&parent_leaves).ok()?;
    assert_eq!(
        parent_root_canonical, config.parent_root,
        "parent_root must match canonical root of parent_leaves",
    );

    let mut revoked_since_leaves = config.revoked_since_leaves.clone();
    revoked_since_leaves.sort();
    let revoked_since_root_canonical = merkle::canonical_set_root(&revoked_since_leaves).ok()?;
    assert_eq!(
        revoked_since_root_canonical, config.revoked_since_root,
        "revoked_since_root must match canonical root of revoked_since_leaves",
    );

    let mut revoked_leaves = config.revoked_leaves.clone();
    revoked_leaves.sort();
    let revoked_root_canonical = merkle::canonical_set_root(&revoked_leaves).ok()?;
    assert_eq!(
        revoked_root_canonical, config.revoked_root,
        "revoked_root must match canonical root of revoked_leaves",
    );

    let parts = AnchorInstanceParts {
        gid: leak_bytes32(config.gid),
        cat: leak_bytes32(config.cat),
        tswe_salt_hash: {
            let salt =
                msphf_core::instance::tswe_salt_hash(&config.gid, &config.parent_root).ok()?;
            leak_bytes32(salt)
        },
        parent_root: leak_bytes32(config.parent_root),
        join_delta_root: leak_bytes32(join_root),
        revoked_since_prev_root: leak_bytes32(config.revoked_since_root),
        revoked_root: leak_bytes32(config.revoked_root),
        pox_r_commit: Some(leak_bytes32(config.pox_commit)),
    };

    let srx_inputs = build_srx_inputs(
        &join_leaves,
        &parent_leaves,
        config.parent_root,
        config.revoked_since_root,
        &revoked_since_leaves,
        &revoked_leaves,
        config.revoked_root,
    )
    .unwrap();
    #[cfg(feature = "zkvrf-pq")]
    let (vrf_secret_key, vrf_public_key) = fixture_vrf_keys();
    let mut fs_epoch_commit = [0u8; 32];
    let mut fs_commit_hasher = Hasher::new();
    fs_commit_hasher.update(b"end-to-end-fs-epoch");
    fs_epoch_commit.copy_from_slice(fs_commit_hasher.finalize().as_bytes());

    let params = OrchestrationParams {
        msphf_crs_id: RLWE_CRS_ID_DEFAULT,
        params_id: RLWE_PARAMS_ID_A1,
        srx: Some(srx_inputs),
        srx_mode: SrxMode::Complete,
        pop_keys: Some(PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: pop_pk,
            secret_key: pop_sk,
        }),
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode: DEFAULT_PROOF_MODE,
        vrf_id: DEFAULT_VRF_ID,
        policy_version: DEFAULT_POLICY_VERSION,
        vrf_secret_key: {
            #[cfg(feature = "zkvrf-pq")]
            {
                Some(vrf_secret_key)
            }
            #[cfg(not(feature = "zkvrf-pq"))]
            {
                None
            }
        },
        vrf_public_key: {
            #[cfg(feature = "zkvrf-pq")]
            {
                Some(vrf_public_key)
            }
            #[cfg(not(feature = "zkvrf-pq"))]
            {
                None
            }
        },
        fs_policy_version: "fs-test-policy",
        fs_epoch_base_ts: 0,
        fs_join: FsJoinInputs {
            fs_ec: 0,
            fs_epoch_commit,
            fs_dev_prev_commit: [0u8; 32],
        },
        fs_merge: FsMergeInputs::default(),
    };

    Some((parts, params, join_leaves))
}

#[derive(Serialize)]
struct SrxCommit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

fn compute_srx_commit(bytes: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(h_l(ds::MSPHF_SRX_COMMIT, &SrxCommit(bytes))?)
}

fn encode_value(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    into_writer(value, &mut buf)?;
    Ok(buf)
}

fn update_srx_payload(
    header: &mut BTreeMap<u64, Value>,
    mutator: impl FnOnce(&mut Value),
) -> Result<(), Box<dyn std::error::Error>> {
    let payload_bytes = match header.get(&122) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => panic!("missing srx payload"),
    };
    let mut payload_value: Value = from_reader(payload_bytes.as_slice())?;
    mutator(&mut payload_value);

    let Value::Array(items) = &mut payload_value else {
        panic!("unexpected payload structure");
    };
    if items.len() != 9 {
        panic!("unexpected payload length: {}", items.len());
    }

    let join_count = items[4]
        .as_array()
        .ok_or_else(|| Box::<dyn std::error::Error>::from("join_leaves not an array"))?
        .len();
    let since_count = items[6]
        .as_array()
        .ok_or_else(|| Box::<dyn std::error::Error>::from("since_leaves not an array"))?
        .len();
    let anchors_count = items[8]
        .as_array()
        .ok_or_else(|| Box::<dyn std::error::Error>::from("anchors not an array"))?
        .len();
    let join_frontier_len = items[5].as_array().map(|arr| arr.len()).unwrap_or(0);
    let since_frontier_len = items[7].as_array().map(|arr| arr.len()).unwrap_or(0);

    set_srx_meta(
        &mut payload_value,
        join_count,
        since_count,
        join_frontier_len,
        since_frontier_len,
    );

    let new_payload_bytes = encode_value(&payload_value)?;
    let payload_len = new_payload_bytes.len() as u64;

    let commit = compute_srx_commit(&new_payload_bytes)?;
    header.insert(120, Value::Text("srx/v1-complete".to_string()));
    header.insert(121, Value::Bytes(commit.to_vec()));
    header.insert(122, Value::Bytes(new_payload_bytes.clone()));

    let hint_counts = Value::Map(vec![
        (
            Value::Text("join".to_string()),
            Value::Integer(Integer::from(join_count as u64)),
        ),
        (
            Value::Text("since".to_string()),
            Value::Integer(Integer::from(since_count as u64)),
        ),
        (
            Value::Text("anchors".to_string()),
            Value::Integer(Integer::from(anchors_count as u64)),
        ),
    ]);
    header.insert(123, Value::Bytes(encode_value(&hint_counts)?));

    let hint_sizes = Value::Map(vec![(
        Value::Text("bytes".to_string()),
        Value::Integer(Integer::from(payload_len)),
    )]);
    header.insert(124, Value::Bytes(encode_value(&hint_sizes)?));
    Ok(())
}

fn set_srx_meta(
    payload_value: &mut Value,
    join_count: usize,
    since_count: usize,
    join_frontier_len: usize,
    since_frontier_len: usize,
) {
    let Value::Array(items) = payload_value else {
        return;
    };
    if items.len() != 9 {
        return;
    }
    items[3] = Value::Map(vec![
        (
            Value::Text("join_count".to_string()),
            Value::Integer(Integer::from(join_count as u64)),
        ),
        (
            Value::Text("since_count".to_string()),
            Value::Integer(Integer::from(since_count as u64)),
        ),
        (
            Value::Text("join_frontier_size".to_string()),
            Value::Integer(Integer::from(join_frontier_len as u64)),
        ),
        (
            Value::Text("since_frontier_size".to_string()),
            Value::Integer(Integer::from(since_frontier_len as u64)),
        ),
    ]);
}

fn anchor_from_result<'a>(
    parts: &'a AnchorInstanceParts<'a>,
    joiner: &'a msphf_orchestrator::JoinerKGenResult,
) -> instance::AnchorInstance<'a> {
    instance::AnchorInstance {
        gid: parts.gid,
        cat: parts.cat,
        we_epoch_id: joiner.we_epoch_id,
        anchor_hdr_ctx: joiner.anchor_hdr_ctx.as_slice(),
        tswe_salt_hash: parts.tswe_salt_hash,
        parent_root: parts.parent_root,
        join_delta_root: parts.join_delta_root,
        revoked_since_prev_root: parts.revoked_since_prev_root,
        revoked_root: parts.revoked_root,
        pox_r_commit: parts.pox_r_commit,
        msphf_hp_commit: Some(&joiner.hp_commit),
    }
}

#[derive(Clone)]
struct AnchorFixtureConfig {
    gid: [u8; 32],
    cat: [u8; 32],
    parent_root: [u8; 32],
    parent_leaves: Vec<[u8; 32]>,
    join_leaves: Vec<[u8; 32]>,
    revoked_since_root: [u8; 32],
    revoked_root: [u8; 32],
    revoked_since_leaves: Vec<[u8; 32]>,
    revoked_leaves: Vec<[u8; 32]>,
    pox_commit: [u8; 32],
}

impl AnchorFixtureConfig {
    fn default() -> Self {
        Self {
            gid: [0x11; 32],
            cat: [0x22; 32],
            parent_root: [0u8; 32],
            parent_leaves: Vec::new(),
            join_leaves: default_join_leaves(),
            revoked_since_root: [0u8; 32],
            revoked_root: [0u8; 32],
            revoked_since_leaves: Vec::new(),
            revoked_leaves: Vec::new(),
            pox_commit: merkle::hash_leaf(b"pox-commit"),
        }
    }
}

struct JoinerFixture {
    parts: AnchorInstanceParts<'static>,
    params: OrchestrationParams<'static>,
    joiner: msphf_orchestrator::JoinerKGenResult,
    header_with_pop: BTreeMap<u64, Value>,
    witness_bytes: Vec<u8>,
    kbroad_secret: Vec<u8>,
    kbroad_registry: BTreeMap<Vec<u8>, Vec<u8>>,
    bootstrap_pk: Vec<u8>,
    bootstrap_sk: pqcrypto_dilithium::dilithium5::SecretKey,
    is_genesis: bool,
}

impl JoinerFixture {
    fn default() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_config(AnchorFixtureConfig::default())
    }

    fn new(join_leaves: Vec<[u8; 32]>) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_config(AnchorFixtureConfig {
            join_leaves,
            ..AnchorFixtureConfig::default()
        })
    }

    fn with_config(config: AnchorFixtureConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let is_genesis = config.parent_root.iter().all(|&b| b == 0)
            && config.revoked_since_root.iter().all(|&b| b == 0)
            && config.revoked_root.iter().all(|&b| b == 0);

        let (parts, params, _) = make_anchor_fixture(config).unwrap();
        let (kbroad_pk, kbroad_sk) = kyber_keypair();
        let kbroad_secret = kbroad_sk.as_bytes().to_vec();
        let kbroad_public = kbroad_pk.as_bytes().to_vec();

        let mut join_root = [0u8; 32];
        join_root.copy_from_slice(parts.join_delta_root);
        let mut parent_root = [0u8; 32];
        parent_root.copy_from_slice(parts.parent_root);
        let mut revoked_root = [0u8; 32];
        revoked_root.copy_from_slice(parts.revoked_root);
        let witness = witness_branch_b(&join_root, &parent_root, &revoked_root);
        let witness_bytes = serialize_witness(&witness).unwrap();

        let joiner = joiner_kgen_or(
            base_header(kbroad_pk.as_bytes()),
            parts.clone(),
            params.clone(),
            None,
            Some(&witness_bytes),
        )
        .map_err(|e| format!("{:?}", e))?;

        let anchor = anchor_from_result(&parts, &joiner);

        let mut header_with_pop = joiner.header_map.clone();
        let (bootstrap_pk, bootstrap_sk) = dsa_keypair();
        if is_genesis {
            attach_bootstrap(
                &mut header_with_pop,
                &anchor,
                &joiner.hp_commit,
                &joiner.seed_ctx_hash,
                &joiner.rho_commit,
                &joiner.seed_bundle_commit,
                bootstrap_pk.as_bytes(),
                &bootstrap_sk,
            )?;
        } else {
            header_with_pop.remove(&HDR_BOOTSTRAP_ALG);
            header_with_pop.remove(&HDR_BOOTSTRAP_SIG);
            header_with_pop.remove(&HDR_BOOTSTRAP_PK);
            refresh_seed_ctx_hash(&mut header_with_pop)?;
        }

        let mut kbroad_registry = BTreeMap::new();
        kbroad_registry.insert(parts.gid.to_vec(), kbroad_public);

        Ok(Self {
            parts,
            params,
            joiner,
            header_with_pop,
            witness_bytes,
            kbroad_secret,
            kbroad_registry,
            bootstrap_pk: bootstrap_pk.as_bytes().to_vec(),
            bootstrap_sk,
            is_genesis,
        })
    }

    fn anchor(&self) -> instance::AnchorInstance<'_> {
        anchor_from_result(&self.parts, &self.joiner)
    }

    fn header(&self) -> BTreeMap<u64, Value> {
        self.header_with_pop.clone()
    }

    fn acceptance_context(&self) -> AcceptanceContext {
        let options = AcceptanceOptions {
            kbroad_registry: Some(self.kbroad_registry.clone()),
            ..AcceptanceOptions::default()
        };
        let mut ctx = AcceptanceContext::with_options(DEFAULT_H_MAX, DEFAULT_T_WINDOW, options);
        ctx.set_bootstrap_policy(BootstrapPolicy::CaMlDsa {
            public_key: self.bootstrap_pk.clone(),
        });
        ctx
    }

    fn witness(&self) -> &[u8] {
        &self.witness_bytes
    }

    fn proof_inputs(&self) -> HpBindingInputs<'_> {
        HpBindingInputs {
            msphf_crs_id: self.params.msphf_crs_id,
            params_id: self.params.params_id,
            seed_ctx_hash: &self.joiner.seed_ctx_hash,
            seed_commit: &self.joiner.seed_commit,
            rho_commit: &self.joiner.rho_commit,
            xk_hash: &self.joiner.xk_hash,
            hp_commit: &self.joiner.hp_commit,
        }
    }

    fn kb_secret(&self) -> &[u8] {
        &self.kbroad_secret
    }

    fn resign_bootstrap(
        &self,
        header: &mut BTreeMap<u64, Value>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !self.is_genesis {
            header.remove(&HDR_BOOTSTRAP_ALG);
            header.remove(&HDR_BOOTSTRAP_SIG);
            header.remove(&HDR_BOOTSTRAP_PK);
            refresh_seed_ctx_hash(header)?;
            return Ok(());
        }
        let anchor = self.anchor();
        let hp_commit = header
            .get(&99)
            .and_then(|value| match value {
                Value::Bytes(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(bytes);
                    Some(arr)
                }
                _ => None,
            })
            .unwrap_or(self.joiner.hp_commit);
        attach_bootstrap(
            header,
            &anchor,
            &hp_commit,
            &self.joiner.seed_ctx_hash,
            &self.joiner.rho_commit,
            &self.joiner.seed_bundle_commit,
            &self.bootstrap_pk,
            &self.bootstrap_sk,
        )?;
        Ok(())
    }
}

fn refresh_seed_ctx_hash(
    header: &mut BTreeMap<u64, Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = build_anchor_seed_ctx(header)?;
    let hash = compute_seed_ctx_hash(&ctx)?;
    header.insert(91, Value::Bytes(hash.to_vec()));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn attach_bootstrap(
    header: &mut BTreeMap<u64, Value>,
    anchor: &instance::AnchorInstance<'_>,
    hp_commit: &[u8; 32],
    seed_ctx_hash: &[u8; 32],
    rho_commit: &[u8; 32],
    seed_bundle_commit: &[u8; 32],
    boot_pk: &[u8],
    boot_sk: &pqcrypto_dilithium::dilithium5::SecretKey,
) -> Result<(), Box<dyn std::error::Error>> {
    header.remove(&HDR_BOOTSTRAP_SIG);
    header.remove(&HDR_BOOTSTRAP_PK);
    header.insert(HDR_BOOTSTRAP_ALG, Value::Text("oob-ca-v1".to_string()));
    let digest = build_bootstrap_digest(
        header,
        anchor,
        hp_commit,
        seed_ctx_hash,
        rho_commit,
        seed_bundle_commit,
    )
    .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;
    let sig = detached_sign(&digest, boot_sk);
    header.insert(HDR_BOOTSTRAP_SIG, Value::Bytes(sig.as_bytes().to_vec()));
    header.insert(HDR_BOOTSTRAP_PK, Value::Bytes(boot_pk.to_vec()));
    refresh_seed_ctx_hash(header)?;
    Ok(())
}

fn base_header(kbroad_pk_bytes: &[u8]) -> BTreeMap<u64, Value> {
    let mut map = BTreeMap::new();
    map.insert(104, Value::Text("ml-kem-768".to_string()));
    map.insert(105, Value::Bytes(kbroad_pk_bytes.to_vec()));
    map
}

#[derive(Serialize)]
struct KekSalt<'a> {
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8; 32],
}

#[derive(Serialize)]
struct NonceCtx<'a> {
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    hp_commit: &'a [u8; 32],
}

fn hkdf_blake3_local(salt: &[u8; 32], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut extract = Hasher::new_keyed(salt);
    extract.update(ikm);
    let prk = extract.finalize();

    let mut expand = Hasher::new_keyed(prk.as_bytes());
    expand.update(info);
    expand.update(&[1u8]);
    let okm = expand.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(okm.as_bytes());
    out
}

fn derive_nonce_bytes(
    label: &str,
    xk_hash: &[u8; 32],
    hp_commit: &[u8; 32],
) -> Result<[u8; 12], Box<dyn std::error::Error>> {
    let digest = h_l(label, &NonceCtx { xk_hash, hp_commit })?;
    let mut out = [0u8; 12];
    out.copy_from_slice(&digest[..12]);
    Ok(out)
}

fn decrypt_chacha20_local(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = nonce_bytes.into();
    Ok(cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| format!("{:?}", e))?)
}

fn derive_hp_material(
    header: &BTreeMap<u64, Value>,
    xk_hash: &[u8; 32],
    hp_commit: &[u8; 32],
    kbroad_sk: &MlKemSecretKey,
) -> Result<([u8; 32], Vec<u8>), Box<dyn std::error::Error>> {
    let Value::Array(items) = header.get(&97).ok_or("msphf_hp not found")? else {
        panic!("msphf_hp not array");
    };
    assert_eq!(items.len(), 5, "msphf_hp length");
    let ct_bytes = match &items[1] {
        Value::Bytes(bytes) => bytes.clone(),
        _ => panic!("ct bytes"),
    };
    let wrap_bytes = match &items[2] {
        Value::Bytes(bytes) => bytes.clone(),
        _ => panic!("wrap bytes"),
    };
    let c_hp_bytes = match &items[3] {
        Value::Bytes(bytes) => bytes.clone(),
        _ => panic!("C_hp bytes"),
    };

    let kem_ct = MlKemCiphertext::from_bytes(ct_bytes.as_slice())?;
    let shared = ml_kem_decapsulate(&kem_ct, kbroad_sk);
    let shared_bytes = shared.as_bytes();

    let salt = h_l("hp/kek/salt", &KekSalt { xk_hash })?;
    let mut info = b"city-g|hp/kek/v1".to_vec();
    info.extend_from_slice(hp_commit);
    let kek = hkdf_blake3_local(&salt, shared_bytes, &info);

    let wrap_nonce = derive_nonce_bytes("hp/kek/nonce", xk_hash, hp_commit)?;
    let k_hp_bytes = decrypt_chacha20_local(&kek, &wrap_nonce, hp_commit, &wrap_bytes)?;
    assert_eq!(k_hp_bytes.len(), 32, "k_hp size");
    let mut k_hp = [0u8; 32];
    k_hp.copy_from_slice(&k_hp_bytes);

    Ok((k_hp, c_hp_bytes))
}

#[test]
fn joiner_to_acceptance_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = JoinerFixture::new(default_join_leaves())?;
    let anchor = fixture.anchor();
    let witness_bytes = fixture.witness();
    let mut header_with_pop = fixture.header();
    fixture.resign_bootstrap(&mut header_with_pop)?;

    let proof_inputs = HpBindingInputs {
        msphf_crs_id: fixture.params.msphf_crs_id,
        params_id: fixture.params.params_id,
        seed_ctx_hash: &fixture.joiner.seed_ctx_hash,
        seed_commit: &fixture.joiner.seed_commit,
        rho_commit: &fixture.joiner.rho_commit,
        xk_hash: &fixture.joiner.xk_hash,
        hp_commit: &fixture.joiner.hp_commit,
    };

    let mut ctx = fixture.acceptance_context();
    let positive = msphf_orchestrator::accept_and_extract_or(
        &mut ctx,
        &anchor,
        &header_with_pop,
        &fixture.joiner.hp_proof,
        &proof_inputs,
        witness_bytes,
    )
    .map_err(|e| format!("{:?}", e))?;

    assert_eq!(positive.outcome.kind, AcceptanceKind::NonMerge);
    assert_eq!(positive.outcome.we_epoch_id, fixture.joiner.we_epoch_id);
    assert_eq!(positive.outcome.seed_ctx_hash, fixture.joiner.seed_ctx_hash);
    assert_eq!(positive.outcome.seed_commit, fixture.joiner.seed_commit);
    assert_eq!(positive.outcome.rho_commit, fixture.joiner.rho_commit);
    assert_eq!(positive.outcome.hp_commit, fixture.joiner.hp_commit);
    let mut parent_root = [0u8; 32];
    parent_root.copy_from_slice(anchor.parent_root);
    #[derive(serde::Serialize)]
    struct WindowInputs<'a> {
        #[serde(with = "serde_bytes")]
        gid: &'a [u8],
        #[serde(with = "serde_bytes")]
        parent_root: &'a [u8; 32],
        #[serde(with = "serde_bytes")]
        seed_ctx_hash: &'a [u8; 32],
    }
    let expected_wid = msphf_core::hash::h_l(
        "mhw/window",
        &WindowInputs {
            gid: anchor.gid,
            parent_root: &parent_root,
            seed_ctx_hash: &fixture.joiner.seed_ctx_hash,
        },
    )
    .map_err(|e| format!("{:?}", e))?;
    assert_eq!(positive.outcome.wid, expected_wid);

    // Provide a non-membership witness that violates the canonical guard.
    let join_root: [u8; 32] = anchor.join_delta_root.try_into()?;
    let revoked_root: [u8; 32] = anchor.revoked_root.try_into()?;
    let bad_witness_bytes = build_noncanonical_witness(&join_root, &revoked_root);
    let err = match msphf_orchestrator::accept_and_extract_or(
        &mut fixture.acceptance_context(),
        &anchor,
        &header_with_pop,
        &fixture.joiner.hp_proof,
        &proof_inputs,
        &bad_witness_bytes,
    ) {
        Err(e) => e,
        Ok(_) => unreachable!("noncanonical witness should freeze"),
    };
    match err {
        AcceptanceError::Freeze(freeze) => {
            assert!(matches!(freeze.code, 9072 | 9074));
            assert_eq!(freeze.reason, "proj_eval_fail");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    Ok(())
}

#[test]
fn srx_parent_conflict_freezes() -> Result<(), Box<dyn std::error::Error>> {
    let (parts, params, _) = make_anchor_fixture(AnchorFixtureConfig::default()).unwrap();

    let (kbroad_pk, kbroad_sk) = kyber_keypair();
    let _kbroad_secret = kbroad_sk.as_bytes().to_vec();

    let mut join_root = [0u8; 32];
    join_root.copy_from_slice(parts.join_delta_root);
    let mut revoked_root = [0u8; 32];
    revoked_root.copy_from_slice(parts.revoked_root);

    let parent_root: [u8; 32] = parts.parent_root.try_into()?;
    let witness_bytes =
        serialize_witness(&witness_branch_b(&join_root, &parent_root, &revoked_root)).unwrap();
    let joiner = joiner_kgen_or(
        base_header(kbroad_pk.as_bytes()),
        parts.clone(),
        params.clone(),
        None,
        Some(&witness_bytes),
    )
    .map_err(|e| format!("{:?}", e))?;

    let mut header_with_pop = joiner.header_map.clone();
    let anchor = anchor_from_result(&parts, &joiner);
    header_with_pop.insert(121, Value::Bytes(vec![0x42; 32]));
    let (bootstrap_pk, bootstrap_sk) = dsa_keypair();
    attach_bootstrap(
        &mut header_with_pop,
        &anchor,
        &joiner.hp_commit,
        &joiner.seed_ctx_hash,
        &joiner.rho_commit,
        &joiner.seed_bundle_commit,
        bootstrap_pk.as_bytes(),
        &bootstrap_sk,
    )?;

    let mut registry = BTreeMap::new();
    registry.insert(parts.gid.to_vec(), kbroad_pk.as_bytes().to_vec());
    let options = AcceptanceOptions {
        kbroad_registry: Some(registry),
        ..AcceptanceOptions::default()
    };
    let mut ctx = AcceptanceContext::with_options(DEFAULT_H_MAX, DEFAULT_T_WINDOW, options);
    ctx.set_bootstrap_policy(BootstrapPolicy::CaMlDsa {
        public_key: bootstrap_pk.as_bytes().to_vec(),
    });
    let err = match ctx.accept_anchor(&parts, joiner.we_epoch_id, &header_with_pop) {
        Err(e) => e,
        Ok(_) => unreachable!("SRX parent conflict should freeze"),
    };

    match err {
        AcceptanceError::Freeze(code) => {
            let expected_invalid = code.code == 930 && code.reason == "srx_invalid";
            assert!(
                expected_invalid,
                "unexpected freeze: {:?}",
                code
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    Ok(())
}

#[test]
fn pivot_parity_remains_keyed_by_parent_root() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = JoinerFixture::default()?;
    let mut ctx = fixture.acceptance_context();
    let anchor = fixture.anchor();
    let mut header = fixture.header();
    fixture.resign_bootstrap(&mut header)?;
    let proof_inputs = fixture.proof_inputs();
    let witness_bytes = fixture.witness();
    let acceptance = msphf_orchestrator::accept_and_extract_or(
        &mut ctx,
        &anchor,
        &header,
        &fixture.joiner.hp_proof,
        &proof_inputs,
        witness_bytes,
    )
    .map_err(|e| format!("{:?}", e))?;

    let gid = anchor.gid;
    let parent_root = slice_to_array32(anchor.parent_root);
    let join_root = slice_to_array32(anchor.join_delta_root);

    let parities_parent = ctx.pivot_parities_for(gid, &parent_root);
    assert!(
        !parities_parent.is_empty(),
        "expected parity entries keyed by parent root"
    );

    let parities_join = ctx.pivot_parities_for(gid, &join_root);
    assert!(
        parities_join.is_empty(),
        "did not expect parities keyed by join root"
    );

    assert_eq!(
        acceptance.pivot_parity.parent_root, parent_root,
        "acceptance parity matches parent root"
    );
    Ok(())
}

#[test]
fn ban_and_reinstate_member_flow() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = JoinerFixture::default()?;
    let mut ctx = fixture.acceptance_context();
    let anchor = fixture.anchor();
    let mut header = fixture.header();
    fixture.resign_bootstrap(&mut header)?;
    let proof_inputs = fixture.proof_inputs();
    let witness_bytes = fixture.witness();
    let kbroad_pub = match header.get(&105) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => panic!("missing KBROAD public key"),
    };
    let acceptance = msphf_orchestrator::accept_and_extract_or(
        &mut ctx,
        &anchor,
        &header,
        &fixture.joiner.hp_proof,
        &proof_inputs,
        witness_bytes,
    )
    .map_err(|e| format!("{:?}", e))?;
    assert_eq!(acceptance.outcome.kind, AcceptanceKind::NonMerge);
    let gid = slice_to_array32(anchor.gid);
    let cat = slice_to_array32(anchor.cat);
    let parent_root = slice_to_array32(anchor.parent_root);
    let pox_commit = slice_to_array32(
        fixture
            .parts
            .pox_r_commit
            .ok_or_else(|| Box::<dyn std::error::Error>::from("missing pox_r_commit"))?,
    );

    let mut join_leaves = default_join_leaves();
    join_leaves.sort();
    let target_leaf = join_leaves[0];
    let revoked_root = merkle::canonical_set_root(&[target_leaf])?;

    let config_ban = AnchorFixtureConfig {
        gid,
        cat,
        parent_root,
        parent_leaves: Vec::new(),
        join_leaves: Vec::new(),
        revoked_since_root: revoked_root,
        revoked_root,
        revoked_since_leaves: vec![target_leaf],
        revoked_leaves: vec![target_leaf],
        pox_commit,
    };
    let (parts_ban, params_ban, _) = make_anchor_fixture(config_ban).unwrap();

    let mut parities = ctx.pivot_parities_for(anchor.gid, &parent_root);
    parities.sort_by_key(|parity| (parity.accept_seq, parity.xk_hash));
    assert!(
        !parities.is_empty(),
        "expected at least one pivot parity before ban"
    );

    let merge_ban = joiner_kgen_merge_or(
        base_header(kbroad_pub.as_slice()),
        &parities,
        Some("ban member"),
        parts_ban.clone(),
        params_ban.clone(),
        None,
    )
    .map_err(|e| format!("{:?}", e))?;
    let header_ban = merge_ban.header_map.clone();
    assert!(
        !header_ban.contains_key(&msphf_orchestrator::hdr::HDR_KBROAD_REPLAY),
        "FS-purge merge must not include KBROAD replay"
    );
    assert!(
        !header_ban.contains_key(&HDR_BOOTSTRAP_SIG),
        "FS-purge merge must not include bootstrap signature"
    );
    assert!(
        !header_ban.contains_key(&HDR_BOOTSTRAP_PK),
        "FS-purge merge must not include bootstrap key"
    );
    assert!(
        !header_ban.contains_key(&HDR_BOOTSTRAP_ALG),
        "FS-purge merge must not include bootstrap algorithm"
    );
    match header_ban.get(&HDR_CRS_ID) {
        Some(Value::Text(text)) => assert_eq!(text, params_ban.msphf_crs_id),
        Some(Value::Bytes(bytes)) => assert_eq!(bytes, params_ban.msphf_crs_id.as_bytes()),
        other => panic!("unexpected CRS representation: {other:?}"),
    }

    let mut parities_unban = ctx.pivot_parities_for(anchor.gid, &parent_root);
    parities_unban.sort_by_key(|parity| (parity.accept_seq, parity.xk_hash));
    assert!(
        !parities_unban.is_empty(),
        "expected pivot parity before unban"
    );

    let config_unban = AnchorFixtureConfig {
        gid,
        cat,
        parent_root,
        parent_leaves: Vec::new(),
        join_leaves: Vec::new(),
        revoked_since_root: [0u8; 32],
        revoked_root: [0u8; 32],
        revoked_since_leaves: Vec::new(),
        revoked_leaves: Vec::new(),
        pox_commit,
    };
    let (parts_unban, params_unban, _) = make_anchor_fixture(config_unban).unwrap();

    let merge_unban = joiner_kgen_merge_or(
        base_header(kbroad_pub.as_slice()),
        &parities_unban,
        Some("reinstate member"),
        parts_unban.clone(),
        params_unban.clone(),
        None,
    )
    .map_err(|e| format!("{:?}", e))?;

    let header_unban = merge_unban.header_map.clone();
    assert!(
        !header_unban.contains_key(&msphf_orchestrator::hdr::HDR_KBROAD_REPLAY),
        "unban merge anchor must not carry KBROAD replay"
    );
    assert!(
        !header_unban.contains_key(&HDR_BOOTSTRAP_SIG),
        "unban merge anchor must not carry bootstrap signature"
    );
    assert!(
        !header_unban.contains_key(&HDR_BOOTSTRAP_PK),
        "unban merge anchor must not carry bootstrap key"
    );
    assert!(
        !header_unban.contains_key(&HDR_BOOTSTRAP_ALG),
        "unban merge anchor must not declare bootstrap algorithm"
    );
    match header_unban.get(&HDR_CRS_ID) {
        Some(Value::Text(text)) => assert_eq!(text, params_unban.msphf_crs_id),
        Some(Value::Bytes(bytes)) => assert_eq!(bytes, params_unban.msphf_crs_id.as_bytes()),
        other => panic!("unexpected CRS representation: {other:?}"),
    }
    Ok(())
}

#[test]
fn srx_revoked_subset_conflict_freezes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = JoinerFixture::default()?;
    let mut header_with_pop = fixture.header();

    header_with_pop.insert(122, Value::Bytes(vec![0xAA, 0xBB, 0xCC]));
    fixture.resign_bootstrap(&mut header_with_pop)?;

    let mut ctx = fixture.acceptance_context();
    let err = match ctx.accept_anchor(&fixture.parts, fixture.joiner.we_epoch_id, &header_with_pop)
    {
        Err(e) => e,
        Ok(_) => unreachable!("SRX subset conflict should freeze"),
    };

    match err {
        AcceptanceError::Freeze(code) => {
            let expected_invalid = code.code == 930 && code.reason == "srx_invalid";
            assert!(
                expected_invalid,
                "unexpected freeze: {:?}",
                code
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    Ok(())
}

#[test]
fn acceptance_loop_smoke_performance() -> Result<(), Box<dyn std::error::Error>> {
    let iterations = 25;
    let fixture = JoinerFixture::default()?;
    let anchor = fixture.anchor();
    let proof_inputs = fixture.proof_inputs();
    let witness = fixture.witness();
    let start = Instant::now();

    for _ in 0..iterations {
        let header_with_pop = fixture.header();
        let mut ctx = fixture.acceptance_context();
        let acceptance = msphf_orchestrator::accept_and_extract_or(
            &mut ctx,
            &anchor,
            &header_with_pop,
            &fixture.joiner.hp_proof,
            &proof_inputs,
            witness,
        )
        .map_err(|e| format!("{:?}", e))?;

        assert_eq!(acceptance.outcome.kind, AcceptanceKind::NonMerge);
    }

    let elapsed = start.elapsed();
    let budget = if option_env!("CARGO_LLVM_COV").is_some() {
        Duration::from_secs(20)
    } else if cfg!(feature = "zkvrf-pq") {
        Duration::from_secs(5)
    } else {
        Duration::from_secs(2)
    };
    assert!(
        elapsed < budget,
        "acceptance loop took too long: {:?}",
        elapsed
    );
    Ok(())
}

#[test]
fn header_tswe_alg_tamper_freezes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = JoinerFixture::default()?;
    let mut header_with_pop = fixture.header();
    header_with_pop.insert(90, Value::Integer(Integer::from(0u8))); // invalid tswe_alg
    fixture.resign_bootstrap(&mut header_with_pop)?;

    let mut ctx = fixture.acceptance_context();
    let err = match msphf_orchestrator::accept_and_extract_or(
        &mut ctx,
        &fixture.anchor(),
        &header_with_pop,
        &fixture.joiner.hp_proof,
        &HpBindingInputs {
            msphf_crs_id: fixture.params.msphf_crs_id,
            params_id: fixture.params.params_id,
            seed_ctx_hash: &fixture.joiner.seed_ctx_hash,
            seed_commit: &fixture.joiner.seed_commit,
            rho_commit: &fixture.joiner.rho_commit,
            xk_hash: &fixture.joiner.xk_hash,
            hp_commit: &fixture.joiner.hp_commit,
        },
        fixture.witness(),
    ) {
        Err(e) => e,
        Ok(_) => unreachable!("tampered tswe_alg must freeze"),
    };

    match err {
        AcceptanceError::Msphf(inner) => {
            let msg = inner.to_string();
            assert!(msg.contains("anchor_hdr_ctx mismatch"));
        }
        other => panic!("expected Msphf error, got {other:?}"),
    }
    Ok(())
}

#[test]
fn kbroad_envelope_malformed_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = JoinerFixture::default()?;
    let mut header_with_pop = fixture.header();

    if let Some(Value::Array(items)) = header_with_pop.get_mut(&97) {
        items[2] = Value::Text("not-bytes".into());
    }
    fixture.resign_bootstrap(&mut header_with_pop)?;

    let proof_inputs = HpBindingInputs {
        msphf_crs_id: fixture.params.msphf_crs_id,
        params_id: fixture.params.params_id,
        seed_ctx_hash: &fixture.joiner.seed_ctx_hash,
        seed_commit: &fixture.joiner.seed_commit,
        rho_commit: &fixture.joiner.rho_commit,
        xk_hash: &fixture.joiner.xk_hash,
        hp_commit: &fixture.joiner.hp_commit,
    };

    let mut ctx = fixture.acceptance_context();
    let err = match msphf_orchestrator::accept_and_extract_or(
        &mut ctx,
        &fixture.anchor(),
        &header_with_pop,
        &fixture.joiner.hp_proof,
        &proof_inputs,
        fixture.witness(),
    ) {
        Err(e) => e,
        Ok(_) => unreachable!("malformed msphf_hp should error"),
    };

    match err {
        AcceptanceError::Freeze(code) => {
            assert_eq!(code.code, 9071);
            assert_eq!(code.reason, "cbor_malformed");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    Ok(())
}

#[test]
fn pop_signature_mismatch_freezes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = JoinerFixture::default()?;
    let mut header_with_pop = fixture.header();

    if let Some(Value::Bytes(sig)) = header_with_pop.get_mut(&109)
        && let Some(first) = sig.first_mut()
    {
        *first ^= 0x01;
    }
    fixture.resign_bootstrap(&mut header_with_pop)?;

    let mut ctx = fixture.acceptance_context();
    let err = match msphf_orchestrator::accept_and_extract_or(
        &mut ctx,
        &fixture.anchor(),
        &header_with_pop,
        &fixture.joiner.hp_proof,
        &fixture.proof_inputs(),
        fixture.witness(),
    ) {
        Err(e) => e,
        Ok(_) => unreachable!("forged pop must freeze"),
    };

    match err {
        AcceptanceError::Freeze(code) => {
            assert_eq!(code.code, 921);
            assert_eq!(code.reason, "msphf_crs_untrusted");
        }
        other => panic!("expected freeze error, got {other:?}"),
    }
    Ok(())
}

#[test]
fn proof_inputs_params_mismatch_fails() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = JoinerFixture::default()?;
    let header_with_pop = fixture.header();

    let mut proof_inputs = fixture.proof_inputs();
    proof_inputs.params_id = "rlwe-params/bad";

    let mut ctx = fixture.acceptance_context();
    let err = match msphf_orchestrator::accept_and_extract_or(
        &mut ctx,
        &fixture.anchor(),
        &header_with_pop,
        &fixture.joiner.hp_proof,
        &proof_inputs,
        fixture.witness(),
    ) {
        Err(e) => e,
        Ok(_) => unreachable!("params mismatch"),
    };

    match err {
        AcceptanceError::Msphf(inner) => {
            let msg = inner.to_string();
            assert!(msg.contains("hp_k proof mismatch"));
        }
        other => panic!("expected Msphf error, got {other:?}"),
    }
    Ok(())
}

#[test]
fn rho_replay_guard_blocks_reuse() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = JoinerFixture::default()?;
    let anchor = fixture.anchor();
    let header_with_pop = fixture.header();
    let witness_bytes = fixture.witness();

    let mut ctx = fixture.acceptance_context();
    msphf_orchestrator::accept_and_extract_or(
        &mut ctx,
        &anchor,
        &header_with_pop,
        &fixture.joiner.hp_proof,
        &fixture.proof_inputs(),
        witness_bytes,
    )
    .map_err(|e| format!("{:?}", e))?;

    let err = match msphf_orchestrator::accept_and_extract_or(
        &mut ctx,
        &anchor,
        &header_with_pop,
        &fixture.joiner.hp_proof,
        &fixture.proof_inputs(),
        witness_bytes,
    ) {
        Err(e) => e,
        Ok(_) => unreachable!("rho reuse should freeze"),
    };

    match err {
        AcceptanceError::Freeze(code) => {
            assert_eq!(code.code, 924);
            assert_eq!(code.reason, "msphf_rho_parity");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    Ok(())
}

#[test]
fn stale_witness_rejected_after_new_anchor() -> Result<(), Box<dyn std::error::Error>> {
    let gid = [0x51u8; 32];
    let cat = [0x52u8; 32];
    let pox_commit = [0x77u8; 32];

    let join_leaf_member_a = merkle::hash_leaf(b"member-a-stale");
    let join_leaf_member_b = merkle::hash_leaf(b"member-b-stale");
    let revoked_root = [0u8; 32];

    let config_genesis = AnchorFixtureConfig {
        gid,
        cat,
        parent_root: [0u8; 32],
        parent_leaves: Vec::new(),
        join_leaves: vec![join_leaf_member_a],
        revoked_since_root: revoked_root,
        revoked_root,
        revoked_since_leaves: Vec::new(),
        revoked_leaves: Vec::new(),
        pox_commit,
    };
    let fixture_genesis = JoinerFixture::with_config(config_genesis.clone())?;
    let anchor0 = fixture_genesis.anchor();
    let header_with_pop0 = fixture_genesis.header();
    let witness_member_a_join = fixture_genesis.witness().to_vec();
    let proof_inputs0 = fixture_genesis.proof_inputs();

    let mut ctx = fixture_genesis.acceptance_context();
    msphf_orchestrator::accept_and_extract_or(
        &mut ctx,
        &anchor0,
        &header_with_pop0,
        &fixture_genesis.joiner.hp_proof,
        &proof_inputs0,
        &witness_member_a_join,
    )
    .map_err(|e| format!("{:?}", e))?;

    let config_round1 = AnchorFixtureConfig {
        gid,
        cat,
        parent_root: join_leaf_member_a,
        parent_leaves: vec![join_leaf_member_a],
        join_leaves: vec![join_leaf_member_b],
        revoked_since_root: revoked_root,
        revoked_root,
        revoked_since_leaves: Vec::new(),
        revoked_leaves: Vec::new(),
        pox_commit,
    };
    let fixture_round1 = JoinerFixture::with_config(config_round1)?;
    let anchor1 = fixture_round1.anchor();
    let header_with_pop1 = fixture_round1.header();
    let witness_member_b_join = fixture_round1.witness();
    let proof_inputs1 = fixture_round1.proof_inputs();

    let mut ctx_round1 = fixture_round1.acceptance_context();
    msphf_orchestrator::accept_and_extract_or(
        &mut ctx_round1,
        &anchor1,
        &header_with_pop1,
        &fixture_round1.joiner.hp_proof,
        &proof_inputs1,
        witness_member_b_join,
    )
    .map_err(|e| format!("{:?}", e))?;

    let kbroad_sk_round1 = MlKemSecretKey::from_bytes(fixture_round1.kbroad_secret.as_slice())?;
    let (k_hp, c_hp) = derive_hp_material(
        &header_with_pop1,
        &fixture_round1.joiner.xk_hash,
        &fixture_round1.joiner.hp_commit,
        &kbroad_sk_round1,
    )?;

    let err = match extract_epoch_msphf_or(
        &anchor1,
        &fixture_round1.joiner.xk_hash,
        &c_hp,
        &k_hp,
        &fixture_round1.joiner.hp_proof,
        &proof_inputs1,
        &witness_member_a_join,
    ) {
        Err(e) => e,
        Ok(_) => unreachable!("stale witness must be rejected"),
    };

    let msg = err.to_string();
    assert!(msg.contains("proj_eval_fail"));
    Ok(())
}

#[test]
fn two_anchor_members_converge_on_epoch_key() -> Result<(), Box<dyn std::error::Error>> {
    let gid = [0x31u8; 32];
    let cat = [0x42u8; 32];
    let pox_commit = [0x77u8; 32];

    let parent_root_genesis = [0u8; 32];
    let join_leaf_member_a = merkle::hash_leaf(b"member-a");
    let join_leaf_member_b = merkle::hash_leaf(b"member-b");
    let revoked_root = [0u8; 32];

    let config_genesis = AnchorFixtureConfig {
        gid,
        cat,
        parent_root: parent_root_genesis,
        parent_leaves: Vec::new(),
        join_leaves: vec![join_leaf_member_a],
        revoked_since_root: revoked_root,
        revoked_root,
        revoked_since_leaves: Vec::new(),
        revoked_leaves: Vec::new(),
        pox_commit,
    };
    let fixture_genesis = JoinerFixture::with_config(config_genesis)?;
    let anchor0 = fixture_genesis.anchor();
    let header_with_pop0 = fixture_genesis.header();
    let witness_member_a_join = fixture_genesis.witness().to_vec();

    let proof_inputs0 = fixture_genesis.proof_inputs();

    let mut accept_ctx = fixture_genesis.acceptance_context();
    let acceptance0 = msphf_orchestrator::accept_and_extract_or(
        &mut accept_ctx,
        &anchor0,
        &header_with_pop0,
        &fixture_genesis.joiner.hp_proof,
        &proof_inputs0,
        &witness_member_a_join,
    )
    .map_err(|e| format!("{:?}", e))?;
    assert_eq!(acceptance0.outcome.kind, AcceptanceKind::NonMerge);
    #[derive(Serialize)]
    struct WindowInputs<'a> {
        #[serde(with = "serde_bytes")]
        gid: &'a [u8],
        #[serde(with = "serde_bytes")]
        parent_root: &'a [u8; 32],
        #[serde(with = "serde_bytes")]
        seed_ctx_hash: &'a [u8; 32],
    }
    let expected_wid0 = h_l(
        "mhw/window",
        &WindowInputs {
            gid: anchor0.gid,
            parent_root: &parent_root_genesis,
            seed_ctx_hash: &fixture_genesis.joiner.seed_ctx_hash,
        },
    )
    .map_err(|e| format!("{:?}", e))?;
    assert_eq!(acceptance0.outcome.wid, expected_wid0);
    let epoch0 = fixture_genesis.joiner.epoch_key;

    let config_round1 = AnchorFixtureConfig {
        gid,
        cat,
        parent_root: join_leaf_member_a,
        parent_leaves: vec![join_leaf_member_a],
        join_leaves: vec![join_leaf_member_b],
        revoked_since_root: revoked_root,
        revoked_root,
        revoked_since_leaves: Vec::new(),
        revoked_leaves: Vec::new(),
        pox_commit,
    };
    let fixture_round1 = JoinerFixture::with_config(config_round1)?;
    let anchor1 = fixture_round1.anchor();
    let header_with_pop1 = fixture_round1.header();
    let witness_member_b_join = fixture_round1.witness();
    let proof_inputs1 = fixture_round1.proof_inputs();

    let mut accept_ctx = fixture_round1.acceptance_context();
    let acceptance1 = msphf_orchestrator::accept_and_extract_or(
        &mut accept_ctx,
        &anchor1,
        &header_with_pop1,
        &fixture_round1.joiner.hp_proof,
        &proof_inputs1,
        witness_member_b_join,
    )
    .map_err(|e| format!("{:?}", e))?;
    assert_eq!(acceptance1.outcome.kind, AcceptanceKind::NonMerge);
    let expected_wid1 = h_l(
        "mhw/window",
        &WindowInputs {
            gid: anchor1.gid,
            parent_root: &join_leaf_member_a,
            seed_ctx_hash: &fixture_round1.joiner.seed_ctx_hash,
        },
    )
    .map_err(|e| format!("{:?}", e))?;
    assert_eq!(acceptance1.outcome.wid, expected_wid1);

    let kbroad_sk_round1 = MlKemSecretKey::from_bytes(fixture_round1.kb_secret())?;
    let (k_hp, c_hp) = derive_hp_material(
        &header_with_pop1,
        &fixture_round1.joiner.xk_hash,
        &fixture_round1.joiner.hp_commit,
        &kbroad_sk_round1,
    )?;
    assert_eq!(k_hp, fixture_round1.joiner.hp_aead_key);

    let witness_member_a_parent =
        serialize_witness(&witness_branch_a(&join_leaf_member_a)).unwrap();

    let epoch_member_a = extract_epoch_msphf_or(
        &anchor1,
        &fixture_round1.joiner.xk_hash,
        &c_hp,
        &k_hp,
        &fixture_round1.joiner.hp_proof,
        &proof_inputs1,
        &witness_member_a_parent,
    )
    .map_err(|e| format!("{:?}", e))?;

    let epoch_member_b = extract_epoch_msphf_or(
        &anchor1,
        &fixture_round1.joiner.xk_hash,
        &c_hp,
        &k_hp,
        &fixture_round1.joiner.hp_proof,
        &proof_inputs1,
        witness_member_b_join,
    )
    .map_err(|e| format!("{:?}", e))?;

    assert_ne!(
        epoch_member_a, epoch0,
        "epoch should rotate after new anchor",
    );
    assert_eq!(epoch_member_a, epoch_member_b);
    assert_eq!(epoch_member_a, fixture_round1.joiner.epoch_key);
    Ok(())
}
