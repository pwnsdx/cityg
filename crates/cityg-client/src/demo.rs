use std::{
    collections::BTreeMap,
    convert::TryFrom,
    fs,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use ciborium::ser::into_writer;
use ciborium::value::Value;
use dirs::config_dir;
use msphf_core::{
    merkle::{canonical_set_root, hash_interval_binding, hash_node},
    params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK},
    witness::{
        CanonicalWitness, RawMembershipWitness, RawNonMembershipWitness, RawPathEntry,
        WitnessVariants,
    },
};
use msphf_orchestrator::hdr;
use msphf_orchestrator::{
    AnchorInstanceParts, DEFAULT_POLICY_VERSION, DEFAULT_PROOF_MODE, DEFAULT_VRF_ID,
    ForwardSecrecyState, FsJoinInputs, FsMergeInputs, LeafIdMode, OrchestrationParams, PopKeypair,
    SrxInputs, SrxMode, SrxNonMembershipAnchor, build_bootstrap_digest, deterministic_lb_vrf_keys,
};
use pqcrypto_dilithium::dilithium5::{SecretKey as MlDsaSecretKey, detached_sign, keypair};
use pqcrypto_kyber::kyber768::{SecretKey as MlKemSecretKey, keypair as kyber_keypair};
use pqcrypto_kyber::kyber768::{
    public_key_bytes as kyber_public_key_bytes, secret_key_bytes as kyber_secret_key_bytes,
};
use pqcrypto_traits::{
    kem::{PublicKey as KemPublicKeyTrait, SecretKey as KemSecretKeyTrait},
    sign::{DetachedSignature, PublicKey, SecretKey},
};

use crate::{CityGClient, CityGError, ClientEpochBundle, witness};

pub const DEMO_GID: [u8; 32] = [0x43; 32];

fn leaf_registry() -> &'static Mutex<BTreeMap<String, [u8; 32]>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<String, [u8; 32]>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn member_leaf(label: &str) -> [u8; 32] {
    let registry = leaf_registry();
    let mut guard = match registry.lock() {
        Ok(g) => g,
        Err(_) => unreachable!(),
    };
    if let Some(existing) = guard.get(label) {
        *existing
    } else {
        let next_index = (guard.len() as u32).saturating_add(1);
        let leaf = witness::sequential_leaf(next_index);
        guard.insert(label.to_string(), leaf);
        leaf
    }
}

pub fn demo_member_leaf(label: &str) -> [u8; 32] {
    member_leaf(label)
}

pub fn demo_bundle(label: &str) -> Result<ClientEpochBundle, CityGError> {
    let base = match label {
        "alice" => Vec::new(),
        "bob" => vec!["alice"],
        _ => vec!["alice", "bob"],
    };
    demo_bundle_with_base(&base, label)
}

pub fn demo_bundle_with_base(
    base_labels: &[&str],
    new_label: &str,
) -> Result<ClientEpochBundle, CityGError> {
    let mut parent_leaves: Vec<[u8; 32]> =
        base_labels.iter().map(|label| member_leaf(label)).collect();
    parent_leaves.sort();
    parent_leaves.dedup();
    let new_leaf = member_leaf(new_label);
    demo_bundle_with_parent_leaves(&parent_leaves, new_leaf)
}

pub fn demo_bundle_with_parent_leaves(
    parent_leaves: &[[u8; 32]],
    new_leaf: [u8; 32],
) -> Result<ClientEpochBundle, CityGError> {
    let mut parent_vec = parent_leaves.to_vec();
    parent_vec.sort();
    parent_vec.dedup();
    demo_bundle_inner(parent_vec, vec![new_leaf])
}

fn demo_bundle_inner(
    mut parent_leaves: Vec<[u8; 32]>,
    mut join_leaves: Vec<[u8; 32]>,
) -> Result<ClientEpochBundle, CityGError> {
    let gid = DEMO_GID;
    let cat = [0x21; 32];
    let revoked_root = [0u8; 32];
    let revoked_since_root = [0u8; 32];
    let pox_commit = witness::demo_pox_commit();

    parent_leaves.sort();
    parent_leaves.dedup();
    join_leaves.sort();
    join_leaves.dedup();

    let parent_root = canonical_set_root(&parent_leaves)?;
    let tswe_salt_hash = msphf_core::instance::tswe_salt_hash(&gid, &parent_root)?;

    let join_delta_root = witness::join_delta_root(&join_leaves)?;

    let (canonical_witness, srx_owned) = witness::build_branch_b_artifacts(
        &parent_leaves,
        &join_leaves,
        parent_root,
        revoked_since_root,
    )?;
    let witness_bytes = witness::witness_to_cbor(&canonical_witness)?;
    let srx_inputs = srx_owned.into_srx_inputs();

    let (pop_pk_obj, pop_sk_obj) = keypair();
    let pop_pk_bytes = pop_pk_obj.as_bytes().to_vec();

    let header = base_header();

    let (vrf_secret_key, vrf_public_key) = deterministic_lb_vrf_keys();

    let params = OrchestrationParams {
        msphf_crs_id: RLWE_CRS_ID_DEFAULT,
        params_id: RLWE_PARAMS_ID_MOCK,
        srx: Some(srx_inputs.clone()),
        srx_mode: SrxMode::Complete,
        pop_keys: Some(PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: pop_pk_bytes.as_slice(),
            secret_key: &pop_sk_obj,
        }),
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode: DEFAULT_PROOF_MODE,
        vrf_id: DEFAULT_VRF_ID,
        policy_version: DEFAULT_POLICY_VERSION,
        vrf_secret_key: Some(vrf_secret_key),
        vrf_public_key: Some(vrf_public_key),
        fs_policy_version: "fs-policy-v1",
        fs_epoch_base_ts: 0,
        fs_join: FsJoinInputs::default(),
        fs_merge: FsMergeInputs::default(),
    };

    let parts = AnchorInstanceParts {
        gid: &gid,
        cat: &cat,
        tswe_salt_hash: tswe_salt_hash.as_ref(),
        parent_root: &parent_root,
        join_delta_root: join_delta_root.as_ref(),
        revoked_since_prev_root: &revoked_since_root,
        revoked_root: &revoked_root,
        pox_r_commit: Some(pox_commit.as_ref()),
    };

    let mut fs_state = ForwardSecrecyState::new([0xAA; 32]);
    let mut bundle =
        CityGClient::generate_epoch(header, parts, params, &mut fs_state, Some(&witness_bytes))?;
    if parent_leaves.is_empty() {
        attach_bootstrap(&mut bundle)?;
    }
    Ok(bundle)
}

pub fn demo_bundle_alice() -> Result<ClientEpochBundle, CityGError> {
    demo_bundle("alice")
}

pub fn demo_bundle_bob() -> Result<ClientEpochBundle, CityGError> {
    demo_bundle("bob")
}

pub fn kbroad_public() -> &'static [u8] {
    kbroad_keys().0.as_slice()
}

pub fn kbroad_secret() -> &'static [u8] {
    kbroad_keys().1.as_slice()
}

pub fn bootstrap_public() -> &'static [u8] {
    bootstrap_keys().0.as_slice()
}

fn kbroad_keys() -> &'static (Vec<u8>, Vec<u8>) {
    static KBROAD_KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    KBROAD_KEYS.get_or_init(|| match load_or_generate_kbroad_keys() {
        Ok(keys) => keys,
        Err(_) => unreachable!(),
    })
}

fn bootstrap_keys() -> &'static (Vec<u8>, Box<MlDsaSecretKey>) {
    static BOOTSTRAP_KEYS: OnceLock<(Vec<u8>, Box<MlDsaSecretKey>)> = OnceLock::new();
    BOOTSTRAP_KEYS.get_or_init(|| match load_or_generate_bootstrap_keys() {
        Ok(keys) => keys,
        Err(_) => unreachable!(),
    })
}

fn bootstrap_key_path() -> Option<PathBuf> {
    config_dir().map(|dir| dir.join("cityg").join("demo-bootstrap.key"))
}

fn kbroad_key_path() -> Option<PathBuf> {
    config_dir().map(|dir| dir.join("cityg").join("demo-kbroad.key"))
}

fn load_or_generate_kbroad_keys() -> Result<(Vec<u8>, Vec<u8>), CityGError> {
    let pk_len = kyber_public_key_bytes();
    let sk_len = kyber_secret_key_bytes();

    if let Some(path) = kbroad_key_path() {
        if let Ok(bytes) = fs::read(&path)
            && bytes.len() == pk_len + sk_len
        {
            let pk = bytes[..pk_len].to_vec();
            let sk = bytes[pk_len..].to_vec();
            <pqcrypto_kyber::kyber768::PublicKey as KemPublicKeyTrait>::from_bytes(pk.as_slice())
                .map_err(|_| CityGError::InvalidInput("kbroad public malformed"))?;
            <MlKemSecretKey as KemSecretKeyTrait>::from_bytes(sk.as_slice())
                .map_err(|_| CityGError::InvalidInput("kbroad secret malformed"))?;
            return Ok((pk, sk));
        }
    }

    let (pk, sk) = kyber_keypair();
    let pair = (pk.as_bytes().to_vec(), sk.as_bytes().to_vec());

    if let Some(path) = kbroad_key_path() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut payload = Vec::with_capacity(pair.0.len() + pair.1.len());
        payload.extend_from_slice(pair.0.as_slice());
        payload.extend_from_slice(pair.1.as_slice());
        let _ = fs::write(path, payload);
    }

    Ok(pair)
}

fn load_or_generate_bootstrap_keys() -> Result<(Vec<u8>, Box<MlDsaSecretKey>), CityGError> {
    let pk_len = pqcrypto_dilithium::dilithium5::public_key_bytes();
    let sk_len = pqcrypto_dilithium::dilithium5::secret_key_bytes();

    if let Some(path) = bootstrap_key_path() {
        if let Ok(bytes) = fs::read(&path)
            && bytes.len() == pk_len + sk_len
        {
            let pk = bytes[..pk_len].to_vec();
            let sk_bytes = &bytes[pk_len..];
            let sk = MlDsaSecretKey::from_bytes(sk_bytes)
                .map_err(|_| CityGError::InvalidInput("bootstrap secret malformed"))?;
            return Ok((pk, Box::new(sk)));
        }

        let (pk, sk) = keypair();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut data = Vec::with_capacity(pk_len + sk_len);
        data.extend_from_slice(pk.as_bytes());
        data.extend_from_slice(sk.as_bytes());
        fs::write(path, data)?;
        Ok((pk.as_bytes().to_vec(), Box::new(sk)))
    } else {
        let (pk, sk) = keypair();
        Ok((pk.as_bytes().to_vec(), Box::new(sk)))
    }
}

pub fn attach_bootstrap(bundle: &mut ClientEpochBundle) -> Result<(), CityGError> {
    let (bootstrap_pk, bootstrap_sk) = bootstrap_keys();

    let signature_bytes = {
        let anchor = bundle.anchor_instance();
        let digest = build_bootstrap_digest(
            &bundle.header_map,
            &anchor,
            &bundle.hp_binding.hp_commit,
            &bundle.hp_binding.seed_ctx_hash,
            &bundle.hp_binding.rho_commit,
            &bundle.hp_binding.seed_bundle_commit,
        )
        .map_err(CityGError::from)?;
        detached_sign(&digest, bootstrap_sk.as_ref())
            .as_bytes()
            .to_vec()
    };

    bundle
        .header_map
        .insert(hdr::HDR_BOOTSTRAP_ALG, Value::Text("oob-ca-v1".to_string()));
    bundle
        .header_map
        .insert(hdr::HDR_BOOTSTRAP_PK, Value::Bytes(bootstrap_pk.clone()));
    bundle
        .header_map
        .insert(hdr::HDR_BOOTSTRAP_SIG, Value::Bytes(signature_bytes));

    Ok(())
}

fn base_header() -> BTreeMap<u64, Value> {
    let mut map = BTreeMap::new();
    map.insert(104, Value::Text("ml-kem-768".to_string()));
    map.insert(105, Value::Bytes(kbroad_public().to_vec()));
    map
}

pub fn witness_branch_b(join_root: &[u8; 32], revoked_root: &[u8; 32]) -> CanonicalWitness {
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

pub fn serialize_witness(witness: &CanonicalWitness) -> Result<Vec<u8>, CityGError> {
    let mut buf = Vec::new();
    into_writer(witness, &mut buf)
        .map_err(|_| CityGError::InvalidInput("unable to serialise witness"))?;
    Ok(buf)
}

pub fn build_srx_inputs(
    join_leaves: &[[u8; 32]],
    parent_leaves: &[[u8; 32]],
    parent_root: [u8; 32],
    revoked_since_root: [u8; 32],
) -> SrxInputs<'static> {
    use std::collections::BTreeMap;

    use ahash::AHashMap;

    let mut parent_sorted = parent_leaves.to_vec();
    parent_sorted.sort();
    let expected_parent_root = match canonical_set_root(&parent_sorted) {
        Ok(root) => root,
        Err(_) => unreachable!(),
    };
    assert_eq!(expected_parent_root, parent_root);

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
                    path: canonical_membership_path(&parent_sorted, &leaf_id),
                });
        }
        if let Some((root, leaf_id)) = right_key {
            anchor_map
                .entry((root, leaf_id))
                .or_insert_with(|| RawMembershipWitness {
                    leaf_id: leaf_id.to_vec(),
                    root: root.to_vec(),
                    path: canonical_membership_path(&parent_sorted, &leaf_id),
                });
        }

        join_nonmem_parent_temp.push((witness, left_key, right_key));
    }

    let mut anchor_mem_pool = Vec::new();
    let mut anchor_lookup: AHashMap<([u8; 32], [u8; 32]), u32> = AHashMap::new();
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

    SrxInputs {
        join_leaf_ids: std::borrow::Cow::Owned(join_leaves.to_vec()),
        join_nonmem_parent,
        join_nonmem_revoked_since,
        since_leaf_ids: std::borrow::Cow::Owned(Vec::new()),
        since_mem_revoked: std::borrow::Cow::Owned(Vec::new()),
        anchor_mem_pool,
        join_frontier: None,
        since_frontier: None,
    }
}

pub fn parent_nonmem_witness(
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
            let left_path = canonical_membership_path(parent_leaves, &l);
            let right_path = canonical_membership_path(parent_leaves, &r);
            let (left_below, right_below, above, lca_left_h, lca_right_h) =
                match split_interval_paths(l, &left_path, r, &right_path, parent_root) {
                    Ok(result) => result,
                    Err(_) => unreachable!(),
                };

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
                    hash_interval_binding(&l, &l, &r, &r, lca_left_h, lca_right_h).to_vec(),
                ),
                lca_left_height: Some(lca_left_h),
                lca_right_height: Some(lca_right_h),
            };

            (witness, Some(l), Some(r))
        }
        (Some(l), None) => {
            let path = canonical_membership_path(parent_leaves, &l);
            let witness = RawNonMembershipWitness {
                query: query.to_vec(),
                root: parent_root.to_vec(),
                left: Some(l.to_vec()),
                right: None,
                path,
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
            let path = canonical_membership_path(parent_leaves, &r);
            let witness = RawNonMembershipWitness {
                query: query.to_vec(),
                root: parent_root.to_vec(),
                left: None,
                right: Some(r.to_vec()),
                path,
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

pub fn sentinel_nonmem(root: [u8; 32], query: [u8; 32]) -> RawNonMembershipWitness {
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

pub fn canonical_membership_path(leaves: &[[u8; 32]], target: &[u8; 32]) -> Vec<RawPathEntry> {
    if leaves.len() <= 1 {
        return Vec::new();
    }

    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut index = match level.iter().position(|leaf| leaf == target) {
        Some(idx) => idx,
        None => unreachable!(),
    };
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
            next.push(hash_node(&chunk[0], &chunk[1]));
        }
        if len % 2 == 1 {
            next.push(*match level.last() {
                Some(carry) => carry,
                None => unreachable!(),
            });
        }
        index /= 2;
        level = next;
    }

    path
}

pub fn fold_step_into(acc: &mut [u8; 32], entry: &RawPathEntry) -> Result<(), CityGError> {
    if entry.sibling.len() != 32 {
        return Err(CityGError::InvalidInput("path sibling length invalid"));
    }
    let mut sibling = [0u8; 32];
    sibling.copy_from_slice(&entry.sibling);
    match entry.dir {
        0 => {
            *acc = hash_node(acc, &sibling);
            Ok(())
        }
        1 => {
            *acc = hash_node(&sibling, acc);
            Ok(())
        }
        _ => Err(CityGError::InvalidInput("path dir invalid")),
    }
}

pub fn build_chain(leaf: [u8; 32], path: &[RawPathEntry]) -> Result<Vec<[u8; 32]>, CityGError> {
    let mut chain = Vec::with_capacity(path.len() + 1);
    let mut acc = leaf;
    chain.push(acc);
    for entry in path {
        fold_step_into(&mut acc, entry)?;
        chain.push(acc);
    }
    Ok(chain)
}

#[allow(clippy::type_complexity)]
pub fn split_interval_paths(
    left_leaf: [u8; 32],
    left_path: &[RawPathEntry],
    right_leaf: [u8; 32],
    right_path: &[RawPathEntry],
    parent_root: [u8; 32],
) -> Result<
    (
        Vec<RawPathEntry>,
        Vec<RawPathEntry>,
        Vec<RawPathEntry>,
        u8,
        u8,
    ),
    CityGError,
> {
    let left_chain = build_chain(left_leaf, left_path)?;
    let right_chain = build_chain(right_leaf, right_path)?;

    let left_root = *left_chain
        .last()
        .ok_or(CityGError::InvalidInput("empty membership path"))?;
    let right_root = *right_chain
        .last()
        .ok_or(CityGError::InvalidInput("empty membership path"))?;

    if left_root != parent_root || right_root != parent_root {
        return Err(CityGError::InvalidInput(
            "membership path inconsistent with root",
        ));
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
        return Err(CityGError::InvalidInput("anchors share no ancestry"));
    }

    let left_len = left_path.len();
    let right_len = right_path.len();
    if common > left_len || common > right_len {
        return Err(CityGError::InvalidInput("invalid LCA depth"));
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
            return Err(CityGError::InvalidInput("shared suffix mismatch"));
        }
        for (l_entry, r_entry) in suffix_left.iter().zip(suffix_right.iter()) {
            if l_entry.dir != r_entry.dir || l_entry.sibling != r_entry.sibling {
                return Err(CityGError::InvalidInput("shared suffix mismatch"));
            }
        }
        for entry in suffix_left.iter() {
            if entry.dir > 1 {
                return Err(CityGError::InvalidInput("shared suffix malformed"));
            }
        }
        suffix_left.to_vec()
    } else {
        Vec::new()
    };

    let l_h = u8::try_from(left_below.len() + 1)
        .map_err(|_| CityGError::InvalidInput("lca depth overflow"))?;
    let r_h = u8::try_from(right_below.len() + 1)
        .map_err(|_| CityGError::InvalidInput("lca depth overflow"))?;

    Ok((left_below, right_below, above, l_h, r_h))
}
