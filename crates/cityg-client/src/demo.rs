use std::{
    collections::BTreeMap,
    convert::TryFrom,
    fs,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use ciborium::ser::into_writer;
use ciborium::value::{Integer, Value};
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
    SrxInputs, SrxMode, SrxNonMembershipAnchor, build_bootstrap_digest, compute_leaf_id,
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

#[derive(Clone)]
struct DemoIdentity {
    leaf: [u8; 32],
    pop_public_key: Vec<u8>,
    pop_secret_key: Vec<u8>,
}

fn identity_registry() -> &'static Mutex<BTreeMap<String, DemoIdentity>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<String, DemoIdentity>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn member_identity(label: &str) -> DemoIdentity {
    let registry = identity_registry();
    let mut guard = match registry.lock() {
        Ok(g) => g,
        Err(_) => unreachable!(),
    };
    if let Some(existing) = guard.get(label) {
        existing.clone()
    } else {
        let (pop_pk, pop_sk) = keypair();
        let pop_public_key = pop_pk.as_bytes().to_vec();
        let pop_secret_key = pop_sk.as_bytes().to_vec();
        let leaf_id = match compute_leaf_id(
            LeafIdMode::PerGroup,
            &DEMO_GID,
            "ML-DSA-65",
            pop_public_key.as_slice(),
        ) {
            Ok(bytes) => bytes,
            Err(_) => unreachable!("demo leaf_id derivation must succeed"),
        };
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(leaf_id.as_slice());
        let identity = DemoIdentity {
            leaf,
            pop_public_key,
            pop_secret_key,
        };
        guard.insert(label.to_string(), identity.clone());
        identity
    }
}

fn identity_for_leaf(leaf: &[u8; 32]) -> Option<DemoIdentity> {
    let registry = identity_registry();
    let guard = match registry.lock() {
        Ok(g) => g,
        Err(_) => unreachable!(),
    };
    guard
        .values()
        .find(|identity| &identity.leaf == leaf)
        .cloned()
}

fn demo_vrf_keys() -> (&'static [u8], &'static [u8]) {
    static VRF_KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    let pair = VRF_KEYS.get_or_init(|| {
        let params = match msphf_orchestrator::lb::generate_parameters([0u8; 32]) {
            Ok(params) => params,
            Err(_) => unreachable!("deterministic demo VRF params must be derivable"),
        };
        match msphf_orchestrator::lb::generate_keypair(&params, [1u8; 32]) {
            Ok(pair) => pair,
            Err(_) => unreachable!("deterministic demo VRF keypair must be derivable"),
        }
    });
    (&pair.0, &pair.1)
}

fn member_leaf(label: &str) -> [u8; 32] {
    member_identity(label).leaf
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
        &[],
        revoked_since_root,
        &[],
        revoked_root,
    )?;
    let witness_bytes = witness::witness_to_cbor(&canonical_witness)?;
    let srx_inputs = srx_owned.into_srx_inputs();

    let (pop_pk_bytes, pop_sk_obj) = if join_leaves.len() == 1 {
        if let Some(identity) = identity_for_leaf(&join_leaves[0]) {
            let pop_sk =
                <MlDsaSecretKey as SecretKey>::from_bytes(identity.pop_secret_key.as_slice())
                    .map_err(|_| CityGError::InvalidInput("demo pop secret malformed"))?;
            (identity.pop_public_key, pop_sk)
        } else {
            let (pop_pk, pop_sk) = keypair();
            (pop_pk.as_bytes().to_vec(), pop_sk)
        }
    } else {
        let (pop_pk, pop_sk) = keypair();
        (pop_pk.as_bytes().to_vec(), pop_sk)
    };

    let header = base_header();

    let (vrf_secret_key, vrf_public_key) = demo_vrf_keys();

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
        fs_policy_version: "7",
        fs_epoch_base_ts: 0,
        barrier_version: 0,
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
    demo_config_root().map(|dir| dir.join("demo-bootstrap.key"))
}

fn kbroad_key_path() -> Option<PathBuf> {
    demo_config_root().map(|dir| dir.join("demo-kbroad.key"))
}

fn demo_config_root() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("CITYG_DEMO_CONFIG_DIR") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    config_dir().map(|dir| dir.join("cityg"))
}

fn load_or_generate_kbroad_keys() -> Result<(Vec<u8>, Vec<u8>), CityGError> {
    let pk_len = kyber_public_key_bytes();
    let sk_len = kyber_secret_key_bytes();

    if let Some(path) = kbroad_key_path()
        && let Ok(bytes) = fs::read(&path)
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
    map.insert(176, Value::Integer(Integer::from(0u64)));
    map.insert(177, Value::Bytes(vec![0x42; 1_184]));
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

    let pos = parent_leaves.partition_point(|leaf| leaf < &query);

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
        (None, None) => unreachable!("non-empty parent set must produce at least one anchor"),
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::witness::sequential_leaf;
    use std::{
        ffi::OsString,
        fs,
        path::PathBuf,
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn demo_vrf_keys_are_stable_across_calls() {
        let (sk1, pk1) = demo_vrf_keys();
        let (sk2, pk2) = demo_vrf_keys();
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
    }

    fn setup_demo_config_dir(label: &str) -> Result<(PathBuf, Option<OsString>), CityGError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CityGError::InvalidInput("time went backwards"))?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("cityg-demo-tests-{label}-{ts}"));
        fs::create_dir_all(&dir)?;
        let previous = std::env::var_os("CITYG_DEMO_CONFIG_DIR");
        // SAFETY: tests are serialized via `env_lock`, so mutating process env is race-free.
        unsafe { std::env::set_var("CITYG_DEMO_CONFIG_DIR", &dir) };
        Ok((dir, previous))
    }

    fn teardown_demo_config_dir(dir: &PathBuf, previous: Option<OsString>) {
        match previous {
            // SAFETY: tests are serialized via `env_lock`, so mutating process env is race-free.
            Some(value) => unsafe { std::env::set_var("CITYG_DEMO_CONFIG_DIR", value) },
            // SAFETY: tests are serialized via `env_lock`, so mutating process env is race-free.
            None => unsafe { std::env::remove_var("CITYG_DEMO_CONFIG_DIR") },
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn demo_config_root_respects_env_override() -> Result<(), CityGError> {
        let _guard = env_lock()
            .lock()
            .map_err(|_| CityGError::InvalidInput("env lock poisoned"))?;
        let (dir, previous) = setup_demo_config_dir("root")?;
        let root = demo_config_root().expect("config root should resolve");
        assert_eq!(root, dir);
        teardown_demo_config_dir(&dir, previous);
        Ok(())
    }

    #[test]
    fn demo_config_root_uses_fallback_when_env_blank() -> Result<(), CityGError> {
        let _guard = env_lock()
            .lock()
            .map_err(|_| CityGError::InvalidInput("env lock poisoned"))?;
        let previous = std::env::var_os("CITYG_DEMO_CONFIG_DIR");
        // SAFETY: tests are serialized via `env_lock`, so mutating process env is race-free.
        unsafe { std::env::set_var("CITYG_DEMO_CONFIG_DIR", "   ") };
        let root = demo_config_root();
        let expected = dirs::config_dir().map(|dir| dir.join("cityg"));
        assert_eq!(root, expected);
        match previous {
            // SAFETY: tests are serialized via `env_lock`, so mutating process env is race-free.
            Some(value) => unsafe { std::env::set_var("CITYG_DEMO_CONFIG_DIR", value) },
            // SAFETY: tests are serialized via `env_lock`, so mutating process env is race-free.
            None => unsafe { std::env::remove_var("CITYG_DEMO_CONFIG_DIR") },
        }
        Ok(())
    }

    #[test]
    fn load_or_generate_kbroad_keys_roundtrips_on_disk() -> Result<(), CityGError> {
        let _guard = env_lock()
            .lock()
            .map_err(|_| CityGError::InvalidInput("env lock poisoned"))?;
        let (dir, previous) = setup_demo_config_dir("kbroad-roundtrip")?;

        let (pk_first, sk_first) = load_or_generate_kbroad_keys()?;
        let stored = fs::read(dir.join("demo-kbroad.key"))?;
        assert_eq!(stored.len(), pk_first.len() + sk_first.len());

        let (pk_second, sk_second) = load_or_generate_kbroad_keys()?;
        assert_eq!(pk_first, pk_second);
        assert_eq!(sk_first, sk_second);

        teardown_demo_config_dir(&dir, previous);
        Ok(())
    }

    #[test]
    fn load_or_generate_kbroad_keys_replaces_malformed_file() -> Result<(), CityGError> {
        let _guard = env_lock()
            .lock()
            .map_err(|_| CityGError::InvalidInput("env lock poisoned"))?;
        let (dir, previous) = setup_demo_config_dir("kbroad-malformed")?;

        fs::write(dir.join("demo-kbroad.key"), [0xAA, 0xBB, 0xCC])?;
        let (pk, sk) = load_or_generate_kbroad_keys()?;
        assert!(!pk.is_empty());
        assert!(!sk.is_empty());

        let rewritten = fs::read(dir.join("demo-kbroad.key"))?;
        assert_eq!(rewritten.len(), pk.len() + sk.len());

        teardown_demo_config_dir(&dir, previous);
        Ok(())
    }

    #[test]
    fn load_or_generate_bootstrap_keys_roundtrips_on_disk() -> Result<(), CityGError> {
        let _guard = env_lock()
            .lock()
            .map_err(|_| CityGError::InvalidInput("env lock poisoned"))?;
        let (dir, previous) = setup_demo_config_dir("bootstrap-roundtrip")?;

        let (pk_first, sk_first) = load_or_generate_bootstrap_keys()?;
        let stored = fs::read(dir.join("demo-bootstrap.key"))?;
        assert_eq!(stored.len(), pk_first.len() + sk_first.as_bytes().len());

        let (pk_second, sk_second) = load_or_generate_bootstrap_keys()?;
        assert_eq!(pk_first, pk_second);
        assert_eq!(sk_first.as_bytes(), sk_second.as_bytes());

        teardown_demo_config_dir(&dir, previous);
        Ok(())
    }

    #[test]
    fn load_or_generate_bootstrap_keys_replaces_malformed_file() -> Result<(), CityGError> {
        let _guard = env_lock()
            .lock()
            .map_err(|_| CityGError::InvalidInput("env lock poisoned"))?;
        let (dir, previous) = setup_demo_config_dir("bootstrap-malformed")?;

        fs::write(dir.join("demo-bootstrap.key"), [0xAA, 0xBB])?;
        let (pk, sk) = load_or_generate_bootstrap_keys()?;
        assert!(!pk.is_empty());
        assert!(!sk.as_bytes().is_empty());

        let rewritten = fs::read(dir.join("demo-bootstrap.key"))?;
        assert_eq!(rewritten.len(), pk.len() + sk.as_bytes().len());

        teardown_demo_config_dir(&dir, previous);
        Ok(())
    }

    #[test]
    fn demo_bundle_attaches_bootstrap_only_for_genesis() -> Result<(), CityGError> {
        let genesis = demo_bundle_with_parent_leaves(&[], sequential_leaf(501))?;
        assert!(genesis.header_map.contains_key(&hdr::HDR_BOOTSTRAP_SIG));
        let parent = [sequential_leaf(1)];
        let joined = demo_bundle_with_parent_leaves(&parent, sequential_leaf(502))?;
        assert!(!joined.header_map.contains_key(&hdr::HDR_BOOTSTRAP_SIG));
        Ok(())
    }

    #[test]
    fn parent_nonmem_witness_covers_all_reachable_shapes() -> Result<(), CityGError> {
        let leaves = vec![
            sequential_leaf(10),
            sequential_leaf(20),
            sequential_leaf(30),
        ];
        let parent_root = canonical_set_root(&leaves)?;

        let (empty_witness, empty_left, empty_right) =
            parent_nonmem_witness(&[], [0x11; 32], sequential_leaf(1));
        assert!(empty_witness.left.is_none());
        assert!(empty_witness.right.is_none());
        assert!(empty_left.is_none());
        assert!(empty_right.is_none());

        let (left_boundary, left_anchor, right_anchor) =
            parent_nonmem_witness(&leaves, parent_root, sequential_leaf(1));
        assert!(left_anchor.is_none());
        assert_eq!(right_anchor, Some(leaves[0]));
        assert!(left_boundary.left.is_none());
        assert!(left_boundary.right.is_some());
        assert!(!left_boundary.path.is_empty());

        let (right_boundary, left_anchor, right_anchor) =
            parent_nonmem_witness(&leaves, parent_root, sequential_leaf(100));
        assert_eq!(left_anchor, Some(leaves[2]));
        assert!(right_anchor.is_none());
        assert!(right_boundary.left.is_some());
        assert!(right_boundary.right.is_none());
        assert!(!right_boundary.path.is_empty());

        let (interval, left_anchor, right_anchor) =
            parent_nonmem_witness(&leaves, parent_root, sequential_leaf(25));
        assert_eq!(left_anchor, Some(leaves[1]));
        assert_eq!(right_anchor, Some(leaves[2]));
        assert!(interval.path.is_empty());
        assert!(interval.left_below.len() <= 1);
        assert!(interval.right_below.len() <= 1);
        assert!(interval.nmint.is_some());
        Ok(())
    }

    #[test]
    fn build_srx_inputs_covers_single_sided_anchor_refs() -> Result<(), CityGError> {
        let parent_leaves = vec![sequential_leaf(1), sequential_leaf(2)];
        let parent_root = canonical_set_root(&parent_leaves)?;

        let left_join = vec![sequential_leaf(0)];
        let left_srx = build_srx_inputs(&left_join, &parent_leaves, parent_root, [0xAA; 32]);
        let left_item = &left_srx.join_nonmem_parent[0];
        assert!(left_item.left_ref.is_none());
        assert!(left_item.right_ref.is_some());

        let right_join = vec![sequential_leaf(99)];
        let right_srx = build_srx_inputs(&right_join, &parent_leaves, parent_root, [0xBB; 32]);
        let right_item = &right_srx.join_nonmem_parent[0];
        assert!(right_item.left_ref.is_some());
        assert!(right_item.right_ref.is_none());
        Ok(())
    }

    #[test]
    fn canonical_membership_path_and_fold_step_cover_success() -> Result<(), CityGError> {
        let leaves = vec![sequential_leaf(7), sequential_leaf(8)];
        let root = canonical_set_root(&leaves)?;

        let left_path = canonical_membership_path(&leaves, &leaves[0]);
        assert_eq!(left_path.len(), 1);
        assert_eq!(left_path[0].dir, 0);
        let mut left_acc = leaves[0];
        fold_step_into(&mut left_acc, &left_path[0])?;
        assert_eq!(left_acc, root);

        let right_path = canonical_membership_path(&leaves, &leaves[1]);
        assert_eq!(right_path.len(), 1);
        assert_eq!(right_path[0].dir, 1);
        let mut right_acc = leaves[1];
        fold_step_into(&mut right_acc, &right_path[0])?;
        assert_eq!(right_acc, root);

        assert!(canonical_membership_path(&[leaves[0]], &leaves[0]).is_empty());
        Ok(())
    }

    #[test]
    fn split_interval_paths_success_and_invalid_depth() -> Result<(), CityGError> {
        let leaves = vec![
            sequential_leaf(11),
            sequential_leaf(12),
            sequential_leaf(13),
            sequential_leaf(14),
        ];
        let root = canonical_set_root(&leaves)?;
        let left_path = canonical_membership_path(&leaves, &leaves[0]);
        let right_path = canonical_membership_path(&leaves, &leaves[1]);
        let (left_below, right_below, above, l_h, r_h) =
            split_interval_paths(leaves[0], &left_path, leaves[1], &right_path, root)?;
        assert_eq!(usize::from(l_h), left_below.len() + 1);
        assert_eq!(usize::from(r_h), right_below.len() + 1);
        assert!(!above.is_empty());

        let err = split_interval_paths(leaves[0], &[], leaves[0], &[], leaves[0])
            .expect_err("expected invalid LCA depth");
        assert!(err.to_string().contains("invalid LCA depth"));
        Ok(())
    }

    #[test]
    fn fold_step_into_rejects_invalid_inputs() {
        let mut acc = [0u8; 32];
        let bad_len = RawPathEntry {
            dir: 0,
            sibling: vec![0u8; 31],
        };
        let bad_dir = RawPathEntry {
            dir: 3,
            sibling: vec![0u8; 32],
        };

        assert!(fold_step_into(&mut acc, &bad_len).is_err());
        assert!(fold_step_into(&mut acc, &bad_dir).is_err());
    }

    #[test]
    fn split_interval_paths_rejects_inconsistent_roots() {
        let leaf_left = [0x11; 32];
        let leaf_right = [0x22; 32];
        let err = split_interval_paths(leaf_left, &[], leaf_right, &[], [0xFF; 32])
            .expect_err("mismatched root should fail");
        assert!(
            err.to_string()
                .contains("membership path inconsistent with root")
        );
    }

    #[test]
    fn build_srx_inputs_populates_anchor_refs_for_interval_join() -> Result<(), CityGError> {
        let parent_leaves = vec![[0x10; 32], [0x30; 32], [0x50; 32]];
        let parent_root = canonical_set_root(&parent_leaves)?;
        let join_leaves = vec![[0x40; 32]];

        let srx = build_srx_inputs(&join_leaves, &parent_leaves, parent_root, [0u8; 32]);
        assert_eq!(srx.join_nonmem_parent.len(), 1);
        let item = &srx.join_nonmem_parent[0];
        assert!(item.left_ref.is_some());
        assert!(item.right_ref.is_some());
        assert!(item.witness.left.is_some());
        assert!(item.witness.right.is_some());
        Ok(())
    }

    #[test]
    fn attach_bootstrap_sets_expected_headers() -> Result<(), CityGError> {
        let mut bundle = demo_bundle_with_parent_leaves(&[], sequential_leaf(1))?;
        attach_bootstrap(&mut bundle)?;
        assert!(bundle.header_map.contains_key(&hdr::HDR_BOOTSTRAP_ALG));
        assert!(bundle.header_map.contains_key(&hdr::HDR_BOOTSTRAP_PK));
        assert!(bundle.header_map.contains_key(&hdr::HDR_BOOTSTRAP_SIG));
        Ok(())
    }
}
