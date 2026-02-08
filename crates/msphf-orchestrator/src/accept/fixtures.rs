#![allow(dead_code)]

use super::*;
use crate::{
    BootstrapPolicy, HpArtifactOwned, HpBindingInputs, HpProof, JoinerKGenResult,
    KBROAD_ML_KEM_ALG, OrchestrationParams, SrxInputs, SrxNonMembershipAnchor, joiner_kgen_or,
    prove_hp_k,
};
use anchor_seed::{build_anchor_seed_ctx, compute_seed_bundle_commit, compute_seed_ctx_hash};
use ciborium::{
    de, ser,
    value::{Integer, Value},
};
use msphf_core::{
    ds,
    hash::{self, hash_bytes_with_label},
    merkle,
    params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK},
    witness::{RawMembershipWitness, RawNonMembershipWitness},
};
use pqcrypto_dilithium::dilithium5::{SecretKey as MlDsaSecretKey, detached_sign, keypair};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use serde::Serialize;
use std::{borrow::Cow, collections::BTreeMap, sync::OnceLock};
pub(crate) fn leak(bytes: [u8; 32]) -> &'static [u8] {
    Box::leak(Box::new(bytes)).as_slice()
}

pub(crate) fn unique_pop_keypair() -> crate::PopKeypair<'static> {
    let (pk, sk) = keypair();
    let pk_static: &'static [u8] = Box::leak(pk.as_bytes().to_vec().into_boxed_slice());
    let sk_static: &'static MlDsaSecretKey = Box::leak(Box::new(sk));
    crate::PopKeypair {
        algorithm: "ML-DSA-65",
        public_key: pk_static,
        secret_key: sk_static,
    }
}

pub(crate) fn leak_digest_vec(data: Vec<[u8; 32]>) -> &'static [[u8; 32]] {
    Box::leak(data.into_boxed_slice())
}

pub(crate) fn leak_mem_vec(data: Vec<RawMembershipWitness>) -> &'static [RawMembershipWitness] {
    Box::leak(data.into_boxed_slice())
}

pub(crate) fn sample_join_leaves() -> Vec<[u8; 32]> {
    let mut leaves = vec![
        merkle::hash_leaf(b"join-leaf-0"),
        merkle::hash_leaf(b"join-leaf-1"),
        merkle::hash_leaf(b"join-leaf-2"),
    ];
    leaves.sort();
    leaves
}

pub(crate) fn sentinel_nonmem(root: &[u8; 32], query: &[u8; 32]) -> RawNonMembershipWitness {
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

pub(crate) fn sample_anchor_fixture() -> (AnchorInstanceParts<'static>, SrxInputs<'static>) {
    let gid = leak([0x11; 32]);
    let cat = leak([0x22; 32]);

    let mut join_leaves = sample_join_leaves();
    if let Ok(pop_leaf) = crate::compute_leaf_id(
        crate::LeafIdMode::PerGroup,
        gid,
        "ML-DSA-65",
        pop_keys_static().0,
    ) && pop_leaf.len() == 32
    {
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(pop_leaf.as_slice());
        join_leaves.push(leaf);
    }
    join_leaves.sort();
    join_leaves.dedup();
    let join_root = match canonical_set_root(&join_leaves) {
        Ok(root) => root,
        Err(_) => unreachable!("canonical_set_root with valid test leaves cannot fail"),
    };
    let parent_root_arr = [0u8; 32];
    let revoked_since_root_arr = [0u8; 32];
    let revoked_root_arr = [0u8; 32];
    let pox_commit_arr = merkle::hash_leaf(b"pox-commit");

    let parent_root = leak(parent_root_arr);
    let join_delta_root = leak(join_root);
    let revoked_since_prev_root = leak(revoked_since_root_arr);
    let revoked_root = leak(revoked_root_arr);
    let pox_r_commit = leak(pox_commit_arr);

    let salt = match msphf_core::instance::tswe_salt_hash(gid, parent_root) {
        Ok(s) => s,
        Err(_) => unreachable!("tswe_salt_hash with valid test inputs cannot fail"),
    };
    let tswe_salt_hash = leak(salt);

    let parts = AnchorInstanceParts {
        gid,
        cat,
        tswe_salt_hash,
        parent_root,
        join_delta_root,
        revoked_since_prev_root,
        revoked_root,
        pox_r_commit: Some(pox_r_commit),
    };

    let join_leaf_ids = leak_digest_vec(join_leaves.clone());
    let since_leaf_ids = leak_digest_vec(Vec::new());

    let join_nonmem_parent = join_leaf_ids
        .iter()
        .map(|leaf| SrxNonMembershipAnchor {
            witness: sentinel_nonmem(&parent_root_arr, leaf),
            left_ref: None,
            right_ref: None,
        })
        .collect();
    let join_nonmem_revoked_since = join_leaf_ids
        .iter()
        .map(|leaf| SrxNonMembershipAnchor {
            witness: sentinel_nonmem(&revoked_since_root_arr, leaf),
            left_ref: None,
            right_ref: None,
        })
        .collect();
    let since_mem_revoked = leak_mem_vec(Vec::new());

    let srx_inputs = SrxInputs {
        join_leaf_ids: Cow::Borrowed(join_leaf_ids),
        join_nonmem_parent,
        join_nonmem_revoked_since,
        since_leaf_ids: Cow::Borrowed(since_leaf_ids),
        since_mem_revoked: Cow::Borrowed(since_mem_revoked),
        anchor_mem_pool: Vec::new(),
        join_frontier: None,
        since_frontier: None,
    };

    (parts, srx_inputs)
}

pub(crate) fn sample_parts() -> AnchorInstanceParts<'static> {
    sample_anchor_fixture().0
}

pub(crate) fn params() -> OrchestrationParams<'static> {
    let (_, srx) = sample_anchor_fixture();
    #[cfg(feature = "zkvrf-pq")]
    let (vrf_secret_key, vrf_public_key) = crate::proofs::zk_vrf::lb::deterministic_key_material();
    OrchestrationParams {
        msphf_crs_id: RLWE_CRS_ID_DEFAULT,
        params_id: RLWE_PARAMS_ID_MOCK,
        srx: Some(srx),
        srx_mode: crate::SrxMode::Complete,
        pop_keys: Some(crate::PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: pop_keys_static().0,
            secret_key: pop_keys_static().1,
        }),
        leaf_id_mode: crate::LeafIdMode::PerGroup,
        proof_mode: crate::DEFAULT_PROOF_MODE,
        vrf_id: crate::DEFAULT_VRF_ID,
        policy_version: crate::DEFAULT_POLICY_VERSION,
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
        fs_policy_version: "fs-policy-test",
        fs_epoch_base_ts: 0,
        fs_join: crate::FsJoinInputs {
            fs_ec: 0,
            fs_epoch_commit: [0xAA; 32],
            fs_dev_prev_commit: [0u8; 32],
        },
        fs_merge: crate::FsMergeInputs::default(),
    }
}

pub(crate) fn sample_header() -> BTreeMap<u64, Value> {
    let mut map = BTreeMap::new();
    map.insert(20, Value::Bytes(vec![0xAA]));
    map.insert(HDR_KBROAD_ALG, Value::Text(KBROAD_ML_KEM_ALG.to_string()));
    let (pk, _) = crate::kbroad_test_keys();
    map.insert(HDR_KBROAD_PUB, Value::Bytes(pk.to_vec()));
    map.insert(
        HDR_FS_POLICY_VERSION,
        Value::Text("fs-policy-test".to_string()),
    );
    map
}

pub fn sample_parts_params_joiner() -> (
    AnchorInstanceParts<'static>,
    OrchestrationParams<'static>,
    JoinerKGenResult,
) {
    let parts = sample_parts();
    let params = params();
    let header = sample_header();
    let joiner = match joiner_kgen_or(header, parts.clone(), params.clone(), None, None) {
        Ok(j) => j,
        Err(_) => unreachable!("joiner_kgen_or with valid test fixtures cannot fail"),
    };
    (parts, params, joiner)
}

pub(crate) fn bootstrap_keys() -> (&'static [u8], &'static MlDsaSecretKey) {
    static KEYS: OnceLock<(&'static [u8], &'static MlDsaSecretKey)> = OnceLock::new();
    *KEYS.get_or_init(|| {
        let (pk, sk) = keypair();
        let pk_static: &'static [u8] = Box::leak(pk.as_bytes().to_vec().into_boxed_slice());
        let sk_static: &'static MlDsaSecretKey = Box::leak(Box::new(sk));
        (pk_static, sk_static)
    })
}

pub(crate) fn pop_keys_static() -> (&'static [u8], &'static MlDsaSecretKey) {
    static KEYS: OnceLock<(&'static [u8], &'static MlDsaSecretKey)> = OnceLock::new();
    *KEYS.get_or_init(|| {
        let (pk, sk) = keypair();
        let pk_static: &'static [u8] = Box::leak(pk.as_bytes().to_vec().into_boxed_slice());
        let sk_static: &'static MlDsaSecretKey = Box::leak(Box::new(sk));
        (pk_static, sk_static)
    })
}

// Generates a one-off keypair and leaks it for the duration of the test process so the
// mocked joiner can own `'static` references without additional fixture plumbing.
pub(crate) fn fresh_pop_keypair() -> crate::PopKeypair<'static> {
    let (pk, sk) = keypair();
    let pk_static: &'static [u8] = Box::leak(pk.as_bytes().to_vec().into_boxed_slice());
    let sk_static: &'static MlDsaSecretKey = Box::leak(Box::new(sk));
    crate::PopKeypair {
        algorithm: "ML-DSA-65",
        public_key: pk_static,
        secret_key: sk_static,
    }
}

pub fn sample_pop_keys() -> (Vec<u8>, MlDsaSecretKey) {
    let (pk, sk) = pop_keys_static();
    (pk.to_vec(), *sk)
}

pub(crate) fn configure_bootstrap(ctx: &mut AcceptanceContext) {
    let (public_key, _) = bootstrap_keys();
    ctx.set_bootstrap_policy(BootstrapPolicy::CaMlDsa {
        public_key: public_key.to_vec(),
    });
}

pub(crate) fn sample_hp_inputs() -> (HpBindingInputs<'static>, HpProof) {
    let artifact = HpArtifactOwned {
        hp_a: vec![0x11; 96],
        hp_b: vec![0x22; 96],
        m_a: vec![0x33; 32],
        m_b: vec![0x44; 32],
        params_id: RLWE_PARAMS_ID_MOCK.to_string(),
        hp_version: 1,
    };
    let mut hp_bytes = Vec::new();
    match ser::into_writer(&artifact, &mut hp_bytes) {
        Ok(()) => (),
        Err(_) => unreachable!("serializing test HP artifact to Vec cannot fail"),
    }
    let hp_commit_arr = match hash_bytes_with_label(ds::MSPHF_HP_COMMIT, &hp_bytes) {
        Ok(arr) => arr,
        Err(_) => unreachable!("hashing test HP bytes cannot fail"),
    };
    let inputs = HpBindingInputs {
        msphf_crs_id: RLWE_CRS_ID_DEFAULT,
        params_id: RLWE_PARAMS_ID_MOCK,
        seed_ctx_hash: Box::leak(Box::new([0x10; 32])),
        seed_commit: Box::leak(Box::new([0x20; 32])),
        rho_commit: Box::leak(Box::new([0x30; 32])),
        xk_hash: Box::leak(Box::new([0x40; 32])),
        hp_commit: Box::leak(Box::new(hp_commit_arr)),
    };
    let proof = match prove_hp_k(&inputs) {
        Ok(p) => p,
        Err(_) => unreachable!("proving HP with valid test inputs cannot fail"),
    };
    (inputs, proof)
}

pub(crate) fn anchor_from_result<'a>(
    parts: &AnchorInstanceParts<'a>,
    result: &'a JoinerKGenResult,
) -> AnchorInstance<'a> {
    AnchorInstance {
        gid: parts.gid,
        cat: parts.cat,
        we_epoch_id: result.we_epoch_id,
        anchor_hdr_ctx: &result.anchor_hdr_ctx,
        tswe_salt_hash: parts.tswe_salt_hash,
        parent_root: parts.parent_root,
        join_delta_root: parts.join_delta_root,
        revoked_since_prev_root: parts.revoked_since_prev_root,
        revoked_root: parts.revoked_root,
        pox_r_commit: parts.pox_r_commit,
        msphf_hp_commit: Some(&result.hp_commit),
    }
}

pub(crate) fn header_with_pop_mode(
    joiner: &JoinerKGenResult,
    parts: &AnchorInstanceParts<'_>,
    pop_pk: &[u8],
    _pop_sk: &MlDsaSecretKey,
    mode: crate::LeafIdMode,
) -> BTreeMap<u64, Value> {
    let mut header = joiner.header_map.clone();
    let effective_pop_pk = header
        .get(&HDR_POP_PK)
        .and_then(|value| match value {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .unwrap_or_else(|| pop_pk.to_vec());
    if header.contains_key(&HDR_SRX_PAYLOAD) {
        mutate_srx_payload_preserving_leaf_auto(
            &mut header,
            parts.gid,
            mode,
            effective_pop_pk.as_slice(),
            |_| {},
        );
    }
    header
}

pub(crate) fn header_with_pop(
    joiner: &JoinerKGenResult,
    parts: &AnchorInstanceParts<'_>,
    pop_pk: &[u8],
    pop_sk: &MlDsaSecretKey,
) -> BTreeMap<u64, Value> {
    header_with_pop_mode(joiner, parts, pop_pk, pop_sk, crate::LeafIdMode::PerGroup)
}

pub(crate) fn seed_capss_with(ctx: &mut AcceptanceContext, witness: &CapssWitnessBundle) {
    ctx.set_pending_capss_witness(Some(witness.clone()));
}

pub(crate) fn seed_capss_from_joiner(ctx: &mut AcceptanceContext, joiner: &JoinerKGenResult) {
    ctx.set_pending_capss_witness(Some(joiner.capss_witness.clone()));
}

pub(crate) fn refresh_seed_bindings(
    header: &mut BTreeMap<u64, Value>,
    parts: &AnchorInstanceParts<'_>,
    joiner: &JoinerKGenResult,
) {
    let ctx = match build_anchor_seed_ctx(header) {
        Ok(c) => c,
        Err(_) => unreachable!("build_anchor_seed_ctx with test header cannot fail"),
    };
    let hash = match compute_seed_ctx_hash(&ctx) {
        Ok(h) => h,
        Err(_) => unreachable!("compute_seed_ctx_hash with valid context cannot fail"),
    };
    header.insert(HDR_SEED_CTX_HASH, Value::Bytes(hash.to_vec()));

    let mut parent_root = [0u8; 32];
    parent_root.copy_from_slice(parts.parent_root);
    let seed_bundle = match compute_seed_bundle_commit(
        &ctx,
        &joiner.rho_commit,
        parts.gid,
        parts.cat,
        &parent_root,
    ) {
        Ok(sb) => sb,
        Err(_) => unreachable!("compute_seed_bundle_commit with valid test inputs cannot fail"),
    };
    header.insert(HDR_SEED_BUNDLE_COMMIT, Value::Bytes(seed_bundle.to_vec()));
}

pub(crate) fn ensure_bootstrap_fields(
    header: &mut BTreeMap<u64, Value>,
    parts: &AnchorInstanceParts<'_>,
    joiner: &JoinerKGenResult,
) {
    if header.contains_key(&HDR_BOOTSTRAP_SIG) {
        return;
    }

    let anchor = anchor_from_result(parts, joiner);
    let (bootstrap_pk, bootstrap_sk) = bootstrap_keys();
    header.insert(HDR_BOOTSTRAP_ALG, Value::Text("oob-ca-v1".to_string()));
    let seed_ctx_hash = header_bytes32(header, HDR_SEED_CTX_HASH);
    let seed_bundle = header_bytes32(header, HDR_SEED_BUNDLE_COMMIT);
    let digest = match build_bootstrap_digest(
        header,
        &anchor,
        &joiner.hp_commit,
        &seed_ctx_hash,
        &joiner.rho_commit,
        &seed_bundle,
    ) {
        Ok(d) => d,
        Err(_) => unreachable!("build_bootstrap_digest with valid test inputs cannot fail"),
    };
    let sig = detached_sign(&digest, bootstrap_sk);
    header.insert(HDR_BOOTSTRAP_SIG, Value::Bytes(sig.as_bytes().to_vec()));
    header.insert(HDR_BOOTSTRAP_PK, Value::Bytes(bootstrap_pk.to_vec()));
}

pub(crate) fn recompute_fs_witness_from_header(
    header: &BTreeMap<u64, Value>,
    parts: &AnchorInstanceParts<'_>,
    joiner: &JoinerKGenResult,
) -> CapssWitnessBundle {
    let we_epoch_id = match compute_we_epoch_id_from_header(parts, header) {
        Ok(id) => id,
        Err(_) => unreachable!("compute_we_epoch_id_from_header with test fixtures cannot fail"),
    };
    let seed_ctx = match build_anchor_seed_ctx(header) {
        Ok(ctx) => ctx,
        Err(_) => unreachable!("build_anchor_seed_ctx with test header cannot fail"),
    };
    let seed_ctx_hash = match compute_seed_ctx_hash(&seed_ctx) {
        Ok(hash) => hash,
        Err(_) => unreachable!("compute_seed_ctx_hash with valid context cannot fail"),
    };
    let anchor = AnchorInstance {
        gid: parts.gid,
        cat: parts.cat,
        we_epoch_id,
        anchor_hdr_ctx: seed_ctx.as_slice(),
        tswe_salt_hash: parts.tswe_salt_hash,
        parent_root: parts.parent_root,
        join_delta_root: parts.join_delta_root,
        revoked_since_prev_root: parts.revoked_since_prev_root,
        revoked_root: parts.revoked_root,
        pox_r_commit: parts.pox_r_commit,
        msphf_hp_commit: Some(&joiner.hp_commit),
    };
    let xk_hash = match anchor.xk_hash() {
        Ok(hash) => hash,
        Err(_) => unreachable!("xk_hash with valid anchor cannot fail"),
    };
    let pop_alg = match header_string_or_freeze(header, HDR_POP_ALG) {
        Ok(alg) => alg,
        Err(_) => unreachable!("pop_alg must be present in test header"),
    };
    let pop_pk_bytes = match header.get(&HDR_POP_PK).and_then(|value| match value {
        Value::Bytes(bytes) => Some(bytes.clone()),
        _ => None,
    }) {
        Some(bytes) => bytes,
        None => unreachable!("pop pk must be present in test header"),
    };
    let leaf_id = match crate::compute_leaf_id(
        crate::LeafIdMode::PerGroup,
        parts.gid,
        pop_alg.as_str(),
        &pop_pk_bytes,
    ) {
        Ok(id) => id,
        Err(_) => unreachable!("compute_leaf_id with valid test inputs cannot fail"),
    };
    let pop_sig = match header.get(&HDR_POP_SIG).and_then(|value| match value {
        Value::Bytes(bytes) => Some(bytes.clone()),
        _ => None,
    }) {
        Some(sig) => sig,
        None => unreachable!("pop sig must be present in test header"),
    };

    let crs_id = match header_string_or_freeze(header, HDR_CRS_ID) {
        Ok(id) => id,
        Err(_) => unreachable!("crs_id must be present in test header"),
    };
    let params_id = match header_string_or_freeze(header, HDR_PARAMS_ID) {
        Ok(id) => id,
        Err(_) => unreachable!("params_id must be present in test header"),
    };

    let inputs = CapssStrictInputs {
        crs_id: &crs_id,
        params_id: &params_id,
        seed_commit: &joiner.seed_commit,
        seed_ctx_hash: &seed_ctx_hash,
        xk_hash: &xk_hash,
        rho_commit: &joiner.rho_commit,
        pop_alg: &pop_alg,
        pop_pk: pop_pk_bytes.as_slice(),
        anchor: &anchor,
        leaf_id: leaf_id.as_slice(),
        pop_sig,
    };

    match recompute_capss_witness(inputs) {
        Ok(witness) => witness,
        Err(_) => unreachable!("recompute_capss_witness with valid test inputs cannot fail"),
    }
}

pub(crate) fn prepare_header_for_acceptance(
    header: &mut BTreeMap<u64, Value>,
    parts: &AnchorInstanceParts<'_>,
    joiner: &JoinerKGenResult,
) -> CapssWitnessBundle {
    ensure_bootstrap_fields(header, parts, joiner);
    refresh_seed_bindings(header, parts, joiner);
    recompute_fs_witness_from_header(header, parts, joiner)
}

pub fn header_ready_with_pop(
    joiner: &JoinerKGenResult,
    parts: &AnchorInstanceParts<'_>,
    pop_pk: &[u8],
    pop_sk: &MlDsaSecretKey,
) -> (BTreeMap<u64, Value>, [u8; 32], CapssWitnessBundle) {
    let (mut header, we_epoch_id) = header_with_pop_and_weid(joiner, parts, pop_pk, pop_sk);
    let witness = prepare_header_for_acceptance(&mut header, parts, joiner);
    (header, we_epoch_id, witness)
}

pub(crate) fn header_with_pop_and_weid(
    joiner: &JoinerKGenResult,
    parts: &AnchorInstanceParts<'_>,
    pop_pk: &[u8],
    pop_sk: &MlDsaSecretKey,
) -> (BTreeMap<u64, Value>, [u8; 32]) {
    let header = header_with_pop(joiner, parts, pop_pk, pop_sk);
    let we_epoch_id = match super::compute_we_epoch_id_from_header(parts, &header) {
        Ok(id) => id,
        Err(_) => unreachable!("compute_we_epoch_id_from_header with test fixtures cannot fail"),
    };
    (header, we_epoch_id)
}

pub(crate) fn accept_with_header(
    ctx: &mut AcceptanceContext,
    parts: &AnchorInstanceParts<'_>,
    header: &BTreeMap<u64, Value>,
) -> Result<AcceptanceOutcome, AcceptanceError> {
    let we_epoch_id = super::compute_we_epoch_id_from_header(parts, header)?;
    ctx.accept_anchor(parts, we_epoch_id, header)
}

pub(crate) fn header_bytes32(header: &BTreeMap<u64, Value>, key: u64) -> [u8; 32] {
    let bytes = match header.get(&key).and_then(|value| match value {
        Value::Bytes(bytes) if bytes.len() == 32 => Some(bytes),
        _ => None,
    }) {
        Some(b) => b,
        None => unreachable!("test header must contain 32-byte field at key {}", key),
    };
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    arr
}

pub(crate) fn reseal_header(
    header: &mut BTreeMap<u64, Value>,
    parts: &AnchorInstanceParts<'_>,
    joiner: &JoinerKGenResult,
) {
    attach_bootstrap_only(header, parts, joiner);
}

pub(crate) fn attach_bootstrap_only(
    header: &mut BTreeMap<u64, Value>,
    parts: &AnchorInstanceParts<'_>,
    joiner: &JoinerKGenResult,
) {
    header.remove(&HDR_BOOTSTRAP_SIG);
    header.remove(&HDR_BOOTSTRAP_PK);
    header.insert(HDR_BOOTSTRAP_ALG, Value::Text("oob-ca-v1".to_string()));
    let anchor_seed_ctx = match build_anchor_seed_ctx(header) {
        Ok(ctx) => ctx,
        Err(_) => unreachable!("build_anchor_seed_ctx with test header cannot fail"),
    };
    let seed_ctx_hash = match compute_seed_ctx_hash(&anchor_seed_ctx) {
        Ok(hash) => hash,
        Err(_) => unreachable!("compute_seed_ctx_hash with valid context cannot fail"),
    };
    header.insert(HDR_SEED_CTX_HASH, Value::Bytes(seed_ctx_hash.to_vec()));

    let mut parent_root = [0u8; 32];
    parent_root.copy_from_slice(parts.parent_root);
    let seed_bundle_commit = match compute_seed_bundle_commit(
        &anchor_seed_ctx,
        &joiner.rho_commit,
        parts.gid,
        parts.cat,
        &parent_root,
    ) {
        Ok(commit) => commit,
        Err(_) => unreachable!("compute_seed_bundle_commit with valid test inputs cannot fail"),
    };
    header.insert(
        HDR_SEED_BUNDLE_COMMIT,
        Value::Bytes(seed_bundle_commit.to_vec()),
    );

    let verify_ctx = match build_anchor_seed_ctx(header) {
        Ok(ctx) => ctx,
        Err(_) => unreachable!("build_anchor_seed_ctx verification with test header cannot fail"),
    };
    let verify_hash = match compute_seed_ctx_hash(&verify_ctx) {
        Ok(hash) => hash,
        Err(_) => unreachable!("compute_seed_ctx_hash verification with valid context cannot fail"),
    };
    assert_eq!(
        verify_hash, seed_ctx_hash,
        "attach_bootstrap_only produced inconsistent seed ctx hash"
    );

    let anchor_ctx_ref: &'static [u8] = Box::leak(anchor_seed_ctx.into_boxed_slice());
    let anchor = AnchorInstance {
        gid: parts.gid,
        cat: parts.cat,
        we_epoch_id: joiner.we_epoch_id,
        anchor_hdr_ctx: anchor_ctx_ref,
        tswe_salt_hash: parts.tswe_salt_hash,
        parent_root: parts.parent_root,
        join_delta_root: parts.join_delta_root,
        revoked_since_prev_root: parts.revoked_since_prev_root,
        revoked_root: parts.revoked_root,
        pox_r_commit: parts.pox_r_commit,
        msphf_hp_commit: Some(&joiner.hp_commit),
    };
    let (bootstrap_pk, bootstrap_sk) = bootstrap_keys();
    let digest = match build_bootstrap_digest(
        header,
        &anchor,
        &joiner.hp_commit,
        &seed_ctx_hash,
        &joiner.rho_commit,
        &seed_bundle_commit,
    ) {
        Ok(d) => d,
        Err(_) => unreachable!("build_bootstrap_digest with valid test inputs cannot fail"),
    };
    let sig = detached_sign(&digest, bootstrap_sk);
    header.insert(HDR_BOOTSTRAP_SIG, Value::Bytes(sig.as_bytes().to_vec()));
    header.insert(HDR_BOOTSTRAP_PK, Value::Bytes(bootstrap_pk.to_vec()));
}

pub(crate) fn refresh_seed_ctx_hash(header: &mut BTreeMap<u64, Value>) {
    let ctx = match build_anchor_seed_ctx(header) {
        Ok(c) => c,
        Err(_) => unreachable!("build_anchor_seed_ctx with test header cannot fail"),
    };
    let hash = match compute_seed_ctx_hash(&ctx) {
        Ok(h) => h,
        Err(_) => unreachable!("compute_seed_ctx_hash with valid context cannot fail"),
    };
    header.insert(HDR_SEED_CTX_HASH, Value::Bytes(hash.to_vec()));
}

#[derive(Serialize)]
struct Commit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

pub(crate) fn compute_srx_commit(bytes: &[u8]) -> [u8; 32] {
    match hash::h_l(ds::MSPHF_SRX_COMMIT, &Commit(bytes)) {
        Ok(hash) => hash,
        Err(_) => unreachable!("hashing SRX commit with valid bytes cannot fail"),
    }
}

pub(crate) fn encode_value(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    match ser::into_writer(value, &mut buf) {
        Ok(()) => (),
        Err(_) => unreachable!("serializing CBOR value to Vec cannot fail"),
    }
    buf
}

pub fn mutate_srx_payload(header: &mut BTreeMap<u64, Value>, mutator: impl FnOnce(&mut Value)) {
    let payload_bytes = match header.get(&HDR_SRX_PAYLOAD).and_then(|value| match value {
        Value::Bytes(bytes) => Some(bytes.clone()),
        _ => None,
    }) {
        Some(bytes) => bytes,
        None => unreachable!("test header must contain srx payload"),
    };
    let mut payload_value: Value = match de::from_reader(payload_bytes.as_slice()) {
        Ok(val) => val,
        Err(_) => unreachable!("decoding test srx payload cannot fail"),
    };
    mutator(&mut payload_value);

    let items = match payload_value.as_array_mut() {
        Some(arr) => arr,
        None => unreachable!("test payload must be array structure"),
    };
    assert_eq!(items.len(), 9, "unexpected payload length");

    let join_leaf_ids = match items[4].as_array() {
        Some(arr) => arr.len(),
        None => unreachable!("join_leaf_ids must be array in test payload"),
    };
    let since_leaf_ids = match items[6].as_array() {
        Some(arr) => arr.len(),
        None => unreachable!("since_leaf_ids must be array in test payload"),
    };
    let anchor_pool = match items[8].as_array() {
        Some(arr) => arr.len(),
        None => unreachable!("anchor_mem_pool must be array in test payload"),
    };
    let join_frontier_len = items[5].as_array().map(|arr| arr.len()).unwrap_or(0);
    let since_frontier_len = items[7].as_array().map(|arr| arr.len()).unwrap_or(0);

    set_srx_meta(
        &mut payload_value,
        join_leaf_ids,
        since_leaf_ids,
        join_frontier_len,
        since_frontier_len,
    );

    let new_payload_bytes = encode_value(&payload_value);
    let payload_len = new_payload_bytes.len() as u64;
    let commit = compute_srx_commit(&new_payload_bytes);

    header.insert(HDR_SRX_COMMIT, Value::Bytes(commit.to_vec()));
    header.insert(HDR_SRX_PAYLOAD, Value::Bytes(new_payload_bytes));

    let hint_counts = Value::Map(vec![
        (
            Value::Text("join".to_string()),
            Value::Integer(Integer::from(join_leaf_ids as u64)),
        ),
        (
            Value::Text("since".to_string()),
            Value::Integer(Integer::from(since_leaf_ids as u64)),
        ),
        (
            Value::Text("anchors".to_string()),
            Value::Integer(Integer::from(anchor_pool as u64)),
        ),
    ]);
    header.insert(123, Value::Bytes(encode_value(&hint_counts)));

    let hint_sizes = Value::Map(vec![(
        Value::Text("bytes".to_string()),
        Value::Integer(Integer::from(payload_len)),
    )]);
    header.insert(124, Value::Bytes(encode_value(&hint_sizes)));
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

pub(crate) fn ensure_leaf_in_payload(payload: &mut Value, leaf: &[u8; 32]) {
    let Value::Array(items) = payload else {
        return;
    };
    if items.len() != 9 {
        return;
    }
    let Value::Array(join_ids) = &mut items[4] else {
        return;
    };
    let leaf_bytes = leaf.to_vec();
    let already = join_ids.iter().any(|entry| match entry {
        Value::Bytes(bytes) => bytes == &leaf_bytes,
        _ => false,
    });
    if !already {
        join_ids.push(Value::Bytes(leaf_bytes));
    }
}

pub(crate) fn mutate_srx_payload_preserving_leaf(
    header: &mut BTreeMap<u64, Value>,
    leaf: &[u8; 32],
    mutator: impl FnOnce(&mut Value),
) {
    mutate_srx_payload(header, |payload| {
        mutator(payload);
        ensure_leaf_in_payload(payload, leaf);
    });
}

pub(crate) fn mutate_srx_payload_preserving_leaf_auto(
    header: &mut BTreeMap<u64, Value>,
    gid: &[u8],
    mode: crate::LeafIdMode,
    pop_pk: &[u8],
    mutator: impl FnOnce(&mut Value),
) {
    if let Ok(leaf_arr) = crate::compute_leaf_id(mode, gid, "ML-DSA-65", pop_pk) {
        mutate_srx_payload_preserving_leaf(header, &leaf_arr, mutator);
        return;
    }
    mutate_srx_payload(header, mutator);
}
