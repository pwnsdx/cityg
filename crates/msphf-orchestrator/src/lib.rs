#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use std::{
    borrow::Cow,
    collections::{BTreeMap, VecDeque},
    convert::TryInto,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anchor_seed::{
    SeedCommitFields, build_anchor_seed_ctx, compute_seed_bundle_commit, compute_seed_commit,
    compute_seed_ctx_hash,
};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ciborium::{
    ser::into_writer,
    value::{Integer, Value},
};
use msphf_core::{
    MsphfError, WitnessValidationError, ds,
    hash::{eid_from_epoch, h_branch_bytes, h_l, hash_bytes_with_label, xof32},
    hkdf::hkdf_blake3,
    instance::{AnchorInstance, epoch_key},
    merkle::{canonical_frontier, canonical_set_root},
    serde_utils::to_cbor_vec,
    witness::{
        CanonicalWitness, RawMembershipWitness, RawNonMembershipWitness, RawPathEntry,
        ValidatedWitness, WitnessMode,
    },
};
use msphf_rlwe::{
    RlweProjectiveParams, derive_branch_material, derive_drbg_seed, hash_full as rlwe_hash_full,
    hash_proj as rlwe_hash_proj,
};
use pqcrypto_dilithium::dilithium5::{SecretKey as MlDsaSecretKey, detached_sign};
use pqcrypto_kyber::kyber768::{
    Ciphertext as MlKemCiphertext, PublicKey as MlKemPublicKey, SecretKey as MlKemSecretKey,
    ciphertext_bytes as ml_kem_ciphertext_bytes, decapsulate as ml_kem_decapsulate,
    encapsulate as ml_kem_encapsulate, public_key_bytes as ml_kem_public_key_bytes,
};
use pqcrypto_traits::sign::DetachedSignature;
use proofs::{capss, srx_smallwood, zk_vrf};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

mod accept;
mod time;
pub use time::AcceptInstant;
pub mod hdr;
pub mod policy;
mod proofs;
#[cfg(feature = "bench-fixtures")]
pub use accept::SrxBenchHarness;
#[cfg(feature = "bench-fixtures")]
pub use accept::fixtures;
pub use accept::{
    AcceptanceContext, AcceptanceError, AcceptanceKind, AcceptanceOptions, AcceptanceOutcome,
    AnnexMTelemetryReport, AnnexMTelemetryRow, BarrierGroupState, BootstrapPolicy,
    DeviceChainState, FREEZE_BARRIER_EXPECTEDPAIRS_FAILURE,
    FREEZE_BARRIER_NON_REVOCATION_REASON_FORBIDDEN_WHILE_PENDING_REVOCATIONS,
    FREEZE_BARRIER_PROACTIVE_FORBIDDEN, FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE,
    FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE, FREEZE_BARRIER_UPDATE_MALFORMED,
    FREEZE_BARRIER_UPDATER_INVALID, FsPolicyConfig, TelemetryCounters, TelemetryKey,
    build_bootstrap_digest,
};
pub use hdr::*;
pub use policy::{
    PolicyDocument, PolicyError, PolicyTrustAnchors, load_policy_journal_from_bytes,
    load_policy_journal_from_reader,
};
pub use proofs::hp_binding::{HpBindingInputs, HpProof, proof_to_cbor, prove_hp_k, verify_hp_k};
pub use proofs::zk_vrf::lb;
pub use proofs::zk_vrf::{MaskDigest, VrfCtx, zk_vrf_impl};
pub mod kat;
#[cfg(any(test, feature = "bench-fixtures"))]
pub fn deterministic_lb_vrf_keys() -> (&'static [u8], &'static [u8]) {
    proofs::zk_vrf::lb::deterministic_key_material()
}
pub mod mhw;
pub mod receiver;
pub use receiver::{FREEZE_MH_PARENT_MISMATCH, ReceiverCache, ReceiverError};

#[derive(Serialize)]
struct WindowIdInputs<'a> {
    #[serde(with = "serde_bytes")]
    gid: &'a [u8],
    #[serde(with = "serde_bytes")]
    parent_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    seed_ctx_hash: &'a [u8; 32],
}

#[derive(Serialize)]
struct RollupCommit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

pub(crate) fn compute_window_id(
    gid: &[u8],
    parent_root: &[u8; 32],
    seed_ctx_hash: &[u8; 32],
) -> Result<[u8; 32], MsphfError> {
    h_l(
        "mhw/window",
        &WindowIdInputs {
            gid,
            parent_root,
            seed_ctx_hash,
        },
    )
}

pub(crate) const MAX_HP_BYTES: usize = 16 * 1024;
pub(crate) const AEAD_TAG_LEN: usize = 16;
const MERKLE_DS_ID: &str = "rpo-256/v2";
const TSWE_ALG_CODE: u8 = 31;
const TSWE_ALG_LABEL: &str = "tswe/msphf-we/fs-hybrid";
const KBROAD_MODE: &str = "kbroad-v1";
const KBROAD_ML_KEM_ALG: &str = "ml-kem-768";
const KBROAD_AEAD_SUITE: &str = "chacha20-poly1305";
const KBROAD_INFO_PREFIX: &[u8] = b"city-g|hp/kek/v1";
const FS_STEP_INFO: &[u8] = b"city-g|fs/step|v1";
const FS_TAU_INFO: &[u8] = b"city-g|fs/tau|v1";
pub const DEFAULT_PROOF_MODE: &str = "lin+zkvrf";
pub const DEFAULT_VRF_ID: &str = "lb-vrf/v1";
pub const DEFAULT_POLICY_VERSION: &str = "0";
const DEFAULT_SRX_SMALLWOOD_PROFILE: &str = "smallwood-v1/anemoi-jive-a1";

type MergeMetadata = (Option<Vec<[u8; 32]>>, Option<String>);

/// Fixture ML-KEM-768 keys for tests and benchmarks, loaded from external
/// asset files so that multi-KB hex literals don't bloat the main source.
///
/// These keys are deterministic test vectors — never use them in production.
#[cfg(any(test, feature = "bench-fixtures"))]
const KBROAD_PUB_HEX: &str = include_str!("../test_fixtures/kbroad_pub.hex");
#[cfg(any(test, feature = "bench-fixtures"))]
const KBROAD_SEC_HEX: &str = include_str!("../test_fixtures/kbroad_sec.hex");

#[cfg(any(test, feature = "bench-fixtures"))]
pub(crate) fn kbroad_test_keys() -> (&'static [u8], &'static [u8]) {
    use std::sync::OnceLock;

    static PUB: OnceLock<Vec<u8>> = OnceLock::new();
    static SEC: OnceLock<Vec<u8>> = OnceLock::new();

    let pub_bytes = PUB.get_or_init(|| match hex::decode(KBROAD_PUB_HEX.trim()) {
        Ok(bytes) => bytes,
        Err(_) => unreachable!("KBROAD_PUB_HEX fixture is a valid hex file"),
    });
    let sec_bytes = SEC.get_or_init(|| match hex::decode(KBROAD_SEC_HEX.trim()) {
        Ok(bytes) => bytes,
        Err(_) => unreachable!("KBROAD_SEC_HEX fixture is a valid hex file"),
    });

    (pub_bytes.as_slice(), sec_bytes.as_slice())
}

pub fn derive_we_epoch_id(
    gid: &[u8],
    parent_root: &[u8],
    seed_ctx_hash: &[u8; 32],
) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct WeId<'a> {
        #[serde(with = "serde_bytes")]
        gid: &'a [u8],
        #[serde(with = "serde_bytes")]
        parent_root: &'a [u8],
        #[serde(with = "serde_bytes")]
        seed_ctx_hash: &'a [u8; 32],
    }
    h_l(
        ds::MSPHF_SLOT_ID,
        &WeId {
            gid,
            parent_root,
            seed_ctx_hash,
        },
    )
}

#[derive(Serialize)]
struct RhoSig<'a> {
    #[serde(with = "serde_bytes")]
    pop_sig: &'a [u8],
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8; 32],
}

fn derive_rho_from_pop(
    pop_sig: &[u8],
    xk_hash: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), MsphfError> {
    let rho_raw = h_l(ds::MSPHF_RHO_DER, &RhoSig { pop_sig, xk_hash })?;
    let rho_commit = hash_bytes_with_label(ds::MSPHF_KGEN_RHO, &rho_raw)?;
    Ok((rho_raw, rho_commit))
}

/// Derive a 96-bit ChaCha20-Poly1305 nonce from `(xk_hash, hp_commit)`.
///
/// # Nonce reuse safety argument
///
/// The AEAD key is fresh per epoch (derived via `HKDF-BLAKE3(ikm=kbroad_ct)`,
/// where `kbroad_ct` is an ML-KEM-768 ciphertext unique to each encapsulation).
/// Even if two anchors shared the same `(xk_hash, hp_commit)` — which cannot
/// happen because `hp_commit := H_L("msphf/hp/commit", hp)` and `hp` is
/// freshly sampled — the key would differ, making the `(key, nonce)` pair
/// unique.
///
/// The 96-bit truncation from the 256-bit BLAKE3 output means the birthday
/// bound for nonce collisions *under the same key* is ~2^48 operations.
/// Because the key is never reused, the effective collision domain is one
/// nonce per key, and the truncation is safe.
fn derive_nonce(label: &str, xk_hash: &[u8; 32], commit: &[u8; 32]) -> Result<Nonce, MsphfError> {
    #[derive(Serialize)]
    struct NonceCtx<'a> {
        #[serde(with = "serde_bytes")]
        xk_hash: &'a [u8; 32],
        #[serde(with = "serde_bytes")]
        hp_commit: &'a [u8; 32],
    }
    let derived = h_l(
        label,
        &NonceCtx {
            xk_hash,
            hp_commit: commit,
        },
    )?;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&derived[..12]);
    Ok(Nonce::from(nonce_bytes))
}

fn derive_hp_nonce(xk_hash: &[u8; 32], commit: &[u8; 32]) -> Result<Nonce, MsphfError> {
    derive_nonce("hp/nonce", xk_hash, commit)
}

fn derive_kek_nonce(xk_hash: &[u8; 32], commit: &[u8; 32]) -> Result<Nonce, MsphfError> {
    derive_nonce("hp/kek/nonce", xk_hash, commit)
}

pub fn compute_proofs_commit_bytes(
    vrf_pi: &[u8],
    fs_capss: &[u8],
    srx_root_sw: Option<&[u8]>,
    srx_smallwood: Option<&[u8]>,
) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct ProofsArray(Vec<serde_bytes::ByteBuf>);

    if srx_root_sw.is_some() != srx_smallwood.is_some() {
        return Err(MsphfError::invalid_input(
            "srx_root_sw and srx_smallwood must be both present or both absent",
        ));
    }

    let mut components = Vec::with_capacity(if srx_root_sw.is_some() { 4 } else { 2 });
    components.push(serde_bytes::ByteBuf::from(vrf_pi.to_vec()));
    components.push(serde_bytes::ByteBuf::from(fs_capss.to_vec()));
    if let Some(root) = srx_root_sw {
        components.push(serde_bytes::ByteBuf::from(root.to_vec()));
    }
    if let Some(proof) = srx_smallwood {
        components.push(serde_bytes::ByteBuf::from(proof.to_vec()));
    }

    h_l("msphf/proofs", &ProofsArray(components))
}

#[derive(Serialize)]
struct FsDevChainV2Preimage<'a> {
    #[serde(with = "serde_bytes")]
    device_pk: &'a [u8],
    fs_ec: u64,
    #[serde(with = "serde_bytes")]
    prev_commit: &'a [u8; 32],
    barrier_version: u64,
    #[serde(with = "serde_bytes")]
    barrier_update_digest: &'a [u8; 32],
}

#[derive(Serialize)]
struct BarrierUpdateDigestArgs<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

fn parse_barrier_version_for_fs_dev_chain(
    header_map: &BTreeMap<u64, Value>,
) -> Result<u64, MsphfError> {
    match header_map.get(&HDR_BARRIER_VERSION) {
        None => Err(MsphfError::invalid_input("missing barrier_version")),
        Some(Value::Integer(value)) => u64::try_from(*value)
            .map_err(|_| MsphfError::invalid_input("barrier_version out of range")),
        Some(_) => Err(MsphfError::invalid_input("barrier_version must be uint")),
    }
}

fn barrier_update_digest_for_fs_dev_chain(
    header_map: &BTreeMap<u64, Value>,
) -> Result<[u8; 32], MsphfError> {
    match header_map.get(&HDR_BARRIER_UPDATE) {
        None => Ok([0u8; 32]),
        Some(Value::Bytes(raw_bytes)) => {
            h_l("barrier/update/digest", &BarrierUpdateDigestArgs(raw_bytes))
        }
        Some(_) => Err(MsphfError::invalid_input("barrier_update must be bytes")),
    }
}

/// Compute the v2 device-chain commit that binds barrier state.
pub fn compute_fs_dev_commit_v2(
    device_pk: &[u8],
    fs_ec: u64,
    prev_commit: &[u8; 32],
    barrier_version: u64,
    barrier_update_digest: &[u8; 32],
) -> Result<[u8; 32], MsphfError> {
    h_l(
        "fs/dev/chain/v2",
        &FsDevChainV2Preimage {
            device_pk,
            fs_ec,
            prev_commit,
            barrier_version,
            barrier_update_digest,
        },
    )
}

#[cfg(test)]
mod fs_dev_chain_v2_tests {
    use super::{barrier_update_digest_for_fs_dev_chain, compute_fs_dev_commit_v2};
    use crate::hdr::HDR_BARRIER_UPDATE;
    use ciborium::value::{Integer, Value};
    use std::collections::BTreeMap;

    #[test]
    fn v2_commit_changes_when_barrier_fields_change() -> Result<(), Box<dyn std::error::Error>> {
        let device_pk = [0xA5u8; 48];
        let fs_ec = 42u64;
        let prev_commit = [0x11u8; 32];
        let barrier_update_digest = [0x22u8; 32];
        let barrier_update_digest_alt = [0x23u8; 32];

        let v2_a =
            compute_fs_dev_commit_v2(&device_pk, fs_ec, &prev_commit, 3, &barrier_update_digest)?;
        let v2_b =
            compute_fs_dev_commit_v2(&device_pk, fs_ec, &prev_commit, 4, &barrier_update_digest)?;
        let v2_c = compute_fs_dev_commit_v2(
            &device_pk,
            fs_ec,
            &prev_commit,
            3,
            &barrier_update_digest_alt,
        )?;

        assert_ne!(v2_a, v2_b, "barrier_version must influence v2 commit");
        assert_ne!(v2_a, v2_c, "barrier_update_digest must influence v2 commit");
        Ok(())
    }

    #[test]
    fn barrier_update_digest_helper_enforces_type_and_changes_on_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut header = BTreeMap::new();
        assert_eq!(
            barrier_update_digest_for_fs_dev_chain(&header)?,
            [0u8; 32],
            "absent barrier_update must map to ZERO32"
        );

        header.insert(HDR_BARRIER_UPDATE, Value::Bytes(vec![0xAA, 0xBB, 0xCC]));
        let digest = barrier_update_digest_for_fs_dev_chain(&header)?;
        assert_ne!(
            digest, [0u8; 32],
            "present barrier_update must influence digest"
        );

        header.insert(HDR_BARRIER_UPDATE, Value::Integer(Integer::from(7u64)));
        assert!(
            barrier_update_digest_for_fs_dev_chain(&header).is_err(),
            "non-bytes barrier_update must fail"
        );
        Ok(())
    }
}

#[derive(Serialize)]
struct FsTauSalt<'a> {
    #[serde(with = "serde_bytes")]
    weid: &'a [u8; 32],
    fs_ec: u64,
}

fn fs_tau_salt(weid: &[u8; 32], fs_ec: u64) -> Result<[u8; 32], MsphfError> {
    h_l("fs/tau/salt", &FsTauSalt { weid, fs_ec })
}

#[derive(Serialize)]
struct FsEpochSkSalt<'a> {
    #[serde(with = "serde_bytes")]
    weid: &'a [u8; 32],
    fs_ec: u64,
}

fn fs_epoch_sk_salt(weid: &[u8; 32], fs_ec: u64) -> Result<[u8; 32], MsphfError> {
    h_l("fs/epoch/sk_salt", &FsEpochSkSalt { weid, fs_ec })
}

#[derive(Serialize)]
struct FsEpochCommit<'a>(#[serde(with = "serde_bytes")] &'a [u8; 32]);

fn fs_epoch_commit_hash(epoch_sk: &[u8; 32]) -> Result<[u8; 32], MsphfError> {
    h_l("fs/epoch/commit", &FsEpochCommit(epoch_sk))
}

#[derive(Serialize)]
struct FsStepSalt<'a> {
    #[serde(with = "serde_bytes")]
    weid: &'a [u8; 32],
    next_ec: u64,
}

fn fs_step_salt(weid: &[u8; 32], next_ec: u64) -> Result<[u8; 32], MsphfError> {
    h_l("fs/step/salt", &FsStepSalt { weid, next_ec })
}

fn evolve_k_fs(current: &[u8; 32], weid: &[u8; 32], next_ec: u64) -> Result<[u8; 32], MsphfError> {
    let salt = fs_step_salt(weid, next_ec)?;
    Ok(hkdf_blake3(&salt, current, FS_STEP_INFO))
}

fn encrypt_chacha20(
    key: &[u8; 32],
    nonce: &Nonce,
    aad: &[u8],
    plaintext: &[u8],
    error_tag: &'static str,
) -> Result<Vec<u8>, MsphfError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| MsphfError::invalid_input(error_tag))
}

fn decrypt_chacha20(
    key: &[u8; 32],
    nonce: &Nonce,
    aad: &[u8],
    ciphertext: &[u8],
    error_tag: &'static str,
) -> Result<Vec<u8>, MsphfError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| MsphfError::invalid_input(error_tag))
}

pub(crate) fn encrypt_hp_bytes(
    plaintext: &[u8],
    xk_hash: &[u8; 32],
    commit: &[u8; 32],
    key: &[u8; 32],
) -> Result<Vec<u8>, MsphfError> {
    if plaintext.len() > MAX_HP_BYTES {
        return Err(MsphfError::invalid_input("hp_k too large"));
    }
    let nonce = derive_hp_nonce(xk_hash, commit)?;
    encrypt_chacha20(
        key,
        &nonce,
        commit,
        plaintext,
        "msphf_hp_ciphertext encrypt failure",
    )
}

pub(crate) fn decrypt_hp_bytes(
    ciphertext: &[u8],
    xk_hash: &[u8; 32],
    commit: &[u8; 32],
    key: &[u8; 32],
) -> Result<Vec<u8>, MsphfError> {
    if ciphertext.len() < AEAD_TAG_LEN {
        return Err(MsphfError::invalid_input("msphf_hp_ciphertext truncated"));
    }
    let nonce = derive_hp_nonce(xk_hash, commit)?;
    let plaintext = decrypt_chacha20(
        key,
        &nonce,
        commit,
        ciphertext,
        "msphf_hp_ciphertext tag mismatch",
    )?;
    if plaintext.len() > MAX_HP_BYTES {
        return Err(MsphfError::invalid_input("hp_k too large"));
    }
    Ok(plaintext)
}

fn value_from_serde<T: Serialize>(item: &T) -> Result<Value, MsphfError> {
    let mut buf = Vec::new();
    into_writer(item, &mut buf).map_err(MsphfError::serialization)?;
    ciborium::de::from_reader(buf.as_slice()).map_err(MsphfError::serialization)
}

fn encode_value(value: &Value) -> Result<Vec<u8>, MsphfError> {
    let mut buf = Vec::new();
    into_writer(value, &mut buf).map_err(MsphfError::serialization)?;
    Ok(buf)
}

fn optional_bytes_value(data: &Option<Vec<u8>>) -> Value {
    match data {
        Some(bytes) => Value::Bytes(bytes.clone()),
        None => Value::Null,
    }
}

fn serialize_path_entry(entry: &RawPathEntry) -> Value {
    Value::Map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(entry.sibling.clone()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(entry.dir)),
        ),
    ])
}

fn to_array32(label: &str, bytes: &[u8]) -> Result<[u8; 32], MsphfError> {
    if bytes.len() != 32 {
        return Err(MsphfError::invalid_input(label));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn parse_fs_policy_version(version: &str) -> Result<u64, MsphfError> {
    version
        .parse::<u64>()
        .map_err(|_| MsphfError::invalid_input("fs_policy_version must be uint"))
}

fn serialize_nonmem_anchor(anchor: &SrxNonMembershipAnchor) -> Result<Value, MsphfError> {
    if anchor.witness.query.len() != 32 || anchor.witness.root.len() != 32 {
        return Err(MsphfError::invalid_input("srx anchor malformed"));
    }
    let path_values: Vec<Value> = anchor
        .witness
        .path
        .iter()
        .map(serialize_path_entry)
        .collect();
    let left_below_values: Vec<Value> = anchor
        .witness
        .left_below
        .iter()
        .map(serialize_path_entry)
        .collect();
    let right_below_values: Vec<Value> = anchor
        .witness
        .right_below
        .iter()
        .map(serialize_path_entry)
        .collect();
    let above_values: Vec<Value> = anchor
        .witness
        .above
        .iter()
        .map(serialize_path_entry)
        .collect();
    let left_ref_value = anchor
        .left_ref
        .map(|idx| Value::Integer(Integer::from(idx as u64)))
        .unwrap_or(Value::Null);
    let right_ref_value = anchor
        .right_ref
        .map(|idx| Value::Integer(Integer::from(idx as u64)))
        .unwrap_or(Value::Null);
    let lca_left_height_value = anchor
        .witness
        .lca_left_height
        .map(|height| Value::Integer(Integer::from(height as u64)))
        .unwrap_or(Value::Null);
    let lca_right_height_value = anchor
        .witness
        .lca_right_height
        .map(|height| Value::Integer(Integer::from(height as u64)))
        .unwrap_or(Value::Null);

    Ok(Value::Map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(anchor.witness.query.clone()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(anchor.witness.root.clone()),
        ),
        (
            Value::Integer(Integer::from(3)),
            optional_bytes_value(&anchor.witness.left),
        ),
        (
            Value::Integer(Integer::from(4)),
            optional_bytes_value(&anchor.witness.right),
        ),
        (Value::Integer(Integer::from(5)), Value::Array(path_values)),
        (Value::Integer(Integer::from(6)), left_ref_value),
        (Value::Integer(Integer::from(7)), right_ref_value),
        (
            Value::Integer(Integer::from(8)),
            Value::Array(left_below_values),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Array(right_below_values),
        ),
        (
            Value::Integer(Integer::from(10)),
            Value::Array(above_values),
        ),
        (
            Value::Integer(Integer::from(11)),
            optional_bytes_value(&anchor.witness.nmint),
        ),
        (Value::Integer(Integer::from(12)), lca_left_height_value),
        (Value::Integer(Integer::from(13)), lca_right_height_value),
    ]))
}

fn validate_anchor_indices(
    anchor: &SrxNonMembershipAnchor,
    pool_len: usize,
) -> Result<(), MsphfError> {
    if anchor.witness.left.is_some() {
        if anchor.left_ref.is_none() {
            return Err(MsphfError::invalid_input("srx anchor missing left ref"));
        }
    } else if anchor.left_ref.is_some() {
        return Err(MsphfError::invalid_input("srx anchor unexpected left ref"));
    }

    if anchor.witness.right.is_some() {
        if anchor.right_ref.is_none() {
            return Err(MsphfError::invalid_input("srx anchor missing right ref"));
        }
    } else if anchor.right_ref.is_some() {
        return Err(MsphfError::invalid_input("srx anchor unexpected right ref"));
    }

    if anchor
        .left_ref
        .is_some_and(|index| index as usize >= pool_len)
    {
        return Err(MsphfError::invalid_input(
            "srx anchor left ref out of range",
        ));
    }
    if anchor
        .right_ref
        .is_some_and(|index| index as usize >= pool_len)
    {
        return Err(MsphfError::invalid_input(
            "srx anchor right ref out of range",
        ));
    }
    Ok(())
}

pub(crate) struct KbroadEnvelope {
    envelope: Value,
    c_hp: Vec<u8>,
    k_hp: [u8; 32],
}

pub(crate) fn build_kbroad_envelope(
    header_map: &BTreeMap<u64, Value>,
    hp_k: &[u8],
    xk_hash: &[u8; 32],
    hp_commit: &[u8; 32],
) -> Result<KbroadEnvelope, MsphfError> {
    let alg_value = header_map
        .get(&104)
        .ok_or_else(|| MsphfError::invalid_input("missing kbroad_alg"))?;
    let alg = match alg_value {
        Value::Text(text) => text.as_str(),
        Value::Bytes(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| MsphfError::invalid_input("kbroad_alg invalid utf8"))?,
        _ => return Err(MsphfError::invalid_input("kbroad_alg must be text")),
    };
    if alg != KBROAD_ML_KEM_ALG {
        return Err(MsphfError::invalid_input("unsupported kbroad_alg"));
    }
    let pub_value = header_map
        .get(&105)
        .ok_or_else(|| MsphfError::invalid_input("missing kbroad_pub"))?;
    let pub_bytes = match pub_value {
        Value::Bytes(bytes) => bytes,
        _ => return Err(MsphfError::invalid_input("kbroad_pub must be bytes")),
    };
    if pub_bytes.len() != ml_kem_public_key_bytes() {
        return Err(MsphfError::invalid_input("kbroad_pub length mismatch"));
    }
    let kem_pk = MlKemPublicKey::from_bytes(pub_bytes.as_slice())
        .map_err(|_| MsphfError::invalid_input("kbroad_pub malformed"))?;

    let (kem_ss, kem_ct) = ml_kem_encapsulate(&kem_pk);
    let kem_ct_bytes = kem_ct.as_bytes().to_vec();
    let expected_ct_len = pqcrypto_kyber::kyber768::ciphertext_bytes();
    if kem_ct_bytes.len() != expected_ct_len {
        return Err(MsphfError::invalid_input("kbroad ct length"));
    }
    let kem_ss_bytes = Zeroizing::new(kem_ss.as_bytes().to_vec());

    #[derive(Serialize)]
    struct KekSalt<'a> {
        #[serde(with = "serde_bytes")]
        xk_hash: &'a [u8; 32],
    }
    let salt = h_l("hp/kek/salt", &KekSalt { xk_hash })?;
    let mut info = Vec::with_capacity(KBROAD_INFO_PREFIX.len() + hp_commit.len());
    info.extend_from_slice(KBROAD_INFO_PREFIX);
    info.extend_from_slice(hp_commit);
    let kek = Zeroizing::new(hkdf_blake3(&salt, kem_ss_bytes.as_slice(), &info));

    let mut k_hp = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(k_hp.as_mut());
    let wrap_nonce = derive_kek_nonce(xk_hash, hp_commit)?;
    let wrap = encrypt_chacha20(
        &kek,
        &wrap_nonce,
        hp_commit,
        k_hp.as_slice(),
        "msphf_hp_wrap encrypt failure",
    )?;
    let c_hp = encrypt_hp_bytes(hp_k, xk_hash, hp_commit, &k_hp)?;
    let k_hp = *k_hp;

    let envelope = Value::Array(vec![
        Value::Text(KBROAD_MODE.to_string()),
        Value::Bytes(kem_ct_bytes),
        Value::Bytes(wrap.clone()),
        Value::Bytes(c_hp.clone()),
        Value::Text(KBROAD_AEAD_SUITE.to_string()),
    ]);

    Ok(KbroadEnvelope {
        envelope,
        c_hp,
        k_hp,
    })
}

pub fn recover_hp_material_from_header(
    header_map: &BTreeMap<u64, Value>,
    xk_hash: &[u8; 32],
    hp_commit: &[u8; 32],
    kbroad_secret: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), MsphfError> {
    let hp_value = header_map
        .get(&HDR_HP_BYTES)
        .ok_or_else(|| MsphfError::invalid_input("missing msphf_hp"))?;
    let items = match hp_value {
        Value::Array(items) => items,
        _ => return Err(MsphfError::invalid_input("msphf_hp must be array")),
    };
    if items.len() != 5 {
        return Err(MsphfError::invalid_input("msphf_hp shape mismatch"));
    }

    let mode = match &items[0] {
        Value::Text(text) => text.as_str(),
        Value::Bytes(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| MsphfError::invalid_input("kbroad mode invalid utf8"))?,
        _ => return Err(MsphfError::invalid_input("kbroad mode malformed")),
    };
    if mode != KBROAD_MODE {
        return Err(MsphfError::invalid_input("unsupported kbroad mode"));
    }

    let ct_bytes = match &items[1] {
        Value::Bytes(bytes) => bytes.as_slice(),
        _ => return Err(MsphfError::invalid_input("kbroad ciphertext malformed")),
    };
    if ct_bytes.len() != ml_kem_ciphertext_bytes() {
        return Err(MsphfError::invalid_input(
            "kbroad ciphertext length mismatch",
        ));
    }

    let wrap_bytes = match &items[2] {
        Value::Bytes(bytes) => bytes.as_slice(),
        _ => return Err(MsphfError::invalid_input("kbroad wrap malformed")),
    };
    if wrap_bytes.len() != (32 + AEAD_TAG_LEN) {
        return Err(MsphfError::invalid_input("kbroad wrap length mismatch"));
    }

    let hp_ciphertext = match &items[3] {
        Value::Bytes(bytes) => bytes.clone(),
        _ => return Err(MsphfError::invalid_input("msphf_hp ciphertext malformed")),
    };
    if hp_ciphertext.is_empty() || hp_ciphertext.len() > (MAX_HP_BYTES + AEAD_TAG_LEN) {
        return Err(MsphfError::invalid_input(
            "msphf_hp ciphertext length mismatch",
        ));
    }

    let aead = match &items[4] {
        Value::Text(text) => text.as_str(),
        Value::Bytes(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| MsphfError::invalid_input("kbroad aead invalid utf8"))?,
        _ => return Err(MsphfError::invalid_input("kbroad aead malformed")),
    };
    if aead != KBROAD_AEAD_SUITE {
        return Err(MsphfError::invalid_input("unsupported kbroad aead"));
    }

    let kem_ct = MlKemCiphertext::from_bytes(ct_bytes)
        .map_err(|_| MsphfError::invalid_input("kbroad ciphertext malformed"))?;
    let kem_sk = MlKemSecretKey::from_bytes(kbroad_secret)
        .map_err(|_| MsphfError::invalid_input("kbroad secret malformed"))?;
    let kem_ss = ml_kem_decapsulate(&kem_ct, &kem_sk);
    let kem_ss_bytes = Zeroizing::new(kem_ss.as_bytes().to_vec());

    #[derive(Serialize)]
    struct KekSalt<'a> {
        #[serde(with = "serde_bytes")]
        xk_hash: &'a [u8; 32],
    }

    let salt = h_l("hp/kek/salt", &KekSalt { xk_hash })?;
    let mut info = Vec::with_capacity(KBROAD_INFO_PREFIX.len() + hp_commit.len());
    info.extend_from_slice(KBROAD_INFO_PREFIX);
    info.extend_from_slice(hp_commit);
    let kek = Zeroizing::new(hkdf_blake3(&salt, kem_ss_bytes.as_slice(), &info));

    let wrap_nonce = derive_kek_nonce(xk_hash, hp_commit)?;
    let hp_key_bytes = Zeroizing::new(decrypt_chacha20(
        &kek,
        &wrap_nonce,
        hp_commit,
        wrap_bytes,
        "msphf_hp_wrap tag mismatch",
    )?);
    let hp_key: [u8; 32] = hp_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| MsphfError::invalid_input("kbroad wrap plaintext malformed"))?;

    Ok((hp_ciphertext, hp_key))
}

#[derive(Clone)]
pub struct PopKeypair<'a> {
    pub algorithm: &'a str,
    pub public_key: &'a [u8],
    pub secret_key: &'a MlDsaSecretKey,
}

/// Parameters selecting the branch instantiation (RLWE, Σ-Merkle, etc.).
#[derive(Clone)]
pub struct OrchestrationParams<'a> {
    pub msphf_crs_id: &'a str,
    pub params_id: &'a str,
    pub srx: Option<SrxInputs<'a>>,
    pub srx_mode: SrxMode,
    pub pop_keys: Option<PopKeypair<'a>>,
    pub leaf_id_mode: LeafIdMode,
    pub proof_mode: &'a str,
    pub vrf_id: &'a str,
    pub policy_version: &'a str,
    pub vrf_secret_key: Option<&'a [u8]>,
    pub vrf_public_key: Option<&'a [u8]>,
    pub fs_policy_version: &'a str,
    pub fs_epoch_base_ts: u64,
    pub barrier_version: u64,
    pub fs_join: FsJoinInputs,
    pub fs_merge: FsMergeInputs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsJoinInputs {
    pub fs_ec: u64,
    pub fs_epoch_commit: [u8; 32],
    pub fs_dev_prev_commit: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ForwardSecrecyPolicy {
    pub epoch_period: Duration,
    pub epoch_base_ts: u64,
    pub tau_cache_retention: Duration,
    pub tau_cache_max_entries: usize,
    pub forward_slack: u64,
    /// Maximum number of ratchet steps performed per autonomic tick.
    /// This bounds catch-up cost for long-offline clients.
    pub ratchet_budget_per_tick: u64,
}

impl Default for ForwardSecrecyPolicy {
    fn default() -> Self {
        Self {
            epoch_period: Duration::from_secs(300),
            epoch_base_ts: 0,
            tau_cache_retention: Duration::from_secs(600),
            tau_cache_max_entries: 2_000,
            forward_slack: 0,
            ratchet_budget_per_tick: 1_024,
        }
    }
}

#[derive(Debug, Clone)]
struct BoundaryCounter {
    epoch_base_ts: u64,
    period_secs: u64,
    forward_slack: u64,
    t0_wall: SystemTime,
    t0_mono: Instant,
    ec0: u64,
    ec_local: u64,
}

#[derive(Debug, Clone)]
struct TauEntry {
    /// Cache key: `(weid, epoch_counter)`.  Both values are public
    /// (weid is the epoch extraction ID, ec is the monotonic counter).
    /// Not zeroized on drop because they carry no secret material.
    key: ([u8; 32], u64),
    /// Derived forward-secrecy token — **secret**.  Zeroized on drop.
    tau: [u8; 32],
    created_at: Instant,
}

impl Drop for TauEntry {
    fn drop(&mut self) {
        self.tau.zeroize();
    }
}

#[derive(Debug, Clone)]
struct TauCache {
    entries: VecDeque<TauEntry>,
    retention: Duration,
    max_entries: usize,
}

#[derive(Debug, Clone)]
pub struct ForwardSecrecyState {
    k_fs: [u8; 32],
    fs_ec: u64,
    fs_dev_commit: [u8; 32],
    last_weid: [u8; 32],
    policy: ForwardSecrecyPolicy,
    boundary: BoundaryCounter,
    tau_cache: TauCache,
}

impl Drop for ForwardSecrecyState {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}

impl ForwardSecrecyState {
    pub fn new(k_fs: [u8; 32]) -> Self {
        Self::with_policy(k_fs, ForwardSecrecyPolicy::default())
    }

    pub fn with_state(
        k_fs: [u8; 32],
        fs_ec: u64,
        fs_dev_commit: [u8; 32],
        last_weid: [u8; 32],
    ) -> Self {
        let mut state = Self::with_policy(k_fs, ForwardSecrecyPolicy::default());
        state.fs_ec = fs_ec;
        state.fs_dev_commit = fs_dev_commit;
        state.boundary.ec_local = fs_ec;
        state.boundary.ec0 = fs_ec;
        state.last_weid = last_weid;
        state
    }

    pub fn with_policy(k_fs: [u8; 32], policy: ForwardSecrecyPolicy) -> Self {
        let boundary = BoundaryCounter::new(&policy);
        let tau_cache = TauCache::new(policy.tau_cache_retention, policy.tau_cache_max_entries);
        Self {
            k_fs,
            fs_ec: boundary.ec_local,
            fs_dev_commit: [0u8; 32],
            last_weid: [0u8; 32],
            policy,
            boundary,
            tau_cache,
        }
    }

    fn clear_secrets(&mut self) {
        self.k_fs.zeroize();
    }

    pub fn set_epoch_base_ts(&mut self, epoch_base_ts: u64) {
        if epoch_base_ts != self.policy.epoch_base_ts {
            self.policy.epoch_base_ts = epoch_base_ts;
            self.boundary.reset_origin(&self.policy);
        }
    }

    pub fn configure_tau_cache(&mut self, retention: Duration, max_entries: usize) {
        self.policy.tau_cache_retention = retention;
        self.policy.tau_cache_max_entries = max_entries;
        self.tau_cache = TauCache::new(retention, max_entries);
    }

    pub fn autonomic_evolve(&mut self) {
        let now_wall = SystemTime::now();
        let now_mono = Instant::now();
        self.autonomic_evolve_with_clock(now_wall, now_mono);
    }

    pub fn snapshot(&self) -> ForwardSecrecySnapshot {
        ForwardSecrecySnapshot {
            k_fs: self.k_fs,
            fs_ec: self.fs_ec,
            fs_dev_commit: self.fs_dev_commit,
            last_weid: self.last_weid,
        }
    }

    pub fn current_ec(&self) -> u64 {
        self.fs_ec
    }

    pub fn cached_tau(&mut self, weid: &[u8; 32], fs_ec: u64) -> Option<[u8; 32]> {
        self.tau_cache.get(weid, fs_ec)
    }

    pub fn record_tau(&mut self, weid: &[u8; 32], fs_ec: u64, tau: [u8; 32]) {
        self.tau_cache.record(weid, fs_ec, tau);
    }

    pub fn set_last_we_epoch_id(&mut self, weid: [u8; 32]) {
        self.last_weid = weid;
    }

    pub fn last_we_epoch_id(&self) -> [u8; 32] {
        self.last_weid
    }

    pub fn prepare_join(
        &mut self,
        device_pk: &[u8],
        we_epoch_id: &[u8; 32],
        barrier_version: u64,
        barrier_update_digest: &[u8; 32],
    ) -> Result<FsJoinArtifacts, MsphfError> {
        self.tau_cache.prune();
        let fs_ec = self.fs_ec;
        let fs_dev_prev_commit = self.fs_dev_commit;

        let tau_salt = fs_tau_salt(we_epoch_id, fs_ec)?;
        let tau_e = hkdf_blake3(&tau_salt, &self.k_fs, FS_TAU_INFO);
        let epoch_sk_salt = fs_epoch_sk_salt(we_epoch_id, fs_ec)?;
        let epoch_sk = hkdf_blake3(&epoch_sk_salt, &self.k_fs, b"city-g|fs/epoch/sk|v1");

        let fs_epoch_commit = fs_epoch_commit_hash(&epoch_sk)?;
        let fs_dev_commit = compute_fs_dev_commit_v2(
            device_pk,
            fs_ec,
            &fs_dev_prev_commit,
            barrier_version,
            barrier_update_digest,
        )?;

        let next_key = evolve_k_fs(&self.k_fs, we_epoch_id, fs_ec + 1)?;
        self.k_fs.zeroize();
        self.k_fs = next_key;
        self.fs_ec = fs_ec + 1;
        self.fs_dev_commit = fs_dev_commit;
        self.record_tau(we_epoch_id, fs_ec, tau_e);
        self.last_weid = *we_epoch_id;

        Ok(FsJoinArtifacts {
            inputs: FsJoinInputs {
                fs_ec,
                fs_epoch_commit,
                fs_dev_prev_commit,
            },
            fs_dev_commit,
            epoch_sk,
            tau_e,
        })
    }

    fn autonomic_evolve_with_clock(&mut self, now_wall: SystemTime, now_mono: Instant) {
        let target = self.boundary.update(now_wall, now_mono, &self.policy);
        let budget = self.policy.ratchet_budget_per_tick.max(1);
        self.advance_to_with_budget(target, budget);
    }

    /// Advance the forward-secrecy ratchet toward `target_ec`, performing at
    /// most `budget` HKDF iterations.  Returns the number of steps actually
    /// taken.  Use [`advance_to`] for unbounded catch-up, or call this in a
    /// loop to amortise the cost across multiple ticks.
    fn advance_to_with_budget(&mut self, target_ec: u64, budget: u64) -> u64 {
        if target_ec <= self.fs_ec {
            return 0;
        }
        if self.last_weid == [0u8; 32] {
            self.fs_ec = target_ec;
            self.boundary.ec_local = self.boundary.ec_local.max(target_ec);
            return 0;
        }
        let steps = (target_ec - self.fs_ec).min(budget);
        let end = self.fs_ec + steps;
        for current in self.fs_ec..end {
            if let Ok(next_key) = evolve_k_fs(&self.k_fs, &self.last_weid, current + 1) {
                self.k_fs.zeroize();
                self.k_fs = next_key;
            }
        }
        self.fs_ec = end;
        self.boundary.ec_local = self.boundary.ec_local.max(end);
        steps
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardSecrecySnapshot {
    pub k_fs: [u8; 32],
    pub fs_ec: u64,
    pub fs_dev_commit: [u8; 32],
    pub last_weid: [u8; 32],
}

impl BoundaryCounter {
    fn new(policy: &ForwardSecrecyPolicy) -> Self {
        let now_wall = SystemTime::now();
        let now_mono = Instant::now();
        let period = policy.epoch_period.as_secs().max(1);
        let ec0 = compute_wall_epoch(now_wall, policy.epoch_base_ts, period);
        Self {
            epoch_base_ts: policy.epoch_base_ts,
            period_secs: period,
            forward_slack: policy.forward_slack,
            t0_wall: now_wall,
            t0_mono: now_mono,
            ec0,
            ec_local: ec0,
        }
    }

    fn reset_origin(&mut self, policy: &ForwardSecrecyPolicy) {
        self.epoch_base_ts = policy.epoch_base_ts;
        self.period_secs = policy.epoch_period.as_secs().max(1);
        self.forward_slack = policy.forward_slack;
        self.t0_wall = SystemTime::now();
        self.t0_mono = Instant::now();
        self.ec0 = compute_wall_epoch(self.t0_wall, self.epoch_base_ts, self.period_secs);
        self.ec_local = self.ec_local.max(self.ec0);
    }

    fn update(
        &mut self,
        now_wall: SystemTime,
        now_mono: Instant,
        policy: &ForwardSecrecyPolicy,
    ) -> u64 {
        if self.epoch_base_ts != policy.epoch_base_ts {
            self.reset_origin(policy);
        }
        let period = self.period_secs.max(1);
        let ec_wall = compute_wall_epoch(now_wall, self.epoch_base_ts, period);
        let mono_elapsed = now_mono
            .checked_duration_since(self.t0_mono)
            .unwrap_or_default()
            .as_secs();
        let ec_pred = self.ec0.saturating_add(mono_elapsed / period);
        let forward_cap = ec_wall.saturating_add(self.forward_slack);
        let target = ec_pred.min(forward_cap);
        if target > self.ec_local {
            self.ec_local = target;
        }
        self.ec_local
    }
}

impl TauCache {
    fn new(retention: Duration, max_entries: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            retention,
            max_entries: max_entries.max(1),
        }
    }

    fn prune(&mut self) {
        let now = Instant::now();
        while let Some(front) = self.entries.front() {
            if now.duration_since(front.created_at) > self.retention {
                self.entries.pop_front();
            } else {
                break;
            }
        }
        while self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }
    }

    fn record(&mut self, weid: &[u8; 32], fs_ec: u64, tau: [u8; 32]) {
        self.prune();
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.key.0 == *weid && entry.key.1 == fs_ec)
        {
            entry.tau.copy_from_slice(&tau);
            entry.created_at = Instant::now();
            return;
        }
        let entry = TauEntry {
            key: (*weid, fs_ec),
            tau,
            created_at: Instant::now(),
        };
        self.entries.push_back(entry);
        self.prune();
    }

    fn get(&mut self, weid: &[u8; 32], fs_ec: u64) -> Option<[u8; 32]> {
        self.prune();
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.key.0 == *weid && entry.key.1 == fs_ec)
            .map(|entry| entry.tau)
    }
}

fn compute_wall_epoch(time: SystemTime, base_ts: u64, period: u64) -> u64 {
    if base_ts == 0 {
        0
    } else {
        let wall_secs = time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if wall_secs <= base_ts {
            0
        } else {
            (wall_secs - base_ts) / period
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod fs_state_tests {
    use super::*;

    #[test]
    fn boundary_counter_advances_ec() -> Result<(), Box<dyn std::error::Error>> {
        let base_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let policy = ForwardSecrecyPolicy {
            epoch_period: Duration::from_secs(60),
            epoch_base_ts: base_ts,
            ..Default::default()
        };
        let mut state = ForwardSecrecyState::with_policy([0x11; 32], policy.clone());
        state.set_last_we_epoch_id([0xAB; 32]);
        let now_wall = SystemTime::UNIX_EPOCH + Duration::from_secs(base_ts + 600);
        let base_mono = Instant::now();
        state.autonomic_evolve_with_clock(now_wall, base_mono + Duration::from_secs(600));
        assert!(state.current_ec() >= 10);
        Ok(())
    }

    #[test]
    fn tau_cache_retains_recent_entries() -> Result<(), Box<dyn std::error::Error>> {
        let mut state = ForwardSecrecyState::new([0x22; 32]);
        let weid = [0xAA; 32];
        state.record_tau(&weid, 1, [0x55; 32]);
        assert!(state.cached_tau(&weid, 1).is_some());
        state.configure_tau_cache(Duration::from_secs(0), 1);
        state.record_tau(&weid, 2, [0x33; 32]);
        assert!(state.cached_tau(&weid, 1).is_none());
        Ok(())
    }

    #[test]
    fn tau_cache_updates_matching_entry() -> Result<(), Box<dyn std::error::Error>> {
        let mut state = ForwardSecrecyState::new([0x33; 32]);
        let weid = [0xBB; 32];
        state.record_tau(&weid, 7, [0x11; 32]);
        let cached = match state.cached_tau(&weid, 7) {
            Some(tau) => tau,
            None => unreachable!("tau should exist after record"),
        };
        assert_eq!(cached, [0x11; 32]);
        state.record_tau(&weid, 7, [0x22; 32]);
        let cached = match state.cached_tau(&weid, 7) {
            Some(tau) => tau,
            None => unreachable!("tau should update in place"),
        };
        assert_eq!(cached, [0x22; 32]);
        assert!(state.cached_tau(&weid, 6).is_none());
        Ok(())
    }

    #[test]
    fn autonomic_evolve_respects_forward_slack() -> Result<(), Box<dyn std::error::Error>> {
        let base_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(60);
        let policy = ForwardSecrecyPolicy {
            epoch_period: Duration::from_secs(5),
            epoch_base_ts: base_ts,
            forward_slack: 3,
            ..Default::default()
        };
        let mut state = ForwardSecrecyState::with_policy([0x44; 32], policy.clone());
        state.set_last_we_epoch_id([0xAB; 32]);
        let future_wall = SystemTime::UNIX_EPOCH + Duration::from_secs(base_ts.saturating_add(120));
        let future_mono = Instant::now() + Duration::from_secs(120);
        state.autonomic_evolve_with_clock(future_wall, future_mono);
        let snapshot = state.snapshot();
        let wall_ec = compute_wall_epoch(
            future_wall,
            policy.epoch_base_ts,
            policy.epoch_period.as_secs(),
        );
        assert!(
            snapshot.fs_ec <= wall_ec + policy.forward_slack,
            "fs_ec {} exceeded wall {} + slack {}",
            snapshot.fs_ec,
            wall_ec,
            policy.forward_slack
        );
        assert!(
            snapshot.fs_ec >= wall_ec,
            "fs_ec {} should never lag behind wall {}",
            snapshot.fs_ec,
            wall_ec
        );
        Ok(())
    }

    #[test]
    fn autonomic_evolve_updates_key_material_when_weid_known()
    -> Result<(), Box<dyn std::error::Error>> {
        let base_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(30);
        let policy = ForwardSecrecyPolicy {
            epoch_period: Duration::from_secs(2),
            epoch_base_ts: base_ts,
            ..Default::default()
        };
        let mut state = ForwardSecrecyState::with_policy([0x55; 32], policy);
        state.set_last_we_epoch_id([0xCD; 32]);
        let before = state.snapshot();
        let future_wall = SystemTime::UNIX_EPOCH + Duration::from_secs(base_ts.saturating_add(120));
        let future_mono = Instant::now() + Duration::from_secs(120);
        state.autonomic_evolve_with_clock(future_wall, future_mono);
        let after = state.snapshot();
        assert!(
            after.fs_ec > before.fs_ec,
            "expected fs_ec to grow (before {}, after {})",
            before.fs_ec,
            after.fs_ec
        );
        assert_ne!(before.k_fs, after.k_fs, "k_fs must evolve with EC");
        Ok(())
    }

    #[test]
    fn autonomic_evolve_respects_ratchet_budget_per_tick() -> Result<(), Box<dyn std::error::Error>>
    {
        let policy = ForwardSecrecyPolicy {
            epoch_period: Duration::from_secs(1),
            epoch_base_ts: 0,
            forward_slack: 200,
            ratchet_budget_per_tick: 5,
            ..Default::default()
        };
        let mut state = ForwardSecrecyState::with_policy([0x66; 32], policy);
        state.set_last_we_epoch_id([0xEF; 32]);
        let base_mono = Instant::now();

        // Monotonic clock implies ~100 epochs elapsed.
        let future_wall = SystemTime::UNIX_EPOCH;
        state.autonomic_evolve_with_clock(future_wall, base_mono + Duration::from_secs(100));
        assert_eq!(
            state.current_ec(),
            5,
            "autonomic evolve should cap work per tick to policy budget"
        );

        // A subsequent tick should advance by another budget-sized chunk.
        state.autonomic_evolve_with_clock(future_wall, base_mono + Duration::from_secs(101));
        assert_eq!(
            state.current_ec(),
            10,
            "subsequent ticks should continue bounded catch-up"
        );
        Ok(())
    }

    #[test]
    fn with_state_and_last_weid_accessors_roundtrip() {
        let mut state = ForwardSecrecyState::with_state([0x10; 32], 7, [0x20; 32], [0x30; 32]);
        assert_eq!(state.current_ec(), 7);
        assert_eq!(state.last_we_epoch_id(), [0x30; 32]);
        let snapshot = state.snapshot();
        assert_eq!(snapshot.fs_ec, 7);
        assert_eq!(snapshot.fs_dev_commit, [0x20; 32]);
        assert_eq!(snapshot.last_weid, [0x30; 32]);
        state.set_last_we_epoch_id([0x31; 32]);
        assert_eq!(state.last_we_epoch_id(), [0x31; 32]);
    }

    #[test]
    fn advance_to_without_last_weid_updates_counter_only() {
        let policy = ForwardSecrecyPolicy {
            epoch_period: Duration::from_secs(1),
            epoch_base_ts: 0,
            forward_slack: 0,
            ratchet_budget_per_tick: 2,
            ..Default::default()
        };
        let mut state = ForwardSecrecyState::with_policy([0x70; 32], policy);
        let before = state.snapshot();
        let steps = state.advance_to_with_budget(9, 3);
        assert_eq!(steps, 0);
        assert_eq!(state.current_ec(), 9);
        assert_eq!(state.snapshot().k_fs, before.k_fs);
    }

    #[test]
    fn tau_cache_enforces_capacity_and_eviction() {
        let mut state = ForwardSecrecyState::new([0x80; 32]);
        state.configure_tau_cache(Duration::from_secs(60), 1);
        let first = [0xA1; 32];
        let second = [0xA2; 32];
        state.record_tau(&first, 1, [0x11; 32]);
        state.record_tau(&second, 2, [0x22; 32]);
        assert!(state.cached_tau(&first, 1).is_none());
        assert_eq!(state.cached_tau(&second, 2), Some([0x22; 32]));
    }

    #[test]
    fn boundary_counter_update_resets_origin_on_policy_shift() {
        let mut policy = ForwardSecrecyPolicy {
            epoch_period: Duration::from_secs(10),
            epoch_base_ts: 100,
            forward_slack: 2,
            ..Default::default()
        };
        let mut state = ForwardSecrecyState::with_policy([0x90; 32], policy.clone());
        state.set_last_we_epoch_id([0x99; 32]);
        state.boundary.epoch_base_ts = 1;
        policy.epoch_base_ts = 100;
        let now_wall = SystemTime::UNIX_EPOCH + Duration::from_secs(260);
        let now_mono = Instant::now() + Duration::from_secs(160);
        let target = state.boundary.update(now_wall, now_mono, &policy);
        assert!(target >= state.boundary.ec0);
    }

    #[test]
    fn clear_secrets_zeroizes_kfs_material() {
        let mut state = ForwardSecrecyState::new([0xA7; 32]);
        assert_ne!(state.snapshot().k_fs, [0u8; 32]);
        state.clear_secrets();
        assert_eq!(state.snapshot().k_fs, [0u8; 32]);
    }
}

#[derive(Debug)]
pub struct FsJoinArtifacts {
    pub inputs: FsJoinInputs,
    pub fs_dev_commit: [u8; 32],
    pub epoch_sk: [u8; 32],
    pub tau_e: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsMergeInputs {
    pub fs_purge_times: Option<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LeafIdMode {
    #[default]
    PerGroup,
    Global,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SrxMode {
    #[default]
    Complete,
}

#[derive(Serialize)]
struct LeafIdTuple<'a>(
    #[serde(with = "serde_bytes")] &'a [u8],
    &'a str,
    #[serde(with = "serde_bytes")] &'a [u8],
);

#[derive(Serialize)]
struct LeafIdTupleGlobal<'a>(&'a str, #[serde(with = "serde_bytes")] &'a [u8]);

pub fn compute_leaf_id(
    mode: LeafIdMode,
    gid: &[u8],
    device_pk_alg: &str,
    device_pk_bytes: &[u8],
) -> Result<[u8; 32], MsphfError> {
    match mode {
        LeafIdMode::PerGroup => h_l(
            ds::MSPHF_LEAF_ID,
            &LeafIdTuple(gid, device_pk_alg, device_pk_bytes),
        ),
        LeafIdMode::Global => h_l(
            ds::MSPHF_LEAF_ID,
            &LeafIdTupleGlobal(device_pk_alg, device_pk_bytes),
        ),
    }
}

#[derive(Debug, Clone)]
pub struct SrxNonMembershipAnchor {
    pub witness: RawNonMembershipWitness,
    pub left_ref: Option<u32>,
    pub right_ref: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SrxInputs<'a> {
    pub join_leaf_ids: Cow<'a, [[u8; 32]]>,
    pub join_nonmem_parent: Vec<SrxNonMembershipAnchor>,
    pub join_nonmem_revoked_since: Vec<SrxNonMembershipAnchor>,
    pub since_leaf_ids: Cow<'a, [[u8; 32]]>,
    pub since_mem_revoked: Cow<'a, [RawMembershipWitness]>,
    pub anchor_mem_pool: Vec<RawMembershipWitness>,
    pub join_frontier: Option<Cow<'a, [[u8; 32]]>>,
    pub since_frontier: Option<Cow<'a, [[u8; 32]]>>,
}

/// Inputs needed to build the public instance `X_k` (without `ANCHOR_HDR_CTX`).
#[derive(Debug, Clone)]
pub struct AnchorInstanceParts<'a> {
    pub gid: &'a [u8],
    pub cat: &'a [u8],
    pub tswe_salt_hash: &'a [u8],
    pub parent_root: &'a [u8],
    pub join_delta_root: &'a [u8],
    pub revoked_since_prev_root: &'a [u8],
    pub revoked_root: &'a [u8],
    pub pox_r_commit: Option<&'a [u8]>,
}

/// Result of the joiner’s KGen pipeline.
#[derive(Debug)]
pub struct JoinerKGenResult {
    pub hp_k: Vec<u8>,
    pub hp_ciphertext: Vec<u8>,
    pub hp_commit: [u8; 32],
    pub hp_aead_key: [u8; 32],
    pub seed_ctx_hash: [u8; 32],
    pub seed_commit: [u8; 32],
    pub seed_bundle_commit: [u8; 32],
    pub rho_commit: [u8; 32],
    pub xk_hash: [u8; 32],
    pub we_epoch_id: [u8; 32],
    pub epoch_key: [u8; 32],
    pub eid: [u8; 32],
    pub anchor_hdr_ctx: Vec<u8>,
    pub retired_heads: Option<Vec<[u8; 32]>>,
    pub mh_note: Option<String>,
    pub hp_proof: HpProof,
    pub header_map: BTreeMap<u64, Value>,
    pub capss_witness: CapssWitnessBundle,
    pub fs_epoch_secret: Option<[u8; 32]>,
    pub fs_tau: Option<[u8; 32]>,
}

pub use msphf_rlwe::CapssWitnessBundle;
impl JoinerKGenResult {
    pub fn hp_proof_cbor(&self) -> Result<Vec<u8>, MsphfError> {
        proof_to_cbor(&self.hp_proof)
    }

    pub fn anchor_header_map(&self) -> &BTreeMap<u64, Value> {
        &self.header_map
    }

    pub fn anchor_header_bytes(&self) -> Result<BTreeMap<u64, Vec<u8>>, MsphfError> {
        let mut out = BTreeMap::new();
        for (key, value) in &self.header_map {
            let bytes = match value {
                Value::Bytes(data) => data.clone(),
                other => {
                    let mut buf = Vec::new();
                    into_writer(other, &mut buf).map_err(MsphfError::serialization)?;
                    buf
                }
            };
            out.insert(*key, bytes);
        }
        Ok(out)
    }

    pub fn retired_heads(&self) -> Option<&[[u8; 32]]> {
        self.retired_heads.as_deref()
    }

    pub fn mh_note(&self) -> Option<&str> {
        self.mh_note.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PivotParity {
    pub gid: Vec<u8>,
    pub cat: Vec<u8>,
    pub parent_root: [u8; 32],
    pub we_epoch_id: [u8; 32],
    pub rho_commit: [u8; 32],
    pub seed_ctx_hash: [u8; 32],
    pub seed_commit: [u8; 32],
    pub hp_commit: [u8; 32],
    pub xk_hash: [u8; 32],
    pub join_delta_root: [u8; 32],
    pub revoked_since_root: [u8; 32],
    pub revoked_root: [u8; 32],
    pub accept_seq: u64,
    pub crs_id: Vec<u8>,
    pub params_id: Vec<u8>,
    pub policy_version: String,
    pub proof_mode: String,
    pub vrf_id: String,
    pub vrf_proof: Vec<u8>,
    pub vrf_public: Vec<u8>,
    pub mask_a: MaskDigest,
    pub mask_b: MaskDigest,
    pub fs_capss: Vec<u8>,
    pub proofs_commit: [u8; 32],
    pub srx_commit: Option<[u8; 32]>,
    pub srx_root_sw: Option<[u8; 32]>,
    pub is_join: bool,
    pub hp_envelope: Arc<[u8]>,
    pub fs_epoch_commit: Option<[u8; 32]>,
    pub fs_ec: Option<u64>,
    pub fs_dev_commit: Option<[u8; 32]>,
}

impl PivotParity {
    pub fn compute_vck(&self) -> Result<[u8; 32], MsphfError> {
        #[derive(Serialize)]
        struct VckPreimage<'a> {
            #[serde(with = "serde_bytes")]
            xk_hash: &'a [u8],
            #[serde(with = "serde_bytes")]
            seed_commit: &'a [u8],
            #[serde(with = "serde_bytes")]
            rho_commit: &'a [u8],
            #[serde(with = "serde_bytes")]
            hp_commit: &'a [u8],
            #[serde(with = "serde_bytes")]
            crs_id: &'a [u8],
            #[serde(with = "serde_bytes")]
            params_id: &'a [u8],
            #[serde(with = "serde_bytes")]
            srx_commit: &'a [u8],
            #[serde(with = "serde_bytes")]
            proofs_commit: &'a [u8],
            proof_mode: &'a str,
            vrf_id: &'a str,
            policy_version: u64,
        }

        let srx_commit = self.srx_commit.unwrap_or([0u8; 32]);
        let fs_policy_version = self
            .policy_version
            .parse::<u64>()
            .map_err(|_| MsphfError::invalid_input("pivot policy_version must be uint"))?;
        let preimage = VckPreimage {
            xk_hash: &self.xk_hash,
            seed_commit: &self.seed_commit,
            rho_commit: &self.rho_commit,
            hp_commit: &self.hp_commit,
            crs_id: self.crs_id.as_slice(),
            params_id: self.params_id.as_slice(),
            srx_commit: &srx_commit,
            proofs_commit: &self.proofs_commit,
            proof_mode: self.proof_mode.as_str(),
            vrf_id: self.vrf_id.as_str(),
            policy_version: fs_policy_version,
        };
        h_l("msphf/vck", &preimage)
    }
}

#[derive(Debug, Clone)]
struct PivotParityEntry {
    parity: PivotParity,
    accept_time: AcceptInstant,
}

#[derive(Debug, Clone)]
pub struct PivotParityStore {
    ttl: Duration,
    entries: BTreeMap<(Vec<u8>, [u8; 32]), Vec<PivotParityEntry>>,
}

impl PivotParityStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: BTreeMap::new(),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn set_ttl(&mut self, ttl: Duration, now: AcceptInstant) {
        self.ttl = ttl;
        self.prune(now);
    }

    fn prune(&mut self, now: AcceptInstant) {
        let ttl = self.ttl;
        self.entries.retain(|_, list| {
            list.retain(|entry| now.duration_since(entry.accept_time) <= ttl);
            !list.is_empty()
        });
    }

    pub fn insert(&mut self, parity: PivotParity, accept_time: AcceptInstant) {
        let key = (parity.gid.clone(), parity.parent_root);
        let entry = PivotParityEntry {
            parity,
            accept_time,
        };
        let list = self.entries.entry(key).or_default();
        if let Some(pos) = list
            .iter()
            .position(|existing| existing.parity.we_epoch_id == entry.parity.we_epoch_id)
        {
            list[pos] = entry;
        } else {
            list.push(entry);
        }
    }

    pub fn retire(&mut self, gid: &[u8], parent_root: &[u8; 32], retired_weids: &[[u8; 32]]) {
        if retired_weids.is_empty() {
            return;
        }
        let key = (gid.to_vec(), *parent_root);
        if let Some(list) = self.entries.get_mut(&key) {
            list.retain(|entry| {
                !retired_weids
                    .iter()
                    .any(|weid| weid == &entry.parity.we_epoch_id)
            });
            if list.is_empty() {
                self.entries.remove(&key);
            }
        }
    }

    pub fn list(
        &mut self,
        gid: &[u8],
        parent_root: &[u8; 32],
        now: AcceptInstant,
    ) -> Vec<PivotParity> {
        self.prune(now);
        let key = (gid.to_vec(), *parent_root);
        self.entries
            .get(&key)
            .map(|list| {
                let mut out: Vec<PivotParity> =
                    list.iter().map(|entry| entry.parity.clone()).collect();
                out.sort_by_key(|parity| parity.accept_seq);
                out
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct AnchorAcceptanceResult {
    pub outcome: AcceptanceOutcome,
    pub pivot_parity: PivotParity,
    pub telemetry_key: TelemetryKey,
    pub telemetry_counters: TelemetryCounters,
}

pub fn accept_anchor_or<'a>(
    ctx: &mut AcceptanceContext,
    anchor: &AnchorInstance<'a>,
    header_map: &BTreeMap<u64, Value>,
) -> Result<AcceptanceOutcome, AcceptanceError> {
    // Ensure the anchor carries the deterministic header context encoded in the header map.
    let anchor_seed_ctx = build_anchor_seed_ctx(header_map).map_err(AcceptanceError::from)?;
    if anchor_seed_ctx.as_slice() != anchor.anchor_hdr_ctx {
        return Err(AcceptanceError::Msphf(MsphfError::invalid_input(
            "anchor_hdr_ctx mismatch",
        )));
    }

    let parts = AnchorInstanceParts {
        gid: anchor.gid,
        cat: anchor.cat,
        tswe_salt_hash: anchor.tswe_salt_hash,
        parent_root: anchor.parent_root,
        join_delta_root: anchor.join_delta_root,
        revoked_since_prev_root: anchor.revoked_since_prev_root,
        revoked_root: anchor.revoked_root,
        pox_r_commit: anchor.pox_r_commit,
    };

    let outcome = ctx.accept_anchor(&parts, anchor.we_epoch_id, header_map)?;

    let commit = anchor.msphf_hp_commit.ok_or_else(|| {
        AcceptanceError::Msphf(MsphfError::invalid_input("missing msphf_hp_commit"))
    })?;
    if commit != outcome.hp_commit {
        return Err(AcceptanceError::Msphf(MsphfError::invalid_input(
            "msphf_hp_commit mismatch",
        )));
    }

    Ok(outcome)
}

pub fn accept_and_extract_or<'a>(
    ctx: &mut AcceptanceContext,
    anchor: &AnchorInstance<'a>,
    header_map: &BTreeMap<u64, Value>,
    proof: &HpProof,
    binding_inputs: &HpBindingInputs<'_>,
    witness: &[u8],
) -> Result<AnchorAcceptanceResult, AcceptanceError> {
    let outcome = accept_anchor_or(ctx, anchor, header_map)?;

    let telemetry_key = TelemetryKey::from_parts(anchor.gid, anchor.parent_root);
    let telemetry_counters = ctx
        .telemetry_lookup(anchor.gid, anchor.parent_root)
        .cloned()
        .unwrap_or_default();

    let mut parent_root = [0u8; 32];
    parent_root.copy_from_slice(anchor.parent_root);
    let policy_version = match header_map.get(&HDR_FS_POLICY_VERSION) {
        Some(Value::Integer(value)) => u64::try_from(*value)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| DEFAULT_POLICY_VERSION.to_string()),
        _ => DEFAULT_POLICY_VERSION.to_string(),
    };
    let proof_mode = match header_map.get(&HDR_PROOF_MODE) {
        Some(Value::Text(text)) => text.clone(),
        _ => DEFAULT_PROOF_MODE.to_string(),
    };
    let vrf_id = match header_map.get(&HDR_VRF_ID) {
        Some(Value::Text(text)) => text.clone(),
        _ => DEFAULT_VRF_ID.to_string(),
    };
    let vrf_proof = match header_map.get(&HDR_VRF_PROOF) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => Vec::new(),
    };
    let vrf_public = match header_map.get(&HDR_VRF_PUBLIC_KEY) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => Vec::new(),
    };
    let mask_a = match header_map.get(&HDR_VRF_MASK_A) {
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            arr
        }
        _ => [0u8; 32],
    };
    let mask_b = match header_map.get(&HDR_VRF_MASK_B) {
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            arr
        }
        _ => [0u8; 32],
    };
    let fs_capss = match header_map.get(&HDR_FS_CAPSS) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => Vec::new(),
    };
    let proofs_commit = match header_map.get(&HDR_PROOFS_COMMIT) {
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            arr
        }
        _ => [0u8; 32],
    };
    let hp_envelope: Arc<[u8]> = header_map
        .get(&HDR_HP_BYTES)
        .and_then(|value| to_cbor_vec(value).ok())
        .map(|bytes| Arc::from(bytes.into_boxed_slice()))
        .unwrap_or_else(|| Arc::from([] as [u8; 0]));
    let join_delta_root_arr = to_array32("join_delta_root", anchor.join_delta_root)?;
    let revoked_since_root_arr =
        to_array32("revoked_since_prev_root", anchor.revoked_since_prev_root)?;
    let revoked_root_arr = to_array32("revoked_root", anchor.revoked_root)?;

    let crs_id = match header_map.get(&HDR_CRS_ID) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        Some(Value::Text(text)) => text.as_bytes().to_vec(),
        _ => Vec::new(),
    };
    let params_id = match header_map.get(&HDR_PARAMS_ID) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        Some(Value::Text(text)) => text.as_bytes().to_vec(),
        _ => Vec::new(),
    };
    let srx_commit = match header_map.get(&HDR_SRX_COMMIT) {
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(arr)
        }
        _ => None,
    };
    let srx_root_sw = match header_map.get(&HDR_SRX_ROOT_SW) {
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(arr)
        }
        _ => None,
    };
    let is_join = matches!(outcome.kind, AcceptanceKind::NonMerge);

    let pivot_parity = PivotParity {
        gid: anchor.gid.to_vec(),
        cat: anchor.cat.to_vec(),
        parent_root,
        we_epoch_id: outcome.we_epoch_id,
        rho_commit: outcome.rho_commit,
        seed_ctx_hash: outcome.seed_ctx_hash,
        seed_commit: outcome.seed_commit,
        hp_commit: outcome.hp_commit,
        xk_hash: outcome.xk_hash,
        join_delta_root: join_delta_root_arr,
        revoked_since_root: revoked_since_root_arr,
        revoked_root: revoked_root_arr,
        accept_seq: outcome.accept_seq,
        crs_id,
        params_id,
        policy_version,
        proof_mode,
        vrf_id,
        vrf_proof,
        vrf_public,
        mask_a,
        mask_b,
        fs_capss,
        proofs_commit,
        srx_commit,
        srx_root_sw,
        is_join,
        hp_envelope,
        fs_epoch_commit: outcome.fs_epoch_commit,
        fs_ec: outcome.fs_ec,
        fs_dev_commit: outcome.fs_dev_commit,
    };

    if matches!(outcome.kind, AcceptanceKind::Merge { .. }) {
        return Ok(AnchorAcceptanceResult {
            outcome,
            pivot_parity,
            telemetry_key,
            telemetry_counters,
        });
    }

    if *binding_inputs.seed_ctx_hash != outcome.seed_ctx_hash {
        return Err(AcceptanceError::Msphf(MsphfError::invalid_input(
            "seed_ctx_hash mismatch",
        )));
    }
    if *binding_inputs.seed_commit != outcome.seed_commit {
        return Err(AcceptanceError::Msphf(MsphfError::invalid_input(
            "seed_commit mismatch",
        )));
    }
    if *binding_inputs.rho_commit != outcome.rho_commit {
        return Err(AcceptanceError::Msphf(MsphfError::invalid_input(
            "rho_commit mismatch",
        )));
    }
    if *binding_inputs.hp_commit != outcome.hp_commit {
        return Err(AcceptanceError::Msphf(MsphfError::invalid_input(
            "hp_commit mismatch",
        )));
    }

    let anchor_xk_hash = anchor.xk_hash().map_err(AcceptanceError::from)?;
    if anchor_xk_hash != *binding_inputs.xk_hash {
        return Err(AcceptanceError::Msphf(MsphfError::invalid_input(
            "xk_hash mismatch",
        )));
    }

    // Validate witness canonical form when supplied to keep noncanonical inputs from
    // slipping through the acceptance pipeline.
    parse_validated_witness(anchor, witness).map_err(AcceptanceError::from)?;

    let accept_time = outcome.accept_time;
    let should_verify = ctx.should_verify_hp(binding_inputs, proof, header_map, accept_time)?;
    if should_verify {
        verify_hp_k(binding_inputs, proof).map_err(AcceptanceError::from)?;
        ctx.record_verified_hp(binding_inputs, proof, header_map, accept_time)?;
    }

    Ok(AnchorAcceptanceResult {
        outcome,
        pivot_parity,
        telemetry_key,
        telemetry_counters,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn process_anchor_or<'a>(
    accept_ctx: &mut AcceptanceContext,
    receiver_cache: &mut ReceiverCache,
    anchor: &AnchorInstance<'a>,
    header_map: &BTreeMap<u64, Value>,
    proof: &HpProof,
    binding_inputs: &HpBindingInputs<'_>,
    witness: &[u8],
) -> Result<AnchorAcceptanceResult, AcceptanceError> {
    let acceptance = accept_and_extract_or(
        accept_ctx,
        anchor,
        header_map,
        proof,
        binding_inputs,
        witness,
    )?;
    receiver_cache.apply_acceptance(&acceptance);
    Ok(acceptance)
}

/// Resolve an accepted head for data-plane usage, returning diagnostic context for telemetry.
pub fn set_merge_heads(
    header_map: &mut BTreeMap<u64, Value>,
    heads: &[[u8; 32]],
    note: Option<&str>,
) -> Result<(), MsphfError> {
    if heads.is_empty() {
        return Err(MsphfError::invalid_input("mh_heads must be non-empty"));
    }
    if !is_sorted_unique(heads) {
        return Err(MsphfError::invalid_input(
            "mh_heads must be sorted and unique",
        ));
    }
    let values: Vec<Value> = heads
        .iter()
        .map(|head| Value::Bytes(head.to_vec()))
        .collect();
    header_map.insert(hdr::HDR_MH_HEADS, Value::Array(values));
    match note {
        Some(text) if !text.is_empty() => {
            header_map.insert(102, Value::Text(text.to_string()));
        }
        _ => {
            header_map.remove(&102);
        }
    }
    Ok(())
}

fn is_sorted_unique(heads: &[[u8; 32]]) -> bool {
    heads.windows(2).all(|window| window[0] < window[1])
}

fn parse_merge_metadata(header_map: &BTreeMap<u64, Value>) -> Result<MergeMetadata, MsphfError> {
    let mut heads_meta = None;
    if let Some(value) = header_map.get(&hdr::HDR_MH_HEADS) {
        let Value::Array(entries) = value else {
            return Err(MsphfError::invalid_input("mh_heads must be array"));
        };
        if entries.is_empty() {
            return Err(MsphfError::invalid_input("mh_heads empty"));
        }
        let mut heads = Vec::with_capacity(entries.len());
        for entry in entries {
            let Value::Bytes(bytes) = entry else {
                return Err(MsphfError::invalid_input("mh_heads entry not bytes"));
            };
            if bytes.len() != 32 {
                return Err(MsphfError::invalid_input("mh_heads entry wrong length"));
            }
            let mut current = [0u8; 32];
            current.copy_from_slice(bytes);
            heads.push(current);
        }
        if !is_sorted_unique(&heads) {
            return Err(MsphfError::invalid_input(
                "mh_heads must be sorted and unique",
            ));
        }
        heads_meta = Some(heads);
    }

    let mh_note = if heads_meta.is_some() {
        match header_map.get(&102) {
            None => None,
            Some(Value::Text(text)) => Some(text.clone()),
            Some(_) => return Err(MsphfError::invalid_input("mh_note must be text")),
        }
    } else {
        None
    };

    Ok((heads_meta, mh_note))
}

#[derive(Serialize)]
struct SrxEmptyRootProfile<'a>(&'a str);

fn default_srx_empty_root_sw() -> [u8; 32] {
    h_l(
        "srx/root_sw/empty",
        &SrxEmptyRootProfile(DEFAULT_SRX_SMALLWOOD_PROFILE),
    )
    .unwrap_or([0u8; 32])
}

fn populate_merge_srx<'a>(
    header: &mut BTreeMap<u64, Value>,
    parts: &AnchorInstanceParts<'a>,
    params: &OrchestrationParams<'a>,
    srx_root_sw_before: &[u8; 32],
) -> Result<(), MsphfError> {
    populate_merge_srx_complete(header, parts, params, srx_root_sw_before)
}

fn populate_merge_srx_complete<'a>(
    header: &mut BTreeMap<u64, Value>,
    parts: &AnchorInstanceParts<'a>,
    params: &OrchestrationParams<'a>,
    srx_root_sw_before: &[u8; 32],
) -> Result<(), MsphfError> {
    let srx_inputs = params
        .srx
        .as_ref()
        .ok_or_else(|| MsphfError::invalid_input("srx inputs required for merge anchor"))?;

    let join_leaf_ids = srx_inputs.join_leaf_ids.as_ref();
    let since_leaf_ids = srx_inputs.since_leaf_ids.as_ref();

    let parent_root = to_array32("parent_root", parts.parent_root)?;
    let revoked_since_root = to_array32("revoked_since_root", parts.revoked_since_prev_root)?;
    let revoked_root = to_array32("revoked_root", parts.revoked_root)?;
    let join_root_expected = to_array32("join_delta_root", parts.join_delta_root)?;

    let join_root_value = canonical_set_root(join_leaf_ids)?;
    let join_root_arr: [u8; 32] = join_root_value
        .as_slice()
        .try_into()
        .map_err(|_| MsphfError::invalid_input("srx join root length"))?;
    if join_root_arr != join_root_expected {
        return Err(MsphfError::invalid_input("srx join root mismatch"));
    }
    let since_root_value = canonical_set_root(since_leaf_ids)?;
    let since_root_arr: [u8; 32] = since_root_value
        .as_slice()
        .try_into()
        .map_err(|_| MsphfError::invalid_input("srx revoked-since root length"))?;
    if since_root_arr != revoked_since_root {
        return Err(MsphfError::invalid_input("srx revoked-since root mismatch"));
    }

    let join_frontier = match &srx_inputs.join_frontier {
        Some(frontier) => frontier.as_ref().to_vec(),
        None => canonical_frontier(join_leaf_ids)?,
    };
    let since_frontier = match &srx_inputs.since_frontier {
        Some(frontier) => frontier.as_ref().to_vec(),
        None => canonical_frontier(since_leaf_ids)?,
    };

    let pool_len = srx_inputs.anchor_mem_pool.len();
    for anchor in srx_inputs
        .join_nonmem_parent
        .iter()
        .chain(srx_inputs.join_nonmem_revoked_since.iter())
    {
        validate_anchor_indices(anchor, pool_len)?;
    }

    use ahash::AHashMap;
    let mut anchor_entries = Vec::with_capacity(pool_len);
    for (idx, witness) in srx_inputs.anchor_mem_pool.iter().enumerate() {
        let root_bytes = witness
            .root
            .as_slice()
            .try_into()
            .map_err(|_| MsphfError::invalid_input("anchor root length"))?;
        let leaf_bytes = witness
            .leaf_id
            .as_slice()
            .try_into()
            .map_err(|_| MsphfError::invalid_input("anchor leaf length"))?;
        anchor_entries.push(((root_bytes, leaf_bytes), witness.clone(), idx as u32));
    }
    anchor_entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut anchor_mem_values = Vec::with_capacity(anchor_entries.len());
    let mut index_map: AHashMap<u32, u32> = AHashMap::new();
    let mut prev_key: Option<([u8; 32], [u8; 32])> = None;
    for (new_idx, (key, witness, old_idx)) in anchor_entries.into_iter().enumerate() {
        if prev_key.is_some_and(|prev| prev >= key) {
            return Err(MsphfError::invalid_input("srx anchor pool unsorted"));
        }
        prev_key = Some(key);
        anchor_mem_values.push(value_from_serde(&witness)?);
        index_map.insert(old_idx, new_idx as u32);
    }

    let remap_anchor = |anchor: &SrxNonMembershipAnchor| -> Result<Value, MsphfError> {
        let mut clone = anchor.clone();
        if let Some(idx) = clone.left_ref {
            let mapped = index_map
                .get(&idx)
                .ok_or_else(|| MsphfError::invalid_input("srx anchor left ref invalid"))?;
            clone.left_ref = Some(*mapped);
        }
        if let Some(idx) = clone.right_ref {
            let mapped = index_map
                .get(&idx)
                .ok_or_else(|| MsphfError::invalid_input("srx anchor right ref invalid"))?;
            clone.right_ref = Some(*mapped);
        }
        serialize_nonmem_anchor(&clone)
    };

    let join_nonmem_parent = srx_inputs
        .join_nonmem_parent
        .iter()
        .map(remap_anchor)
        .collect::<Result<Vec<_>, _>>()?;
    let join_nonmem_revoked_since = srx_inputs
        .join_nonmem_revoked_since
        .iter()
        .map(remap_anchor)
        .collect::<Result<Vec<_>, _>>()?;
    let since_mem_revoked = srx_inputs
        .since_mem_revoked
        .as_ref()
        .iter()
        .map(value_from_serde)
        .collect::<Result<Vec<_>, _>>()?;

    let join_leaf_values: Vec<Value> = join_leaf_ids
        .iter()
        .map(|leaf| Value::Bytes(leaf.to_vec()))
        .collect();
    let since_leaf_values: Vec<Value> = since_leaf_ids
        .iter()
        .map(|leaf| Value::Bytes(leaf.to_vec()))
        .collect();
    let join_frontier_value = if srx_inputs.join_frontier.is_some() {
        Value::Array(
            join_frontier
                .iter()
                .map(|node| Value::Bytes(node.to_vec()))
                .collect(),
        )
    } else {
        Value::Null
    };
    let since_frontier_value = if srx_inputs.since_frontier.is_some() {
        Value::Array(
            since_frontier
                .iter()
                .map(|node| Value::Bytes(node.to_vec()))
                .collect(),
        )
    } else {
        Value::Null
    };
    let join_frontier_len = if srx_inputs.join_frontier.is_some() {
        join_frontier.len() as u64
    } else {
        0
    };
    let since_frontier_len = if srx_inputs.since_frontier.is_some() {
        since_frontier.len() as u64
    } else {
        0
    };

    let meta_value = Value::Map(vec![
        (
            Value::Text("join_count".to_string()),
            Value::Integer(Integer::from(join_leaf_ids.len() as u64)),
        ),
        (
            Value::Text("since_count".to_string()),
            Value::Integer(Integer::from(since_leaf_ids.len() as u64)),
        ),
        (
            Value::Text("join_frontier_size".to_string()),
            Value::Integer(Integer::from(join_frontier_len)),
        ),
        (
            Value::Text("since_frontier_size".to_string()),
            Value::Integer(Integer::from(since_frontier_len)),
        ),
    ]);

    let srx_value = Value::Array(vec![
        Value::Array(join_nonmem_parent),
        Value::Array(join_nonmem_revoked_since),
        Value::Array(since_mem_revoked),
        meta_value,
        Value::Array(join_leaf_values),
        join_frontier_value,
        Value::Array(since_leaf_values),
        since_frontier_value,
        Value::Array(anchor_mem_values),
    ]);

    let payload_bytes = encode_value(&srx_value)?;
    #[derive(Serialize)]
    struct SrxCommit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);
    let commit = h_l(ds::MSPHF_SRX_COMMIT, &SrxCommit(&payload_bytes))?;

    header.insert(121, Value::Bytes(commit.to_vec()));

    attach_srx_smallwood_proof(
        header,
        params,
        srx_root_sw_before,
        &parent_root,
        &join_root_arr,
        &revoked_since_root,
        &revoked_root,
        &commit,
        &payload_bytes,
    )?;

    header.insert(122, Value::Bytes(payload_bytes));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn attach_srx_smallwood_proof(
    header: &mut BTreeMap<u64, Value>,
    params: &OrchestrationParams<'_>,
    shadow_root_before: &[u8; 32],
    parent_root: &[u8; 32],
    join_root: &[u8; 32],
    revoked_since_root: &[u8; 32],
    revoked_root: &[u8; 32],
    srx_commit: &[u8; 32],
    payload_bytes: &[u8],
) -> Result<(), MsphfError> {
    let fs_policy_version_u64 = parse_fs_policy_version(params.fs_policy_version)?;
    let payload_digest = srx_smallwood::payload_digest(payload_bytes)?;
    let shadow_after = srx_smallwood::compute_shadow_root(
        parent_root,
        join_root,
        revoked_since_root,
        revoked_root,
        Some(srx_commit),
        Some(&payload_digest),
    );
    let bridge_ctx = srx_smallwood::compute_bridge_ctx(
        parent_root,
        join_root,
        revoked_since_root,
        revoked_root,
        srx_commit,
        &payload_digest,
        &shadow_after,
    )?;

    let inputs = srx_smallwood::Inputs {
        shadow_root_before,
        shadow_root_after: &shadow_after,
        parent_root,
        join_root,
        revoked_since_root,
        revoked_root,
        srx_commit,
        srx_payload_digest: &payload_digest,
        srx_bridge_ctx: &bridge_ctx,
        proof_mode: params.proof_mode,
        fs_policy_version: fs_policy_version_u64,
        vrf_id: params.vrf_id,
    };

    let mut rng = OsRng;
    let proof = srx_smallwood::prove(&mut rng, &inputs)?;
    let proof_bytes = proof.as_bytes();
    if proof_bytes.len() > srx_smallwood::SRX_SMALLWOOD_MAX_BYTES {
        return Err(MsphfError::invalid_input("srx smallwood proof oversize"));
    }

    header.insert(HDR_SRX_ROOT_SW, Value::Bytes(shadow_after.to_vec()));
    header.insert(HDR_SRX_SMALLWOOD, Value::Bytes(proof_bytes.to_vec()));

    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct HpArtifactOwned {
    #[serde(with = "serde_bytes")]
    pub(crate) hp_a: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) hp_b: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) m_a: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) m_b: Vec<u8>,
    pub(crate) params_id: String,
    pub(crate) hp_version: u8,
}

/// Performs the joiner-side KGen as described in the City‑G joiner specification.
pub fn joiner_kgen_or<'a>(
    mut header_map: BTreeMap<u64, Value>,
    parts: AnchorInstanceParts<'a>,
    params: OrchestrationParams<'a>,
    forward_state: Option<&mut ForwardSecrecyState>,
    witness_bytes: Option<&[u8]>,
) -> Result<JoinerKGenResult, MsphfError> {
    let fs_policy_version_u64 = parse_fs_policy_version(params.fs_policy_version)?;
    match header_map.get(&90).cloned() {
        None => {
            header_map.insert(90, Value::Integer(Integer::from(TSWE_ALG_CODE)));
        }
        Some(Value::Integer(value)) => {
            let code = u8::try_from(value)
                .map_err(|_| MsphfError::invalid_input("tswe_alg out of range"))?;
            if code != TSWE_ALG_CODE {
                return Err(MsphfError::invalid_input("tswe_alg mismatch"));
            }
        }
        Some(Value::Text(text)) => {
            if text.as_str() == TSWE_ALG_LABEL {
                header_map.insert(90, Value::Integer(Integer::from(TSWE_ALG_CODE)));
            } else {
                return Err(MsphfError::invalid_input("tswe_alg mismatch"));
            }
        }
        Some(Value::Bytes(bytes)) => {
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| MsphfError::invalid_input("tswe_alg invalid utf8"))?;
            if text == TSWE_ALG_LABEL {
                header_map.insert(90, Value::Integer(Integer::from(TSWE_ALG_CODE)));
            } else {
                return Err(MsphfError::invalid_input("tswe_alg mismatch"));
            }
        }
        Some(_) => {
            return Err(MsphfError::invalid_input("tswe_alg invalid type"));
        }
    }

    match header_map.get(&92) {
        None => {
            header_map.insert(92, Value::Text(MERKLE_DS_ID.to_string()));
        }
        Some(Value::Text(text)) => {
            if text != MERKLE_DS_ID {
                return Err(MsphfError::invalid_input("merkle_ds_id mismatch"));
            }
        }
        Some(_) => {
            return Err(MsphfError::invalid_input("merkle_ds_id must be text"));
        }
    }

    match header_map.get(&98) {
        None => {
            header_map.insert(98, Value::Text(params.msphf_crs_id.to_string()));
        }
        Some(Value::Text(text)) => {
            if text != params.msphf_crs_id {
                return Err(MsphfError::invalid_input("msphf_crs_id mismatch"));
            }
        }
        Some(Value::Bytes(bytes)) => {
            let as_str = std::str::from_utf8(bytes)
                .map_err(|_| MsphfError::invalid_input("msphf_crs_id invalid utf8"))?;
            if as_str != params.msphf_crs_id {
                return Err(MsphfError::invalid_input("msphf_crs_id mismatch"));
            }
        }
        Some(_) => {
            return Err(MsphfError::invalid_input("msphf_crs_id invalid type"));
        }
    }

    match header_map.get(&106) {
        None => {
            header_map.insert(106, Value::Text(params.params_id.to_string()));
        }
        Some(Value::Text(text)) => {
            if text != params.params_id {
                return Err(MsphfError::invalid_input("msphf_params_id mismatch"));
            }
        }
        Some(Value::Bytes(bytes)) => {
            if bytes.len() != 32 {
                return Err(MsphfError::invalid_input("msphf_params_id length"));
            }
        }
        Some(_) => {
            return Err(MsphfError::invalid_input("msphf_params_id invalid type"));
        }
    }

    header_map.insert(110, Value::Bytes(parts.parent_root.to_vec()));
    header_map.insert(111, Value::Bytes(parts.join_delta_root.to_vec()));
    header_map.insert(112, Value::Bytes(parts.revoked_since_prev_root.to_vec()));
    header_map.insert(113, Value::Bytes(parts.revoked_root.to_vec()));
    header_map.insert(
        HDR_FS_POLICY_VERSION,
        Value::Integer(Integer::from(fs_policy_version_u64)),
    );
    header_map.insert(
        HDR_FS_EPOCH_BASE_TS,
        Value::Integer(Integer::from(params.fs_epoch_base_ts)),
    );
    match header_map.get(&HDR_BARRIER_VERSION) {
        None => {
            header_map.insert(
                HDR_BARRIER_VERSION,
                Value::Integer(Integer::from(params.barrier_version)),
            );
        }
        Some(Value::Integer(value)) => {
            let parsed = u64::try_from(*value)
                .map_err(|_| MsphfError::invalid_input("barrier_version out of range"))?;
            if parsed != params.barrier_version {
                return Err(MsphfError::invalid_input("barrier_version mismatch"));
            }
        }
        Some(_) => return Err(MsphfError::invalid_input("barrier_version must be uint")),
    }
    let device_pk_bytes = if let Some(pop) = &params.pop_keys {
        pop.public_key.to_vec()
    } else {
        match header_map.get(&HDR_POP_PK) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(MsphfError::invalid_input("fs_join requires pop_public_key")),
        }
    };
    let barrier_version_for_fs = parse_barrier_version_for_fs_dev_chain(&header_map)?;
    let barrier_update_digest_for_fs = barrier_update_digest_for_fs_dev_chain(&header_map)?;
    let mut fs_inputs = params.fs_join;
    let mut fs_dev_commit = compute_fs_dev_commit_v2(
        &device_pk_bytes,
        fs_inputs.fs_ec,
        &fs_inputs.fs_dev_prev_commit,
        barrier_version_for_fs,
        &barrier_update_digest_for_fs,
    )?;
    header_map.insert(HDR_FS_EC, Value::Integer(Integer::from(fs_inputs.fs_ec)));
    header_map.insert(
        HDR_FS_EPOCH_COMMIT,
        Value::Bytes(fs_inputs.fs_epoch_commit.to_vec()),
    );
    header_map.insert(
        HDR_FS_DEV_PREV_COMMIT,
        Value::Bytes(fs_inputs.fs_dev_prev_commit.to_vec()),
    );
    header_map.insert(HDR_FS_DEV_COMMIT, Value::Bytes(fs_dev_commit.to_vec()));

    let (retired_heads, mh_note) = parse_merge_metadata(&header_map)?;

    // Build ANCHOR_SEED_CTX with the current header (seed fields will be refined below).
    let mut anchor_seed_ctx = build_anchor_seed_ctx(&header_map)?;
    let mut seed_ctx_hash = compute_seed_ctx_hash(&anchor_seed_ctx)?;
    header_map.insert(91, Value::Bytes(seed_ctx_hash.to_vec()));
    let mut we_epoch_id = derive_we_epoch_id(parts.gid, parts.parent_root, &seed_ctx_hash)?;

    let mut fs_epoch_secret = None;
    let mut fs_tau = None;

    if let Some(state_ref) = forward_state {
        let original_state = state_ref.clone();
        let mut final_state = original_state.clone();
        let mut final_inputs = fs_inputs;
        let mut final_dev_commit = fs_dev_commit;
        let mut final_secret = None;
        let mut final_tau_val = None;

        for _ in 0..4 {
            let mut work_state = original_state.clone();
            let artifacts = work_state.prepare_join(
                &device_pk_bytes,
                &we_epoch_id,
                barrier_version_for_fs,
                &barrier_update_digest_for_fs,
            )?;
            final_inputs = artifacts.inputs;
            final_dev_commit = artifacts.fs_dev_commit;
            final_secret = Some(artifacts.epoch_sk);
            final_tau_val = Some(artifacts.tau_e);

            header_map.insert(HDR_FS_EC, Value::Integer(Integer::from(final_inputs.fs_ec)));
            header_map.insert(
                HDR_FS_EPOCH_COMMIT,
                Value::Bytes(final_inputs.fs_epoch_commit.to_vec()),
            );
            header_map.insert(
                HDR_FS_DEV_PREV_COMMIT,
                Value::Bytes(final_inputs.fs_dev_prev_commit.to_vec()),
            );
            header_map.insert(HDR_FS_DEV_COMMIT, Value::Bytes(final_dev_commit.to_vec()));

            let new_anchor_seed_ctx = build_anchor_seed_ctx(&header_map)?;
            let new_seed_ctx_hash = compute_seed_ctx_hash(&new_anchor_seed_ctx)?;
            header_map.insert(91, Value::Bytes(new_seed_ctx_hash.to_vec()));
            let new_we_epoch_id =
                derive_we_epoch_id(parts.gid, parts.parent_root, &new_seed_ctx_hash)?;

            final_state = work_state.clone();

            if new_we_epoch_id == we_epoch_id {
                anchor_seed_ctx = new_anchor_seed_ctx;
                seed_ctx_hash = new_seed_ctx_hash;
                we_epoch_id = new_we_epoch_id;
                break;
            }

            anchor_seed_ctx = new_anchor_seed_ctx;
            seed_ctx_hash = new_seed_ctx_hash;
            we_epoch_id = new_we_epoch_id;
        }

        final_state.fs_dev_commit = final_dev_commit;
        *state_ref = final_state;
        fs_inputs = final_inputs;
        fs_dev_commit = final_dev_commit;
        fs_epoch_secret = final_secret;
        fs_tau = final_tau_val;
    } else {
        // No forward-secrecy state supplied; header already carries the provided inputs.
        anchor_seed_ctx = build_anchor_seed_ctx(&header_map)?;
        seed_ctx_hash = compute_seed_ctx_hash(&anchor_seed_ctx)?;
        header_map.insert(91, Value::Bytes(seed_ctx_hash.to_vec()));
        we_epoch_id = derive_we_epoch_id(parts.gid, parts.parent_root, &seed_ctx_hash)?;
    }

    let anchor_hdr_ctx = anchor_seed_ctx.clone();

    let anchor_instance = AnchorInstance {
        gid: parts.gid,
        cat: parts.cat,
        we_epoch_id,
        anchor_hdr_ctx: &anchor_hdr_ctx,
        tswe_salt_hash: parts.tswe_salt_hash,
        parent_root: parts.parent_root,
        join_delta_root: parts.join_delta_root,
        revoked_since_prev_root: parts.revoked_since_prev_root,
        revoked_root: parts.revoked_root,
        pox_r_commit: parts.pox_r_commit,
        msphf_hp_commit: None,
    };

    let xk_hash = anchor_instance.xk_hash()?;

    let (rho, rho_commit) = match &params.pop_keys {
        Some(pop) => {
            #[derive(Serialize)]
            struct PopMsg<'a> {
                #[serde(with = "serde_bytes")]
                xk: &'a [u8],
                #[serde(with = "serde_bytes")]
                leaf_id: &'a [u8],
                #[serde(with = "serde_bytes")]
                epoch: &'a [u8],
            }

            let leaf_id = compute_leaf_id(
                params.leaf_id_mode,
                parts.gid,
                pop.algorithm,
                pop.public_key,
            )?;
            let xk_bytes = anchor_instance.to_cbor_bytes()?;
            let pop_msg = h_l(
                ds::MSPHF_POP_MSG,
                &PopMsg {
                    xk: &xk_bytes,
                    leaf_id: &leaf_id,
                    epoch: &we_epoch_id,
                },
            )?;
            let pop_sig = detached_sign(&pop_msg, pop.secret_key);
            header_map.insert(107, Value::Text(pop.algorithm.to_string()));
            header_map.insert(108, Value::Bytes(pop.public_key.to_vec()));
            header_map.insert(109, Value::Bytes(pop_sig.as_bytes().to_vec()));
            let (rho_raw, rho_commit) = derive_rho_from_pop(pop_sig.as_bytes(), &xk_hash)?;
            (rho_raw, rho_commit)
        }
        None => {
            header_map.remove(&107);
            header_map.remove(&108);
            header_map.remove(&109);
            let mut rho = [0u8; 32];
            OsRng.fill_bytes(&mut rho);
            let rho_commit = hash_bytes_with_label(ds::MSPHF_KGEN_RHO, &rho)?;
            (rho, rho_commit)
        }
    };

    header_map.insert(93, Value::Bytes(rho_commit.to_vec()));

    let fields = SeedCommitFields {
        gid: parts.gid,
        cat: parts.cat,
        we_epoch_id,
    };
    let seed_commit = compute_seed_commit(&anchor_seed_ctx, &fields)?;
    let parent_root_arr: [u8; 32] = parts
        .parent_root
        .try_into()
        .map_err(|_| MsphfError::invalid_input("parent_root length"))?;
    let seed_bundle_commit = compute_seed_bundle_commit(
        &anchor_seed_ctx,
        &rho_commit,
        parts.gid,
        parts.cat,
        &parent_root_arr,
    )?;
    header_map.insert(94, Value::Bytes(seed_bundle_commit.to_vec()));

    // 3) Derive DRBG seed from (seed_commit, rho).
    let seed_drbg = derive_drbg_seed(&seed_commit, &rho, &xk_hash, &seed_ctx_hash)?;

    #[derive(Serialize)]
    struct SeedRef<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

    let seed_a = h_l(ds::MSPHF_KGEN_A, &SeedRef(&seed_drbg))?;
    let seed_b = h_l(ds::MSPHF_KGEN_B, &SeedRef(&seed_drbg))?;
    let (sk_a, _) = derive_branch_material(&seed_a, "branch-a")?;
    let (sk_b, _) = derive_branch_material(&seed_b, "branch-b")?;
    let _validated_witness = if let Some(bytes) = witness_bytes {
        let parsed: CanonicalWitness = ciborium::de::from_reader(bytes)
            .map_err(|_| MsphfError::Witness(WitnessValidationError::CborMalformed))?;
        Some(parsed.validate_against(&anchor_instance)?)
    } else {
        None
    };
    let full_a = rlwe_hash_full(
        &sk_a,
        "A",
        params.msphf_crs_id,
        params.params_id,
        &anchor_instance,
        &xk_hash,
    )?;
    let full_b = rlwe_hash_full(
        &sk_b,
        "B",
        params.msphf_crs_id,
        params.params_id,
        &anchor_instance,
        &xk_hash,
    )?;
    let capss_bundle = CapssWitnessBundle {
        branch_a: full_a.capss_witness.clone(),
        branch_b: full_b.capss_witness.clone(),
    };
    let hp_a_bytes = full_a.projective.hp_bytes().to_vec();
    let hp_b_bytes = full_b.projective.hp_bytes().to_vec();

    // 5) Epoch target (private r_Y)
    let r_y = xof32("msphf/y*", &seed_drbg);
    #[derive(Serialize)]
    struct YStar<'a> {
        #[serde(with = "serde_bytes")]
        r_y: &'a [u8],
        #[serde(with = "serde_bytes")]
        xk: &'a [u8],
        crs: &'a str,
        params: &'a str,
    }
    let xk_bytes = anchor_instance.to_cbor_bytes()?;
    let y_star = h_l(
        ds::MSPHF_YSTAR,
        &YStar {
            r_y: &r_y,
            xk: &xk_bytes,
            crs: params.msphf_crs_id,
            params: params.params_id,
        },
    )?;

    // 6) Masks
    let mask_a_material = h_branch_bytes(
        ds::MSPHF_MASK,
        "A",
        params.msphf_crs_id,
        params.params_id,
        &[full_a.y_full.as_ref()],
    )?;
    let mask_b_material = h_branch_bytes(
        ds::MSPHF_MASK,
        "B",
        params.msphf_crs_id,
        params.params_id,
        &[full_b.y_full.as_ref()],
    )?;
    let mut m_a = [0u8; 32];
    let mut m_b = [0u8; 32];
    for i in 0..32 {
        m_a[i] = y_star[i] ^ mask_a_material[i];
        m_b[i] = y_star[i] ^ mask_b_material[i];
    }

    let mut mask_digest_a = [0u8; 32];
    mask_digest_a.copy_from_slice(blake3::hash(&mask_a_material).as_bytes());
    let mut mask_digest_b = [0u8; 32];
    mask_digest_b.copy_from_slice(blake3::hash(&mask_b_material).as_bytes());
    header_map.insert(HDR_VRF_MASK_A, Value::Bytes(mask_digest_a.to_vec()));
    header_map.insert(HDR_VRF_MASK_B, Value::Bytes(mask_digest_b.to_vec()));

    // 7) Encode hp_k artifact
    #[derive(Serialize)]
    struct HpArtifact<'a> {
        #[serde(with = "serde_bytes")]
        hp_a: &'a [u8],
        #[serde(with = "serde_bytes")]
        hp_b: &'a [u8],
        #[serde(with = "serde_bytes")]
        m_a: &'a [u8],
        #[serde(with = "serde_bytes")]
        m_b: &'a [u8],
        params_id: &'a str,
        pub(crate) hp_version: u8,
    }
    let hp_artifact = HpArtifact {
        hp_a: &hp_a_bytes,
        hp_b: &hp_b_bytes,
        m_a: &m_a,
        m_b: &m_b,
        params_id: params.params_id,
        hp_version: 1,
    };
    let hp_k = to_cbor_vec(&hp_artifact)?;
    let hp_commit = hash_bytes_with_label(ds::MSPHF_HP_COMMIT, &hp_k)?;
    let KbroadEnvelope {
        envelope: kbroad_envelope,
        c_hp: hp_ciphertext,
        k_hp: hp_aead_key,
    } = build_kbroad_envelope(&header_map, &hp_k, &xk_hash, &hp_commit)?;
    header_map.insert(HDR_HP_BYTES, kbroad_envelope);

    // 8) Epoch key and eid
    let epoch_key = epoch_key(&anchor_instance, &y_star)?;
    let eid = eid_from_epoch(&epoch_key)?;

    let proof_inputs = HpBindingInputs {
        msphf_crs_id: params.msphf_crs_id,
        params_id: params.params_id,
        seed_ctx_hash: &seed_ctx_hash,
        seed_commit: &seed_commit,
        rho_commit: &rho_commit,
        xk_hash: &xk_hash,
        hp_commit: &hp_commit,
    };
    let hp_proof = prove_hp_k(&proof_inputs)?;
    header_map.insert(HDR_HP_COMMIT, Value::Bytes(hp_commit.to_vec()));
    let fs_capss_inputs = capss::Inputs {
        seed_commit: &seed_commit,
        seed_bundle_commit: &seed_bundle_commit,
        rho_commit: &rho_commit,
        hp_commit: &hp_commit,
        bind: capss::BindingInputs {
            xk_hash: &xk_hash,
            crs_id: params.msphf_crs_id,
            params_id: params.params_id,
            proof_mode: params.proof_mode,
            fs_policy_version: fs_policy_version_u64,
            vrf_id: params.vrf_id,
            parent_root: parts.parent_root,
            join_delta_root: parts.join_delta_root,
            revoked_since_prev_root: parts.revoked_since_prev_root,
            revoked_root: parts.revoked_root,
            fs_epoch_commit: &fs_inputs.fs_epoch_commit,
            fs_ec: fs_inputs.fs_ec,
            fs_dev_prev_commit: &fs_inputs.fs_dev_prev_commit,
            fs_dev_commit: &fs_dev_commit,
        },
    };
    let mut fs_rng = OsRng;
    let fs_capss_proof = capss::prove(&mut fs_rng, &fs_capss_inputs)?;
    let fs_capss_bytes = fs_capss_proof.as_bytes().to_vec();

    let mut srx_commit_arr = [0u8; 32];
    if let Some(bytes) = header_map
        .get(&HDR_SRX_COMMIT)
        .and_then(|value| match value {
            Value::Bytes(bytes) if bytes.len() == 32 => Some(bytes.as_slice()),
            _ => None,
        })
    {
        srx_commit_arr.copy_from_slice(bytes);
    }
    let vrf_secret_payload = match params.vrf_secret_key {
        Some(key) => key,
        None => {
            return Err(MsphfError::invalid_input(
                "lb-vrf secret key payload required",
            ));
        }
    };

    let vrf_public_payload =
        zk_vrf::zk_vrf_impl::public_for_epoch(vrf_secret_payload, &we_epoch_id)
            .map_err(MsphfError::invalid_input)?;

    // Extract SRX root when present (field #160)
    let srx_root_sw_bytes = header_map
        .get(&HDR_SRX_ROOT_SW)
        .and_then(|value| match value {
            Value::Bytes(bytes) if bytes.len() == 32 => Some(bytes.clone()),
            _ => None,
        });
    let srx_root_sw_arr = srx_root_sw_bytes.as_ref().map(|bytes| {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        arr
    });

    let vrf_ctx = VrfCtx {
        xk_hash: &xk_hash,
        rho_commit: &rho_commit,
        seed_bundle_commit: &seed_bundle_commit,
        crs_id: params.msphf_crs_id,
        hp_commit: &hp_commit,
        params_id: params.params_id,
        parent_root: parts.parent_root,
        join_delta_root: parts.join_delta_root,
        revoked_since_prev_root: parts.revoked_since_prev_root,
        revoked_root: parts.revoked_root,
        proof_mode: params.proof_mode,
        fs_policy_version: fs_policy_version_u64,
        meor_vrf_id: params.vrf_id,
        fs_epoch_commit: &fs_inputs.fs_epoch_commit,
        fs_ec: fs_inputs.fs_ec,
        fs_dev_prev_commit: &fs_inputs.fs_dev_prev_commit,
        fs_dev_commit: &fs_dev_commit,
        srx_root_sw: srx_root_sw_arr.as_ref(),
        we_epoch_id: &we_epoch_id,
    };
    let vrf_proof = zk_vrf::zk_vrf_impl::prove(
        vrf_secret_payload,
        &vrf_ctx,
        (&mask_digest_a, &mask_digest_b),
    )
    .map_err(MsphfError::invalid_input)?;
    let vrf_pi_bytes = vrf_proof.bytes.clone();
    let srx_smallwood_bytes = header_map
        .get(&HDR_SRX_SMALLWOOD)
        .and_then(|value| match value {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        });
    let proofs_commit = compute_proofs_commit_bytes(
        &vrf_pi_bytes,
        &fs_capss_bytes,
        srx_root_sw_bytes.as_deref(),
        srx_smallwood_bytes.as_deref(),
    )?;
    header_map.insert(HDR_FS_CAPSS, Value::Bytes(fs_capss_bytes.clone()));
    header_map.insert(HDR_VRF_PROOF, Value::Bytes(vrf_pi_bytes.clone()));
    header_map.insert(HDR_VRF_PUBLIC_KEY, Value::Bytes(vrf_public_payload));
    header_map.insert(HDR_PROOF_MODE, Value::Text(params.proof_mode.to_string()));
    header_map.insert(HDR_VRF_ID, Value::Text(params.vrf_id.to_string()));
    header_map.insert(HDR_PROOFS_COMMIT, Value::Bytes(proofs_commit.to_vec()));

    Ok(JoinerKGenResult {
        hp_k,
        hp_ciphertext,
        hp_commit,
        hp_aead_key,
        seed_ctx_hash,
        seed_commit,
        seed_bundle_commit,
        rho_commit,
        xk_hash,
        we_epoch_id,
        epoch_key,
        eid,
        anchor_hdr_ctx,
        retired_heads,
        mh_note,
        hp_proof,
        header_map,
        capss_witness: capss_bundle,
        fs_epoch_secret,
        fs_tau,
    })
}

pub fn joiner_kgen_merge_or_with_state<'a>(
    mut header_map: BTreeMap<u64, Value>,
    retired_parities: &[PivotParity],
    note: Option<&str>,
    parts: AnchorInstanceParts<'a>,
    params: OrchestrationParams<'a>,
    forward_state: Option<&mut ForwardSecrecyState>,
    witness_bytes: Option<&[u8]>,
) -> Result<JoinerKGenResult, MsphfError> {
    if retired_parities.is_empty() {
        return Err(MsphfError::invalid_input("merge requires parity"));
    }

    let mut retired_heads: Vec<[u8; 32]> = retired_parities.iter().map(|p| p.we_epoch_id).collect();
    retired_heads.sort();
    if !is_sorted_unique(&retired_heads) {
        return Err(MsphfError::invalid_input("merge heads must be distinct"));
    }

    set_merge_heads(&mut header_map, &retired_heads, note)?;
    let mut result = joiner_kgen_or(
        header_map,
        parts.clone(),
        params.clone(),
        forward_state,
        witness_bytes,
    )?;

    let fs_policy_version = parse_fs_policy_version(params.fs_policy_version)?;
    let fs_base_ts = params.fs_epoch_base_ts;
    result.header_map.insert(
        HDR_FS_POLICY_VERSION,
        Value::Integer(Integer::from(fs_policy_version)),
    );
    result.header_map.insert(
        HDR_FS_EPOCH_BASE_TS,
        Value::Integer(Integer::from(fs_base_ts)),
    );

    let max_fs_ec = retired_parities
        .iter()
        .filter_map(|parity| parity.fs_ec)
        .max()
        .ok_or_else(|| MsphfError::invalid_input("retired parity missing fs_ec"))?;
    result.header_map.insert(
        HDR_FS_CHECKPOINT_EC,
        Value::Integer(Integer::from(max_fs_ec)),
    );
    result
        .header_map
        .insert(HDR_FS_EVOLUTION_BOUNDARY, Value::Bool(true));
    result
        .header_map
        .insert(HDR_ROLLUP_FS_MODE, Value::Text("fs-purge".to_string()));

    if let Some(fs_merge) = params.fs_merge.fs_purge_times {
        let value = Value::Map(vec![
            (
                Value::Text("purge_ts".to_string()),
                Value::Integer(Integer::from(fs_merge.0)),
            ),
            (
                Value::Text("grace_end_ts".to_string()),
                Value::Integer(Integer::from(fs_merge.1)),
            ),
        ]);
        result.header_map.insert(HDR_FS_PURGE_TIMES, value);
    } else {
        result.header_map.remove(&HDR_FS_PURGE_TIMES);
    }

    for key in [
        HDR_HP_BYTES,
        HDR_HP_COMMIT,
        HDR_POP_ALG,
        HDR_POP_SIG,
        HDR_BARRIER_LEAF_PK,
    ] {
        result.header_map.remove(&key);
    }
    let pop_keys = params
        .pop_keys
        .as_ref()
        .ok_or_else(|| MsphfError::invalid_input("merge requires pop_public_key"))?;
    result
        .header_map
        .insert(HDR_POP_PK, Value::Bytes(pop_keys.public_key.to_vec()));

    let pivot = select_pivot_parity(retired_parities)?;
    ensure_merge_domain(retired_parities, pivot)?;

    let parity_lookup: BTreeMap<_, _> = retired_parities
        .iter()
        .map(|parity| (parity.we_epoch_id, parity))
        .collect();

    result.header_map.insert(
        HDR_ROLLUP_PIVOT_WEID,
        Value::Bytes(pivot.we_epoch_id.to_vec()),
    );

    let mut epoch_replay_values = Vec::with_capacity(retired_heads.len());
    let mut provenance_values = Vec::with_capacity(retired_heads.len());
    let mut vck_values = Vec::with_capacity(retired_heads.len());

    for head in &retired_heads {
        let parity = parity_lookup
            .get(head)
            .copied()
            .ok_or_else(|| MsphfError::invalid_input("missing retired parity"))?;
        epoch_replay_values.push(Value::Array(vec![
            Value::Bytes(head.to_vec()),
            Value::Bytes(parity.xk_hash.to_vec()),
            Value::Array(vec![
                Value::Bytes(parity.parent_root.to_vec()),
                Value::Bytes(parity.join_delta_root.to_vec()),
                Value::Bytes(parity.revoked_since_root.to_vec()),
                Value::Bytes(parity.revoked_root.to_vec()),
            ]),
            Value::Bool(parity.is_join),
        ]));
        let vck = parity.compute_vck()?;
        provenance_values.push(Value::Array(vec![
            Value::Bytes(head.to_vec()),
            Value::Bytes(vck.to_vec()),
            Value::Bytes(parity.xk_hash.to_vec()),
        ]));
        vck_values.push(Value::Bytes(vck.to_vec()));
    }

    result
        .header_map
        .insert(HDR_ROLLUP_EPOCH_REPLAY, Value::Array(epoch_replay_values));
    let is_fs_purge = matches!(
        result
            .header_map
            .get(&HDR_ROLLUP_FS_MODE)
            .and_then(|value| value.as_text()),
        Some(mode) if mode == "fs-purge"
    );
    if is_fs_purge {
        result.header_map.remove(&HDR_KBROAD_REPLAY);
        for key in [HDR_BOOTSTRAP_ALG, HDR_BOOTSTRAP_PK, HDR_BOOTSTRAP_SIG] {
            result.header_map.remove(&key);
        }
    }

    let provenance_value = Value::Array(provenance_values);
    let mut provenance_buf = Vec::new();
    into_writer(&provenance_value, &mut provenance_buf)
        .map_err(|_| MsphfError::invalid_input("rollup provenance encoding"))?;
    let provenance_commit = h_l("msphf/rollup/prov", &RollupCommit(&provenance_buf))?;
    result.header_map.insert(
        HDR_ROLLUP_PROVENANCE_COMMIT,
        Value::Bytes(provenance_commit.to_vec()),
    );

    let vck_value = Value::Array(vck_values);
    let mut vck_buf = Vec::new();
    into_writer(&vck_value, &mut vck_buf)
        .map_err(|_| MsphfError::invalid_input("rollup vck encoding"))?;
    let vck_commit = h_l("msphf/rollup/vck", &RollupCommit(&vck_buf))?;
    result
        .header_map
        .insert(HDR_ROLLUP_VCK_COMMIT, Value::Bytes(vck_commit.to_vec()));

    let revoked_since_root_new =
        to_array32("revoked_since_prev_root", parts.revoked_since_prev_root)?;
    let revoked_root_new = to_array32("revoked_root", parts.revoked_root)?;
    let requires_srx = revoked_since_root_new != pivot.revoked_since_root
        || revoked_root_new != pivot.revoked_root;
    let srx_root_sw_before = pivot.srx_root_sw.unwrap_or_else(default_srx_empty_root_sw);
    if requires_srx {
        populate_merge_srx(&mut result.header_map, &parts, &params, &srx_root_sw_before)?;
    } else {
        for key in [
            HDR_SRX_COMMIT,
            HDR_SRX_PAYLOAD,
            HDR_SRX_ROOT_SW,
            HDR_SRX_SMALLWOOD,
            // Clear legacy SRX keys as defense-in-depth.
            HDR_SRX_MODE,
            HDR_SRX_HINT_COUNTS,
            HDR_SRX_HINT_SIZES,
        ] {
            result.header_map.remove(&key);
        }
    }
    if requires_srx
        && ![
            HDR_SRX_COMMIT,
            HDR_SRX_PAYLOAD,
            HDR_SRX_ROOT_SW,
            HDR_SRX_SMALLWOOD,
        ]
        .into_iter()
        .all(|key| result.header_map.contains_key(&key))
    {
        return Err(MsphfError::invalid_input("merge requires srx"));
    }

    result.retired_heads = Some(retired_heads);
    result.mh_note = note.map(|s| s.to_string());

    result
        .header_map
        .insert(93, Value::Bytes(pivot.rho_commit.to_vec()));

    let anchor_seed_ctx = build_anchor_seed_ctx(&result.header_map)?;
    let seed_ctx_hash = compute_seed_ctx_hash(&anchor_seed_ctx)?;
    result
        .header_map
        .insert(91, Value::Bytes(seed_ctx_hash.to_vec()));

    let mut parent_root_arr = [0u8; 32];
    parent_root_arr.copy_from_slice(parts.parent_root);
    let seed_bundle = compute_seed_bundle_commit(
        &anchor_seed_ctx,
        &pivot.rho_commit,
        parts.gid,
        parts.cat,
        &parent_root_arr,
    )?;
    result
        .header_map
        .insert(94, Value::Bytes(seed_bundle.to_vec()));

    let derived_weid = derive_we_epoch_id(parts.gid, parts.parent_root, &seed_ctx_hash)?;
    result.we_epoch_id = derived_weid;

    let seed_commit = compute_seed_commit(
        &anchor_seed_ctx,
        &SeedCommitFields {
            gid: parts.gid,
            cat: parts.cat,
            we_epoch_id: derived_weid,
        },
    )?;
    result.seed_commit = seed_commit;

    result
        .header_map
        .insert(HDR_HP_COMMIT, Value::Bytes(pivot.hp_commit.to_vec()));
    let pivot_fs_policy_version = parse_fs_policy_version(pivot.policy_version.as_str())?;
    result.header_map.insert(
        HDR_FS_POLICY_VERSION,
        Value::Integer(Integer::from(pivot_fs_policy_version)),
    );
    result
        .header_map
        .insert(HDR_PROOF_MODE, Value::Text(pivot.proof_mode.clone()));
    result
        .header_map
        .insert(HDR_VRF_ID, Value::Text(pivot.vrf_id.clone()));
    result
        .header_map
        .insert(HDR_VRF_MASK_A, Value::Bytes(pivot.mask_a.to_vec()));
    result
        .header_map
        .insert(HDR_VRF_MASK_B, Value::Bytes(pivot.mask_b.to_vec()));
    result
        .header_map
        .insert(HDR_VRF_PUBLIC_KEY, Value::Bytes(pivot.vrf_public.clone()));
    result
        .header_map
        .insert(HDR_VRF_PROOF, Value::Bytes(pivot.vrf_proof.clone()));
    result
        .header_map
        .insert(HDR_FS_CAPSS, Value::Bytes(pivot.fs_capss.clone()));

    let srx_root_sw_bytes = result
        .header_map
        .get(&HDR_SRX_ROOT_SW)
        .and_then(|value| match value {
            Value::Bytes(bytes) if bytes.len() == 32 => Some(bytes.as_slice()),
            _ => None,
        });
    let srx_smallwood_bytes =
        result
            .header_map
            .get(&HDR_SRX_SMALLWOOD)
            .and_then(|value| match value {
                Value::Bytes(bytes) => Some(bytes.as_slice()),
                _ => None,
            });
    let proofs_commit = compute_proofs_commit_bytes(
        pivot.vrf_proof.as_slice(),
        pivot.fs_capss.as_slice(),
        srx_root_sw_bytes,
        srx_smallwood_bytes,
    )?;
    result
        .header_map
        .insert(HDR_PROOFS_COMMIT, Value::Bytes(proofs_commit.to_vec()));

    let anchor_instance = AnchorInstance {
        gid: parts.gid,
        cat: parts.cat,
        we_epoch_id: derived_weid,
        anchor_hdr_ctx: anchor_seed_ctx.as_slice(),
        tswe_salt_hash: parts.tswe_salt_hash,
        parent_root: parts.parent_root,
        join_delta_root: parts.join_delta_root,
        revoked_since_prev_root: parts.revoked_since_prev_root,
        revoked_root: parts.revoked_root,
        pox_r_commit: parts.pox_r_commit,
        msphf_hp_commit: None,
    };
    let xk_hash = anchor_instance.xk_hash()?;

    result.anchor_hdr_ctx = anchor_seed_ctx;
    result.seed_ctx_hash = seed_ctx_hash;
    result.seed_bundle_commit = seed_bundle;
    result.rho_commit = pivot.rho_commit;
    result.xk_hash = xk_hash;
    result.epoch_key = [0u8; 32];
    result.eid = [0u8; 32];

    result.hp_commit = pivot.hp_commit;
    result.capss_witness = CapssWitnessBundle::default();

    Ok(result)
}

pub fn joiner_kgen_merge_or<'a>(
    header_map: BTreeMap<u64, Value>,
    retired_parities: &[PivotParity],
    note: Option<&str>,
    parts: AnchorInstanceParts<'a>,
    params: OrchestrationParams<'a>,
    witness_bytes: Option<&[u8]>,
) -> Result<JoinerKGenResult, MsphfError> {
    joiner_kgen_merge_or_with_state(
        header_map,
        retired_parities,
        note,
        parts,
        params,
        None,
        witness_bytes,
    )
}

pub fn joiner_kgen_merge_from_acceptances<'a>(
    header_map: BTreeMap<u64, Value>,
    retired_acceptances: &[AnchorAcceptanceResult],
    note: Option<&str>,
    parts: AnchorInstanceParts<'a>,
    params: OrchestrationParams<'a>,
    witness_bytes: Option<&[u8]>,
) -> Result<JoinerKGenResult, MsphfError> {
    if retired_acceptances.is_empty() {
        return Err(MsphfError::invalid_input("merge requires heads"));
    }
    let mut parities: Vec<PivotParity> = Vec::with_capacity(retired_acceptances.len());
    for acceptance in retired_acceptances {
        match &acceptance.outcome.kind {
            AcceptanceKind::NonMerge => parities.push(acceptance.pivot_parity.clone()),
            AcceptanceKind::Merge { .. } => {
                return Err(MsphfError::invalid_input(
                    "cannot retire merge acceptance outcome",
                ));
            }
        }
    }
    joiner_kgen_merge_or(header_map, &parities, note, parts, params, witness_bytes)
}

fn select_pivot_parity(parities: &[PivotParity]) -> Result<&PivotParity, MsphfError> {
    parities
        .iter()
        .max_by(|a, b| {
            a.accept_seq
                .cmp(&b.accept_seq)
                .then_with(|| b.xk_hash.cmp(&a.xk_hash))
        })
        .ok_or_else(|| MsphfError::invalid_input("merge requires parity"))
}

fn ensure_merge_domain(parities: &[PivotParity], pivot: &PivotParity) -> Result<(), MsphfError> {
    for parity in parities {
        if parity.parent_root != pivot.parent_root
            || parity.gid != pivot.gid
            || parity.cat != pivot.cat
        {
            return Err(MsphfError::invalid_input("merge parity mismatch"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn extract_epoch_msphf_or_impl<'a>(
    instance: &AnchorInstance<'a>,
    expected_xk_hash: &[u8; 32],
    hp_ciphertext: &[u8],
    hp_key: &[u8; 32],
    proof: &HpProof,
    binding_inputs: &HpBindingInputs<'_>,
    witness: &[u8],
    verify_proof: bool,
) -> Result<[u8; 32], MsphfError> {
    let computed_hash = instance.xk_hash()?;
    if &computed_hash != expected_xk_hash {
        return Err(MsphfError::invalid_input("xk_hash mismatch"));
    }

    if hp_ciphertext.len() > MAX_HP_BYTES + AEAD_TAG_LEN {
        return Err(MsphfError::invalid_input("hp_k too large"));
    }

    if verify_proof {
        verify_hp_k(binding_inputs, proof)?;
    }

    let anchor_commit = instance
        .msphf_hp_commit
        .ok_or_else(|| MsphfError::invalid_input("missing msphf_hp_commit"))?;
    let anchor_commit_arr: &[u8; 32] = anchor_commit
        .try_into()
        .map_err(|_| MsphfError::invalid_input("msphf_hp_commit length"))?;
    let hp_plain = decrypt_hp_bytes(hp_ciphertext, expected_xk_hash, anchor_commit_arr, hp_key)?;
    let computed_commit = hash_bytes_with_label(ds::MSPHF_HP_COMMIT, &hp_plain)?;
    if anchor_commit_arr != binding_inputs.hp_commit || &computed_commit != binding_inputs.hp_commit
    {
        return Err(MsphfError::invalid_input("msphf_hp_commit mismatch"));
    }

    let validated_witness = parse_validated_witness(instance, witness)?;
    let mode = validated_witness
        .as_ref()
        .map(|w| w.mode)
        .unwrap_or(WitnessMode::A);

    let artifact: HpArtifactOwned = ciborium::de::from_reader(hp_plain.as_slice())
        .map_err(|_| MsphfError::Witness(WitnessValidationError::CborMalformed))?;
    if artifact.hp_version != 1 {
        return Err(MsphfError::invalid_input("unsupported hp_version"));
    }

    let hp_a = artifact.hp_a.clone();
    let hp_b = artifact.hp_b.clone();
    let m_a: [u8; 32] = artifact
        .m_a
        .as_slice()
        .try_into()
        .map_err(|_| MsphfError::invalid_input("mask length"))?;
    let m_b: [u8; 32] = artifact
        .m_b
        .as_slice()
        .try_into()
        .map_err(|_| MsphfError::invalid_input("mask length"))?;
    if artifact.params_id.is_empty() {
        return Err(MsphfError::invalid_input("missing params_id"));
    }

    let pp_a = RlweProjectiveParams::new(hp_a);
    let pp_b = RlweProjectiveParams::new(hp_b);

    let (branch, mask_bytes, params) = match mode {
        WitnessMode::A => ("A", &m_a, &pp_a),
        WitnessMode::B => ("B", &m_b, &pp_b),
    };
    let crs_id = binding_inputs.msphf_crs_id;
    let params_id = binding_inputs.params_id;
    let y_proj = rlwe_hash_proj(
        params,
        branch,
        crs_id,
        params_id,
        instance,
        validated_witness.as_ref(),
    )?;
    let mask_material = h_branch_bytes(
        ds::MSPHF_MASK,
        branch,
        crs_id,
        params_id,
        &[y_proj.as_ref()],
    )?;
    let mut y_star = [0u8; 32];
    for i in 0..32 {
        y_star[i] = mask_bytes[i] ^ mask_material[i];
    }

    epoch_key(instance, &y_star)
}

fn parse_validated_witness(
    instance: &AnchorInstance<'_>,
    witness_bytes: &[u8],
) -> Result<Option<ValidatedWitness>, MsphfError> {
    if witness_bytes.is_empty() {
        return Ok(None);
    }
    let canonical: CanonicalWitness = ciborium::de::from_reader(witness_bytes)
        .map_err(|_| MsphfError::Witness(WitnessValidationError::CborMalformed))?;
    Ok(Some(canonical.validate_against(instance)?))
}

pub fn extract_epoch_msphf_or<'a>(
    instance: &AnchorInstance<'a>,
    expected_xk_hash: &[u8; 32],
    hp_ciphertext: &[u8],
    hp_key: &[u8; 32],
    proof: &HpProof,
    binding_inputs: &HpBindingInputs<'_>,
    witness: &[u8],
) -> Result<[u8; 32], MsphfError> {
    extract_epoch_msphf_or_impl(
        instance,
        expected_xk_hash,
        hp_ciphertext,
        hp_key,
        proof,
        binding_inputs,
        witness,
        true,
    )
}

pub fn extract_epoch_msphf_or_preverified<'a>(
    instance: &AnchorInstance<'a>,
    expected_xk_hash: &[u8; 32],
    hp_ciphertext: &[u8],
    hp_key: &[u8; 32],
    proof: &HpProof,
    binding_inputs: &HpBindingInputs<'_>,
    witness: &[u8],
) -> Result<[u8; 32], MsphfError> {
    extract_epoch_msphf_or_impl(
        instance,
        expected_xk_hash,
        hp_ciphertext,
        hp_key,
        proof,
        binding_inputs,
        witness,
        false,
    )
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::todo,
    clippy::unimplemented
)]
mod tests {
    use super::*;
    use crate::accept::{FREEZE_HASH_NONCANONICAL, FREEZE_HASH_PATH_OVERSIZE};
    use anchor_seed::{
        SeedCommitFields, build_anchor_seed_ctx, compute_seed_ctx_hash, derive_seed_artifacts,
    };
    use blake3::Hasher;
    use ciborium::{de, ser};
    use msphf_core::WitnessValidationError;
    use msphf_core::params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK};
    use msphf_core::{
        MsphfError, ds, hash,
        merkle::{hash_interval_binding, hash_leaf, hash_node},
        witness::{
            CanonicalWitness, RawMembershipWitness, RawNonMembershipWitness, RawPathEntry,
            WitnessVariants,
        },
    };
    use pqcrypto_dilithium::dilithium5::{SecretKey as MlDsaSecretKey, detached_sign, keypair};
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
    use std::borrow::Cow;
    fn leak(bytes: [u8; 32]) -> &'static [u8] {
        Box::leak(Box::new(bytes)).as_slice()
    }
    fn sample_kbroad_keys() -> (&'static [u8], &'static [u8]) {
        super::kbroad_test_keys()
    }

    #[test]
    fn fixture_keys_load_from_external_files() {
        let (pub_bytes, sec_bytes) = super::kbroad_test_keys();
        // ML-KEM-768 public key is 1184 bytes, secret key is 2400 bytes.
        assert_eq!(pub_bytes.len(), 1184, "kbroad public key has wrong length");
        assert_eq!(sec_bytes.len(), 2400, "kbroad secret key has wrong length");
        // Idempotent: a second call returns the same slices (OnceLock).
        let (pub2, sec2) = super::kbroad_test_keys();
        assert!(std::ptr::eq(pub_bytes, pub2));
        assert!(std::ptr::eq(sec_bytes, sec2));
    }

    #[test]
    fn deterministic_lb_vrf_key_material_is_stable() {
        let (secret_a, public_a) = deterministic_lb_vrf_keys();
        let (secret_b, public_b) = deterministic_lb_vrf_keys();
        assert!(!secret_a.is_empty());
        assert!(!public_a.is_empty());
        assert_eq!(secret_a, secret_b);
        assert_eq!(public_a, public_b);
    }

    #[test]
    fn parse_merge_metadata_validates_shapes_and_note_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_MH_HEADS, Value::Text("bad".to_string()));
        assert!(parse_merge_metadata(&header).is_err());

        header.insert(hdr::HDR_MH_HEADS, Value::Array(Vec::new()));
        assert!(parse_merge_metadata(&header).is_err());

        header.insert(
            hdr::HDR_MH_HEADS,
            Value::Array(vec![Value::Integer(7u64.into())]),
        );
        assert!(parse_merge_metadata(&header).is_err());

        header.insert(
            hdr::HDR_MH_HEADS,
            Value::Array(vec![Value::Bytes(vec![0x01; 16])]),
        );
        assert!(parse_merge_metadata(&header).is_err());

        header.insert(
            hdr::HDR_MH_HEADS,
            Value::Array(vec![
                Value::Bytes(vec![0x22; 32]),
                Value::Bytes(vec![0x11; 32]),
            ]),
        );
        assert!(parse_merge_metadata(&header).is_err());

        header.insert(
            hdr::HDR_MH_HEADS,
            Value::Array(vec![Value::Bytes(vec![0x33; 32])]),
        );
        header.insert(102, Value::Integer(1u64.into()));
        assert!(parse_merge_metadata(&header).is_err());

        header.insert(102, Value::Text("merge-note".to_string()));
        let (heads, note) = parse_merge_metadata(&header)?;
        assert_eq!(heads.expect("heads should parse").len(), 1);
        assert_eq!(note.as_deref(), Some("merge-note"));

        let mut no_heads = BTreeMap::new();
        no_heads.insert(102, Value::Text("ignored".to_string()));
        let (heads, note) = parse_merge_metadata(&no_heads)?;
        assert!(heads.is_none());
        assert!(note.is_none());

        Ok(())
    }

    #[test]
    fn kbroad_build_and_recover_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let (kbroad_pub, kbroad_sec) = sample_kbroad_keys();
        let mut header = BTreeMap::new();
        header.insert(HDR_KBROAD_ALG, Value::Text(KBROAD_ML_KEM_ALG.to_string()));
        header.insert(HDR_KBROAD_PUB, Value::Bytes(kbroad_pub.to_vec()));

        let xk_hash = [0x41; 32];
        let hp_commit = [0x52; 32];
        let hp_plaintext = b"hp/plaintext/regression";

        let envelope = build_kbroad_envelope(&header, hp_plaintext, &xk_hash, &hp_commit)?;
        header.insert(HDR_HP_BYTES, envelope.envelope.clone());

        let (hp_ciphertext, hp_key) =
            recover_hp_material_from_header(&header, &xk_hash, &hp_commit, kbroad_sec)?;
        assert_eq!(hp_ciphertext, envelope.c_hp);
        assert_eq!(hp_key, envelope.k_hp);

        let recovered_hp = decrypt_hp_bytes(&hp_ciphertext, &xk_hash, &hp_commit, &hp_key)?;
        assert_eq!(recovered_hp, hp_plaintext);
        Ok(())
    }

    #[test]
    fn crypto_helpers_cover_nonce_and_ciphertext_error_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = [0x11; 32];
        let xk_hash = [0x22; 32];
        let hp_commit = [0x33; 32];
        let plaintext = b"helper-regression";

        let (rho_raw, rho_commit) = derive_rho_from_pop(&[0x41; 32], &xk_hash)?;
        assert_ne!(rho_raw, [0u8; 32]);
        assert_ne!(rho_commit, [0u8; 32]);

        let hp_nonce = derive_hp_nonce(&xk_hash, &hp_commit)?;
        let kek_nonce = derive_kek_nonce(&xk_hash, &hp_commit)?;
        assert_ne!(hp_nonce.as_slice(), kek_nonce.as_slice());

        let ciphertext = encrypt_hp_bytes(plaintext, &xk_hash, &hp_commit, &key)?;
        assert_eq!(
            decrypt_hp_bytes(&ciphertext, &xk_hash, &hp_commit, &key)?,
            plaintext
        );

        assert!(
            encrypt_hp_bytes(&vec![0x55; MAX_HP_BYTES + 1], &xk_hash, &hp_commit, &key).is_err()
        );
        assert!(decrypt_hp_bytes(&[0x00; AEAD_TAG_LEN - 1], &xk_hash, &hp_commit, &key).is_err());
        let mut wrong_key = key;
        wrong_key[0] ^= 0x01;
        assert!(decrypt_hp_bytes(&ciphertext, &xk_hash, &hp_commit, &wrong_key).is_err());

        Ok(())
    }

    #[test]
    fn srx_anchor_helpers_cover_serialization_and_index_matrix()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = RawPathEntry {
            sibling: vec![0xAA; 32],
            dir: 1,
        };
        let serialized_path = serialize_path_entry(&path);
        assert!(matches!(serialized_path, Value::Map(_)));
        assert_eq!(
            optional_bytes_value(&Some(vec![0x11, 0x22])),
            Value::Bytes(vec![0x11, 0x22])
        );
        assert_eq!(optional_bytes_value(&None), Value::Null);

        let base_anchor = SrxNonMembershipAnchor {
            witness: RawNonMembershipWitness {
                query: vec![0x01; 32],
                root: vec![0x02; 32],
                left: Some(vec![0x03; 32]),
                right: Some(vec![0x04; 32]),
                path: vec![path.clone()],
                left_below: vec![path.clone()],
                right_below: vec![path.clone()],
                above: vec![path.clone()],
                nmint: None,
                lca_left_height: Some(1),
                lca_right_height: Some(1),
            },
            left_ref: Some(0),
            right_ref: Some(0),
        };
        serialize_nonmem_anchor(&base_anchor)?;
        validate_anchor_indices(&base_anchor, 1)?;

        let mut missing_left_ref = base_anchor.clone();
        missing_left_ref.left_ref = None;
        assert!(validate_anchor_indices(&missing_left_ref, 1).is_err());

        let mut unexpected_left_ref = base_anchor.clone();
        unexpected_left_ref.witness.left = None;
        unexpected_left_ref.left_ref = Some(0);
        assert!(validate_anchor_indices(&unexpected_left_ref, 1).is_err());

        let mut missing_right_ref = base_anchor.clone();
        missing_right_ref.right_ref = None;
        assert!(validate_anchor_indices(&missing_right_ref, 1).is_err());

        let mut unexpected_right_ref = base_anchor.clone();
        unexpected_right_ref.witness.right = None;
        unexpected_right_ref.right_ref = Some(0);
        assert!(validate_anchor_indices(&unexpected_right_ref, 1).is_err());

        let mut left_oob = base_anchor.clone();
        left_oob.left_ref = Some(2);
        assert!(validate_anchor_indices(&left_oob, 1).is_err());

        let mut right_oob = base_anchor;
        right_oob.right_ref = Some(2);
        assert!(validate_anchor_indices(&right_oob, 1).is_err());
        Ok(())
    }

    #[test]
    fn kbroad_envelope_and_recovery_error_matrix() -> Result<(), Box<dyn std::error::Error>> {
        let (kbroad_pub, kbroad_sec) = sample_kbroad_keys();
        let xk_hash = [0x31; 32];
        let hp_commit = [0x42; 32];
        let hp_plaintext = b"kbroad-regression";

        let mut base = BTreeMap::new();
        base.insert(HDR_KBROAD_ALG, Value::Text(KBROAD_ML_KEM_ALG.to_string()));
        base.insert(HDR_KBROAD_PUB, Value::Bytes(kbroad_pub.to_vec()));
        let built = build_kbroad_envelope(&base, hp_plaintext, &xk_hash, &hp_commit)?;
        base.insert(HDR_HP_BYTES, built.envelope.clone());
        assert!(recover_hp_material_from_header(&base, &xk_hash, &hp_commit, kbroad_sec).is_ok());

        let mut bad_alg_type = base.clone();
        bad_alg_type.insert(HDR_KBROAD_ALG, Value::Integer(Integer::from(7u64)));
        assert!(build_kbroad_envelope(&bad_alg_type, hp_plaintext, &xk_hash, &hp_commit).is_err());

        let mut bad_alg_value = base.clone();
        bad_alg_value.insert(HDR_KBROAD_ALG, Value::Text("wrong".to_string()));
        assert!(build_kbroad_envelope(&bad_alg_value, hp_plaintext, &xk_hash, &hp_commit).is_err());

        let mut bad_pub_type = base.clone();
        bad_pub_type.insert(HDR_KBROAD_PUB, Value::Text("wrong".to_string()));
        assert!(build_kbroad_envelope(&bad_pub_type, hp_plaintext, &xk_hash, &hp_commit).is_err());

        let mut bad_pub_len = base.clone();
        bad_pub_len.insert(HDR_KBROAD_PUB, Value::Bytes(vec![0x22; 8]));
        assert!(build_kbroad_envelope(&bad_pub_len, hp_plaintext, &xk_hash, &hp_commit).is_err());

        let base_items = built
            .envelope
            .as_array()
            .cloned()
            .expect("kbroad envelope must be array");
        let run_recover_case = |items: Vec<Value>| {
            let mut header = base.clone();
            header.insert(HDR_HP_BYTES, Value::Array(items));
            recover_hp_material_from_header(&header, &xk_hash, &hp_commit, kbroad_sec).is_err()
        };

        assert!(run_recover_case(vec![]));
        assert!({
            let mut header = base.clone();
            header.insert(HDR_HP_BYTES, Value::Map(Vec::new()));
            recover_hp_material_from_header(&header, &xk_hash, &hp_commit, kbroad_sec).is_err()
        });

        let mut mode_utf8 = base_items.clone();
        mode_utf8[0] = Value::Bytes(vec![0xFF]);
        assert!(run_recover_case(mode_utf8));

        let mut wrong_mode = base_items.clone();
        wrong_mode[0] = Value::Text("mode-x".to_string());
        assert!(run_recover_case(wrong_mode));

        let mut bad_ct_type = base_items.clone();
        bad_ct_type[1] = Value::Integer(Integer::from(1u64));
        assert!(run_recover_case(bad_ct_type));

        let mut bad_ct_len = base_items.clone();
        bad_ct_len[1] = Value::Bytes(vec![0u8; 8]);
        assert!(run_recover_case(bad_ct_len));

        let mut bad_wrap_type = base_items.clone();
        bad_wrap_type[2] = Value::Null;
        assert!(run_recover_case(bad_wrap_type));

        let mut bad_wrap_len = base_items.clone();
        bad_wrap_len[2] = Value::Bytes(vec![0u8; 8]);
        assert!(run_recover_case(bad_wrap_len));

        let mut bad_cipher_type = base_items.clone();
        bad_cipher_type[3] = Value::Bool(true);
        assert!(run_recover_case(bad_cipher_type));

        let mut bad_cipher_len = base_items.clone();
        bad_cipher_len[3] = Value::Bytes(Vec::new());
        assert!(run_recover_case(bad_cipher_len));

        let mut bad_aead_utf8 = base_items.clone();
        bad_aead_utf8[4] = Value::Bytes(vec![0xFF]);
        assert!(run_recover_case(bad_aead_utf8));

        let mut bad_aead = base_items.clone();
        bad_aead[4] = Value::Text("aes-gcm".to_string());
        assert!(run_recover_case(bad_aead));

        assert!(recover_hp_material_from_header(&base, &xk_hash, &hp_commit, &[0u8; 12]).is_err());
        Ok(())
    }

    #[test]
    fn joiner_kgen_popless_and_optional_srx_matrix() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let mut params = fixture.params();
        params.pop_keys = None;

        let missing_pk_err = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            params.clone(),
            None,
            Some(fixture.witness.as_slice()),
        )
        .expect_err("missing POP public key must fail");
        assert!(format!("{missing_pk_err:?}").contains("fs_join requires pop_public_key"));

        let mut bad_tswe_header = sample_header();
        bad_tswe_header.insert(90, Value::Bytes(b"wrong-tswe".to_vec()));
        let (pop_pk_bad_tswe, _) = crate::accept::fixtures::sample_pop_keys();
        bad_tswe_header.insert(HDR_POP_PK, Value::Bytes(pop_pk_bad_tswe));
        let bad_tswe_err = joiner_kgen_or(
            bad_tswe_header,
            fixture.parts.clone(),
            params.clone(),
            None,
            Some(fixture.witness.as_slice()),
        )
        .expect_err("bad tswe bytes must fail");
        assert!(format!("{bad_tswe_err:?}").contains("tswe_alg mismatch"));

        let mut bad_crs_header = sample_header();
        let (pop_pk_bad_crs, _) = crate::accept::fixtures::sample_pop_keys();
        bad_crs_header.insert(HDR_POP_PK, Value::Bytes(pop_pk_bad_crs));
        bad_crs_header.insert(98, Value::Bytes(b"wrong-crs".to_vec()));
        let bad_crs_err = joiner_kgen_or(
            bad_crs_header,
            fixture.parts.clone(),
            params.clone(),
            None,
            Some(fixture.witness.as_slice()),
        )
        .expect_err("bad crs bytes must fail");
        assert!(format!("{bad_crs_err:?}").contains("msphf_crs_id mismatch"));

        let mut valid_header = sample_header();
        let (pop_pk, _) = crate::accept::fixtures::sample_pop_keys();
        valid_header.insert(HDR_POP_PK, Value::Bytes(pop_pk));
        valid_header.insert(90, Value::Bytes(TSWE_ALG_LABEL.as_bytes().to_vec()));
        valid_header.insert(98, Value::Bytes(params.msphf_crs_id.as_bytes().to_vec()));
        valid_header.insert(HDR_SRX_COMMIT, Value::Bytes([0x41; 32].to_vec()));
        valid_header.insert(HDR_SRX_ROOT_SW, Value::Bytes([0x51; 32].to_vec()));
        valid_header.insert(HDR_SRX_SMALLWOOD, Value::Bytes(vec![0x61, 0x62]));
        let result = joiner_kgen_or(
            valid_header,
            fixture.parts.clone(),
            params.clone(),
            None,
            Some(fixture.witness.as_slice()),
        )?;
        assert!(!result.header_map.contains_key(&HDR_POP_ALG));
        assert!(!result.header_map.contains_key(&HDR_POP_PK));
        assert!(!result.header_map.contains_key(&HDR_POP_SIG));

        let mut text_tswe_header = sample_header();
        let (pop_pk_text_tswe, _) = crate::accept::fixtures::sample_pop_keys();
        text_tswe_header.insert(HDR_POP_PK, Value::Bytes(pop_pk_text_tswe));
        text_tswe_header.insert(90, Value::Text(TSWE_ALG_LABEL.to_string()));
        joiner_kgen_or(
            text_tswe_header,
            fixture.parts.clone(),
            params.clone(),
            None,
            Some(fixture.witness.as_slice()),
        )?;

        let mut missing_vrf_params = params;
        missing_vrf_params.vrf_secret_key = None;
        let mut missing_vrf_header = sample_header();
        let (pop_pk_missing_vrf, _) = crate::accept::fixtures::sample_pop_keys();
        missing_vrf_header.insert(HDR_POP_PK, Value::Bytes(pop_pk_missing_vrf));
        let missing_vrf_err = joiner_kgen_or(
            missing_vrf_header,
            fixture.parts.clone(),
            missing_vrf_params,
            None,
            Some(fixture.witness.as_slice()),
        )
        .expect_err("missing VRF secret must fail");
        assert!(format!("{missing_vrf_err:?}").contains("lb-vrf secret key payload required"));
        Ok(())
    }

    #[test]
    fn joiner_kgen_with_forward_state_emits_fs_artifacts() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = sample_fixture();
        let mut state = ForwardSecrecyState::new([0x9A; 32]);
        state.set_last_we_epoch_id([0x55; 32]);
        let mut params = fixture.params();
        params.pop_keys = None;
        let (pop_pk, _) = crate::accept::fixtures::sample_pop_keys();
        let mut header = sample_header();
        header.insert(HDR_POP_PK, Value::Bytes(pop_pk));
        let result = joiner_kgen_or(
            header,
            fixture.parts.clone(),
            params,
            Some(&mut state),
            Some(fixture.witness.as_slice()),
        )?;
        assert!(result.fs_epoch_secret.is_some());
        assert!(result.fs_tau.is_some());
        Ok(())
    }

    #[test]
    fn populate_merge_srx_complete_covers_core_paths() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let parts = fixture.parts.clone();
        let params = fixture.params();
        let srx_before = default_srx_empty_root_sw();

        let mut rich_params = params.clone();
        let mut rich_srx = rich_params
            .srx
            .clone()
            .expect("fixture must include srx inputs");
        rich_srx.anchor_mem_pool = vec![RawMembershipWitness {
            leaf_id: vec![0x91; 32],
            root: vec![0x92; 32],
            path: Vec::new(),
        }];
        let bound = rich_srx.anchor_mem_pool[0].leaf_id.clone();
        if let Some(first_anchor) = rich_srx.join_nonmem_parent.first_mut() {
            first_anchor.witness.left = Some(bound.clone());
            first_anchor.left_ref = Some(0);
            first_anchor.witness.right = Some(bound);
            first_anchor.right_ref = Some(0);
        }
        rich_params.srx = Some(rich_srx);

        let mut header = BTreeMap::new();
        populate_merge_srx_complete(&mut header, &parts, &rich_params, &srx_before)?;
        assert!(header.contains_key(&HDR_SRX_COMMIT));
        assert!(header.contains_key(&HDR_SRX_PAYLOAD));
        assert!(header.contains_key(&HDR_SRX_ROOT_SW));
        assert!(header.contains_key(&HDR_SRX_SMALLWOOD));

        let mut wrong_join_root = [0u8; 32];
        wrong_join_root.copy_from_slice(parts.join_delta_root);
        wrong_join_root[0] ^= 0xFF;
        let bad_join_parts = AnchorInstanceParts {
            gid: parts.gid,
            cat: parts.cat,
            tswe_salt_hash: parts.tswe_salt_hash,
            parent_root: parts.parent_root,
            join_delta_root: &wrong_join_root,
            revoked_since_prev_root: parts.revoked_since_prev_root,
            revoked_root: parts.revoked_root,
            pox_r_commit: parts.pox_r_commit,
        };
        assert!(
            populate_merge_srx_complete(
                &mut BTreeMap::new(),
                &bad_join_parts,
                &rich_params,
                &srx_before
            )
            .is_err()
        );

        let mut wrong_since_root = [0u8; 32];
        wrong_since_root.copy_from_slice(parts.revoked_since_prev_root);
        wrong_since_root[0] ^= 0x55;
        let bad_since_parts = AnchorInstanceParts {
            gid: parts.gid,
            cat: parts.cat,
            tswe_salt_hash: parts.tswe_salt_hash,
            parent_root: parts.parent_root,
            join_delta_root: parts.join_delta_root,
            revoked_since_prev_root: &wrong_since_root,
            revoked_root: parts.revoked_root,
            pox_r_commit: parts.pox_r_commit,
        };
        assert!(
            populate_merge_srx_complete(
                &mut BTreeMap::new(),
                &bad_since_parts,
                &rich_params,
                &srx_before
            )
            .is_err()
        );

        let mut frontier_params = rich_params.clone();
        let mut frontier_srx = frontier_params
            .srx
            .clone()
            .expect("fixture must include srx inputs");
        frontier_srx.join_frontier = Some(Cow::Owned(msphf_core::merkle::canonical_frontier(
            frontier_srx.join_leaf_ids.as_ref(),
        )?));
        frontier_srx.since_frontier = Some(Cow::Owned(msphf_core::merkle::canonical_frontier(
            frontier_srx.since_leaf_ids.as_ref(),
        )?));
        frontier_params.srx = Some(frontier_srx.clone());
        populate_merge_srx_complete(&mut BTreeMap::new(), &parts, &frontier_params, &srx_before)?;

        let mut bad_ref_params = frontier_params;
        let mut bad_ref_srx = bad_ref_params
            .srx
            .take()
            .expect("fixture must include srx inputs");
        if let Some(first_anchor) = bad_ref_srx.join_nonmem_parent.first_mut() {
            first_anchor.witness.left = Some(vec![0xAB; 32]);
            first_anchor.left_ref = Some(u32::MAX);
        }
        bad_ref_params.srx = Some(bad_ref_srx);
        assert!(
            populate_merge_srx_complete(&mut BTreeMap::new(), &parts, &bad_ref_params, &srx_before)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn pivot_store_and_extract_preverified_helpers_roundtrip()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = PivotParityStore::new(Duration::from_secs(30));
        assert_eq!(store.ttl(), Duration::from_secs(30));
        store.set_ttl(Duration::from_secs(10), AcceptInstant::from_ticks(5));
        assert_eq!(store.ttl(), Duration::from_secs(10));
        store.retire(b"gid", &[0u8; 32], &[]);

        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let inputs = build_inputs(&result, &result.hp_k, &result.hp_commit);
        let verified = extract_epoch_msphf_or(
            &anchor,
            &result.xk_hash,
            &result.hp_ciphertext,
            &result.hp_aead_key,
            &result.hp_proof,
            &inputs,
            &fixture.witness,
        )?;
        let preverified = extract_epoch_msphf_or_preverified(
            &anchor,
            &result.xk_hash,
            &result.hp_ciphertext,
            &result.hp_aead_key,
            &result.hp_proof,
            &inputs,
            &fixture.witness,
        )?;
        assert_eq!(verified, preverified);
        Ok(())
    }

    #[test]
    fn forward_secrecy_helper_derivations_are_stable() -> Result<(), Box<dyn std::error::Error>> {
        let weid = [0x66; 32];
        let base_key = [0x77; 32];

        let salt_a = fs_tau_salt(&weid, 1)?;
        let salt_b = fs_tau_salt(&weid, 2)?;
        assert_ne!(salt_a, salt_b);

        let sk_salt = fs_epoch_sk_salt(&weid, 1)?;
        let epoch_sk = hkdf_blake3(&sk_salt, &base_key, b"city-g|fs/epoch/sk|v1");
        let commit = fs_epoch_commit_hash(&epoch_sk)?;
        assert_ne!(commit, [0u8; 32]);

        let step_salt_a = fs_step_salt(&weid, 2)?;
        let step_salt_b = fs_step_salt(&weid, 3)?;
        assert_ne!(step_salt_a, [0u8; 32]);
        assert_ne!(step_salt_a, step_salt_b);
        let evolved_1 = evolve_k_fs(&base_key, &weid, 2)?;
        let evolved_2 = evolve_k_fs(&base_key, &weid, 3)?;
        assert_ne!(evolved_1, evolved_2);

        Ok(())
    }

    #[test]
    fn accept_anchor_or_reports_missing_or_mismatched_commit()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )?;
        let header = header_with_pop(&result, &fixture.parts, &fixture);

        let anchor_missing_commit = AnchorInstance {
            gid: fixture.parts.gid,
            cat: fixture.parts.cat,
            we_epoch_id: result.we_epoch_id,
            anchor_hdr_ctx: &result.anchor_hdr_ctx,
            tswe_salt_hash: fixture.parts.tswe_salt_hash,
            parent_root: fixture.parts.parent_root,
            join_delta_root: fixture.parts.join_delta_root,
            revoked_since_prev_root: fixture.parts.revoked_since_prev_root,
            revoked_root: fixture.parts.revoked_root,
            pox_r_commit: fixture.parts.pox_r_commit,
            msphf_hp_commit: None,
        };
        let mut ctx = acceptance_ctx(&fixture);
        let err_missing = accept_anchor_or(&mut ctx, &anchor_missing_commit, &header)
            .expect_err("missing anchor commit must fail");
        assert!(format!("{err_missing:?}").contains("missing msphf_hp_commit"));

        let wrong_commit = [0xAB; 32];
        let anchor_wrong_commit = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &wrong_commit,
        );
        let mut ctx = acceptance_ctx(&fixture);
        let err_mismatch = accept_anchor_or(&mut ctx, &anchor_wrong_commit, &header)
            .expect_err("mismatched anchor commit must fail");
        assert!(format!("{err_mismatch:?}").contains("msphf_hp_commit mismatch"));
        Ok(())
    }

    #[test]
    fn accept_and_extract_binding_mismatch_matrix() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let header = header_with_pop(&result, &fixture.parts, &fixture);

        let check_case = |inputs: HpBindingInputs<'_>, needle: &str| {
            let mut ctx = acceptance_ctx(&fixture);
            ctx.set_pending_capss_witness(Some(result.capss_witness.clone()));
            let err = accept_and_extract_or(
                &mut ctx,
                &anchor,
                &header,
                &result.hp_proof,
                &inputs,
                &fixture.witness,
            )
            .expect_err("binding mismatch must fail");
            assert!(format!("{err:?}").contains(needle));
        };

        let mut bad_seed_ctx = result.seed_ctx_hash;
        bad_seed_ctx[0] ^= 0x01;
        check_case(
            HpBindingInputs {
                msphf_crs_id: RLWE_CRS_ID_DEFAULT,
                params_id: RLWE_PARAMS_ID_MOCK,
                seed_ctx_hash: &bad_seed_ctx,
                seed_commit: &result.seed_commit,
                rho_commit: &result.rho_commit,
                xk_hash: &result.xk_hash,
                hp_commit: &result.hp_commit,
            },
            "seed_ctx_hash mismatch",
        );

        let mut bad_seed_commit = result.seed_commit;
        bad_seed_commit[0] ^= 0x01;
        check_case(
            HpBindingInputs {
                msphf_crs_id: RLWE_CRS_ID_DEFAULT,
                params_id: RLWE_PARAMS_ID_MOCK,
                seed_ctx_hash: &result.seed_ctx_hash,
                seed_commit: &bad_seed_commit,
                rho_commit: &result.rho_commit,
                xk_hash: &result.xk_hash,
                hp_commit: &result.hp_commit,
            },
            "seed_commit mismatch",
        );

        let mut bad_rho_commit = result.rho_commit;
        bad_rho_commit[0] ^= 0x01;
        check_case(
            HpBindingInputs {
                msphf_crs_id: RLWE_CRS_ID_DEFAULT,
                params_id: RLWE_PARAMS_ID_MOCK,
                seed_ctx_hash: &result.seed_ctx_hash,
                seed_commit: &result.seed_commit,
                rho_commit: &bad_rho_commit,
                xk_hash: &result.xk_hash,
                hp_commit: &result.hp_commit,
            },
            "rho_commit mismatch",
        );

        let mut bad_hp_commit = result.hp_commit;
        bad_hp_commit[0] ^= 0x01;
        check_case(
            HpBindingInputs {
                msphf_crs_id: RLWE_CRS_ID_DEFAULT,
                params_id: RLWE_PARAMS_ID_MOCK,
                seed_ctx_hash: &result.seed_ctx_hash,
                seed_commit: &result.seed_commit,
                rho_commit: &result.rho_commit,
                xk_hash: &result.xk_hash,
                hp_commit: &bad_hp_commit,
            },
            "hp_commit mismatch",
        );

        let mut bad_xk_hash = result.xk_hash;
        bad_xk_hash[0] ^= 0x01;
        check_case(
            HpBindingInputs {
                msphf_crs_id: RLWE_CRS_ID_DEFAULT,
                params_id: RLWE_PARAMS_ID_MOCK,
                seed_ctx_hash: &result.seed_ctx_hash,
                seed_commit: &result.seed_commit,
                rho_commit: &result.rho_commit,
                xk_hash: &bad_xk_hash,
                hp_commit: &result.hp_commit,
            },
            "xk_hash mismatch",
        );
        Ok(())
    }

    fn sample_pivot_parity(seed_ctx_hash: [u8; 32], rho_commit: [u8; 32]) -> PivotParity {
        PivotParity {
            gid: vec![1u8; 4],
            cat: vec![2u8; 2],
            parent_root: [0u8; 32],
            we_epoch_id: [0x11; 32],
            rho_commit,
            seed_ctx_hash,
            seed_commit: [0x55; 32],
            hp_commit: [0x33; 32],
            xk_hash: [0x44; 32],
            join_delta_root: [0u8; 32],
            revoked_since_root: [0u8; 32],
            revoked_root: [0u8; 32],
            accept_seq: 7,
            crs_id: b"crs".to_vec(),
            params_id: vec![0x77; 32],
            policy_version: DEFAULT_POLICY_VERSION.to_string(),
            proof_mode: DEFAULT_PROOF_MODE.to_string(),
            vrf_id: DEFAULT_VRF_ID.to_string(),
            vrf_proof: vec![0x10],
            vrf_public: vec![0x20],
            mask_a: [0xAA; 32],
            mask_b: [0xBB; 32],
            fs_capss: vec![0x40],
            proofs_commit: [0x99; 32],
            srx_commit: None,
            srx_root_sw: None,
            is_join: true,
            hp_envelope: Arc::from([] as [u8; 0]),
            fs_epoch_commit: None,
            fs_ec: None,
            fs_dev_commit: None,
        }
    }

    fn parity_from_parts(
        parts: &AnchorInstanceParts<'_>,
        accept_seq: u64,
        we_epoch_tag: u8,
        xk_hash_tag: u8,
        rho_tag: u8,
        hp_tag: u8,
        proof_tag: u8,
    ) -> PivotParity {
        let mut parent_root = [0u8; 32];
        parent_root.copy_from_slice(parts.parent_root);
        let mask_a = [proof_tag; 32];
        let mask_b_value = proof_tag.wrapping_add(0x55);
        let mask_b = [mask_b_value; 32];
        let proofs_commit_byte = proof_tag.wrapping_add(0xA0);
        let proofs_commit = [proofs_commit_byte; 32];
        let join_delta_root =
            to_array32("join_delta_root", parts.join_delta_root).unwrap_or([0u8; 32]);
        let revoked_since_root =
            to_array32("revoked_since_prev_root", parts.revoked_since_prev_root)
                .unwrap_or([0u8; 32]);
        let revoked_root = to_array32("revoked_root", parts.revoked_root).unwrap_or([0u8; 32]);
        let mut seed_commit = [0u8; 32];
        seed_commit.fill(we_epoch_tag);
        PivotParity {
            gid: parts.gid.to_vec(),
            cat: parts.cat.to_vec(),
            parent_root,
            we_epoch_id: [we_epoch_tag; 32],
            rho_commit: [rho_tag; 32],
            seed_ctx_hash: [xk_hash_tag; 32],
            seed_commit,
            hp_commit: [hp_tag; 32],
            xk_hash: [xk_hash_tag; 32],
            join_delta_root,
            revoked_since_root,
            revoked_root,
            accept_seq,
            crs_id: b"crs".to_vec(),
            params_id: vec![0xCC; 32],
            policy_version: DEFAULT_POLICY_VERSION.to_string(),
            proof_mode: DEFAULT_PROOF_MODE.to_string(),
            vrf_id: DEFAULT_VRF_ID.to_string(),
            vrf_proof: vec![proof_tag, proof_tag.wrapping_add(1)],
            vrf_public: vec![proof_tag.wrapping_add(2)],
            mask_a,
            mask_b,
            fs_capss: vec![proof_tag.wrapping_add(4)],
            proofs_commit,
            srx_commit: Some([proof_tag; 32]),
            srx_root_sw: Some([proof_tag; 32]),
            is_join: true,
            hp_envelope: Arc::from([] as [u8; 0]),
            fs_epoch_commit: Some([rho_tag; 32]),
            fs_ec: Some(accept_seq),
            fs_dev_commit: Some([hp_tag; 32]),
        }
    }

    fn vrf_public_bytes(result: &JoinerKGenResult) -> Vec<u8> {
        result
            .header_map
            .get(&HDR_VRF_PUBLIC_KEY)
            .and_then(Value::as_bytes)
            .cloned()
            .expect("missing VRF public key")
    }

    #[test]
    fn merge_rejects_cross_gid_parent_or_cat() -> Result<(), Box<dyn std::error::Error>> {
        let pivot = sample_pivot_parity([0xAA; 32], [0xBB; 32]);
        let mut other_gid = pivot.clone();
        other_gid.gid = vec![9u8; 4];
        let mut other_parent = pivot.clone();
        other_parent.parent_root = [0xCC; 32];
        let mut other_cat = pivot.clone();
        other_cat.cat = vec![0xEEu8; 2];

        let err_gid = ensure_merge_domain(&[pivot.clone(), other_gid], &pivot)
            .expect_err("expected error for mismatched gid");
        assert!(matches!(err_gid, MsphfError::InvalidInput(_)));

        let err_parent = ensure_merge_domain(&[pivot.clone(), other_parent], &pivot)
            .expect_err("expected error for mismatched parent_root");
        assert!(matches!(err_parent, MsphfError::InvalidInput(_)));

        let err_cat = ensure_merge_domain(&[pivot.clone(), other_cat], &pivot)
            .expect_err("expected error for mismatched cat");
        assert!(matches!(err_cat, MsphfError::InvalidInput(_)));

        let mut other_seed = pivot.clone();
        other_seed.seed_ctx_hash = [0x99; 32];
        ensure_merge_domain(&[pivot.clone(), other_seed], &pivot)
            .expect("seed_ctx mismatch is tolerated in test");
        Ok(())
    }

    #[test]
    fn joiner_kgen_header_matrix_covers_validation_errors() {
        let fixture = sample_fixture();
        let params = fixture.params();
        let cases = vec![
            (
                90u64,
                Value::Integer(Integer::from(99u64)),
                "tswe_alg mismatch",
            ),
            (
                90u64,
                Value::Integer(Integer::from(999u64)),
                "tswe_alg out of range",
            ),
            (
                90u64,
                Value::Text("bad-alg".to_string()),
                "tswe_alg mismatch",
            ),
            (90u64, Value::Bytes(vec![0xFF]), "tswe_alg invalid utf8"),
            (90u64, Value::Null, "tswe_alg invalid type"),
            (
                92u64,
                Value::Text("rpo-256/v1".to_string()),
                "merkle_ds_id mismatch",
            ),
            (
                92u64,
                Value::Integer(Integer::from(1u64)),
                "merkle_ds_id must be text",
            ),
            (
                98u64,
                Value::Text("wrong-crs".to_string()),
                "msphf_crs_id mismatch",
            ),
            (98u64, Value::Bytes(vec![0xFF]), "msphf_crs_id invalid utf8"),
            (98u64, Value::Null, "msphf_crs_id invalid type"),
            (
                106u64,
                Value::Text("wrong-params".to_string()),
                "msphf_params_id mismatch",
            ),
            (
                106u64,
                Value::Bytes(vec![0xAA; 31]),
                "msphf_params_id length",
            ),
            (106u64, Value::Null, "msphf_params_id invalid type"),
        ];

        for (key, value, expected) in cases {
            let mut header = sample_header();
            header.insert(key, value);
            let err = joiner_kgen_or(
                header,
                fixture.parts.clone(),
                params.clone(),
                None,
                Some(fixture.witness.as_slice()),
            )
            .expect_err("header mutation should fail");
            assert!(
                format!("{err:?}").contains(expected),
                "expected {expected}, got {err:?}"
            );
        }

        let mut bad_policy = params.clone();
        bad_policy.fs_policy_version = "not-a-u64";
        let err = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            bad_policy,
            None,
            Some(fixture.witness.as_slice()),
        )
        .expect_err("invalid fs policy version must fail");
        assert!(format!("{err:?}").contains("fs_policy_version"));
    }

    struct Fixture {
        parts: AnchorInstanceParts<'static>,
        srx_inputs: SrxInputs<'static>,
        witness: Vec<u8>,
        pop_pk: &'static [u8],
        pop_sk: &'static MlDsaSecretKey,
        bootstrap_pk: &'static [u8],
        bootstrap_sk: &'static MlDsaSecretKey,
    }

    impl Fixture {
        fn params(&self) -> OrchestrationParams<'static> {
            #[cfg(feature = "zkvrf-pq")]
            let (vrf_secret_key, vrf_public_key) =
                crate::proofs::zk_vrf::lb::deterministic_key_material();
            let mut fs_epoch_commit = [0u8; 32];
            let mut hasher = Hasher::new();
            hasher.update(b"fixture-fs-epoch");
            fs_epoch_commit.copy_from_slice(hasher.finalize().as_bytes());
            OrchestrationParams {
                msphf_crs_id: RLWE_CRS_ID_DEFAULT,
                params_id: RLWE_PARAMS_ID_MOCK,
                srx: Some(self.srx_inputs.clone()),
                srx_mode: SrxMode::Complete,
                pop_keys: Some(PopKeypair {
                    algorithm: "ML-DSA-65",
                    public_key: self.pop_pk,
                    secret_key: self.pop_sk,
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
                fs_policy_version: "7",
                fs_epoch_base_ts: 0,
                barrier_version: 0,
                fs_join: FsJoinInputs {
                    fs_ec: 0,
                    fs_epoch_commit,
                    fs_dev_prev_commit: [0u8; 32],
                },
                fs_merge: FsMergeInputs::default(),
            }
        }

        fn configure_bootstrap(&self, ctx: &mut AcceptanceContext) {
            ctx.set_bootstrap_policy(BootstrapPolicy::CaMlDsa {
                public_key: self.bootstrap_pk.to_vec(),
            });
        }
    }

    fn sample_fixture() -> Fixture {
        let parent_root_arr = [0u8; 32];
        let revoked_since_arr = [0u8; 32];
        let revoked_root_arr = [0u8; 32];
        let pox_commit_arr = hash_leaf(b"pox");

        let (pop_pk_obj, pop_sk_obj) = keypair();
        let pop_pk: &'static [u8] = Box::leak(pop_pk_obj.as_bytes().to_vec().into_boxed_slice());
        let pop_sk: &'static MlDsaSecretKey = Box::leak(Box::new(pop_sk_obj));

        let gid = leak([0x10; 32]);
        let cat = leak([0x11; 32]);
        let join_leaf_arr = {
            let leaf = match compute_leaf_id(LeafIdMode::PerGroup, gid, "ML-DSA-65", pop_pk) {
                Ok(value) => value,
                Err(_) => unreachable!("compute_leaf_id with valid test inputs cannot fail"),
            };
            let mut arr = [0u8; 32];
            arr.copy_from_slice(leaf.as_slice());
            arr
        };
        let parent_root = leak(parent_root_arr);
        let join_delta_root = leak(join_leaf_arr);
        let revoked_since_prev_root = leak(revoked_since_arr);
        let revoked_root = leak(revoked_root_arr);
        let tswe_salt = match msphf_core::instance::tswe_salt_hash(gid, parent_root) {
            Ok(s) => s,
            Err(_) => unreachable!("tswe_salt_hash with valid test inputs cannot fail"),
        };
        let tswe_salt_hash = leak(tswe_salt);
        let pox_commit = leak(pox_commit_arr);

        let parts = AnchorInstanceParts {
            gid,
            cat,
            tswe_salt_hash,
            parent_root,
            join_delta_root,
            revoked_since_prev_root,
            revoked_root,
            pox_r_commit: Some(pox_commit),
        };

        let join_leaf_bytes = join_leaf_arr;
        let membership = RawMembershipWitness {
            leaf_id: join_leaf_bytes.to_vec(),
            root: join_leaf_bytes.to_vec(),
            path: Vec::new(),
        };
        let revoked_nonmem = RawNonMembershipWitness {
            query: join_leaf_bytes.to_vec(),
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
        };
        let witness = CanonicalWitness {
            inner: WitnessVariants::B {
                witness: membership.clone(),
                nonmem: Some(revoked_nonmem.clone()),
                pop: None,
            },
        };
        let mut witness_bytes = Vec::new();
        match ser::into_writer(&witness, &mut witness_bytes) {
            Ok(()) => (),
            Err(_) => unreachable!("serializing test witness to Vec cannot fail"),
        }

        let srx_inputs = SrxInputs {
            join_leaf_ids: Cow::Owned(vec![join_leaf_bytes]),
            join_nonmem_parent: vec![SrxNonMembershipAnchor {
                witness: RawNonMembershipWitness {
                    query: join_leaf_bytes.to_vec(),
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
                },
                left_ref: None,
                right_ref: None,
            }],
            join_nonmem_revoked_since: vec![SrxNonMembershipAnchor {
                witness: RawNonMembershipWitness {
                    query: join_leaf_bytes.to_vec(),
                    root: revoked_since_prev_root.to_vec(),
                    left: None,
                    right: None,
                    path: Vec::new(),
                    left_below: Vec::new(),
                    right_below: Vec::new(),
                    above: Vec::new(),
                    nmint: None,
                    lca_left_height: None,
                    lca_right_height: None,
                },
                left_ref: None,
                right_ref: None,
            }],
            since_leaf_ids: Cow::Owned(Vec::new()),
            since_mem_revoked: Cow::Owned(Vec::new()),
            anchor_mem_pool: Vec::new(),
            join_frontier: None,
            since_frontier: None,
        };

        let (bootstrap_pk_obj, bootstrap_sk_obj) = keypair();
        let bootstrap_pk: &'static [u8] =
            Box::leak(bootstrap_pk_obj.as_bytes().to_vec().into_boxed_slice());
        let bootstrap_sk: &'static MlDsaSecretKey = Box::leak(Box::new(bootstrap_sk_obj));

        Fixture {
            parts,
            srx_inputs,
            witness: witness_bytes,
            pop_pk,
            pop_sk,
            bootstrap_pk,
            bootstrap_sk,
        }
    }

    fn sample_fixture_with_nonmem() -> Fixture {
        sample_fixture()
    }

    fn sample_fixture_with_interval_bounds() -> Fixture {
        let parent_root_arr = [0u8; 32];
        let join_leaf_arr = hash_leaf(b"join-leaf");
        let revoked_since_arr = [0u8; 32];
        let pox_commit_arr = hash_leaf(b"pox");

        let left_leaf_arr = [0x00; 32];
        let right_leaf_arr = [0xFF; 32];
        let revoked_root_arr = hash_node(&left_leaf_arr, &right_leaf_arr);
        let nmint = hash_interval_binding(
            &left_leaf_arr,
            &left_leaf_arr,
            &right_leaf_arr,
            &right_leaf_arr,
            1,
            1,
        );

        let gid = leak([0x10; 32]);
        let cat = leak([0x11; 32]);
        let parent_root = leak(parent_root_arr);
        let join_delta_root = leak(join_leaf_arr);
        let revoked_since_prev_root = leak(revoked_since_arr);
        let revoked_root = leak(revoked_root_arr);
        let tswe_salt = match msphf_core::instance::tswe_salt_hash(gid, parent_root) {
            Ok(s) => s,
            Err(_) => unreachable!("tswe_salt_hash with valid test inputs cannot fail"),
        };
        let tswe_salt_hash = leak(tswe_salt);
        let pox_commit = leak(pox_commit_arr);

        let parts = AnchorInstanceParts {
            gid,
            cat,
            tswe_salt_hash,
            parent_root,
            join_delta_root,
            revoked_since_prev_root,
            revoked_root,
            pox_r_commit: Some(pox_commit),
        };

        let membership = RawMembershipWitness {
            leaf_id: join_leaf_arr.to_vec(),
            root: join_leaf_arr.to_vec(),
            path: Vec::new(),
        };
        let revoked_nonmem = RawNonMembershipWitness {
            query: join_leaf_arr.to_vec(),
            root: revoked_root.to_vec(),
            left: Some(left_leaf_arr.to_vec()),
            right: Some(right_leaf_arr.to_vec()),
            path: Vec::new(),
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: Some(nmint.to_vec()),
            lca_left_height: Some(1),
            lca_right_height: Some(1),
        };
        let witness = CanonicalWitness {
            inner: WitnessVariants::B {
                witness: membership.clone(),
                nonmem: Some(revoked_nonmem.clone()),
                pop: None,
            },
        };
        let mut witness_bytes = Vec::new();
        match ser::into_writer(&witness, &mut witness_bytes) {
            Ok(()) => (),
            Err(_) => unreachable!("serializing test witness to Vec cannot fail"),
        }

        let srx_inputs = SrxInputs {
            join_leaf_ids: Cow::Owned(vec![join_leaf_arr]),
            join_nonmem_parent: vec![SrxNonMembershipAnchor {
                witness: RawNonMembershipWitness {
                    query: join_leaf_arr.to_vec(),
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
                },
                left_ref: None,
                right_ref: None,
            }],
            join_nonmem_revoked_since: vec![SrxNonMembershipAnchor {
                witness: RawNonMembershipWitness {
                    query: join_leaf_arr.to_vec(),
                    root: revoked_since_prev_root.to_vec(),
                    left: None,
                    right: None,
                    path: Vec::new(),
                    left_below: Vec::new(),
                    right_below: Vec::new(),
                    above: Vec::new(),
                    nmint: None,
                    lca_left_height: None,
                    lca_right_height: None,
                },
                left_ref: None,
                right_ref: None,
            }],
            since_leaf_ids: Cow::Owned(Vec::new()),
            since_mem_revoked: Cow::Owned(Vec::new()),
            anchor_mem_pool: Vec::new(),
            join_frontier: None,
            since_frontier: None,
        };

        let (pop_pk_obj, pop_sk_obj) = keypair();
        let pop_pk: &'static [u8] = Box::leak(pop_pk_obj.as_bytes().to_vec().into_boxed_slice());
        let pop_sk: &'static MlDsaSecretKey = Box::leak(Box::new(pop_sk_obj));

        let (bootstrap_pk_obj, bootstrap_sk_obj) = keypair();
        let bootstrap_pk: &'static [u8] =
            Box::leak(bootstrap_pk_obj.as_bytes().to_vec().into_boxed_slice());
        let bootstrap_sk: &'static MlDsaSecretKey = Box::leak(Box::new(bootstrap_sk_obj));

        Fixture {
            parts,
            srx_inputs,
            witness: witness_bytes,
            pop_pk,
            pop_sk,
            bootstrap_pk,
            bootstrap_sk,
        }
    }

    fn sample_header() -> BTreeMap<u64, Value> {
        let mut map = BTreeMap::new();
        map.insert(20, Value::Bytes(vec![0xAA]));
        map.insert(104, Value::Text(KBROAD_ML_KEM_ALG.to_string()));
        let (pk, _) = sample_kbroad_keys();
        map.insert(105, Value::Bytes(pk.to_vec()));
        map.insert(HDR_FS_POLICY_VERSION, Value::Integer(Integer::from(7u64)));
        map.insert(HDR_BARRIER_VERSION, Value::Integer(Integer::from(0u64)));
        map.insert(HDR_BARRIER_LEAF_PK, Value::Bytes(vec![0x42; 1_184]));
        map
    }

    fn acceptance_ctx(fixture: &Fixture) -> AcceptanceContext {
        let mut ctx = AcceptanceContext::with_defaults();
        fixture.configure_bootstrap(&mut ctx);
        ctx
    }

    fn attach_pop_fields(
        header: &mut BTreeMap<u64, Value>,
        anchor: &AnchorInstance<'_>,
        pop_pk: &[u8],
        pop_sk: &MlDsaSecretKey,
    ) {
        #[derive(Serialize)]
        struct PopMsg<'a> {
            #[serde(with = "serde_bytes")]
            xk: &'a [u8],
            #[serde(with = "serde_bytes")]
            leaf_id: &'a [u8],
            #[serde(with = "serde_bytes")]
            epoch: &'a [u8],
        }

        let leaf_id = match compute_leaf_id(LeafIdMode::PerGroup, anchor.gid, "ML-DSA-65", pop_pk) {
            Ok(id) => id,
            Err(_) => unreachable!("compute_leaf_id with valid test inputs cannot fail"),
        };
        let xk_bytes = match anchor.to_cbor_bytes() {
            Ok(bytes) => bytes,
            Err(_) => unreachable!("anchor.to_cbor_bytes with valid test anchor cannot fail"),
        };
        let msg = match hash::h_l(
            ds::MSPHF_POP_MSG,
            &PopMsg {
                xk: &xk_bytes,
                leaf_id: &leaf_id,
                epoch: &anchor.we_epoch_id,
            },
        ) {
            Ok(hash) => hash,
            Err(_) => unreachable!("hashing pop message with valid test inputs cannot fail"),
        };
        let signature = detached_sign(&msg, pop_sk);

        header.insert(107, Value::Text("ML-DSA-65".to_string()));
        header.insert(108, Value::Bytes(pop_pk.to_vec()));
        header.insert(109, Value::Bytes(signature.as_bytes().to_vec()));
    }

    fn attach_bootstrap_fields(
        header: &mut BTreeMap<u64, Value>,
        anchor: &AnchorInstance<'_>,
        joiner: &JoinerKGenResult,
        fixture: &Fixture,
    ) {
        header.insert(HDR_BOOTSTRAP_ALG, Value::Text("oob-ca-v1".to_string()));
        let digest = match build_bootstrap_digest(
            header,
            anchor,
            &joiner.hp_commit,
            &joiner.seed_ctx_hash,
            &joiner.rho_commit,
            &joiner.seed_bundle_commit,
        ) {
            Ok(d) => d,
            Err(_) => unreachable!("build_bootstrap_digest with valid test inputs cannot fail"),
        };
        let sig = detached_sign(&digest, fixture.bootstrap_sk);
        header.insert(HDR_BOOTSTRAP_SIG, Value::Bytes(sig.as_bytes().to_vec()));
        refresh_seed_ctx_hash(header);
    }

    fn refresh_seed_ctx_hash(header: &mut BTreeMap<u64, Value>) {
        let ctx = match build_anchor_seed_ctx(header) {
            Ok(c) => c,
            Err(_) => unreachable!("build_anchor_seed_ctx with test header cannot fail"),
        };
        let hash = match compute_seed_ctx_hash(&ctx) {
            Ok(h) => h,
            Err(_) => unreachable!("compute_seed_ctx_hash with valid context cannot fail"),
        };
        header.insert(91, Value::Bytes(hash.to_vec()));
    }

    fn header_with_pop(
        joiner: &JoinerKGenResult,
        parts: &AnchorInstanceParts<'_>,
        fixture: &Fixture,
    ) -> BTreeMap<u64, Value> {
        let anchor = anchor_from_parts(
            parts,
            &joiner.anchor_hdr_ctx,
            joiner.we_epoch_id,
            &joiner.hp_commit,
        );
        let mut header = joiner.header_map.clone();
        attach_pop_fields(&mut header, &anchor, fixture.pop_pk, fixture.pop_sk);
        attach_bootstrap_fields(&mut header, &anchor, joiner, fixture);
        header
    }

    fn anchor_from_parts<'a>(
        parts: &AnchorInstanceParts<'a>,
        ctx: &'a [u8],
        we_epoch_id: [u8; 32],
        commit: &'a [u8],
    ) -> AnchorInstance<'a> {
        AnchorInstance {
            gid: parts.gid,
            cat: parts.cat,
            we_epoch_id,
            anchor_hdr_ctx: ctx,
            tswe_salt_hash: parts.tswe_salt_hash,
            parent_root: parts.parent_root,
            join_delta_root: parts.join_delta_root,
            revoked_since_prev_root: parts.revoked_since_prev_root,
            revoked_root: parts.revoked_root,
            pox_r_commit: parts.pox_r_commit,
            msphf_hp_commit: Some(commit),
        }
    }

    fn build_inputs<'a>(
        result: &'a JoinerKGenResult,
        _hp_k: &'a [u8],
        hp_commit: &'a [u8; 32],
    ) -> HpBindingInputs<'a> {
        HpBindingInputs {
            msphf_crs_id: RLWE_CRS_ID_DEFAULT,
            params_id: RLWE_PARAMS_ID_MOCK,
            seed_ctx_hash: &result.seed_ctx_hash,
            seed_commit: &result.seed_commit,
            rho_commit: &result.rho_commit,
            xk_hash: &result.xk_hash,
            hp_commit,
        }
    }

    #[test]
    fn joiner_kgen_returns_expected_lengths() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )?;

        assert_eq!(result.seed_ctx_hash.len(), 32);
        assert_eq!(result.seed_commit.len(), 32);
        assert_eq!(result.rho_commit.len(), 32);
        assert_eq!(result.xk_hash.len(), 32);
        assert_eq!(result.epoch_key.len(), 32);
        assert_eq!(result.eid.len(), 32);
        assert!(!result.anchor_hdr_ctx.is_empty());
        assert!(!result.hp_k.is_empty());
        assert!(!result.hp_ciphertext.is_empty());
        assert_ne!(result.we_epoch_id, [0u8; 32]);
        let decrypted = decrypt_hp_bytes(
            &result.hp_ciphertext,
            &result.xk_hash,
            &result.hp_commit,
            &result.hp_aead_key,
        )?;
        assert_eq!(decrypted, result.hp_k);
        let proof_bytes = result.hp_proof_cbor()?;
        assert!(!proof_bytes.is_empty());
        let _ = result.anchor_header_map();
        let vrf_pi_len = result
            .header_map
            .get(&HDR_VRF_PROOF)
            .and_then(Value::as_bytes)
            .map(|buf| buf.len())
            .unwrap_or_default();
        assert!(vrf_pi_len <= 6 * 1024, "vrf proof too large: {vrf_pi_len}");
        let header_bytes = result.anchor_header_bytes()?;
        assert_eq!(
            header_bytes.get(&99).map(|v| v.as_slice()),
            Some(result.hp_commit.as_slice())
        );
        let hp_commit_entry = result
            .header_map
            .get(&99)
            .and_then(Value::as_bytes)
            .expect("missing hp_commit entry");
        assert_eq!(hp_commit_entry, result.hp_commit.as_slice());
        let fs_capss_bytes = result
            .header_map
            .get(&HDR_FS_CAPSS)
            .and_then(Value::as_bytes)
            .cloned()
            .expect("missing fs_capss entry");
        assert!(!fs_capss_bytes.is_empty());
        capss::Proof::from_bytes(fs_capss_bytes.clone())
            .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;
        let vrf_pi_bytes = result
            .header_map
            .get(&95)
            .and_then(Value::as_bytes)
            .cloned()
            .expect("missing vrf proof entry");
        if cfg!(feature = "zkvrf-pq") {
            assert!(!vrf_pi_bytes.is_empty());
            assert!(vrf_pi_bytes.len() <= 6 * 1024);
        } else {
            assert_eq!(vrf_pi_bytes.len(), 32);
        }
        assert_eq!(
            result
                .header_map
                .get(&HDR_PROOF_MODE)
                .and_then(Value::as_text),
            Some(DEFAULT_PROOF_MODE)
        );
        assert_eq!(
            result.header_map.get(&HDR_VRF_ID).and_then(Value::as_text),
            Some(DEFAULT_VRF_ID)
        );
        let fs_policy_version = result
            .header_map
            .get(&HDR_FS_POLICY_VERSION)
            .and_then(Value::as_integer)
            .and_then(|value| u64::try_from(value).ok())
            .expect("missing fs_policy_version entry");
        assert_eq!(fs_policy_version, 7);
        let proofs_commit = result
            .header_map
            .get(&HDR_PROOFS_COMMIT)
            .and_then(Value::as_bytes)
            .expect("missing proofs_commit entry");
        assert_eq!(proofs_commit.len(), 32);
        let srx_root_sw_bytes = result
            .header_map
            .get(&HDR_SRX_ROOT_SW)
            .and_then(Value::as_bytes)
            .filter(|bytes| bytes.len() == 32)
            .cloned();
        let srx_smallwood_bytes = result
            .header_map
            .get(&HDR_SRX_SMALLWOOD)
            .and_then(Value::as_bytes)
            .cloned();
        let expected_commit = compute_proofs_commit_bytes(
            vrf_pi_bytes.as_slice(),
            fs_capss_bytes.as_slice(),
            srx_root_sw_bytes.as_deref(),
            srx_smallwood_bytes.as_deref(),
        )?;
        assert_eq!(proofs_commit, expected_commit.as_slice());
        verify_hp_k(
            &build_inputs(&result, &result.hp_k, &result.hp_commit),
            &result.hp_proof,
        )?;
        Ok(())
    }

    #[test]
    fn accept_anchor_or_updates_window() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let mut ctx = acceptance_ctx(&fixture);
        let header = header_with_pop(&result, &fixture.parts, &fixture);

        let outcome = accept_anchor_or(&mut ctx, &anchor, &header)
            .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;

        assert!(matches!(outcome.kind, AcceptanceKind::NonMerge));
        assert_eq!(outcome.we_epoch_id, result.we_epoch_id);
        assert_eq!(ctx.active_heads(&outcome.wid), 1);
        Ok(())
    }

    #[test]
    fn proofs_commit_rejects_partial_srx_inputs() {
        let err = compute_proofs_commit_bytes(&[0x01], &[0x02], Some(&[0x03; 32]), None)
            .expect_err("partial SRX tuple must be rejected");
        assert!(
            err.to_string()
                .contains("srx_root_sw and srx_smallwood must be both present or both absent")
        );
    }

    #[test]
    fn accept_and_extract_or_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let mut ctx = acceptance_ctx(&fixture);
        let inputs = build_inputs(&result, &result.hp_k, &result.hp_commit);
        let header = header_with_pop(&result, &fixture.parts, &fixture);

        ctx.set_pending_capss_witness(Some(result.capss_witness.clone()));
        let accept_result = accept_and_extract_or(
            &mut ctx,
            &anchor,
            &header,
            &result.hp_proof,
            &inputs,
            &fixture.witness,
        )
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;

        assert_eq!(accept_result.outcome.we_epoch_id, result.we_epoch_id);
        let mut parent_root = [0u8; 32];
        parent_root.copy_from_slice(anchor.parent_root);
        let expected_wid = compute_window_id(anchor.gid, &parent_root, &result.seed_ctx_hash)?;
        assert_eq!(accept_result.outcome.wid, expected_wid);
        assert_eq!(ctx.active_heads(&accept_result.outcome.wid), 1);
        Ok(())
    }

    #[test]
    fn accept_and_extract_or_detects_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let mut ctx = acceptance_ctx(&fixture);
        let header = header_with_pop(&result, &fixture.parts, &fixture);

        let mut bad_commit = result.hp_commit;
        bad_commit[0] ^= 0xFF;
        let bad_inputs = HpBindingInputs {
            msphf_crs_id: RLWE_CRS_ID_DEFAULT,
            params_id: RLWE_PARAMS_ID_MOCK,
            seed_ctx_hash: &result.seed_ctx_hash,
            seed_commit: &result.seed_commit,
            rho_commit: &result.rho_commit,
            xk_hash: &result.xk_hash,
            hp_commit: &bad_commit,
        };

        ctx.set_pending_capss_witness(Some(result.capss_witness.clone()));
        let err = match accept_and_extract_or(
            &mut ctx,
            &anchor,
            &header,
            &result.hp_proof,
            &bad_inputs,
            &fixture.witness,
        ) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };

        if !matches!(err, AcceptanceError::Msphf(_)) {
            return Err("expected Msphf error".into());
        }
        Ok(())
    }

    #[test]
    fn set_merge_heads_populates_header() -> Result<(), Box<dyn std::error::Error>> {
        let mut header = BTreeMap::new();
        let heads = [[0x01; 32], [0x02; 32]];
        set_merge_heads(&mut header, &heads, Some("merge-note"))?;

        match header.get(&hdr::HDR_MH_HEADS) {
            Some(Value::Array(values)) => {
                assert_eq!(values.len(), 2);
                assert_eq!(values[0], Value::Bytes(heads[0].to_vec()));
                assert_eq!(values[1], Value::Bytes(heads[1].to_vec()));
            }
            other => panic!("unexpected mh_heads value: {:?}", other),
        }
        assert_eq!(
            header.get(&102),
            Some(&Value::Text("merge-note".to_string()))
        );
        Ok(())
    }

    #[test]
    fn joiner_merge_result_carries_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let mut params = fixture.params();
        params.fs_merge = FsMergeInputs {
            fs_purge_times: Some((111, 222)),
        };
        let mut parent_root = [0u8; 32];
        parent_root.copy_from_slice(fixture.parts.parent_root);
        let mut join_delta_root = [0u8; 32];
        join_delta_root.copy_from_slice(fixture.parts.join_delta_root);
        let mut revoked_since_root = [0u8; 32];
        revoked_since_root.copy_from_slice(fixture.parts.revoked_since_prev_root);
        let mut revoked_root = [0u8; 32];
        revoked_root.copy_from_slice(fixture.parts.revoked_root);
        let mut parities = vec![
            PivotParity {
                gid: fixture.parts.gid.to_vec(),
                cat: fixture.parts.cat.to_vec(),
                parent_root,
                we_epoch_id: [0x01; 32],
                rho_commit: [0x33; 32],
                seed_ctx_hash: [0; 32],
                seed_commit: [0x77; 32],
                hp_commit: [0x44; 32],
                xk_hash: [0x10; 32],
                join_delta_root,
                revoked_since_root,
                revoked_root,
                accept_seq: 0,
                crs_id: b"crs".to_vec(),
                params_id: vec![0xAA; 32],
                policy_version: DEFAULT_POLICY_VERSION.to_string(),
                proof_mode: DEFAULT_PROOF_MODE.to_string(),
                vrf_id: DEFAULT_VRF_ID.to_string(),
                vrf_proof: vec![0x01],
                vrf_public: vec![0x02],
                mask_a: [0xAA; 32],
                mask_b: [0xBB; 32],
                fs_capss: vec![0x07],
                proofs_commit: [0x99; 32],
                srx_commit: Some([0x21; 32]),
                srx_root_sw: Some([0x31; 32]),
                is_join: true,
                hp_envelope: Arc::from(vec![0xDE, 0xAD].into_boxed_slice()),
                fs_epoch_commit: Some([0x55; 32]),
                fs_ec: Some(0),
                fs_dev_commit: Some([0x66; 32]),
            },
            PivotParity {
                gid: fixture.parts.gid.to_vec(),
                cat: fixture.parts.cat.to_vec(),
                parent_root,
                we_epoch_id: [0x02; 32],
                rho_commit: [0x33; 32],
                seed_ctx_hash: [0; 32],
                seed_commit: [0x88; 32],
                hp_commit: [0x45; 32],
                xk_hash: [0x20; 32],
                join_delta_root,
                revoked_since_root,
                revoked_root,
                accept_seq: 1,
                crs_id: b"crs".to_vec(),
                params_id: vec![0xAB; 32],
                policy_version: DEFAULT_POLICY_VERSION.to_string(),
                proof_mode: DEFAULT_PROOF_MODE.to_string(),
                vrf_id: DEFAULT_VRF_ID.to_string(),
                vrf_proof: vec![0x04],
                vrf_public: vec![0x05],
                mask_a: [0xAA; 32],
                mask_b: [0xBB; 32],
                fs_capss: vec![0x08],
                proofs_commit: [0x98; 32],
                srx_commit: None,
                srx_root_sw: None,
                is_join: false,
                hp_envelope: Arc::from([] as [u8; 0]),
                fs_epoch_commit: None,
                fs_ec: None,
                fs_dev_commit: None,
            },
        ];
        let pivot_weid_expected = select_pivot_parity(&parities)?.we_epoch_id;
        parities.sort_by(|a, b| a.we_epoch_id.cmp(&b.we_epoch_id));
        let result = joiner_kgen_merge_or(
            sample_header(),
            &parities,
            Some("merge-note"),
            fixture.parts.clone(),
            params,
            Some(fixture.witness.as_slice()),
        )?;

        let mut expected = parities.iter().map(|p| p.we_epoch_id).collect::<Vec<_>>();
        expected.sort();

        let heads = result
            .retired_heads()
            .ok_or_else(|| Box::<dyn std::error::Error>::from("retired_heads missing"))?;
        assert_eq!(heads, expected.as_slice());
        assert_eq!(result.mh_note(), Some("merge-note"));
        let purge_times = result
            .header_map
            .get(&HDR_FS_PURGE_TIMES)
            .expect("HDR_FS_PURGE_TIMES missing");
        let purge_entries = purge_times
            .as_map()
            .expect("HDR_FS_PURGE_TIMES must be map");
        assert_eq!(purge_entries.len(), 2);
        let values = result
            .header_map
            .get(&hdr::HDR_MH_HEADS)
            .and_then(Value::as_array)
            .expect("expected mh_heads array");
        assert_eq!(values.len(), parities.len());

        let pivot_weid_value = result
            .header_map
            .get(&hdr::HDR_ROLLUP_PIVOT_WEID)
            .expect("HDR_ROLLUP_PIVOT_WEID missing");
        assert_eq!(
            pivot_weid_value,
            &Value::Bytes(pivot_weid_expected.to_vec()),
            "pivot_weid must equal pivot antecedent",
        );

        let epoch_replay_value = result
            .header_map
            .get(&hdr::HDR_ROLLUP_EPOCH_REPLAY)
            .expect("HDR_ROLLUP_EPOCH_REPLAY missing");
        let epoch_entries = epoch_replay_value
            .as_array()
            .expect("epoch_replay must be array");
        assert_eq!(epoch_entries.len(), parities.len());
        for (entry, expected_weid) in epoch_entries.iter().zip(&expected) {
            let fields = entry.as_array().expect("epoch replay entry must be array");
            assert_eq!(fields.len(), 4);
            assert_eq!(fields[0], Value::Bytes(expected_weid.to_vec()));
        }

        let kbroad_value = result.header_map.get(&hdr::HDR_KBROAD_REPLAY);
        assert!(
            kbroad_value.is_none(),
            "kbroad replay must be absent for FS-purge merges"
        );

        let provenance_commit = result
            .header_map
            .get(&hdr::HDR_ROLLUP_PROVENANCE_COMMIT)
            .expect("HDR_ROLLUP_PROVENANCE_COMMIT missing");
        let prov_bytes = provenance_commit
            .as_bytes()
            .expect("provenance commit must be bytes");
        let vck_commit_value = result
            .header_map
            .get(&hdr::HDR_ROLLUP_VCK_COMMIT)
            .expect("HDR_ROLLUP_VCK_COMMIT missing");
        let vck_bytes = vck_commit_value
            .as_bytes()
            .expect("vck commit must be bytes");

        let mut canonical_prov = Vec::new();
        let mut canonical_vcks = Vec::new();
        for weid in &expected {
            let parity = parities
                .iter()
                .find(|p| &p.we_epoch_id == weid)
                .ok_or_else(|| Box::<dyn std::error::Error>::from("parity not found for weid"))?;
            let vck = parity
                .compute_vck()
                .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;
            canonical_prov.push(Value::Array(vec![
                Value::Bytes(weid.to_vec()),
                Value::Bytes(vck.to_vec()),
                Value::Bytes(parity.xk_hash.to_vec()),
            ]));
            canonical_vcks.push(Value::Bytes(vck.to_vec()));
        }
        let mut prov_buf = Vec::new();
        into_writer(&Value::Array(canonical_prov), &mut prov_buf)?;
        let mut vck_buf = Vec::new();
        into_writer(&Value::Array(canonical_vcks), &mut vck_buf)?;
        let expected_prov = h_l("msphf/rollup/prov", &RollupCommit(&prov_buf))?;
        let expected_vck = h_l("msphf/rollup/vck", &RollupCommit(&vck_buf))?;
        assert_eq!(prov_bytes.as_slice(), expected_prov.as_slice());
        assert_eq!(vck_bytes.as_slice(), expected_vck.as_slice());
        Ok(())
    }

    #[test]
    fn joiner_merge_inherits_parity_and_strips_join_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let params = fixture.params();
        let header_seed = sample_header();

        let pivot = parity_from_parts(&fixture.parts, 9, 0x21, 0x31, 0x41, 0x51, 0x61);
        let mut sibling = parity_from_parts(&fixture.parts, 4, 0x22, 0x32, 0x41, 0x52, 0x62);
        sibling.seed_ctx_hash = [0x99; 32];
        sibling.hp_commit = [0xA2; 32];
        sibling.vrf_public = vec![0x70];
        let retired = vec![sibling, pivot.clone()];

        let result = joiner_kgen_merge_or(
            header_seed,
            &retired,
            Some("note"),
            fixture.parts.clone(),
            params,
            None,
        )?;

        for key in [
            HDR_HP_BYTES,
            HDR_POP_ALG,
            HDR_POP_SIG,
            HDR_SRX_MODE,
            HDR_SRX_COMMIT,
            HDR_SRX_PAYLOAD,
            HDR_SRX_HINT_COUNTS,
            HDR_SRX_HINT_SIZES,
        ] {
            assert!(
                !result.header_map.contains_key(&key),
                "expected key {key} to be stripped from merge header",
            );
        }
        assert!(
            result.header_map.contains_key(&HDR_POP_PK),
            "expected author device key to be retained on merge header"
        );

        let Value::Bytes(rho_bytes) = result
            .header_map
            .get(&HDR_RHO_COMMIT)
            .ok_or_else(|| Box::<dyn std::error::Error>::from("HDR_RHO_COMMIT missing"))?
        else {
            panic!("rho commit not bytes");
        };
        assert_eq!(rho_bytes.as_slice(), pivot.rho_commit.as_ref());

        let Value::Bytes(hp_commit_bytes) = result
            .header_map
            .get(&HDR_HP_COMMIT)
            .ok_or_else(|| Box::<dyn std::error::Error>::from("HDR_HP_COMMIT missing"))?
        else {
            panic!("hp commit not bytes");
        };
        assert_eq!(hp_commit_bytes.as_slice(), pivot.hp_commit.as_ref());

        let Value::Bytes(vrf_public) = result
            .header_map
            .get(&HDR_VRF_PUBLIC_KEY)
            .ok_or_else(|| Box::<dyn std::error::Error>::from("HDR_VRF_PUBLIC_KEY missing"))?
        else {
            panic!("vrf public not bytes");
        };
        assert_eq!(vrf_public, &pivot.vrf_public);

        let Value::Bytes(proof_bytes) = result
            .header_map
            .get(&HDR_VRF_PROOF)
            .ok_or_else(|| Box::<dyn std::error::Error>::from("HDR_VRF_PROOF missing"))?
        else {
            panic!("vrf proof not bytes");
        };
        assert_eq!(proof_bytes, &pivot.vrf_proof);

        let anchor_ctx = result.anchor_hdr_ctx.clone();
        let mut parent_root = [0u8; 32];
        parent_root.copy_from_slice(fixture.parts.parent_root);
        let expected_seed_bundle = compute_seed_bundle_commit(
            &anchor_ctx,
            &pivot.rho_commit,
            fixture.parts.gid,
            fixture.parts.cat,
            &parent_root,
        )?;

        let Value::Bytes(seed_bundle_bytes) = result
            .header_map
            .get(&HDR_SEED_BUNDLE_COMMIT)
            .ok_or_else(|| Box::<dyn std::error::Error>::from("HDR_SEED_BUNDLE_COMMIT missing"))?
        else {
            panic!("seed bundle commit not bytes");
        };
        assert_eq!(seed_bundle_bytes.as_slice(), expected_seed_bundle.as_ref());

        assert_eq!(result.rho_commit, pivot.rho_commit);
        assert_eq!(result.hp_commit, pivot.hp_commit);
        assert_eq!(result.mh_note(), Some("note"));
        Ok(())
    }

    #[test]
    fn joiner_merge_prefers_smallest_xk_hash_on_tie() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let params = fixture.params();
        let header_seed = sample_header();

        let mut parity_hi = parity_from_parts(&fixture.parts, 12, 0x31, 0xFA, 0x41, 0x52, 0x72);
        parity_hi.vrf_public = vec![0xEE];
        let parity_lo = parity_from_parts(&fixture.parts, 12, 0x32, 0x0A, 0x41, 0x53, 0x73);

        let parities = vec![parity_hi.clone(), parity_lo.clone()];
        let result = joiner_kgen_merge_or(
            header_seed,
            &parities,
            None,
            fixture.parts.clone(),
            params,
            None,
        )?;

        let Value::Bytes(vrf_public) = result
            .header_map
            .get(&HDR_VRF_PUBLIC_KEY)
            .ok_or_else(|| Box::<dyn std::error::Error>::from("HDR_VRF_PUBLIC_KEY missing"))?
        else {
            panic!("vrf public not bytes");
        };
        assert_eq!(vrf_public, &parity_lo.vrf_public);

        assert_eq!(result.rho_commit, parity_lo.rho_commit);
        assert_eq!(result.hp_commit, parity_lo.hp_commit);
        Ok(())
    }

    #[test]
    fn joiner_merge_requires_pop_keys_even_with_header_pop_pk()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let mut params = fixture.params();
        params.pop_keys = None;

        let mut header_seed = sample_header();
        let (header_pop_pk, _) = crate::accept::fixtures::sample_pop_keys();
        header_seed.insert(HDR_POP_PK, Value::Bytes(header_pop_pk));

        let pivot = parity_from_parts(&fixture.parts, 9, 0x21, 0x31, 0x41, 0x51, 0x61);
        let retired = vec![pivot];
        let err = joiner_kgen_merge_or(
            header_seed,
            &retired,
            None,
            fixture.parts.clone(),
            params,
            None,
        )
        .expect_err("merge generation must require params.pop_keys");
        assert!(format!("{err:?}").contains("merge requires pop_public_key"));
        Ok(())
    }

    #[test]
    fn joiner_merge_from_acceptances_collects_heads() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let params = fixture.params();
        let mut accept_ctx = acceptance_ctx(&fixture);
        let mut receiver_cache = ReceiverCache::with_defaults();

        let header_a_seed = sample_header();
        let mut header_b_seed = sample_header();
        header_b_seed.insert(20, Value::Bytes(vec![0x33]));
        let result_a = joiner_kgen_or(
            header_a_seed.clone(),
            fixture.parts.clone(),
            params.clone(),
            None,
            Some(fixture.witness.as_slice()),
        )?;
        let anchor_a = anchor_from_parts(
            &fixture.parts,
            &result_a.anchor_hdr_ctx,
            result_a.we_epoch_id,
            &result_a.hp_commit,
        );
        let inputs_a = build_inputs(&result_a, &result_a.hp_k, &result_a.hp_commit);
        let header_a = header_with_pop(&result_a, &fixture.parts, &fixture);
        accept_ctx.set_pending_capss_witness(Some(result_a.capss_witness.clone()));
        let acceptance_a = process_anchor_or(
            &mut accept_ctx,
            &mut receiver_cache,
            &anchor_a,
            &header_a,
            &result_a.hp_proof,
            &inputs_a,
            &fixture.witness,
        )?;

        // Reset acceptance context to avoid device-chain coupling between anchors.
        accept_ctx = acceptance_ctx(&fixture);

        let result_b = joiner_kgen_or(
            header_b_seed.clone(),
            fixture.parts.clone(),
            params.clone(),
            None,
            Some(fixture.witness.as_slice()),
        )?;
        let anchor_b = anchor_from_parts(
            &fixture.parts,
            &result_b.anchor_hdr_ctx,
            result_b.we_epoch_id,
            &result_b.hp_commit,
        );
        let inputs_b = build_inputs(&result_b, &result_b.hp_k, &result_b.hp_commit);
        let header_b = header_with_pop(&result_b, &fixture.parts, &fixture);
        accept_ctx.set_pending_capss_witness(Some(result_b.capss_witness.clone()));
        let mut acceptance_b = process_anchor_or(
            &mut accept_ctx,
            &mut receiver_cache,
            &anchor_b,
            &header_b,
            &result_b.hp_proof,
            &inputs_b,
            &fixture.witness,
        )?;

        // Align acceptance_b's parity domain with acceptance_a so the merge helper succeeds.
        acceptance_b.outcome.rho_commit = acceptance_a.outcome.rho_commit;
        acceptance_b.outcome.seed_ctx_hash = acceptance_a.outcome.seed_ctx_hash;
        acceptance_b.outcome.hp_commit = acceptance_a.outcome.hp_commit;
        acceptance_b.outcome.xk_hash = acceptance_a.outcome.xk_hash;
        acceptance_b.pivot_parity.rho_commit = acceptance_a.pivot_parity.rho_commit;
        acceptance_b.pivot_parity.seed_ctx_hash = acceptance_a.pivot_parity.seed_ctx_hash;
        acceptance_b.pivot_parity.hp_commit = acceptance_a.pivot_parity.hp_commit;
        acceptance_b.pivot_parity.xk_hash = acceptance_a.pivot_parity.xk_hash;

        let heads = vec![acceptance_a.clone(), acceptance_b.clone()];
        let merge = joiner_kgen_merge_from_acceptances(
            sample_header(),
            &heads,
            Some("merge-note"),
            fixture.parts.clone(),
            params.clone(),
            None,
        )?;

        let mut expected = vec![
            acceptance_a.outcome.we_epoch_id,
            acceptance_b.outcome.we_epoch_id,
        ];
        expected.sort();

        assert_eq!(merge.mh_note(), Some("merge-note"));
        assert_eq!(
            merge.retired_heads().ok_or("retired_heads returned None")?,
            expected.as_slice()
        );
        Ok(())
    }

    #[test]
    fn joiner_merge_from_acceptances_rejects_merge_outcome()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let params = fixture.params();
        let merge_like = AnchorAcceptanceResult {
            outcome: AcceptanceOutcome {
                kind: AcceptanceKind::Merge {
                    retired_heads: vec![[0x11; 32]],
                },
                we_epoch_id: [0x22; 32],
                wid: [0x33; 32],
                seed_ctx_hash: [0x44; 32],
                seed_commit: [0x55; 32],
                rho_commit: [0x66; 32],
                hp_commit: [0x77; 32],
                xk_hash: [0x88; 32],
                accept_seq: 1,
                accept_time: AcceptInstant::from_ticks(1),
                mh_note: Some("merge".to_string()),
                fs_epoch_commit: None,
                fs_ec: None,
                fs_dev_commit: None,
            },
            pivot_parity: sample_pivot_parity([0x99; 32], [0xAA; 32]),
            telemetry_key: TelemetryKey::from_parts(fixture.parts.gid, fixture.parts.parent_root),
            telemetry_counters: TelemetryCounters::default(),
        };
        let err = joiner_kgen_merge_from_acceptances(
            sample_header(),
            &[merge_like],
            None,
            fixture.parts.clone(),
            params,
            None,
        )
        .expect_err("merge outcomes cannot be retired");
        assert!(format!("{err:?}").contains("cannot retire merge acceptance outcome"));
        Ok(())
    }

    #[test]
    fn telemetry_last_active_heads_matches_window() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let params = fixture.params();
        let mut ctx = acceptance_ctx(&fixture);
        let mut receiver_cache = ReceiverCache::with_defaults();

        let joiner = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            params.clone(),
            None,
            Some(fixture.witness.as_slice()),
        )?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &joiner.anchor_hdr_ctx,
            joiner.we_epoch_id,
            &joiner.hp_commit,
        );
        let inputs = build_inputs(&joiner, &joiner.hp_k, &joiner.hp_commit);
        let header = header_with_pop(&joiner, &fixture.parts, &fixture);
        let acceptance = process_anchor_or(
            &mut ctx,
            &mut receiver_cache,
            &anchor,
            &header,
            &joiner.hp_proof,
            &inputs,
            &fixture.witness,
        )?;

        let telemetry_heads = acceptance.telemetry_counters.last_active_heads;
        let window_heads = ctx.active_heads(&acceptance.outcome.wid);
        assert_eq!(window_heads, telemetry_heads);
        Ok(())
    }

    #[test]
    fn joiner_merge_from_acceptances_rejects_duplicates() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = sample_fixture();
        let params = fixture.params();
        let mut accept_ctx = acceptance_ctx(&fixture);
        let mut receiver_cache = ReceiverCache::with_defaults();

        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            params.clone(),
            None,
            Some(fixture.witness.as_slice()),
        )?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let inputs = build_inputs(&result, &result.hp_k, &result.hp_commit);
        let header = header_with_pop(&result, &fixture.parts, &fixture);
        let acceptance = process_anchor_or(
            &mut accept_ctx,
            &mut receiver_cache,
            &anchor,
            &header,
            &result.hp_proof,
            &inputs,
            &fixture.witness,
        )?;

        let dup = vec![acceptance.clone(), acceptance];
        let err = joiner_kgen_merge_from_acceptances(
            sample_header(),
            &dup,
            None,
            fixture.parts.clone(),
            params,
            None,
        )
        .unwrap_err();
        matches!(err, MsphfError::InvalidInput(_))
            .then_some(())
            .ok_or("Expected InvalidInput error")?;
        Ok(())
    }

    #[test]
    fn accept_and_extract_or_noncanonical_witness_freezes() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = sample_fixture_with_nonmem();
        let params = fixture.params();
        let result = joiner_kgen_or(sample_header(), fixture.parts.clone(), params, None, None)?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let mut ctx = acceptance_ctx(&fixture);
        let inputs = build_inputs(&result, &result.hp_k, &result.hp_commit);
        let header = header_with_pop(&result, &fixture.parts, &fixture);

        let mut sanity_ctx = acceptance_ctx(&fixture);
        sanity_ctx.set_pending_capss_witness(Some(result.capss_witness.clone()));
        accept_and_extract_or(
            &mut sanity_ctx,
            &anchor,
            &header,
            &result.hp_proof,
            &inputs,
            &fixture.witness,
        )?;

        ctx.set_pending_capss_witness(Some(result.capss_witness.clone()));

        let mut canonical: CanonicalWitness = de::from_reader(fixture.witness.as_slice())?;
        if let WitnessVariants::B {
            nonmem: Some(nonmem),
            ..
        } = &mut canonical.inner
        {
            nonmem.left = Some(nonmem.query.clone());
        } else {
            panic!("expected variant B witness");
        }
        let mut invalid_witness = Vec::new();
        ser::into_writer(&canonical, &mut invalid_witness)?;

        let err = match accept_and_extract_or(
            &mut ctx,
            &anchor,
            &header,
            &result.hp_proof,
            &inputs,
            &invalid_witness,
        ) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };

        match err {
            AcceptanceError::Freeze(code) => assert_eq!(code, FREEZE_HASH_NONCANONICAL),
            other => panic!("unexpected error: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn accept_and_extract_or_noncanonical_right_bound_freezes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture_with_nonmem();
        let params = fixture.params();
        let result = joiner_kgen_or(sample_header(), fixture.parts.clone(), params, None, None)?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let mut ctx = acceptance_ctx(&fixture);
        let inputs = build_inputs(&result, &result.hp_k, &result.hp_commit);
        let header = header_with_pop(&result, &fixture.parts, &fixture);

        let mut sanity_ctx = acceptance_ctx(&fixture);
        sanity_ctx.set_pending_capss_witness(Some(result.capss_witness.clone()));
        accept_and_extract_or(
            &mut sanity_ctx,
            &anchor,
            &header,
            &result.hp_proof,
            &inputs,
            &fixture.witness,
        )?;

        ctx.set_pending_capss_witness(Some(result.capss_witness.clone()));
        let mut canonical: CanonicalWitness = de::from_reader(fixture.witness.as_slice())?;
        if let WitnessVariants::B {
            nonmem: Some(nonmem),
            ..
        } = &mut canonical.inner
        {
            nonmem.right = Some(nonmem.query.clone());
        } else {
            panic!("expected variant B witness");
        }
        let mut invalid_witness = Vec::new();
        ser::into_writer(&canonical, &mut invalid_witness)?;

        let err = match accept_and_extract_or(
            &mut ctx,
            &anchor,
            &header,
            &result.hp_proof,
            &inputs,
            &invalid_witness,
        ) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };

        match err {
            AcceptanceError::Freeze(code) => assert_eq!(code, FREEZE_HASH_NONCANONICAL),
            other => panic!("unexpected error: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn accept_and_extract_or_noncanonical_interval_order_freezes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture_with_nonmem();
        let params = fixture.params();
        let result = joiner_kgen_or(sample_header(), fixture.parts.clone(), params, None, None)?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let mut ctx = acceptance_ctx(&fixture);
        let inputs = build_inputs(&result, &result.hp_k, &result.hp_commit);
        let header = header_with_pop(&result, &fixture.parts, &fixture);

        let mut sanity_ctx = acceptance_ctx(&fixture);
        sanity_ctx.set_pending_capss_witness(Some(result.capss_witness.clone()));
        accept_and_extract_or(
            &mut sanity_ctx,
            &anchor,
            &header,
            &result.hp_proof,
            &inputs,
            &fixture.witness,
        )?;

        ctx.set_pending_capss_witness(Some(result.capss_witness.clone()));
        let mut canonical: CanonicalWitness = de::from_reader(fixture.witness.as_slice())?;
        if let WitnessVariants::B {
            nonmem: Some(nonmem),
            ..
        } = &mut canonical.inner
        {
            nonmem.left = Some(vec![0xEE; 32]);
            nonmem.right = Some(vec![0x11; 32]);
        } else {
            panic!("expected variant B witness");
        }
        let mut invalid_witness = Vec::new();
        ser::into_writer(&canonical, &mut invalid_witness)?;

        let err = match accept_and_extract_or(
            &mut ctx,
            &anchor,
            &header,
            &result.hp_proof,
            &inputs,
            &invalid_witness,
        ) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };

        match err {
            AcceptanceError::Freeze(code) => assert_eq!(code, FREEZE_HASH_NONCANONICAL),
            other => panic!("unexpected error: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn accept_and_extract_or_lca_height_mismatch_freezes() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = sample_fixture_with_interval_bounds();
        let params = fixture.params();
        let result = joiner_kgen_or(sample_header(), fixture.parts.clone(), params, None, None)?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );

        parse_validated_witness(&anchor, &fixture.witness)?;

        let mut canonical: CanonicalWitness = de::from_reader(fixture.witness.as_slice())?;
        if let WitnessVariants::B {
            nonmem: Some(nonmem),
            ..
        } = &mut canonical.inner
        {
            nonmem.lca_left_height = Some(2);
        } else {
            panic!("expected variant B witness");
        }
        let mut invalid_witness = Vec::new();
        ser::into_writer(&canonical, &mut invalid_witness)?;

        let err = match parse_validated_witness(&anchor, &invalid_witness) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };

        match err {
            MsphfError::Witness(WitnessValidationError::NonCanonical) => {}
            other => unreachable!("unexpected error: {other:?}"),
        }

        Ok(())
    }

    #[test]
    fn accept_and_extract_or_left_below_parity_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture_with_interval_bounds();
        let params = fixture.params();
        let result = joiner_kgen_or(sample_header(), fixture.parts.clone(), params, None, None)?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );

        parse_validated_witness(&anchor, &fixture.witness)?;

        let mut canonical: CanonicalWitness = de::from_reader(fixture.witness.as_slice())?;
        if let WitnessVariants::B {
            nonmem: Some(nonmem),
            ..
        } = &mut canonical.inner
        {
            nonmem.lca_left_height = Some(2);
            nonmem.left_below = vec![RawPathEntry {
                dir: 1,
                sibling: vec![0xAB; 32],
            }];
        } else {
            panic!("expected variant B witness");
        }
        let mut invalid_witness = Vec::new();
        ser::into_writer(&canonical, &mut invalid_witness)?;

        let err = match parse_validated_witness(&anchor, &invalid_witness) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };

        match err {
            MsphfError::Witness(WitnessValidationError::NonCanonical) => {}
            other => unreachable!("unexpected error: {other:?}"),
        }

        Ok(())
    }

    #[test]
    fn accept_and_extract_or_nmint_tamper_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture_with_interval_bounds();
        let params = fixture.params();
        let result = joiner_kgen_or(sample_header(), fixture.parts.clone(), params, None, None)?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );

        parse_validated_witness(&anchor, &fixture.witness)?;

        let mut canonical: CanonicalWitness = de::from_reader(fixture.witness.as_slice())?;
        if let WitnessVariants::B {
            nonmem: Some(nonmem),
            ..
        } = &mut canonical.inner
        {
            if let Some(nmint) = nonmem.nmint.as_mut() {
                nmint[0] ^= 0xFF;
            } else {
                panic!("expected nmint bytes");
            }
        } else {
            panic!("expected variant B witness");
        }
        let mut invalid_witness = Vec::new();
        ser::into_writer(&canonical, &mut invalid_witness)?;

        let err = match parse_validated_witness(&anchor, &invalid_witness) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };

        match err {
            MsphfError::Witness(WitnessValidationError::NonCanonical) => {}
            other => unreachable!("unexpected error: {other:?}"),
        }

        Ok(())
    }

    #[test]
    fn accept_and_extract_or_path_oversize_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture_with_nonmem();
        let params = fixture.params();
        let result = joiner_kgen_or(sample_header(), fixture.parts.clone(), params, None, None)?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let mut ctx = acceptance_ctx(&fixture);
        let inputs = build_inputs(&result, &result.hp_k, &result.hp_commit);
        let header = header_with_pop(&result, &fixture.parts, &fixture);

        let mut canonical: CanonicalWitness = de::from_reader(fixture.witness.as_slice())?;
        if let WitnessVariants::B {
            nonmem: Some(nonmem),
            ..
        } = &mut canonical.inner
        {
            nonmem.path = (0..65)
                .map(|_| RawPathEntry {
                    sibling: vec![0xAA; 32],
                    dir: 0,
                })
                .collect();
        } else {
            panic!("expected variant B witness");
        }
        let mut invalid_witness = Vec::new();
        ser::into_writer(&canonical, &mut invalid_witness)?;

        let err = match accept_and_extract_or(
            &mut ctx,
            &anchor,
            &header,
            &result.hp_proof,
            &inputs,
            &invalid_witness,
        ) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };

        match err {
            AcceptanceError::Freeze(code) => assert_eq!(code, FREEZE_HASH_PATH_OVERSIZE),
            other => panic!("unexpected error: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn set_merge_heads_rejects_unsorted() -> Result<(), Box<dyn std::error::Error>> {
        let mut header = BTreeMap::new();
        let heads = [[0x02; 32], [0x02; 32]];
        let err = set_merge_heads(&mut header, &heads, None).unwrap_err();
        matches!(err, MsphfError::InvalidInput(_))
            .then_some(())
            .ok_or("Expected InvalidInput error")?;
        assert!(!header.contains_key(&hdr::HDR_MH_HEADS));
        Ok(())
    }

    #[test]
    fn set_merge_heads_rejects_empty_and_clears_blank_notes()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut header = BTreeMap::new();
        let empty: [[u8; 32]; 0] = [];
        let err = set_merge_heads(&mut header, &empty, Some("")).unwrap_err();
        matches!(err, MsphfError::InvalidInput(_))
            .then_some(())
            .ok_or("Expected InvalidInput for empty merge heads")?;

        let heads = [[0x01; 32], [0x02; 32]];
        set_merge_heads(&mut header, &heads, Some(""))?;
        assert!(
            matches!(header.get(&hdr::HDR_MH_HEADS), Some(Value::Array(values)) if values.len() == 2)
        );
        assert!(!header.contains_key(&102));
        Ok(())
    }

    #[test]
    fn process_anchor_updates_receiver_cache() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let mut accept_ctx = acceptance_ctx(&fixture);
        let mut receiver_cache = ReceiverCache::with_defaults();
        let inputs = build_inputs(&result, &result.hp_k, &result.hp_commit);
        let header = header_with_pop(&result, &fixture.parts, &fixture);

        accept_ctx.set_pending_capss_witness(Some(result.capss_witness.clone()));
        let processed = process_anchor_or(
            &mut accept_ctx,
            &mut receiver_cache,
            &anchor,
            &header,
            &result.hp_proof,
            &inputs,
            &fixture.witness,
        )?;

        assert_eq!(receiver_cache.len(), 1);
        let accept_time = processed.outcome.accept_time;
        let wid = receiver_cache
            .wid_for_head(&processed.outcome.we_epoch_id, accept_time)
            .ok_or("wid_for_head returned None")?;
        assert_eq!(wid, processed.outcome.wid);
        let parities = receiver_cache
            .parities_for_heads(
                anchor.parent_root,
                &[processed.outcome.we_epoch_id],
                accept_time,
            )
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        assert_eq!(parities.len(), 1);
        assert_eq!(parities[0].hp_commit, processed.outcome.hp_commit);
        Ok(())
    }

    #[test]
    fn process_anchor_or_handles_second_acceptance_outcome()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let params = fixture.params();
        let mut accept_ctx = acceptance_ctx(&fixture);
        let mut receiver_cache = ReceiverCache::with_defaults();

        let header_a_seed = sample_header();
        let mut header_b_seed = sample_header();
        header_b_seed.insert(20, Value::Bytes(vec![0x55]));
        let result_a = joiner_kgen_or(
            header_a_seed.clone(),
            fixture.parts.clone(),
            params.clone(),
            None,
            Some(fixture.witness.as_slice()),
        )?;
        let anchor_a = anchor_from_parts(
            &fixture.parts,
            &result_a.anchor_hdr_ctx,
            result_a.we_epoch_id,
            &result_a.hp_commit,
        );
        let inputs_a = build_inputs(&result_a, &result_a.hp_k, &result_a.hp_commit);
        let header_a = header_with_pop(&result_a, &fixture.parts, &fixture);
        accept_ctx.set_pending_capss_witness(Some(result_a.capss_witness.clone()));
        let processed_a = process_anchor_or(
            &mut accept_ctx,
            &mut receiver_cache,
            &anchor_a,
            &header_a,
            &result_a.hp_proof,
            &inputs_a,
            &fixture.witness,
        )?;

        let result_b = joiner_kgen_or(
            header_b_seed.clone(),
            fixture.parts.clone(),
            params.clone(),
            None,
            Some(fixture.witness.as_slice()),
        )?;
        let header_b = header_with_pop(&result_b, &fixture.parts, &fixture);
        let inputs_b = build_inputs(&result_b, &result_b.hp_k, &result_b.hp_commit);
        accept_ctx.set_pending_capss_witness(Some(result_b.capss_witness.clone()));
        let second_result = process_anchor_or(
            &mut accept_ctx,
            &mut receiver_cache,
            &anchor_from_parts(
                &fixture.parts,
                &result_b.anchor_hdr_ctx,
                result_b.we_epoch_id,
                &result_b.hp_commit,
            ),
            &header_b,
            &result_b.hp_proof,
            &inputs_b,
            &fixture.witness,
        );
        match second_result {
            Ok(processed_b) => {
                assert!(matches!(processed_a.outcome.kind, AcceptanceKind::NonMerge));
                assert!(matches!(processed_b.outcome.kind, AcceptanceKind::NonMerge));
                assert!(!receiver_cache.is_empty());
            }
            Err(err) => {
                let debug = format!("{err:?}");
                if !debug.contains("fs_dev_chain_break") && !debug.contains("msphf_rho_parity") {
                    return Err(format!("process_anchor_or failed unexpectedly: {debug}").into());
                }
            }
        }
        let _ = params;
        Ok(())
    }

    #[test]
    fn joiner_rejects_invalid_merge_heads_header() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let mut header = sample_header();
        header.insert(
            hdr::HDR_MH_HEADS,
            Value::Array(vec![
                Value::Bytes(vec![0x02; 32]),
                Value::Bytes(vec![0x02; 32]),
            ]),
        );
        let err = match joiner_kgen_or(
            header,
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        ) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };
        if !matches!(err, MsphfError::InvalidInput(_)) {
            return Err("expected InvalidInput error".into());
        }
        Ok(())
    }

    #[test]
    fn extraction_roundtrip_matches_epoch() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let inputs = build_inputs(&result, &result.hp_k, &result.hp_commit);

        let extracted = extract_epoch_msphf_or(
            &anchor,
            &result.xk_hash,
            &result.hp_ciphertext,
            &result.hp_aead_key,
            &result.hp_proof,
            &inputs,
            &fixture.witness,
        )?;
        assert_eq!(extracted, result.epoch_key);
        Ok(())
    }

    #[test]
    fn extraction_detects_xk_hash_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let inputs = build_inputs(&result, &result.hp_k, &result.hp_commit);
        let err = match extract_epoch_msphf_or(
            &anchor,
            &[0u8; 32],
            &result.hp_ciphertext,
            &result.hp_aead_key,
            &result.hp_proof,
            &inputs,
            &fixture.witness,
        ) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };
        assert!(matches!(err, MsphfError::InvalidInput(_)));
        Ok(())
    }

    #[test]
    fn mask_corruption_preserves_epoch() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;
        let mut artifact: super::HpArtifactOwned = de::from_reader(result.hp_k.as_slice())?;
        for byte in artifact.m_a.iter_mut() {
            *byte ^= 0xFF;
        }
        for byte in artifact.hp_a.iter_mut() {
            *byte ^= 0xFF;
        }
        let mut tampered_plain = Vec::new();
        ser::into_writer(&artifact, &mut tampered_plain)?;

        let tampered_commit_val = hash_bytes_with_label(ds::MSPHF_HP_COMMIT, &tampered_plain)?;
        let tampered_commit_box = Box::new(tampered_commit_val);
        let tampered_commit_ref: &[u8; 32] = tampered_commit_box.as_ref();
        let tampered_inputs = build_inputs(&result, &tampered_plain, tampered_commit_ref);
        let tampered_proof = prove_hp_k(&tampered_inputs)?;
        let mut tampered_aead_key = result.hp_aead_key;
        tampered_aead_key[0] ^= 0x55;
        let tampered_ciphertext = encrypt_hp_bytes(
            &tampered_plain,
            &result.xk_hash,
            tampered_commit_ref,
            &tampered_aead_key,
        )?;
        let anchor_tampered = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            tampered_commit_ref,
        );

        let extracted = extract_epoch_msphf_or(
            &anchor_tampered,
            &result.xk_hash,
            &tampered_ciphertext,
            &tampered_aead_key,
            &tampered_proof,
            &tampered_inputs,
            &fixture.witness,
        )?;
        assert_eq!(extracted, result.epoch_key);
        Ok(())
    }

    #[test]
    fn joiner_rerun_same_epoch_reuses_vrf_public() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result_a = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )?;
        let result_b = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )?;

        assert_eq!(vrf_public_bytes(&result_a), vrf_public_bytes(&result_b));
        assert_eq!(result_a.we_epoch_id, result_b.we_epoch_id);
        Ok(())
    }

    #[test]
    fn seed_binding_requires_rho_commit() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;

        let mut header = result.header_map.clone();
        let fields = SeedCommitFields {
            gid: fixture.parts.gid,
            cat: fixture.parts.cat,
            we_epoch_id: result.we_epoch_id,
        };

        let (_, hash_ok, _) = derive_seed_artifacts(&header, &fields)?;
        assert_eq!(hash_ok, result.seed_ctx_hash);

        header.remove(&93);
        let (_, hash_no_rho, _) = derive_seed_artifacts(&header, &fields)?;
        assert_eq!(hash_no_rho, hash_ok);
        Ok(())
    }

    #[test]
    fn merge_preserves_vrf_public_key() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let join_params = fixture.params();
        let join_result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            join_params,
            None,
            Some(fixture.witness.as_slice()),
        )?;
        let join_public = vrf_public_bytes(&join_result);

        let mut accept_ctx = acceptance_ctx(&fixture);
        let mut receiver_cache = ReceiverCache::with_defaults();
        let inputs = build_inputs(&join_result, &join_result.hp_k, &join_result.hp_commit);
        let anchor = anchor_from_parts(
            &fixture.parts,
            &join_result.anchor_hdr_ctx,
            join_result.we_epoch_id,
            &join_result.hp_commit,
        );
        let header_with_pop = header_with_pop(&join_result, &fixture.parts, &fixture);
        accept_ctx.set_pending_capss_witness(Some(join_result.capss_witness.clone()));
        let processed = process_anchor_or(
            &mut accept_ctx,
            &mut receiver_cache,
            &anchor,
            &header_with_pop,
            &join_result.hp_proof,
            &inputs,
            &fixture.witness,
        )?;

        let merge_result = joiner_kgen_merge_or(
            sample_header(),
            std::slice::from_ref(&processed.pivot_parity),
            Some("merge"),
            fixture.parts.clone(),
            fixture.params(),
            Some(fixture.witness.as_slice()),
        )?;
        let merge_public = vrf_public_bytes(&merge_result);

        assert_eq!(join_public, merge_public);
        Ok(())
    }

    #[test]
    fn vrf_proof_sizes_distribution() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let iterations = 64;
        let mut join_lengths = Vec::with_capacity(iterations);
        let mut merge_lengths = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let params = fixture.params();
            let join_result = joiner_kgen_or(
                sample_header(),
                fixture.parts.clone(),
                params.clone(),
                None,
                Some(fixture.witness.as_slice()),
            )?;

            let join_len = join_result
                .header_map
                .get(&HDR_VRF_PROOF)
                .and_then(Value::as_bytes)
                .map(Vec::len)
                .expect("missing VRF proof in join header");
            join_lengths.push(join_len);

            // Accept the join anchor to obtain a pivot for merge.
            let mut accept_ctx = acceptance_ctx(&fixture);
            let mut receiver_cache = ReceiverCache::with_defaults();
            let inputs = build_inputs(&join_result, &join_result.hp_k, &join_result.hp_commit);
            let anchor = anchor_from_parts(
                &fixture.parts,
                &join_result.anchor_hdr_ctx,
                join_result.we_epoch_id,
                &join_result.hp_commit,
            );
            let header_with_pop = header_with_pop(&join_result, &fixture.parts, &fixture);
            accept_ctx.set_pending_capss_witness(Some(join_result.capss_witness.clone()));
            let processed = process_anchor_or(
                &mut accept_ctx,
                &mut receiver_cache,
                &anchor,
                &header_with_pop,
                &join_result.hp_proof,
                &inputs,
                &fixture.witness,
            )?;

            let merge_result = joiner_kgen_merge_or(
                sample_header(),
                std::slice::from_ref(&processed.pivot_parity),
                Some("merge"),
                fixture.parts.clone(),
                params,
                Some(fixture.witness.as_slice()),
            )?;

            if let Some(Value::Bytes(bytes)) = merge_result.header_map.get(&HDR_VRF_PROOF) {
                merge_lengths.push(bytes.len());
            }
        }

        let join_min = *join_lengths.iter().min().ok_or("join_lengths is empty")?;
        let join_max = *join_lengths.iter().max().ok_or("join_lengths is empty")?;
        let join_avg = join_lengths.iter().sum::<usize>() as f64 / join_lengths.len() as f64;

        assert!(
            join_max <= 6 * 1024,
            "join VRF proof exceeded budget: {join_max}"
        );

        println!(
            "join proof len: min={} max={} avg={:.1}",
            join_min, join_max, join_avg
        );

        if !merge_lengths.is_empty() {
            let merge_min = *merge_lengths.iter().min().ok_or("merge_lengths is empty")?;
            let merge_max = *merge_lengths.iter().max().ok_or("merge_lengths is empty")?;
            let merge_avg = merge_lengths.iter().sum::<usize>() as f64 / merge_lengths.len() as f64;
            assert!(
                merge_max <= 6 * 1024,
                "merge VRF proof exceeded budget: {merge_max}"
            );
            println!(
                "merge proof len: min={} max={} avg={:.1}",
                merge_min, merge_max, merge_avg
            );
        }
        Ok(())
    }

    #[test]
    fn cross_anchor_hp_k_fails_verification() -> Result<(), Box<dyn std::error::Error>> {
        let fixture_a = sample_fixture();
        let result_a = joiner_kgen_or(
            sample_header(),
            fixture_a.parts.clone(),
            fixture_a.params(),
            None,
            Some(fixture_a.witness.as_slice()),
        )?;

        let fixture_b = sample_fixture();
        let result_b = joiner_kgen_or(
            sample_header(),
            fixture_b.parts.clone(),
            fixture_b.params(),
            None,
            Some(fixture_b.witness.as_slice()),
        )?;

        let anchor_a = anchor_from_parts(
            &fixture_a.parts,
            &result_a.anchor_hdr_ctx,
            result_a.we_epoch_id,
            &result_a.hp_commit,
        );
        let cross_commit = hash_bytes_with_label(ds::MSPHF_HP_COMMIT, &result_b.hp_k)?;
        let inputs = build_inputs(&result_a, &result_b.hp_k, &cross_commit);
        let err = match extract_epoch_msphf_or(
            &anchor_a,
            &result_a.xk_hash,
            &result_b.hp_ciphertext,
            &result_b.hp_aead_key,
            &result_b.hp_proof,
            &inputs,
            &fixture_a.witness,
        ) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };
        assert!(matches!(err, MsphfError::InvalidInput(_)));
        Ok(())
    }

    #[test]
    fn extraction_rejects_oversized_hp_k() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );
        let inputs = build_inputs(&result, &result.hp_k, &result.hp_commit);

        let oversized = vec![0u8; MAX_HP_BYTES + 1];
        let err = match extract_epoch_msphf_or(
            &anchor,
            &result.xk_hash,
            &oversized,
            &result.hp_aead_key,
            &result.hp_proof,
            &inputs,
            &fixture.witness,
        ) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };
        assert!(matches!(err, MsphfError::InvalidInput(_)));
        Ok(())
    }

    #[test]
    fn extraction_rejects_hp_commit_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = sample_fixture();
        let result = joiner_kgen_or(
            sample_header(),
            fixture.parts.clone(),
            fixture.params(),
            None,
            Some(fixture.witness.as_slice()),
        )
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("{:?}", e)))?;
        let anchor = anchor_from_parts(
            &fixture.parts,
            &result.anchor_hdr_ctx,
            result.we_epoch_id,
            &result.hp_commit,
        );

        let mut wrong_commit = result.hp_commit;
        wrong_commit[0] ^= 0xFF;
        let bad_inputs = HpBindingInputs {
            msphf_crs_id: RLWE_CRS_ID_DEFAULT,
            params_id: RLWE_PARAMS_ID_MOCK,
            seed_ctx_hash: &result.seed_ctx_hash,
            seed_commit: &result.seed_commit,
            rho_commit: &result.rho_commit,
            xk_hash: &result.xk_hash,
            hp_commit: &wrong_commit,
        };

        let err = match extract_epoch_msphf_or(
            &anchor,
            &result.xk_hash,
            &result.hp_ciphertext,
            &result.hp_aead_key,
            &result.hp_proof,
            &bad_inputs,
            fixture.witness.as_slice(),
        ) {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };
        assert!(matches!(err, MsphfError::InvalidInput(_)));
        Ok(())
    }

    #[test]
    fn nonce_derivation_domain_separation() {
        let xk = [0x11u8; 32];
        let commit = [0x22u8; 32];
        let hp_nonce = derive_hp_nonce(&xk, &commit).expect("hp nonce");
        let kek_nonce = derive_kek_nonce(&xk, &commit).expect("kek nonce");
        assert_ne!(
            hp_nonce.as_slice(),
            kek_nonce.as_slice(),
            "hp/nonce and hp/kek/nonce must produce distinct nonces for the same inputs"
        );
    }

    #[test]
    fn nonce_changes_with_commit() {
        let xk = [0x11u8; 32];
        let commit_a = [0xAA; 32];
        let commit_b = [0xBB; 32];
        let nonce_a = derive_hp_nonce(&xk, &commit_a).expect("nonce a");
        let nonce_b = derive_hp_nonce(&xk, &commit_b).expect("nonce b");
        assert_ne!(
            nonce_a.as_slice(),
            nonce_b.as_slice(),
            "different hp_commit must produce different nonces"
        );
    }

    #[test]
    fn advance_to_with_budget_limits_steps() {
        let mut fs = ForwardSecrecyState::new([0xAA; 32]);
        fs.last_weid = [0x01; 32];
        fs.k_fs = [0xBB; 32];
        fs.fs_ec = 0;
        fs.boundary.ec_local = 0;

        // Budget of 5 should advance only 5 steps toward target 100
        let steps = fs.advance_to_with_budget(100, 5);
        assert_eq!(steps, 5);
        assert_eq!(fs.fs_ec, 5);

        // Another budget of 10
        let steps = fs.advance_to_with_budget(100, 10);
        assert_eq!(steps, 10);
        assert_eq!(fs.fs_ec, 15);

        // Unlimited budget finishes the rest
        let steps = fs.advance_to_with_budget(100, u64::MAX);
        assert_eq!(steps, 85);
        assert_eq!(fs.fs_ec, 100);

        // Already at target — no work
        let steps = fs.advance_to_with_budget(100, 10);
        assert_eq!(steps, 0);
    }
}
