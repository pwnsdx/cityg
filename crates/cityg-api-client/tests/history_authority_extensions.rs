use std::error::Error as StdError;

use cityg_api_client::{
    BarrierJoinOccupancyRecord, BarrierRevokedOccupancyRecord, GlobalHistoryAttestation,
    HelperCompletenessAttestation, HistoryAuthorityDescriptor, HistoryCommitment,
    parse_fetch_public_tree_completeness_attestation_bytes, parse_global_history_attestation_bytes,
    parse_history_authority_descriptor_bytes,
    parse_join_occupancies_since_completeness_attestation_bytes,
    parse_revoked_occupancies_completeness_attestation_bytes,
    verify_fetch_public_tree_completeness_attestation,
    verify_join_occupancies_since_completeness_attestation,
    verify_revoked_occupancies_completeness_attestation,
};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde::{Deserialize, Serialize};

const HELPER_KIND_REVOKED_OCCUPANCIES: &str = "resolve_revoked_occupancies";
const HELPER_KIND_JOIN_OCCUPANCIES_SINCE: &str = "resolve_join_occupancies_since";
const HELPER_KIND_FETCH_PUBLIC_TREE: &str = "fetch_public_tree";

#[derive(Serialize, Deserialize)]
struct HistoryAuthorityDescriptorWire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Serialize, Deserialize)]
struct GlobalHistoryAttestationWire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    u64,
    u64,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    String,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Serialize, Deserialize)]
struct HelperCompletenessAttestationWire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    String,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Serialize)]
struct GlobalHistoryAttestationSignedPayload<'a>(
    &'static str,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u64,
    u64,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    &'a str,
);

#[derive(Serialize)]
struct HelperCompletenessSignedPayload<'a, T> {
    label: &'static str,
    #[serde(with = "serde_bytes")]
    scope_id: &'a [u8; 32],
    helper_kind: &'a str,
    #[serde(with = "serde_bytes")]
    history_view_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    history_commitment_id: &'a [u8; 32],
    page_offset: u32,
    total_entries: u32,
    selector: T,
}

#[derive(Serialize)]
struct RevokedOccupanciesSelector<'a> {
    #[serde(with = "serde_bytes")]
    revocation_roots_hash: &'a [u8; 32],
    records: &'a [BarrierRevokedOccupancyRecord],
}

#[derive(Serialize)]
struct JoinsSinceSelector<'a> {
    prev_barrier_version: u64,
    records: &'a [BarrierJoinOccupancyRecord],
}

#[derive(Serialize)]
struct FetchPublicTreeSelector<'a> {
    #[serde(with = "serde_bytes")]
    kem_tree_hash_after: &'a [u8; 32],
    pk_entries: &'a [Vec<u8>],
}

fn encode_cbor_det<T: Serialize>(value: &T) -> Result<Vec<u8>, Box<dyn StdError>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn history_authority(seed: u8) -> (HistoryAuthorityDescriptor, dilithium5::SecretKey) {
    let (public_key, secret_key) = dilithium5::keypair();
    (
        HistoryAuthorityDescriptor {
            scope_id: [seed; 32],
            public_key: public_key.as_bytes().to_vec(),
        },
        secret_key,
    )
}

fn parent_attestation_id(prev_history_commitment_id: &[u8; 32]) -> [u8; 32] {
    if *prev_history_commitment_id == [0u8; 32] {
        return [0u8; 32];
    }
    let mut parent = *prev_history_commitment_id;
    parent[0] ^= 0xA5;
    parent
}

fn sign_global_history_attestation(
    authority: &HistoryAuthorityDescriptor,
    secret_key: &dilithium5::SecretKey,
    gid: &[u8; 32],
    history_commitment: &HistoryCommitment,
    barrier_version: u64,
    kem_tree_hash_after: &[u8; 32],
) -> Result<(Vec<u8>, GlobalHistoryAttestation), Box<dyn StdError>> {
    let parent_attestation_id =
        parent_attestation_id(&history_commitment.prev_history_commitment_id);
    let finality_kind = "local-append-only".to_string();
    let payload = encode_cbor_det(&GlobalHistoryAttestationSignedPayload(
        "cityg/global-history-attestation-v1",
        &authority.scope_id,
        gid,
        &history_commitment.history_view_id,
        &history_commitment.history_commitment_id,
        &history_commitment.prev_history_commitment_id,
        history_commitment.history_seq,
        barrier_version,
        kem_tree_hash_after,
        &parent_attestation_id,
        finality_kind.as_str(),
    ))?;
    let signature = dilithium5::detached_sign(payload.as_slice(), secret_key)
        .as_bytes()
        .to_vec();
    let wire = encode_cbor_det(&GlobalHistoryAttestationWire(
        authority.scope_id.to_vec(),
        gid.to_vec(),
        history_commitment.history_view_id.to_vec(),
        history_commitment.history_commitment_id.to_vec(),
        history_commitment.prev_history_commitment_id.to_vec(),
        history_commitment.history_seq,
        barrier_version,
        kem_tree_hash_after.to_vec(),
        parent_attestation_id.to_vec(),
        finality_kind.clone(),
        signature.clone(),
    ))?;
    Ok((
        wire,
        GlobalHistoryAttestation {
            scope_id: authority.scope_id,
            gid: *gid,
            history_commitment: *history_commitment,
            barrier_version,
            kem_tree_hash_after: *kem_tree_hash_after,
            parent_attestation_id,
            finality_kind,
            signature,
        },
    ))
}

fn sign_helper_completeness_attestation<T: Serialize>(
    authority: &HistoryAuthorityDescriptor,
    secret_key: &dilithium5::SecretKey,
    helper_kind: &'static str,
    history_commitment: &HistoryCommitment,
    page_offset: u32,
    total_entries: u32,
    selector: T,
) -> Result<Vec<u8>, Box<dyn StdError>> {
    let payload = encode_cbor_det(&HelperCompletenessSignedPayload {
        label: "cityg/helper-completeness-attestation-v1",
        scope_id: &authority.scope_id,
        helper_kind,
        history_view_id: &history_commitment.history_view_id,
        history_commitment_id: &history_commitment.history_commitment_id,
        page_offset,
        total_entries,
        selector,
    })?;
    let signature = dilithium5::detached_sign(payload.as_slice(), secret_key)
        .as_bytes()
        .to_vec();
    encode_cbor_det(&HelperCompletenessAttestationWire(
        authority.scope_id.to_vec(),
        helper_kind.to_string(),
        signature,
    ))
}

#[test]
fn parses_and_verifies_history_authority_extensions() -> Result<(), Box<dyn StdError>> {
    let gid = [0x41; 32];
    let history_commitment = HistoryCommitment {
        history_view_id: [0xD1; 32],
        history_commitment_id: [0xE1; 32],
        prev_history_commitment_id: [0x00; 32],
        history_seq: 7,
    };
    let (authority, secret_key) = history_authority(0xA1);
    let descriptor_bytes = encode_cbor_det(&HistoryAuthorityDescriptorWire(
        authority.scope_id.to_vec(),
        authority.public_key.clone(),
    ))?;
    let parsed_authority = parse_history_authority_descriptor_bytes(&descriptor_bytes)?
        .ok_or("authority descriptor should parse")?;
    assert_eq!(parsed_authority, authority);

    let (global_attestation_bytes, expected_attestation) = sign_global_history_attestation(
        &authority,
        &secret_key,
        &gid,
        &history_commitment,
        7,
        &[0xCF; 32],
    )?;
    let parsed_attestation =
        parse_global_history_attestation_bytes(&global_attestation_bytes, Some(&authority))?
            .ok_or("global attestation should parse")?;
    assert_eq!(parsed_attestation, expected_attestation);

    let revoked_bytes = sign_helper_completeness_attestation(
        &authority,
        &secret_key,
        HELPER_KIND_REVOKED_OCCUPANCIES,
        &history_commitment,
        0,
        2,
        RevokedOccupanciesSelector {
            revocation_roots_hash: &[0xDD; 32],
            records: &[
                BarrierRevokedOccupancyRecord {
                    slot_index: 1,
                    slot_generation: 0,
                },
                BarrierRevokedOccupancyRecord {
                    slot_index: 7,
                    slot_generation: 2,
                },
            ],
        },
    )?;
    let revoked_attestation =
        parse_revoked_occupancies_completeness_attestation_bytes(&revoked_bytes, &authority)?
            .ok_or("revoked helper attestation should parse")?;
    assert_eq!(
        revoked_attestation,
        HelperCompletenessAttestation {
            scope_id: authority.scope_id,
            helper_kind: HELPER_KIND_REVOKED_OCCUPANCIES.to_string(),
            signature: revoked_attestation.signature.clone(),
        }
    );
    verify_revoked_occupancies_completeness_attestation(
        &revoked_attestation,
        &authority,
        &history_commitment,
        &[0xDD; 32],
        0,
        2,
        &[
            BarrierRevokedOccupancyRecord {
                slot_index: 1,
                slot_generation: 0,
            },
            BarrierRevokedOccupancyRecord {
                slot_index: 7,
                slot_generation: 2,
            },
        ],
    )?;

    let join_record = BarrierJoinOccupancyRecord {
        device_pk: vec![0xAA; 32],
        slot_index: 9,
        slot_generation: 0,
        ek_leaf: vec![0xBB; 1184],
    };
    let joins_bytes = sign_helper_completeness_attestation(
        &authority,
        &secret_key,
        HELPER_KIND_JOIN_OCCUPANCIES_SINCE,
        &history_commitment,
        0,
        1,
        JoinsSinceSelector {
            prev_barrier_version: 3,
            records: std::slice::from_ref(&join_record),
        },
    )?;
    let joins_attestation =
        parse_join_occupancies_since_completeness_attestation_bytes(&joins_bytes, &authority)?
            .ok_or("joins helper attestation should parse")?;
    verify_join_occupancies_since_completeness_attestation(
        &joins_attestation,
        &authority,
        &history_commitment,
        3,
        0,
        1,
        std::slice::from_ref(&join_record),
    )?;

    let pk_entries = vec![Vec::new(); 15];
    let tree_bytes = sign_helper_completeness_attestation(
        &authority,
        &secret_key,
        HELPER_KIND_FETCH_PUBLIC_TREE,
        &history_commitment,
        0,
        pk_entries.len() as u32,
        FetchPublicTreeSelector {
            kem_tree_hash_after: &[0xCF; 32],
            pk_entries: pk_entries.as_slice(),
        },
    )?;
    let tree_attestation =
        parse_fetch_public_tree_completeness_attestation_bytes(&tree_bytes, &authority)?
            .ok_or("tree helper attestation should parse")?;
    verify_fetch_public_tree_completeness_attestation(
        &tree_attestation,
        &authority,
        &history_commitment,
        &[0xCF; 32],
        0,
        pk_entries.len() as u32,
        pk_entries.as_slice(),
    )?;

    Ok(())
}

#[test]
fn helper_completeness_attestation_binds_slot_generation() -> Result<(), Box<dyn StdError>> {
    let history_commitment = HistoryCommitment {
        history_view_id: [0x61; 32],
        history_commitment_id: [0x62; 32],
        prev_history_commitment_id: [0x63; 32],
        history_seq: 23,
    };
    let (authority, secret_key) = history_authority(0xB1);

    let revoked_records = [
        BarrierRevokedOccupancyRecord {
            slot_index: 7,
            slot_generation: 0,
        },
        BarrierRevokedOccupancyRecord {
            slot_index: 7,
            slot_generation: 2,
        },
    ];
    let revoked_bytes = sign_helper_completeness_attestation(
        &authority,
        &secret_key,
        HELPER_KIND_REVOKED_OCCUPANCIES,
        &history_commitment,
        0,
        2,
        RevokedOccupanciesSelector {
            revocation_roots_hash: &[0x91; 32],
            records: &revoked_records,
        },
    )?;
    let revoked_attestation =
        parse_revoked_occupancies_completeness_attestation_bytes(&revoked_bytes, &authority)?
            .ok_or("revoked helper attestation should parse")?;
    verify_revoked_occupancies_completeness_attestation(
        &revoked_attestation,
        &authority,
        &history_commitment,
        &[0x91; 32],
        0,
        2,
        &revoked_records,
    )?;
    let mut tampered_revoked_records = revoked_records;
    tampered_revoked_records[1].slot_generation = 3;
    assert!(
        verify_revoked_occupancies_completeness_attestation(
            &revoked_attestation,
            &authority,
            &history_commitment,
            &[0x91; 32],
            0,
            2,
            &tampered_revoked_records,
        )
        .is_err(),
        "revoked helper attestation must bind slot_generation",
    );

    let join_record = BarrierJoinOccupancyRecord {
        device_pk: vec![0xAA; 32],
        slot_index: 9,
        slot_generation: 2,
        ek_leaf: vec![0xBB; 1184],
    };
    let joins_bytes = sign_helper_completeness_attestation(
        &authority,
        &secret_key,
        HELPER_KIND_JOIN_OCCUPANCIES_SINCE,
        &history_commitment,
        0,
        1,
        JoinsSinceSelector {
            prev_barrier_version: 8,
            records: std::slice::from_ref(&join_record),
        },
    )?;
    let joins_attestation =
        parse_join_occupancies_since_completeness_attestation_bytes(&joins_bytes, &authority)?
            .ok_or("joins helper attestation should parse")?;
    verify_join_occupancies_since_completeness_attestation(
        &joins_attestation,
        &authority,
        &history_commitment,
        8,
        0,
        1,
        std::slice::from_ref(&join_record),
    )?;
    let mut tampered_join_record = join_record.clone();
    tampered_join_record.slot_generation = 3;
    assert!(
        verify_join_occupancies_since_completeness_attestation(
            &joins_attestation,
            &authority,
            &history_commitment,
            8,
            0,
            1,
            std::slice::from_ref(&tampered_join_record),
        )
        .is_err(),
        "joins helper attestation must bind slot_generation",
    );

    Ok(())
}
