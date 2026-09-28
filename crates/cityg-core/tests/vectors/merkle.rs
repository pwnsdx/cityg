//! `merkle.json`: the labelled Merkle trees of the message log,
//! authorization batches and the membership log (docs/specs-v0.5-draft.md
//! sections 4.8 to 4.10), and the records of the membership log.

use cityg_core::card::CardKey;
use cityg_core::cbor;
use cityg_core::crypto::{PROFILE, h};
use cityg_core::membership::{self, MembershipLog, MembershipRecord};
use cityg_core::merkle;
use cityg_core::objects::ChangeKind;
use serde_json::{Value, json};

use crate::crypto_basics::labelled;
use crate::support::{
    Sampler, bytes, digest, digest_list, get, hex, list, replay, text, u32_of, uint,
};

pub const FILE: &str = "merkle.json";

const LABELS: [&str; 3] = ["msg-log", "authorized", "membership-log"];
const COUNTS: [usize; 6] = [0, 1, 2, 3, 5, 8];
const RECORDS: [(ChangeKind, u32); 4] = [
    (ChangeKind::Removal, 2),
    (ChangeKind::Join, 5),
    (ChangeKind::Update, 9),
    (ChangeKind::ReEntry, 12),
];

/// `MTH(label, leaves)` from its definition.
pub fn mth(label: &str, leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves {
        [] => labelled(label, vec![]).1,
        [only] => labelled(label, vec![cbor::bytes(only)]).1,
        _ => {
            let mut k = 1;
            while k * 2 < leaves.len() {
                k *= 2;
            }
            labelled(
                label,
                vec![
                    cbor::bytes(&mth(label, &leaves[..k])),
                    cbor::bytes(&mth(label, &leaves[k..])),
                ],
            )
            .1
        }
    }
}

pub fn generate(s: &mut Sampler) -> Value {
    let trees: Vec<Value> = LABELS
        .iter()
        .map(|label| {
            let cases: Vec<Value> = COUNTS
                .iter()
                .map(|count| {
                    let leaves: Vec<[u8; 32]> = (0..*count).map(|_| s.seed()).collect();
                    let root = merkle::root(label, &leaves).unwrap();
                    assert_eq!(root, mth(label, &leaves));
                    let proofs: Vec<Value> = (0..*count)
                        .map(|index| {
                            let proof = merkle::inclusion_proof(label, &leaves, index).unwrap();
                            Value::Array(proof.iter().map(|digest| hex(digest)).collect())
                        })
                        .collect();
                    json!({
                        "count": count,
                        "leaves": leaves.iter().map(|leaf| hex(leaf)).collect::<Vec<_>>(),
                        "root": hex(&root),
                        "proofs": proofs,
                    })
                })
                .collect();
            json!({"label": label, "cases": cases})
        })
        .collect();
    let records: Vec<(MembershipRecord, [u8; 32], Vec<u8>)> = RECORDS
        .iter()
        .map(|(kind, leaf)| {
            let device_id = s.seed();
            let card_seed = s.seed();
            let card = replay(&[&card_seed], CardKey::generate).card();
            (
                MembershipRecord::new(*kind, *leaf, device_id, &card).unwrap(),
                card_seed,
                cbor::encode(&card.value()).unwrap(),
            )
        })
        .collect();
    let plain: Vec<MembershipRecord> = records.iter().map(|(record, _, _)| *record).collect();
    let log = MembershipLog::of(&plain).unwrap();
    let listed: Vec<Value> = records
        .iter()
        .enumerate()
        .map(|(index, (record, card_seed, card))| {
            json!({
                "kind": record.kind.code(),
                "leaf": record.leaf,
                "device_id": hex(&record.device_id),
                "card_seed": hex(card_seed),
                "card": hex(card),
                "card_prefix": hex(&record.card_prefix),
                "encoded": hex(&cbor::encode(&record.value()).unwrap()),
                "hash": hex(&record.hash().unwrap()),
                "proof": membership::inclusion_proof(&plain, index).unwrap().iter().map(|digest| hex(digest)).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "profile": PROFILE,
        "trees": trees,
        "membership_log": {
            "records": listed,
            "count": log.count,
            "root": hex(&log.root),
            "encoded": hex(&cbor::encode(&log.value()).unwrap()),
        },
    })
}

/// Check the file: roots follow from the leaves, and every proof verifies.
pub fn check(v: &Value) {
    assert_eq!(text(v, "profile"), PROFILE);
    for tree in list(v, "trees") {
        let label = text(tree, "label");
        for case in list(tree, "cases") {
            let leaves = digest_list(case, "leaves");
            assert_eq!(leaves.len(), usize::try_from(uint(case, "count")).unwrap());
            let root = digest(case, "root");
            assert_eq!(mth(label, &leaves), root);
            let proofs = list(case, "proofs");
            assert_eq!(proofs.len(), leaves.len());
            for (index, (leaf, proof)) in leaves.iter().zip(proofs).enumerate() {
                let proof: Vec<[u8; 32]> = proof
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(crate::support::digest_of)
                    .collect();
                let count = u64::try_from(leaves.len()).unwrap();
                merkle::verify_inclusion(label, &root, count, index as u64, leaf, &proof).unwrap();
                let other = leaves[(index + 1) % leaves.len()];
                if other != *leaf {
                    assert!(
                        merkle::verify_inclusion(label, &root, count, index as u64, &other, &proof)
                            .is_err()
                    );
                }
            }
        }
    }
    let log = get(v, "membership_log");
    let records: Vec<MembershipRecord> = list(log, "records")
        .iter()
        .map(|record| {
            let encoded = bytes(record, "encoded");
            let decoded =
                MembershipRecord::from_value(cbor::decode(&encoded, 128, "record").unwrap())
                    .unwrap();
            assert_eq!(decoded.kind.code(), uint(record, "kind"));
            assert_eq!(decoded.leaf, u32_of(record, "leaf"));
            assert_eq!(decoded.device_id, digest(record, "device_id"));
            let card_hash = labelled(
                "card",
                vec![cbor::decode(&bytes(record, "card"), 4096, "card").unwrap()],
            )
            .1;
            assert_eq!(card_hash[..8], decoded.card_prefix);
            assert_eq!(decoded.card_prefix.to_vec(), bytes(record, "card_prefix"));
            assert_eq!(h(&encoded), digest(record, "hash"));
            decoded
        })
        .collect();
    let sealed = MembershipLog {
        count: uint(log, "count"),
        root: digest(log, "root"),
    };
    assert_eq!(
        cbor::encode(&sealed.value()).unwrap(),
        bytes(log, "encoded")
    );
    sealed.check(&records).unwrap();
    let hashes: Vec<[u8; 32]> = records
        .iter()
        .map(|record| record.hash().unwrap())
        .collect();
    assert_eq!(mth("membership-log", &hashes), sealed.root);
    for (index, (record, listed)) in records.iter().zip(list(log, "records")).enumerate() {
        let proof = digest_list(listed, "proof");
        sealed
            .verify_inclusion(index as u64, record, &proof)
            .unwrap();
    }
}
