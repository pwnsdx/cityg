//! `registry.json`: sparse Merkle maps and registry headers (docs/specs.md
//! section 8, with the map of keys, the admission mode and the authorizer
//! of docs/specs-v0.5-draft.md sections 4.2 and 4.9).

use std::collections::BTreeMap;

use ciborium::value::Value as Cbor;
use cityg_core::cbor;
use cityg_core::crypto::{PROFILE, ZERO32};
use cityg_core::objects::AdmissionMode;
use cityg_core::registry::RegistryHeader;
use cityg_core::smm::{Smm, SmmProof};
use cityg_core::tree::Occupancy;
use serde_json::{Value, json};

use crate::crypto_basics::labelled;
use crate::support::{
    Sampler, digest, digest_list, get, hex, list, occupancy, occupancy_of, text, uint,
};

pub const FILE: &str = "registry.json";

const SIZES: [usize; 3] = [0, 1, 4];
const ABSENT: usize = 2;

fn entries_of(v: &Value) -> Vec<([u8; 32], Occupancy)> {
    list(v, "entries")
        .iter()
        .map(|entry| (digest(entry, "key"), occupancy_of(get(entry, "value"))))
        .collect()
}

fn smm_case(s: &mut Sampler, size: usize) -> (Smm, Value) {
    let mut map = Smm::new();
    let entries: Vec<([u8; 32], Occupancy)> = (0..size)
        .map(|i| {
            let occupancy = Occupancy {
                leaf: u32::try_from(3 * i).unwrap(),
                since: u64::try_from(i).unwrap(),
            };
            (s.seed(), occupancy)
        })
        .collect();
    for (key, value) in &entries {
        map.insert(*key, *value);
    }
    let root = map.root().unwrap();
    let mut queries: Vec<[u8; 32]> = entries.iter().map(|(key, _)| *key).collect();
    queries.extend((0..ABSENT).map(|_| s.seed()));
    let proofs: Vec<Value> = queries
        .iter()
        .map(|key| {
            let proof = map.prove(key).unwrap();
            let value = proof.verify(&root, key).unwrap();
            assert_eq!(value, map.get(key));
            json!({
                "key": hex(key),
                "siblings": proof.siblings.iter().map(|digest| hex(digest)).collect::<Vec<_>>(),
                "terminal": proof.terminal.map_or(Value::Null, |(key, value)| json!({"key": hex(&key), "value": occupancy(value)})),
                "value": value.map_or(Value::Null, occupancy),
            })
        })
        .collect();
    let case = json!({
        "entries": entries.iter().map(|(key, value)| json!({"key": hex(key), "value": occupancy(*value)})).collect::<Vec<_>>(),
        "root": hex(&root),
        "proofs": proofs,
    });
    (map, case)
}

fn header_fields(header: &RegistryHeader) -> Vec<Cbor> {
    vec![
        cbor::array(
            header
                .admins
                .iter()
                .map(|(occupancy, key)| cbor::array(vec![occupancy.value(), cbor::bytes(key)]))
                .collect(),
        ),
        cbor::bytes(&header.devices_root),
        cbor::bytes(&header.admissions_root),
        cbor::bytes(&header.keys_root),
        header
            .policy
            .as_ref()
            .map_or(Cbor::Null, |digest| cbor::bytes(digest)),
        cbor::uint(header.admission.code()),
        header
            .authorizer
            .as_ref()
            .map_or(Cbor::Null, |digest| cbor::bytes(digest)),
    ]
}

/// The vector of a registry header: its fields, the preimage of its hash
/// and the hash.
pub fn header_json(header: &RegistryHeader) -> Value {
    let (fields, hash) = labelled("registry", header_fields(header));
    assert_eq!(hash, header.hash().unwrap());
    json!({
        "admins": header.admins.iter().map(|(occupancy, key)| json!({"occupancy": crate::support::occupancy(*occupancy), "public_key": hex(key)})).collect::<Vec<_>>(),
        "devices_root": hex(&header.devices_root),
        "admissions_root": hex(&header.admissions_root),
        "keys_root": hex(&header.keys_root),
        "policy": header.policy.map_or(Value::Null, |digest| hex(&digest)),
        "admission_mode": header.admission.code(),
        "authorizer": header.authorizer.map_or(Value::Null, |digest| hex(&digest)),
        "preimage": hex(&fields),
        "hash": hex(&hash),
    })
}

/// The registry header a vector lists.
pub fn header_of(v: &Value) -> RegistryHeader {
    let optional = |key: &str| match get(v, key) {
        Value::Null => None,
        other => Some(crate::support::digest_of(other)),
    };
    RegistryHeader {
        admins: list(v, "admins")
            .iter()
            .map(|admin| {
                (
                    occupancy_of(get(admin, "occupancy")),
                    crate::support::bytes(admin, "public_key"),
                )
            })
            .collect(),
        devices_root: digest(v, "devices_root"),
        admissions_root: digest(v, "admissions_root"),
        keys_root: digest(v, "keys_root"),
        policy: optional("policy"),
        admission: AdmissionMode::from_code(uint(v, "admission_mode")).unwrap(),
        authorizer: optional("authorizer"),
    }
}

pub fn generate(s: &mut Sampler) -> Value {
    let mut maps = Vec::new();
    let mut cases = Vec::new();
    for size in SIZES {
        let (map, case) = smm_case(s, size);
        maps.push(map);
        cases.push(case);
    }
    let (_, creator) = s.device();
    let (_, other) = s.device();
    let authorized = RegistryHeader {
        admins: BTreeMap::from([
            (
                Occupancy { leaf: 0, since: 0 },
                creator.public_key().to_vec(),
            ),
            (Occupancy { leaf: 5, since: 2 }, other.public_key().to_vec()),
        ]),
        devices_root: maps[2].root().unwrap(),
        admissions_root: maps[1].root().unwrap(),
        keys_root: maps[2].root().unwrap(),
        policy: Some(s.seed()),
        admission: AdmissionMode::Authorized,
        authorizer: Some(s.seed()),
    };
    let closed = RegistryHeader {
        admins: BTreeMap::from([(
            Occupancy { leaf: 0, since: 0 },
            creator.public_key().to_vec(),
        )]),
        devices_root: maps[1].root().unwrap(),
        admissions_root: ZERO32,
        keys_root: maps[1].root().unwrap(),
        policy: None,
        admission: AdmissionMode::Closed,
        authorizer: None,
    };
    json!({
        "profile": PROFILE,
        "sparse_merkle_maps": cases,
        "registry_headers": [header_json(&authorized), header_json(&closed)],
    })
}

/// Check the file: roots follow from the entries, proofs verify, and the
/// registry hash follows from the header's fields.
pub fn check(v: &Value) {
    assert_eq!(text(v, "profile"), PROFILE);
    for case in list(v, "sparse_merkle_maps") {
        let entries = entries_of(case);
        let mut map = Smm::new();
        for (key, value) in &entries {
            map.insert(*key, *value);
        }
        let root = digest(case, "root");
        assert_eq!(map.root().unwrap(), root);
        match entries.as_slice() {
            [] => assert_eq!(root, ZERO32),
            [(key, value)] => assert_eq!(
                root,
                labelled("smm/leaf", vec![cbor::bytes(key), value.value()]).1
            ),
            _ => {}
        }
        for proof in list(case, "proofs") {
            let key = digest(proof, "key");
            let expected = match get(proof, "value") {
                Value::Null => None,
                value => Some(occupancy_of(value)),
            };
            let terminal = match get(proof, "terminal") {
                Value::Null => None,
                terminal => Some((
                    digest(terminal, "key"),
                    occupancy_of(get(terminal, "value")),
                )),
            };
            let proof = SmmProof {
                siblings: digest_list(proof, "siblings"),
                terminal,
            };
            assert_eq!(proof.verify(&root, &key).unwrap(), expected);
            assert_eq!(
                expected,
                entries
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, value)| *value)
            );
        }
    }
    for record in list(v, "registry_headers") {
        let header = header_of(record);
        let (preimage, hash) = labelled("registry", header_fields(&header));
        assert_eq!(preimage, crate::support::bytes(record, "preimage"));
        assert_eq!(hash, digest(record, "hash"));
        assert_eq!(header.hash().unwrap(), hash);
    }
}
