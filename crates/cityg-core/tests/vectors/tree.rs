//! `tree.json`: leaf and parent nodes, the hashes of a small tree and leaf
//! proofs (docs/specs.md section 5 with the leaf of
//! docs/specs-v0.5-draft.md section 4.1).

use ciborium::value::Value as Cbor;
use cityg_core::card::{CardKey, LeafKeys};
use cityg_core::cbor;
use cityg_core::crypto::{PROFILE, ZERO32, node_key};
use cityg_core::tree::{
    Divisions, LeafNode, LeafProof, NodeId, Occupancy, ParentNode, ProofStep, PublicTree,
};
use serde_json::{Value, json};

use crate::crypto_basics::labelled;
use crate::support::{
    Sampler, bytes, digest, digest_of, get, hex, list, node, node_of, occupancy, occupancy_of,
    optional_bytes, optional_hex, replay, text, u8_of, u32_of, uint,
};

pub const FILE: &str = "tree.json";

const HEIGHT: u8 = 2;
const DIVISIONS: (u8, u8, u8) = (2, 1, 1);
/// Occupied leaves: index, since, updated, and whether an admission hash
/// is set (the creator's is `ZERO32`).
const LEAVES: [(u32, u64, u64, bool); 2] = [(0, 0, 0, false), (2, 1, 1, true)];
/// Keyed parents and their taints.
const PARENTS: [((u8, u32), (u32, u64)); 2] = [((1, 0), (0, 0)), ((2, 0), (2, 1))];

fn divisions() -> Divisions {
    Divisions::new(DIVISIONS.0, DIVISIONS.1, DIVISIONS.2).unwrap()
}

fn all_nodes(height: u8) -> Vec<NodeId> {
    (0..=height)
        .flat_map(|level| (0..1u32 << (height - level)).map(move |index| NodeId { level, index }))
        .collect()
}

pub fn generate(s: &mut Sampler) -> Value {
    let gid = s.seed();
    let mut tree = PublicTree::new(HEIGHT, divisions()).unwrap();
    let leaves: Vec<Value> = LEAVES
        .iter()
        .map(|(index, since, updated, admitted)| {
            let (device_seed, device) = s.device();
            let (leaf_seed, leaf_key) = s.kem();
            let encryption_key = leaf_key.public_key();
            let card_seed = s.seed();
            let card = replay(&[&card_seed], CardKey::generate).card();
            let admission_hash = if *admitted { s.seed() } else { ZERO32 };
            let leaf = LeafNode::new(
                &gid,
                device.public_key(),
                *since,
                LeafKeys {
                    encryption_key: &encryption_key,
                    card: &card,
                },
                admission_hash,
                *updated,
            )
            .unwrap();
            tree.set_leaf(*index, Some(leaf.clone())).unwrap();
            json!({
                "index": index,
                "device_seed": hex(&device_seed),
                "device_pk": hex(device.public_key()),
                "device_id": hex(&leaf.device_id),
                "since": since,
                "leaf_seed": hex(&leaf_seed),
                "encryption_key": hex(&encryption_key),
                "card_seed": hex(&card_seed),
                "card": hex(&cbor::encode(&card.value()).unwrap()),
                "admission_hash": hex(&admission_hash),
                "updated": updated,
                "value": hex(&cbor::encode(&leaf.value()).unwrap()),
                "summary": hex(&cbor::encode(&leaf.summary().unwrap()).unwrap()),
                "hash": hex(&tree.node_hash(NodeId::leaf(*index)).unwrap()),
            })
        })
        .collect();
    let parents: Vec<Value> = PARENTS
        .iter()
        .map(|((level, index), (leaf, since))| {
            let secret = s.seed();
            let parent = ParentNode {
                encryption_key: node_key(&secret).unwrap().public_key(),
                taint: Occupancy {
                    leaf: *leaf,
                    since: *since,
                },
            };
            let id = NodeId {
                level: *level,
                index: *index,
            };
            tree.set_parent(id, Some(parent.clone())).unwrap();
            json!({
                "node": node(id),
                "secret": hex(&secret),
                "encryption_key": hex(&parent.encryption_key),
                "taint": occupancy(parent.taint),
                "content_digest": hex(&parent.content_digest().unwrap()),
            })
        })
        .collect();
    let node_hashes: Vec<Value> = all_nodes(HEIGHT)
        .into_iter()
        .map(|id| json!({"node": node(id), "hash": hex(&tree.node_hash(id).unwrap())}))
        .collect();
    let proofs: Vec<Value> = (0..1u32 << HEIGHT)
        .map(|index| {
            let proof = tree.leaf_proof(index).unwrap();
            json!({
                "index": index,
                "leaf": optional_hex(proof.leaf.as_ref().map(|leaf| cbor::encode(&leaf.value()).unwrap()).as_deref()),
                "steps": proof.steps.iter().map(|step| json!({
                    "content": optional_hex(step.content.as_ref().map(|digest| &digest[..])),
                    "sibling_hash": hex(&step.sibling_hash),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "profile": PROFILE,
        "gid": hex(&gid),
        "divisions": {"district_bits": DIVISIONS.0, "island_bits": DIVISIONS.1, "subcity_bits": DIVISIONS.2},
        "height": HEIGHT,
        "empty_hashes": (0..=HEIGHT).map(|level| hex(&tree.empty_hash(level))).collect::<Vec<_>>(),
        "leaves": leaves,
        "parents": parents,
        "node_hashes": node_hashes,
        "tree_hash": hex(&tree.tree_hash().unwrap()),
        "district_hashes": (0..tree.shape().district_count()).map(|district| json!({"district": district, "hash": hex(&tree.district_hash(district).unwrap())})).collect::<Vec<_>>(),
        "leaf_proofs": proofs,
    })
}

fn leaf_hash(summary: Option<&[u8]>) -> [u8; 32] {
    let summary = summary.map_or(Cbor::Null, |summary| {
        cbor::decode(summary, 4096, "summary").unwrap()
    });
    labelled("tree/leaf", vec![summary]).1
}

fn parent_hash(content: Option<&[u8; 32]>, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    labelled(
        "tree/parent",
        vec![
            content.map_or(Cbor::Null, |digest| cbor::bytes(digest)),
            cbor::bytes(left),
            cbor::bytes(right),
        ],
    )
    .1
}

/// Check the file: every hash follows from the nodes, and every proof
/// verifies.
pub fn check(v: &Value) {
    assert_eq!(text(v, "profile"), PROFILE);
    let gid = digest(v, "gid");
    let height = u8_of(v, "height");
    let empty: Vec<[u8; 32]> = list(v, "empty_hashes").iter().map(digest_of).collect();
    assert_eq!(empty[0], leaf_hash(None));
    for level in 1..=usize::from(height) {
        assert_eq!(
            empty[level],
            parent_hash(None, &empty[level - 1], &empty[level - 1])
        );
    }
    let mut hashes = std::collections::BTreeMap::new();
    for record in list(v, "node_hashes") {
        hashes.insert(node_of(get(record, "node")), digest(record, "hash"));
    }
    let mut occupied = std::collections::BTreeMap::new();
    for record in list(v, "leaves") {
        let index = u32_of(record, "index");
        let value = bytes(record, "value");
        let leaf = LeafNode::from_value(cbor::decode(&value, 8192, "leaf").unwrap(), &gid).unwrap();
        assert_eq!(cbor::encode(&leaf.value()).unwrap(), value);
        assert_eq!(leaf.device_pk, bytes(record, "device_pk"));
        assert_eq!(
            leaf.device_id,
            labelled(
                "device-id",
                vec![cbor::bytes(&gid), cbor::bytes(&leaf.device_pk)]
            )
            .1
        );
        assert_eq!(leaf.device_id, digest(record, "device_id"));
        assert_eq!(
            (leaf.since, leaf.updated),
            (uint(record, "since"), uint(record, "updated"))
        );
        assert_eq!(leaf.encryption_key, bytes(record, "encryption_key"));
        assert_eq!(
            cbor::encode(&leaf.card.value()).unwrap(),
            bytes(record, "card")
        );
        assert_eq!(leaf.admission_hash, digest(record, "admission_hash"));
        let summary = bytes(record, "summary");
        let expected_summary = cbor::encode(&cbor::array(vec![
            cbor::bytes(&leaf.device_id),
            cbor::uint(leaf.since),
            cbor::bytes(&labelled("tree/leaf-key", vec![cbor::bytes(&leaf.encryption_key)]).1),
            leaf.card.value(),
            cbor::bytes(&leaf.admission_hash),
            cbor::uint(leaf.updated),
        ]))
        .unwrap();
        assert_eq!(summary, expected_summary);
        let hash = leaf_hash(Some(&summary));
        assert_eq!(hash, digest(record, "hash"));
        assert_eq!(hashes[&NodeId::leaf(index)], hash);
        occupied.insert(index, leaf);
    }
    let mut keyed = std::collections::BTreeMap::new();
    for record in list(v, "parents") {
        let id = node_of(get(record, "node"));
        let parent = ParentNode {
            encryption_key: bytes(record, "encryption_key"),
            taint: occupancy_of(get(record, "taint")),
        };
        assert_eq!(
            parent.encryption_key,
            node_key(&digest(record, "secret")).unwrap().public_key()
        );
        let content = labelled(
            "tree/node",
            vec![cbor::bytes(&parent.encryption_key), parent.taint.value()],
        )
        .1;
        assert_eq!(content, digest(record, "content_digest"));
        keyed.insert(id, content);
    }
    for (id, hash) in &hashes {
        if id.level == 0 {
            assert_eq!(*hash, occupied.get(&id.index).map_or(empty[0], |_| *hash));
            continue;
        }
        let [left, right] = id.children();
        assert_eq!(
            *hash,
            parent_hash(keyed.get(id), &hashes[&left], &hashes[&right])
        );
    }
    let tree_hash = digest(v, "tree_hash");
    assert_eq!(
        tree_hash,
        hashes[&NodeId {
            level: height,
            index: 0
        }]
    );
    for record in list(v, "leaf_proofs") {
        let proof = LeafProof {
            index: u32_of(record, "index"),
            leaf: optional_bytes(record, "leaf").map(|value| {
                LeafNode::from_value(cbor::decode(&value, 8192, "leaf").unwrap(), &gid).unwrap()
            }),
            steps: list(record, "steps")
                .iter()
                .map(|step| ProofStep {
                    content: optional_bytes(step, "content")
                        .map(|digest| digest.try_into().unwrap()),
                    sibling_hash: digest(step, "sibling_hash"),
                })
                .collect(),
        };
        proof.verify(&tree_hash).unwrap();
        assert_eq!(proof.leaf, occupied.get(&proof.index).cloned());
    }
}
