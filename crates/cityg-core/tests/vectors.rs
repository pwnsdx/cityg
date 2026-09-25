#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Conformance vectors of the v0.3 profile (`kat/v0.3/vectors.json`).
//!
//! Every vector is computed here with the public API of `cityg-core` from
//! fixed inputs and seeded randomness, and compared with the published
//! file. `kat/v0.3/verify_vectors.py` recomputes the same values with an
//! independent implementation of the profile's encodings, derivations,
//! X-Wing and ML-DSA-65 verification.
//!
//! Regenerate the file after an intended change:
//! `CITYG_WRITE_VECTORS=1 cargo test -p cityg-core --test vectors`.

use std::path::PathBuf;

use ciborium::value::{Integer, Value};
use cityg_core::admission::{Invite, SignedAdmission, SignedInviteRevocation, invite_id};
use cityg_core::binding::{AliasBinding, SessionAuth};
use cityg_core::cbor::{array, bytes, encode, text, uint};
use cityg_core::commit::{Commit, CommitContent, CommitKind};
use cityg_core::cover::{CoverFailureReason, CoverFailureReport};
use cityg_core::group_info::GroupInfo;
use cityg_core::hash::{ZERO32, derive_secret, expand_label_into, extract, h, h_l, mac};
use cityg_core::identity::{DeviceIdentity, device_id, group_id};
use cityg_core::join::{JoinSecrets, SignedJoinRequest, Welcome};
use cityg_core::kem::{KemSecret, encapsulate, pk_hash};
use cityg_core::key_schedule::{
    EpochSecrets, GroupContext, confirmed_transcript_hash, external_init, interim_transcript_hash,
    joiner_secret,
};
use cityg_core::light::{LightCommit, LightJoin};
use cityg_core::message::{Envelope, EpochMessages, epoch_ref};
use cityg_core::proposal::{RemoveProposal, proposal_ref};
use cityg_core::registry::Registry;
use cityg_core::state::{stage_genesis, verify_genesis};
use cityg_core::tree::{
    LeafNode, MemberRef, PathContext, PublicTree, generate_update_path_from_leaf_secret,
    leaf_key_from_secret,
};
use cityg_pqc::SignatureContext;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde_json::{Value as Json, json};

fn hx(data: &[u8]) -> String {
    hex::encode(data)
}

fn filled(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../kat/v0.3/vectors.json")
}

/// A generator that returns fixed bytes (for the X-Wing draft vector).
struct Fixed(Vec<u8>);

impl RngCore for Fixed {
    fn next_u32(&mut self) -> u32 {
        let mut word = [0u8; 4];
        self.fill_bytes(&mut word);
        u32::from_le_bytes(word)
    }
    fn next_u64(&mut self) -> u64 {
        let mut word = [0u8; 8];
        self.fill_bytes(&mut word);
        u64::from_le_bytes(word)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let rest = self.0.split_off(dest.len());
        dest.copy_from_slice(&self.0);
        self.0 = rest;
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Fixed {}

/// CBOR value from the typed JSON notation of the vector file.
fn cbor_value(notation: &Json) -> Value {
    let object = notation.as_object().expect("typed value");
    let (kind, inner) = object.iter().next().expect("one entry");
    match kind.as_str() {
        "uint" => uint(inner.as_u64().expect("uint")),
        "nint" => Value::Integer(Integer::from(inner.as_i64().expect("nint"))),
        "bytes" => bytes(&hex::decode(inner.as_str().expect("hex")).expect("hex")),
        "text" => text(inner.as_str().expect("text")),
        "bool" => Value::Bool(inner.as_bool().expect("bool")),
        "null" => Value::Null,
        "array" => array(
            inner
                .as_array()
                .expect("array")
                .iter()
                .map(cbor_value)
                .collect(),
        ),
        "map" => Value::Map(
            inner
                .as_array()
                .expect("map")
                .iter()
                .map(|pair| {
                    let pair = pair.as_array().expect("pair");
                    (cbor_value(&pair[0]), cbor_value(&pair[1]))
                })
                .collect(),
        ),
        other => panic!("unknown typed value {other}"),
    }
}

fn cbor_cases() -> Json {
    let cases = [
        ("uint/0", json!({"uint": 0})),
        ("uint/23", json!({"uint": 23})),
        ("uint/24", json!({"uint": 24})),
        ("uint/255", json!({"uint": 255})),
        ("uint/256", json!({"uint": 256})),
        ("uint/65536", json!({"uint": 65536})),
        ("uint/2^32", json!({"uint": 4_294_967_296_u64})),
        ("nint/-1", json!({"nint": -1})),
        ("nint/-500", json!({"nint": -500})),
        ("bytes/empty", json!({"bytes": ""})),
        ("bytes/24", json!({"bytes": hx(&[0xAB; 24])})),
        ("text/ascii", json!({"text": "city-g/v0.3"})),
        ("text/utf8", json!({"text": "élan"})),
        ("bool/true", json!({"bool": true})),
        ("null", json!({"null": null})),
        (
            "array/nested",
            json!({"array": [{"uint": 1}, {"array": [{"text": "a"}, {"bytes": "00ff"}]}, {"array": []}]}),
        ),
        (
            "map/keys-sorted-by-encoding",
            json!({"map": [
                [{"uint": 111}, {"bytes": "11"}],
                [{"uint": 2}, {"bytes": "02"}],
                [{"uint": 17}, {"uint": 4}],
                [{"uint": 108}, {"bytes": "6c"}],
                [{"text": "a"}, {"null": null}],
                [{"nint": -1}, {"bool": false}]
            ]}),
        ),
    ];
    Json::Array(
        cases
            .into_iter()
            .map(|(id, value)| {
                let encoding = encode(&cbor_value(&value)).unwrap();
                json!({"id": format!("cbor/{id}"), "value": value, "encoding": hx(&encoding)})
            })
            .collect(),
    )
}

fn h_l_cases() -> Json {
    let cases = [
        ("empty-args", "test", json!([])),
        (
            "uint-and-bytes",
            "test",
            json!([{"uint": 1}, {"bytes": "61"}]),
        ),
        (
            "device-id-shape",
            "device-id",
            json!([{"bytes": hx(&filled(0x01))}, {"bytes": hx(&[0x02; 40])}]),
        ),
        (
            "registry-shape",
            "registry",
            json!([{"uint": 8}, {"array": [{"uint": 0}, {"uint": 3}]}, {"array": [{"array": [{"bytes": hx(&filled(0x05))}, {"uint": 4100}]}]}, {"uint": 0}]),
        ),
    ];
    Json::Array(
        cases
            .into_iter()
            .map(|(id, label, args)| {
                let values: Vec<Value> = args.as_array().unwrap().iter().map(cbor_value).collect();
                let digest = h_l(label, values).unwrap();
                json!({"id": format!("h_l/{id}"), "label": label, "args": args, "digest": hx(&digest)})
            })
            .collect(),
    )
}

fn kdf_cases() -> Json {
    let secret = filled(0x0B);
    let mut expand = Vec::new();
    for (label, context, length) in [
        ("epoch", vec![0x01u8; 32], 32usize),
        ("msg nonce", Vec::new(), 12),
        ("tree node key", Vec::new(), 32),
        ("long output", b"context".to_vec(), 100),
    ] {
        let mut out = vec![0u8; length];
        expand_label_into(&secret, label, &context, &mut out).unwrap();
        expand.push(json!({
            "secret": hx(&secret), "label": label, "context": hx(&context),
            "length": length, "output": hx(&out)
        }));
    }
    let prk = extract(&filled(0x01), &filled(0x02));
    json!({
        "h": [
            {"input": "", "digest": hx(&h(b""))},
            {"input": hx(b"city-g"), "digest": hx(&h(b"city-g"))}
        ],
        "extract": [
            {"salt": hx(&filled(0x01)), "ikm": hx(&filled(0x02)), "prk": hx(prk.as_ref())},
            {"salt": hx(&ZERO32), "ikm": "", "prk": hx(extract(&ZERO32, b"").as_ref())}
        ],
        "expand_label": expand,
        "derive_secret": [
            {"secret": hx(&secret), "label": "init",
             "output": hx(derive_secret(&secret, "init").unwrap().as_ref())},
            {"secret": hx(&secret), "label": "tree path",
             "output": hx(derive_secret(&secret, "tree path").unwrap().as_ref())}
        ],
        "mac": [
            {"key": hx(&filled(0x0C)), "data": hx(&filled(0x0D)),
             "tag": hx(&mac(&filled(0x0C), &filled(0x0D)).unwrap())}
        ]
    })
}

/// The primitives of the suite: X-Wing (draft vector 1, and `KeyGen` of a
/// derived key) and ML-DSA-65 (a key from a seed and a signature with a
/// context).
fn suite_case() -> Json {
    let seed: [u8; 32] =
        hex::decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
            .unwrap()
            .try_into()
            .unwrap();
    let eseed = hex::decode(
        "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2\
         35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
    )
    .unwrap();
    let key = KemSecret::from_seed(seed);
    let public_key = key.public_key();
    let (ciphertext, shared) = encapsulate(&public_key, &mut Fixed(eseed.clone())).unwrap();
    assert_eq!(
        hex::encode(*shared),
        "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384"
    );
    let derived = KemSecret::derive(&filled(0x21), "tree node key").unwrap();

    let mut rng = ChaCha20Rng::seed_from_u64(0x5A);
    let signer = DeviceIdentity::from_seed(&filled(0x22));
    let message = b"city-g signature vector";
    let signature = signer
        .sign(SignatureContext::MESSAGE, message, &mut rng)
        .unwrap();
    json!({
        "x_wing": {
            "seed": hx(&seed),
            "public_key": hx(&public_key),
            "eseed": hx(&eseed),
            "ciphertext": hx(&ciphertext),
            "shared_secret": hx(shared.as_ref())
        },
        "x_wing_keygen": {
            "secret": hx(&filled(0x21)),
            "label": "tree node key",
            "seed": hx(derived.seed()),
            "public_key": hx(&derived.public_key())
        },
        "ml_dsa_65": {
            "seed": hx(&filled(0x22)),
            "public_key": hx(signer.public_key()),
            "context": String::from_utf8(SignatureContext::MESSAGE.as_bytes().to_vec()).unwrap(),
            "message": hx(message),
            "signature": hx(&signature)
        }
    })
}

fn identifier_cases() -> Json {
    let device = DeviceIdentity::from_seed(&filled(0x31));
    let gid = filled(0x40);
    let nonce = filled(0x41);
    let invite = DeviceIdentity::from_seed(&filled(0x32));
    let kem = KemSecret::derive(&filled(0x33), "vector kem").unwrap();
    let kem_pk = kem.public_key();
    let member = MemberRef { leaf: 5, since: 12 };
    json!({
        "device_seed": hx(&filled(0x31)),
        "device_pk": hx(device.public_key()),
        "gid": hx(&gid),
        "device_id": hx(&device_id(&gid, device.public_key()).unwrap()),
        "group_nonce": hx(&nonce),
        "group_id": hx(&group_id(device.public_key(), &nonce).unwrap()),
        "invite_pk": hx(invite.public_key()),
        "invite_id": hx(&invite_id(invite.public_key()).unwrap()),
        "proposal": hx(b"signed proposal bytes"),
        "proposal_ref": hx(&proposal_ref(b"signed proposal bytes").unwrap()),
        "epoch": 7,
        "epoch_ref": hx(&epoch_ref(&gid, 7).unwrap()),
        "kem_seed": hx(kem.seed()),
        "kem_pk": hx(&kem_pk),
        "kem_pk_hash": hx(&pk_hash(&kem_pk).unwrap()),
        "member_ref": {"leaf": member.leaf, "since": member.since,
                       "encoding": hx(&encode(&member.to_value()).unwrap())}
    })
}

fn key_schedule_case() -> Json {
    let context = GroupContext {
        gid: filled(0x51),
        epoch: 3,
        tree_hash: filled(0x52),
        registry_hash: filled(0x53),
        confirmed_transcript_hash: filled(0x54),
    };
    let commit_secret = filled(0x55);
    let prev_init = filled(0x56);
    let joiner = joiner_secret(&prev_init, &commit_secret, &context).unwrap();
    let secrets = EpochSecrets::derive(&prev_init, &commit_secret, &context).unwrap();
    let from_joiner = EpochSecrets::from_joiner_secret(&joiner).unwrap();
    assert_eq!(secrets.init_secret(), from_joiner.init_secret());
    let retained = secrets.retained();
    let external_key = secrets.external_key().unwrap();
    let tag = secrets
        .confirmation_tag(&context.confirmed_transcript_hash)
        .unwrap();
    let confirmed = |rotation: Option<&[u8]>| {
        confirmed_transcript_hash(&filled(0x57), b"anchor tbs", b"signature", rotation).unwrap()
    };
    let plain = confirmed(None);
    let rotated = confirmed(Some(b"rotation signature"));
    let interim = interim_transcript_hash(&plain, &tag).unwrap();

    // External init: a joiner encapsulates to the epoch's external key.
    let mut rng = ChaCha20Rng::seed_from_u64(0xE1);
    let (kem_output, init) = external_init(&external_key.public_key(), &mut rng).unwrap();
    let shared = external_key.decapsulate(&kem_output).unwrap();
    assert_eq!(
        retained.external_init_secret(&kem_output).unwrap().as_ref(),
        init.as_ref()
    );
    json!({
        "group_context": {
            "gid": hx(&context.gid), "epoch": context.epoch,
            "tree_hash": hx(&context.tree_hash), "registry_hash": hx(&context.registry_hash),
            "confirmed_transcript_hash": hx(&context.confirmed_transcript_hash),
            "encoding": hx(&context.encode().unwrap()),
            "hash": hx(&context.hash().unwrap())
        },
        "commit_secret": hx(&commit_secret),
        "prev_init_secret": hx(&prev_init),
        "joiner_secret": hx(joiner.as_ref()),
        "init_secret": hx(secrets.init_secret()),
        "msg_secret": hx(secrets.msg_secret()),
        "external_secret": hx(retained.external_secret()),
        "external_kem_seed": hx(external_key.seed()),
        "external_public_key": hx(&external_key.public_key()),
        "confirmation_tag": hx(&tag),
        "transcript": {
            "prev_interim": hx(&filled(0x57)),
            "anchor_tbs": hx(b"anchor tbs"),
            "signature": hx(b"signature"),
            "rotation_signature": hx(b"rotation signature"),
            "confirmed": hx(&plain),
            "confirmed_with_rotation": hx(&rotated),
            "confirmation_tag": hx(&tag),
            "interim": hx(&interim)
        },
        "external_init": {
            "kem_output": hx(&kem_output),
            "shared_secret": hx(shared.as_ref()),
            "init_secret": hx(init.as_ref())
        }
    })
}

fn leaf(tag: u8, since: u64) -> LeafNode {
    LeafNode {
        device_pk: DeviceIdentity::from_seed(&filled(tag))
            .public_key()
            .to_vec(),
        since,
        encryption_key: KemSecret::derive(&filled(tag), "vector leaf")
            .unwrap()
            .public_key(),
        admission_hash: filled(tag.wrapping_add(1)),
    }
}

/// A tree of capacity 8: five members, a self-update by leaf 1 that keys
/// its path, then a removal (leaf 3) and a batched entry (leaf 3 again and
/// leaf 5), which leave blank and unmerged nodes.
fn sample_tree() -> PublicTree {
    let mut rng = ChaCha20Rng::seed_from_u64(0x7E);
    let mut tree = PublicTree::new(8).unwrap();
    for (index, tag) in [0x61u8, 0x62, 0x63, 0x64, 0x65].into_iter().enumerate() {
        tree.add_leaf(index as u32, leaf(tag, 1)).unwrap();
    }
    let context = PathContext {
        gid: filled(0x60),
        epoch: 2,
        author_leaf: 1,
    };
    let (path, _) =
        generate_update_path_from_leaf_secret(&tree, &context, &filled(0x6F), &mut rng).unwrap();
    tree.apply_update_path(1, &path).unwrap();
    tree.remove_leaf(3).unwrap();
    tree.add_leaf(3, leaf(0x66, 3)).unwrap();
    tree.add_leaf(5, leaf(0x67, 3)).unwrap();
    tree
}

fn tree_case() -> Json {
    let tree = sample_tree();
    let proofs = tree.leaf_proofs([2, 3, 6]).unwrap();
    let resolutions: Vec<Json> = [1u32, 3, 5, 7, 11, 13]
        .iter()
        .map(|node| json!({"node": node, "resolution": tree.resolution(*node)}))
        .collect();
    let leaf_proofs: Vec<Json> = proofs
        .iter()
        .map(|proof| json!({"leaf": proof.leaf, "encoding": hx(&proof.encode().unwrap())}))
        .collect();
    json!({
        "encoding": hx(&tree.to_cbor().unwrap()),
        "width": tree.width(),
        "tree_hash": hx(&tree.tree_hash().unwrap()),
        "resolutions": resolutions,
        "leaf_proofs": leaf_proofs
    })
}

fn registry_case() -> Json {
    let mut registry = Registry::genesis(8).unwrap();
    registry.grant_admin(3).unwrap();
    registry.retire(&filled(0x71), 2, 9);
    registry.retire(&filled(0x72), 5, 9);
    registry.retire(&ZERO32, 0, 9);
    registry.prune(10);
    let retired: Vec<Json> = registry
        .retired()
        .map(|entry| {
            json!({"admission_hash": hx(&entry.admission_hash), "expires_epoch": entry.expires_epoch})
        })
        .collect();
    // A registry whose retired list overflowed: the floor is the expiry of
    // the entry it dropped.
    let overflowed = Registry::from_cbor(
        &encode(&array(vec![
            uint(8),
            array(vec![uint(0)]),
            array(vec![array(vec![bytes(&filled(0x73)), uint(4200)])]),
            uint(4100),
        ]))
        .unwrap(),
    )
    .unwrap();
    json!({
        "capacity": registry.capacity(),
        "admins": registry.admins().collect::<Vec<_>>(),
        "retired": retired,
        "retired_floor": registry.retired_floor(),
        "encoding": hx(&registry.to_cbor().unwrap()),
        "registry_hash": hx(&registry.registry_hash().unwrap()),
        "overflowed": {
            "retired_floor": overflowed.retired_floor(),
            "encoding": hx(&overflowed.to_cbor().unwrap()),
            "registry_hash": hx(&overflowed.registry_hash().unwrap())
        }
    })
}

/// A two-leaf tree: the author in leaf 1 wraps `path_secret[0]` to leaf 0.
fn path_wrap_case() -> Json {
    let mut rng = ChaCha20Rng::seed_from_u64(0x77);
    let gid = filled(0x81);
    let member_key = KemSecret::derive(&filled(0x82), "vector member").unwrap();
    let author_leaf_secret = filled(0x83);
    let author_key = leaf_key_from_secret(&author_leaf_secret).unwrap();
    let mut tree = PublicTree::new(2).unwrap();
    let member = |key: &KemSecret, tag: u8| LeafNode {
        device_pk: DeviceIdentity::from_seed(&filled(tag))
            .public_key()
            .to_vec(),
        since: 0,
        encryption_key: key.public_key(),
        admission_hash: ZERO32,
    };
    tree.add_leaf(0, member(&member_key, 0x84)).unwrap();
    tree.add_leaf(1, member(&author_key, 0x85)).unwrap();
    let context = PathContext {
        gid,
        epoch: 9,
        author_leaf: 1,
    };
    let (path, secrets) =
        generate_update_path_from_leaf_secret(&tree, &context, &author_leaf_secret, &mut rng)
            .unwrap();
    let node = &path.nodes[0];
    let target = &node.targets[0];
    let shared = member_key.decapsulate(&target.kem_ciphertext).unwrap();
    json!({
        "gid": hx(&gid),
        "epoch": 9,
        "author_leaf": 1,
        "author_leaf_secret": hx(&author_leaf_secret),
        "leaf_public_key": hx(&path.leaf_public_key),
        "node": node.node,
        "node_public_key": hx(&node.public_key),
        "target": target.target,
        "target_seed": hx(member_key.seed()),
        "target_public_key": hx(&member_key.public_key()),
        "kem_ciphertext": hx(&target.kem_ciphertext),
        "shared_secret": hx(shared.as_ref()),
        "wrapped_secret": hx(&target.wrapped_secret),
        "commit_secret": hx(secrets.commit_secret.as_ref())
    })
}

/// A join request and the welcome sealed to its init key.
fn welcome_case() -> Json {
    let mut rng = ChaCha20Rng::seed_from_u64(0x3C);
    let gid = filled(0xA1);
    let admin = DeviceIdentity::from_seed(&filled(0xA2));
    let joiner = DeviceIdentity::from_seed(&filled(0xA3));
    let admission =
        SignedAdmission::by_admin(&gid, &joiner.device_id(&gid).unwrap(), 40, &admin, &mut rng)
            .unwrap();
    let secrets = JoinSecrets::generate(&mut rng);
    let request = SignedJoinRequest::create(&joiner, &secrets, &admission, &mut rng).unwrap();
    let joiner_secret = filled(0xA4);
    let welcome = Welcome::seal(12, &request, &joiner_secret, &mut rng).unwrap();
    assert_eq!(*welcome.open(&secrets.init_key).unwrap(), joiner_secret);
    json!({
        "request": hx(request.encoded()),
        "request_ref": hx(&request.reference().unwrap()),
        "init_seed": hx(secrets.init_key.seed()),
        "epoch": 12,
        "joiner_secret": hx(&joiner_secret),
        "welcome": hx(&welcome.encode().unwrap())
    })
}

/// Genesis commit built step by step with a known leaf secret, then two
/// messages of the creator in epoch 0.
fn genesis_case() -> Json {
    let mut rng = ChaCha20Rng::seed_from_u64(0x6E);
    let creator_seed = filled(0x71);
    let creator = DeviceIdentity::from_seed(&creator_seed);
    let nonce = filled(0x72);
    let leaf_secret = filled(0x73);
    let capacity = 4;
    let gid = group_id(creator.public_key(), &nonce).unwrap();

    let leaf_key = leaf_key_from_secret(&leaf_secret).unwrap();
    let staged = stage_genesis(capacity, creator.public_key(), &leaf_key.public_key()).unwrap();
    let context = PathContext {
        gid,
        epoch: 0,
        author_leaf: 0,
    };
    let (update_path, path_secrets) =
        generate_update_path_from_leaf_secret(&staged.tree, &context, &leaf_secret, &mut rng)
            .unwrap();
    let mut tree = staged.tree.clone();
    tree.apply_update_path(0, &update_path).unwrap();
    let content = CommitContent {
        gid,
        epoch: 0,
        kind: CommitKind::Genesis,
        prev_interim_transcript_hash: ZERO32,
        author_leaf: 0,
        author_device_pk: creator.public_key().to_vec(),
        tree_hash: tree.tree_hash().unwrap(),
        registry_hash: staged.registry.registry_hash().unwrap(),
        update_path,
        removals: Vec::new(),
        joins: Vec::new(),
        admin_changes: Vec::new(),
        admission: None,
        external_init: None,
        group_nonce: Some(nonce),
        capacity: Some(capacity),
        new_device_pk: None,
    };
    let signature = content.sign(&creator, &mut rng).unwrap();
    let anchor_tbs = content.tbs().unwrap();
    let confirmed = confirmed_transcript_hash(&ZERO32, &anchor_tbs, &signature, None).unwrap();
    let group_context = GroupContext {
        gid,
        epoch: 0,
        tree_hash: content.tree_hash,
        registry_hash: content.registry_hash,
        confirmed_transcript_hash: confirmed,
    };
    let joiner = joiner_secret(&ZERO32, &path_secrets.commit_secret, &group_context).unwrap();
    let secrets = EpochSecrets::from_joiner_secret(&joiner).unwrap();
    let confirmation_tag = secrets.confirmation_tag(&confirmed).unwrap();
    let commit = Commit {
        content,
        signature,
        rotation_signature: None,
        confirmation_tag,
    }
    .encode()
    .unwrap();
    // The reference verifier accepts it.
    let transition = verify_genesis(&commit).unwrap();
    assert_eq!(transition.next.confirmed_transcript_hash, confirmed);

    let external_pk = secrets.external_key().unwrap().public_key();
    let group_info = GroupInfo {
        group_context: group_context.clone(),
        confirmation_tag,
        external_public_key: external_pk,
        signer_leaf: 0,
    }
    .sign(&creator, &mut rng)
    .unwrap();

    let me = MemberRef { leaf: 0, since: 0 };
    let mut messages = EpochMessages::new(&gid, 0, secrets.msg_secret(), [me], me).unwrap();
    let plaintexts: [&[u8]; 2] = [b"hello, city-g", b"second message"];
    let envelopes: Vec<Json> = plaintexts
        .iter()
        .enumerate()
        .map(|(index, plaintext)| {
            let envelope = messages
                .encrypt(
                    &creator,
                    1,
                    b"aad",
                    plaintext,
                    1_760_000_000_000 + index as u64,
                    &mut rng,
                )
                .unwrap();
            let decoded = Envelope::decode(&envelope).unwrap();
            json!({
                "generation": decoded.header.generation,
                "content_type": 1,
                "authenticated_data": hx(b"aad"),
                "signed_timestamp_ms": 1_760_000_000_000_u64 + index as u64,
                "plaintext": hx(plaintext),
                "envelope": hx(&envelope)
            })
        })
        .collect();

    json!({
        "creator_seed": hx(&creator_seed),
        "creator_device_pk": hx(creator.public_key()),
        "group_nonce": hx(&nonce),
        "capacity": capacity,
        "leaf_secret": hx(&leaf_secret),
        "gid": hx(&gid),
        "leaf_public_key": hx(&tree.leaf(0).unwrap().encryption_key),
        "tree_hash": hx(&group_context.tree_hash),
        "registry_hash": hx(&group_context.registry_hash),
        "commit": hx(&commit),
        "anchor_tbs": hx(&anchor_tbs),
        "confirmed_transcript_hash": hx(&confirmed),
        "interim_transcript_hash": hx(&transition.next.interim_transcript_hash),
        "group_context": hx(&group_context.encode().unwrap()),
        "joiner_secret": hx(joiner.as_ref()),
        "confirmation_tag": hx(&confirmation_tag),
        "init_secret": hx(secrets.init_secret()),
        "msg_secret": hx(secrets.msg_secret()),
        "external_secret": hx(secrets.retained().external_secret()),
        "group_info": hx(group_info.encoded()),
        "messages": envelopes
    })
}

fn signed_objects() -> Json {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5E);
    let gid = filled(0x91);
    let admin = DeviceIdentity::from_seed(&filled(0x92));
    let joiner = DeviceIdentity::from_seed(&filled(0x93));
    let invite_seed = filled(0x94);
    let joiner_id = joiner.device_id(&gid).unwrap();

    let proposal = RemoveProposal {
        gid,
        target_leaf: 0,
        target_since: 0,
        proposer_device_pk: admin.public_key().to_vec(),
    }
    .sign(&admin, &mut rng)
    .unwrap();
    let invite = Invite::from_seed(
        &gid,
        &invite_seed,
        1_800_000_000_000,
        16,
        admin.public_key(),
    )
    .sign(&admin, &mut rng)
    .unwrap();
    let by_invite =
        SignedAdmission::with_invite(&joiner_id, 50, &invite, &invite_seed, &mut rng).unwrap();
    let by_admin = SignedAdmission::by_admin(&gid, &joiner_id, 50, &admin, &mut rng).unwrap();
    let revocation =
        SignedInviteRevocation::sign(&gid, &invite.id().unwrap(), &admin, &mut rng).unwrap();
    let secrets = JoinSecrets::generate(&mut rng);
    let request = SignedJoinRequest::create(&joiner, &secrets, &by_invite, &mut rng).unwrap();
    let alias = AliasBinding::sign(&gid, "alice", &admin, &mut rng).unwrap();
    let session = SessionAuth::sign(&gid, 1_760_000_000_000, &admin, &mut rng).unwrap();
    let cover = CoverFailureReport::sign(&gid, 5, CoverFailureReason::NotCovered, &admin, &mut rng)
        .unwrap();
    let object =
        |id: &str, label: &str, context: SignatureContext, fields: usize, encoded: &[u8]| {
            json!({
                "id": id, "label": label, "fields": fields, "encoded": hx(encoded),
                "context": String::from_utf8(context.as_bytes().to_vec()).unwrap()
            })
        };
    json!([
        object(
            "remove-proposal",
            "city-g/remove/v3",
            SignatureContext::REMOVE_PROPOSAL,
            5,
            proposal.encoded()
        ),
        object(
            "invite",
            "city-g/invite/v2",
            SignatureContext::INVITE,
            6,
            invite.encoded()
        ),
        object(
            "admission/invite",
            "city-g/admission/v2",
            SignatureContext::ADMISSION,
            7,
            by_invite.encoded()
        ),
        object(
            "admission/admin",
            "city-g/admission/v2",
            SignatureContext::ADMISSION,
            7,
            by_admin.encoded()
        ),
        object(
            "invite-revocation",
            "city-g/invite-revocation/v1",
            SignatureContext::INVITE_REVOCATION,
            4,
            revocation.encoded()
        ),
        object(
            "join-request",
            "city-g/join-request/v1",
            SignatureContext::JOIN_REQUEST,
            6,
            request.encoded()
        ),
        object(
            "alias",
            "city-g/alias/v1",
            SignatureContext::IDENTITY_BINDING,
            4,
            alias.encoded()
        ),
        object(
            "session-auth",
            "city-g/session-auth/v1",
            SignatureContext::SESSION_AUTH,
            4,
            session.encoded()
        ),
        object(
            "cover-failure",
            "city-g/cover-failure/v2",
            SignatureContext::COVER_FAILURE,
            5,
            cover.encoded()
        ),
    ])
}

/// Light-member objects over the sample tree: a LightCommit with two
/// proofs, and a LightJoin.
fn light_case() -> Json {
    let tree = sample_tree();
    let commit = LightCommit {
        proofs: tree.leaf_proofs([1, 4]).unwrap(),
    };
    let mut registry = Registry::genesis(8).unwrap();
    registry.grant_admin(1).unwrap();
    let join = LightJoin {
        registry,
        members: tree.member_refs().collect(),
        joiner_proof: tree.leaf_proof(5).unwrap(),
    };
    json!({
        "tree_hash": hx(&tree.tree_hash().unwrap()),
        "light_commit": hx(&commit.encode().unwrap()),
        "light_join": hx(&join.encode().unwrap())
    })
}

fn compute() -> Json {
    json!({
        "profile": "city-g/v0.3",
        "generator": "crates/cityg-core/tests/vectors.rs",
        "independent_verifier": "kat/v0.3/verify_vectors.py",
        "cbor_det": cbor_cases(),
        "h_l": h_l_cases(),
        "kdf": kdf_cases(),
        "suite": suite_case(),
        "identifiers": identifier_cases(),
        "key_schedule": key_schedule_case(),
        "tree": tree_case(),
        "registry": registry_case(),
        "path_wrap": path_wrap_case(),
        "welcome": welcome_case(),
        "genesis": genesis_case(),
        "signed_objects": signed_objects(),
        "light": light_case(),
    })
}

#[test]
fn vectors_match_the_published_file() {
    let computed = compute();
    let path = vectors_path();
    if std::env::var_os("CITYG_WRITE_VECTORS").is_some() {
        let mut text = serde_json::to_string_pretty(&computed).unwrap();
        text.push('\n');
        std::fs::write(&path, text).unwrap();
        return;
    }
    let published: Json = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("kat/v0.3/vectors.json is published"),
    )
    .unwrap();
    let computed_sections = computed.as_object().unwrap();
    let published_sections = published.as_object().unwrap();
    let differing: Vec<&String> = computed_sections
        .keys()
        .filter(|key| computed_sections.get(*key) != published_sections.get(*key))
        .collect();
    assert!(
        differing.is_empty() && computed_sections.len() == published_sections.len(),
        "vectors differ in sections {differing:?}; regenerate with CITYG_WRITE_VECTORS=1 after an intended change"
    );
}

#[test]
fn vectors_are_reproducible() {
    assert_eq!(compute(), compute());
}
