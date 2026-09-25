#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Conformance vectors of the v0.2 profile (`kat/v0.2/vectors.json`).
//!
//! Every vector is computed here with the public API of `cityg-core` from
//! fixed inputs and seeded randomness, and compared with the published
//! file. `kat/v0.2/verify_vectors.py` recomputes the same values with an
//! independent implementation of the profile's encodings and derivations.
//!
//! Regenerate the file after an intended change:
//! `CITYG_WRITE_VECTORS=1 cargo test -p cityg-core --test vectors`.

use std::path::PathBuf;

use ciborium::value::{Integer, Value};
use cityg_core::admission::{Invite, SignedAdmission, invite_id};
use cityg_core::binding::{AliasBinding, SessionAuth};
use cityg_core::cbor::{array, bytes, encode, text, uint};
use cityg_core::commit::{Commit, CommitContent, CommitKind};
use cityg_core::cover::{CoverFailureReason, CoverFailureReport};
use cityg_core::group_info::GroupInfo;
use cityg_core::hash::{ZERO32, derive_secret, expand_label_into, extract, h, h_l, mac};
use cityg_core::identity::{DeviceIdentity, group_id, leaf_id};
use cityg_core::kem::{KemSecret, pk_hash};
use cityg_core::key_schedule::{
    EpochSecrets, GroupContext, commit_secret, confirmed_transcript_hash, external_init,
    interim_transcript_hash,
};
use cityg_core::message::{Envelope, EpochMessages, epoch_ref};
use cityg_core::proposal::RemoveProposal;
use cityg_core::roster::{MemberRecord, Roster};
use cityg_core::state::{stage_genesis, verify_genesis};
use cityg_core::tree::{
    LeafNode, PathContext, PublicTree, generate_update_path_from_leaf_secret, leaf_key_from_secret,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value as Json, json};

fn hx(data: &[u8]) -> String {
    hex::encode(data)
}

fn filled(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../kat/v0.2/vectors.json")
}

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
        ("text/ascii", json!({"text": "city-g/v0.2"})),
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
                [{"uint": 110}, {"bytes": "10"}],
                [{"uint": 2}, {"bytes": "02"}],
                [{"uint": 15}, {"uint": 4}],
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
            "leaf-id-shape",
            "leaf-id",
            json!([{"bytes": hx(&filled(0x01))}, {"bytes": hx(&[0x02; 40])}]),
        ),
        (
            "nested",
            "roster",
            json!([{"array": [{"array": [{"uint": 0}, {"uint": 1}]}]}, {"array": []}]),
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
        ("tree node key", Vec::new(), 64),
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

fn identifier_cases() -> Json {
    let device = DeviceIdentity::from_seed(&filled(0x31));
    let gid = filled(0x40);
    let nonce = filled(0x41);
    let invite = DeviceIdentity::from_seed(&filled(0x32));
    let kem_pk = KemSecret::derive(&filled(0x33), "vector kem")
        .unwrap()
        .public_key();
    json!({
        "device_seed": hx(&filled(0x31)),
        "device_pk": hx(device.public_key()),
        "gid": hx(&gid),
        "leaf_id": hx(&leaf_id(&gid, device.public_key()).unwrap()),
        "group_nonce": hx(&nonce),
        "group_id": hx(&group_id(device.public_key(), &nonce).unwrap()),
        "invite_pk": hx(invite.public_key()),
        "invite_id": hx(&invite_id(invite.public_key()).unwrap()),
        "epoch": 7,
        "epoch_ref": hx(&epoch_ref(&gid, 7).unwrap()),
        "kem_pk": hx(&kem_pk),
        "kem_pk_hash": hx(&pk_hash(&kem_pk).unwrap())
    })
}

fn key_schedule_case() -> Json {
    let context = GroupContext {
        gid: filled(0x51),
        epoch: 3,
        tree_hash: filled(0x52),
        roster_hash: filled(0x53),
        confirmed_transcript_hash: filled(0x54),
    };
    let root_path_secret = filled(0x55);
    let prev_init = filled(0x56);
    let commit = commit_secret(&root_path_secret).unwrap();
    let secrets = EpochSecrets::derive(&prev_init, &commit, &context).unwrap();
    let retained = secrets.retained();
    let external_key = secrets.external_key().unwrap();
    let tag = secrets
        .confirmation_tag(&context.confirmed_transcript_hash)
        .unwrap();
    let confirmed = confirmed_transcript_hash(&filled(0x57), b"anchor tbs", b"signature").unwrap();
    let interim = interim_transcript_hash(&confirmed, &tag).unwrap();

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
            "tree_hash": hx(&context.tree_hash), "roster_hash": hx(&context.roster_hash),
            "confirmed_transcript_hash": hx(&context.confirmed_transcript_hash),
            "encoding": hx(&context.encode().unwrap()),
            "hash": hx(&context.hash().unwrap())
        },
        "root_path_secret": hx(&root_path_secret),
        "commit_secret": hx(commit.as_ref()),
        "prev_init_secret": hx(&prev_init),
        "init_secret": hx(secrets.init_secret()),
        "msg_secret": hx(secrets.msg_secret()),
        "external_secret": hx(retained.external_secret()),
        "external_kem_seed": hx(external_key.seed()),
        "confirmation_tag": hx(&tag),
        "transcript": {
            "prev_interim": hx(&filled(0x57)),
            "anchor_tbs": hx(b"anchor tbs"),
            "signature": hx(b"signature"),
            "confirmed": hx(&confirmed),
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

fn roster_case() -> Json {
    let gid = filled(0x61);
    let alice = DeviceIdentity::from_seed(&filled(0x62));
    let bob = DeviceIdentity::from_seed(&filled(0x63));
    let mut roster = Roster::genesis(&gid, alice.public_key()).unwrap();
    roster
        .add_member(MemberRecord {
            leaf_id: leaf_id(&gid, bob.public_key()).unwrap(),
            device_pk: bob.public_key().to_vec(),
            slot: 1,
            generation: 1,
            admission_hash: filled(0x64),
        })
        .unwrap();
    roster.grant_admin(bob.public_key()).unwrap();
    // Carol joins slot 2 and is removed: her leaf id is retired.
    let carol = DeviceIdentity::from_seed(&filled(0x65));
    roster
        .add_member(MemberRecord {
            leaf_id: leaf_id(&gid, carol.public_key()).unwrap(),
            device_pk: carol.public_key().to_vec(),
            slot: 2,
            generation: 1,
            admission_hash: filled(0x66),
        })
        .unwrap();
    roster.remove_member(2, 1).unwrap();
    let member = |record: &MemberRecord| {
        json!({
            "leaf_id": hx(&record.leaf_id), "device_pk": hx(&record.device_pk),
            "slot": record.slot, "generation": record.generation,
            "admission_hash": hx(&record.admission_hash)
        })
    };
    json!({
        "gid": hx(&gid),
        "members": roster.members().map(member).collect::<Vec<_>>(),
        "admins": roster.admins().map(|admin| hx(admin)).collect::<Vec<_>>(),
        "last_generation": [[0, 1], [1, 1], [2, 1]],
        "retired": roster.retired().map(|leaf| hx(leaf)).collect::<Vec<_>>(),
        "roster_hash": hx(&roster.roster_hash().unwrap())
    })
}

/// Genesis commit built step by step with a known leaf secret, then a
/// message of the creator in epoch 0.
fn genesis_case() -> Json {
    let mut rng = ChaCha20Rng::seed_from_u64(0x6E);
    let creator_seed = filled(0x71);
    let creator = DeviceIdentity::from_seed(&creator_seed);
    let nonce = filled(0x72);
    let leaf_secret = filled(0x73);
    let n_max = 4;
    let gid = group_id(creator.public_key(), &nonce).unwrap();
    let author_leaf_id = leaf_id(&gid, creator.public_key()).unwrap();

    let leaf_key = leaf_key_from_secret(&leaf_secret).unwrap();
    let staged = stage_genesis(&gid, n_max, creator.public_key(), &leaf_key.public_key()).unwrap();
    let context = PathContext {
        gid,
        epoch: 0,
        author_slot: 0,
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
        author_leaf_id,
        author_device_pk: creator.public_key().to_vec(),
        roster_hash: staged.roster.roster_hash().unwrap(),
        tree_hash: tree.tree_hash().unwrap(),
        update_path,
        removals: Vec::new(),
        admin_changes: Vec::new(),
        join: None,
        external_init: None,
        group_nonce: Some(nonce),
        n_max: Some(n_max),
    };
    let signature = content.sign(&creator, &mut rng).unwrap();
    let anchor_tbs = content.tbs().unwrap();
    let confirmed = confirmed_transcript_hash(&ZERO32, &anchor_tbs, &signature).unwrap();
    let group_context = GroupContext {
        gid,
        epoch: 0,
        tree_hash: content.tree_hash,
        roster_hash: content.roster_hash,
        confirmed_transcript_hash: confirmed,
    };
    let secrets = EpochSecrets::derive(
        &ZERO32,
        &commit_secret(&path_secrets.root_secret).unwrap(),
        &group_context,
    )
    .unwrap();
    let confirmation_tag = secrets.confirmation_tag(&confirmed).unwrap();
    let commit = Commit {
        content,
        signature,
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
        signer_leaf_id: author_leaf_id,
    }
    .sign(&creator, &mut rng)
    .unwrap();

    let mut messages = EpochMessages::new(
        &gid,
        0,
        secrets.msg_secret(),
        &staged.roster,
        &author_leaf_id,
    )
    .unwrap();
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

    let parents: Vec<Json> = (0..n_max - 1)
        .map(|node| json!({"node": node, "public_key": tree.node_public_key(node).map(hx)}))
        .collect();
    let leaf = tree.leaf(0).unwrap();
    json!({
        "creator_seed": hx(&creator_seed),
        "creator_device_pk": hx(creator.public_key()),
        "group_nonce": hx(&nonce),
        "n_max": n_max,
        "leaf_secret": hx(&leaf_secret),
        "gid": hx(&gid),
        "author_leaf_id": hx(&author_leaf_id),
        "leaf_public_key": hx(&leaf.public_key),
        "tree_parents": parents,
        "tree_hash": hx(&group_context.tree_hash),
        "roster_hash": hx(&group_context.roster_hash),
        "commit": hx(&commit),
        "anchor_tbs": hx(&anchor_tbs),
        "confirmed_transcript_hash": hx(&confirmed),
        "interim_transcript_hash": hx(&transition.next.interim_transcript_hash),
        "group_context": hx(&group_context.encode().unwrap()),
        "confirmation_tag": hx(&confirmation_tag),
        "init_secret": hx(secrets.init_secret()),
        "msg_secret": hx(secrets.msg_secret()),
        "external_secret": hx(secrets.retained().external_secret()),
        "group_info": hx(group_info.encoded()),
        "messages": envelopes
    })
}

/// A two-slot tree: the author in slot 1 wraps the root path secret to the
/// leaf of slot 0.
fn path_wrap_case() -> Json {
    let mut rng = ChaCha20Rng::seed_from_u64(0x77);
    let gid = filled(0x81);
    let member_key = KemSecret::derive(&filled(0x82), "vector member").unwrap();
    let author_leaf_secret = filled(0x83);
    let author_key = leaf_key_from_secret(&author_leaf_secret).unwrap();
    let mut tree = PublicTree::new(2).unwrap();
    tree.add_leaf(
        0,
        LeafNode {
            leaf_id: filled(0x84),
            generation: 1,
            public_key: member_key.public_key(),
        },
    )
    .unwrap();
    tree.add_leaf(
        1,
        LeafNode {
            leaf_id: filled(0x85),
            generation: 1,
            public_key: author_key.public_key(),
        },
    )
    .unwrap();
    let context = PathContext {
        gid,
        epoch: 9,
        author_slot: 1,
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
        "author_slot": 1,
        "author_leaf_secret": hx(&author_leaf_secret),
        "node": node.node,
        "target": target.target,
        "target_public_key": hx(&member_key.public_key()),
        "kem_ciphertext": hx(&target.kem_ciphertext),
        "shared_secret": hx(shared.as_ref()),
        "wrapped_secret": hx(&target.wrapped_secret),
        "root_path_secret": hx(secrets.root_secret.as_ref())
    })
}

fn signed_objects() -> Json {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5E);
    let gid = filled(0x91);
    let admin = DeviceIdentity::from_seed(&filled(0x92));
    let joiner = DeviceIdentity::from_seed(&filled(0x93));
    let roster = Roster::genesis(&gid, admin.public_key()).unwrap();
    let admin_record = roster.member_in_slot(0).unwrap().clone();
    let invite_seed = filled(0x94);
    let joiner_leaf = leaf_id(&gid, joiner.public_key()).unwrap();

    let proposal = RemoveProposal::for_member(&gid, &admin_record, admin.public_key())
        .sign(&admin, &mut rng)
        .unwrap();
    let invite = Invite::from_seed(&gid, &invite_seed, 1_800_000_000_000, admin.public_key())
        .sign(&admin, &mut rng)
        .unwrap();
    let by_invite =
        SignedAdmission::with_invite(&joiner_leaf, &invite, &invite_seed, &mut rng).unwrap();
    let by_admin = SignedAdmission::by_admin(&gid, &joiner_leaf, &admin, &mut rng).unwrap();
    let alias = AliasBinding::sign(&gid, "alice", &admin, &mut rng).unwrap();
    let session = SessionAuth::sign(&gid, 1_760_000_000_000, &admin, &mut rng).unwrap();
    let cover = CoverFailureReport::sign(&gid, 5, CoverFailureReason::NotCovered, &admin, &mut rng)
        .unwrap();
    let object = |id: &str, label: &str, fields: usize, encoded: &[u8]| json!({"id": id, "label": label, "fields": fields, "encoded": hx(encoded)});
    json!([
        object("remove-proposal", "city-g/remove/v2", 6, proposal.encoded()),
        object("invite", "city-g/invite/v1", 5, invite.encoded()),
        object(
            "admission/invite",
            "city-g/admission/v1",
            6,
            by_invite.encoded()
        ),
        object(
            "admission/admin",
            "city-g/admission/v1",
            6,
            by_admin.encoded()
        ),
        object("alias", "city-g/alias/v1", 4, alias.encoded()),
        object(
            "session-auth",
            "city-g/session-auth/v1",
            4,
            session.encoded()
        ),
        object(
            "cover-failure",
            "city-g/cover-failure/v1",
            5,
            cover.encoded()
        ),
    ])
}

fn compute() -> Json {
    json!({
        "profile": "city-g/v0.2",
        "generator": "crates/cityg-core/tests/vectors.rs",
        "independent_verifier": "kat/v0.2/verify_vectors.py",
        "cbor_det": cbor_cases(),
        "h_l": h_l_cases(),
        "kdf": kdf_cases(),
        "identifiers": identifier_cases(),
        "key_schedule": key_schedule_case(),
        "roster": roster_case(),
        "path_wrap": path_wrap_case(),
        "genesis": genesis_case(),
        "signed_objects": signed_objects(),
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
        &std::fs::read_to_string(&path).expect("kat/v0.2/vectors.json is published"),
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
