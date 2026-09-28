//! `objects.json`: one instance of each encoded object of the profile,
//! signed with a recorded seed and randomness (docs/specs.md sections 6,
//! 10 and 11, docs/specs-v0.5-draft.md sections 2.3, 3.2, 3.7, 3.8 and
//! 4.9), and two genesis seals with the secrets of their epoch.

use std::collections::BTreeMap;
use std::sync::Arc;

use cityg_core::authorizer::{Authorization, AuthorizationBatch, Authorizer, authorizer_pk_hash};
use cityg_core::card::{Card, CardKey, LeafKeys};
use cityg_core::cbor;
use cityg_core::commit::Change;
use cityg_core::commit::{CityTask, CityTaskContent, DistrictCommit, DistrictCommitContent, Seal};
use cityg_core::crypto::{
    self, PROFILE, ZERO32, commit_secret, extract, fresh_secret, h, kem_pk_hash, node_key,
    task_hedge,
};
use cityg_core::dispute::{Dispute, DisputeContent, DisputeKind, DisputeStatement};
use cityg_core::identity::DeviceIdentity;
use cityg_core::kem::KemSecret;
use cityg_core::member::Member;
use cityg_core::objects::{
    Admission, AdmissionMode, Admitters, CatchUpRequest, ChangeKind, Checkpoint, CheckpointContent,
    Eviction, GroupPolicy, Invite, JoinRequest, PolicyTerms, ReEntryRequest, RemoveProposal,
    RepairRequest, UpdateRequest, Urgency, device_id, group_id,
};
use cityg_core::rekey::NodeUpdate;
use cityg_core::schedule::{
    EpochSecrets, GroupContext, confirmed_transcript_hash, interim_transcript_hash,
};
use cityg_core::top::{RelayContext, RelayElement, Repair, flat_element, open_flat};
use cityg_core::tree::{CityPart, Divisions, NodeId, Occupancy, Shape};
use cityg_core::welcome::Welcome;
use cityg_core::window::PublicState;
use serde_json::{Map, Value, json};

use crate::crypto_basics::{
    aead_open, check_hedged, check_wrap_record, derive, expand_label, extract_raw, hedged_coins,
    labelled, mac_raw, wrap_record,
};
use crate::key_schedule::context_encoding;
use crate::registry::{header_json, header_of};
use crate::support::{
    Sampler, bytes, digest, digest_list, get, hex, list, node, occupancy, occupancy_of,
    optional_bytes, optional_hex, replay, text, u8_of, u32_of, uint,
};

pub const FILE: &str = "objects.json";

const CREATOR: Occupancy = Occupancy { leaf: 0, since: 0 };
const MEMBER: Occupancy = Occupancy { leaf: 2, since: 1 };
/// The window most objects are for: the one that creates epoch 5.
const EPOCH: u64 = 5;
const NOT_AFTER: u64 = 12;
const TIME_MS: u64 = 1_000;

/// The devices of the vectors, by name.
struct Cast {
    nonce: [u8; 32],
    creator: DeviceIdentity,
    member: DeviceIdentity,
    joiners: Vec<DeviceIdentity>,
    authorizer: DeviceIdentity,
}

/// A leaf key and a card, drawn from recorded seeds.
struct Keys {
    leaf_seed: [u8; 32],
    leaf_key: KemSecret,
    card_seed: [u8; 32],
    card: Card,
}

impl Keys {
    fn draw(s: &mut Sampler) -> Self {
        let (leaf_seed, leaf_key) = s.kem();
        let card_seed = s.seed();
        let card = replay(&[&card_seed], CardKey::generate).card();
        Self {
            leaf_seed,
            leaf_key,
            card_seed,
            card,
        }
    }

    fn leaf_keys(&self) -> (Vec<u8>, &Card) {
        (self.leaf_key.public_key(), &self.card)
    }

    fn json(&self, into: &mut Map<String, Value>) {
        into.insert("leaf_seed".into(), hex(&self.leaf_seed));
        into.insert("encryption_key".into(), hex(&self.leaf_key.public_key()));
        into.insert("card_seed".into(), hex(&self.card_seed));
        into.insert(
            "card".into(),
            hex(&cbor::encode(&self.card.value()).unwrap()),
        );
    }
}

fn signed(signer: &str, rnd: &[u8; 32], encoded: &[u8]) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("signer".into(), json!(signer));
    map.insert("rnd".into(), hex(rnd));
    map.insert("encoded".into(), hex(encoded));
    map
}

fn insert(map: &mut Map<String, Value>, fields: Vec<(&str, Value)>) {
    for (key, value) in fields {
        map.insert(key.to_string(), value);
    }
}

fn device_json(gid: &[u8; 32], seed: &[u8; 32], identity: &DeviceIdentity) -> Value {
    json!({
        "seed": hex(seed),
        "public_key": hex(identity.public_key()),
        "device_id": hex(&device_id(gid, identity.public_key()).unwrap()),
    })
}

pub fn generate(s: &mut Sampler) -> Value {
    let (creator_seed, creator) = s.device();
    let (member_seed, member) = s.device();
    let joiner_seeds: Vec<([u8; 32], DeviceIdentity)> = (0..3).map(|_| s.device()).collect();
    let (authorizer_seed, authorizer) = s.device();
    let nonce = s.seed();
    let gid = group_id(creator.public_key(), &nonce).unwrap();
    let cast = Cast {
        nonce,
        creator,
        member,
        joiners: joiner_seeds
            .iter()
            .map(|(_, identity)| identity.clone())
            .collect(),
        authorizer,
    };
    let mut devices = Map::new();
    devices.insert(
        "creator".into(),
        device_json(&gid, &creator_seed, &cast.creator),
    );
    devices.insert(
        "member".into(),
        device_json(&gid, &member_seed, &cast.member),
    );
    for (index, (seed, identity)) in joiner_seeds.iter().enumerate() {
        devices.insert(
            format!("joiner_{}", index + 1),
            device_json(&gid, seed, identity),
        );
    }
    devices.insert(
        "authorizer".into(),
        device_json(&gid, &authorizer_seed, &cast.authorizer),
    );

    let mut out = Map::new();
    out.insert("profile".into(), json!(PROFILE));
    out.insert("gid".into(), hex(&gid));
    out.insert("group_nonce".into(), hex(&nonce));
    out.insert("devices".into(), Value::Object(devices));

    // Invites and admissions.
    let invite_seed = s.seed();
    let rnd = s.seed();
    let invite = replay(&[&rnd], |rng| {
        Invite::sign(
            &gid,
            &invite_seed,
            1_700_000_000_000,
            3,
            CREATOR,
            &cast.creator,
            rng,
        )
    })
    .unwrap();
    let mut record = signed("creator", &rnd, invite.encoded());
    insert(
        &mut record,
        vec![
            ("invite_seed", hex(&invite_seed)),
            ("invite_pk", hex(&invite.invite_pk)),
            ("expires_at_ms", json!(invite.expires_at_ms)),
            ("max_uses", json!(invite.max_uses)),
            ("inviter", occupancy(invite.inviter)),
            ("id", hex(&invite.id().unwrap())),
        ],
    );
    out.insert("invite".into(), Value::Object(record));

    let joiner_1_id = device_id(&gid, cast.joiners[0].public_key()).unwrap();
    let rnd = s.seed();
    let by_admin = replay(&[&rnd], |rng| {
        Admission::by_admin(&gid, &joiner_1_id, NOT_AFTER, CREATOR, &cast.creator, rng)
    })
    .unwrap();
    let mut record = signed("creator", &rnd, by_admin.encoded());
    insert(
        &mut record,
        vec![
            ("device", json!("joiner_1")),
            ("device_id", hex(&joiner_1_id)),
            ("not_after_epoch", json!(NOT_AFTER)),
            ("admin", occupancy(CREATOR)),
            ("hash", hex(&by_admin.hash())),
        ],
    );
    out.insert("admission_by_admin".into(), Value::Object(record));

    let joiner_2_id = device_id(&gid, cast.joiners[1].public_key()).unwrap();
    let rnd = s.seed();
    let with_invite = replay(&[&rnd], |rng| {
        Admission::with_invite(&invite, &invite_seed, &joiner_2_id, NOT_AFTER, rng)
    })
    .unwrap();
    let mut record = signed("invite", &rnd, with_invite.encoded());
    insert(
        &mut record,
        vec![
            ("device", json!("joiner_2")),
            ("device_id", hex(&joiner_2_id)),
            ("not_after_epoch", json!(NOT_AFTER)),
            ("hash", hex(&with_invite.hash())),
        ],
    );
    out.insert("admission_with_invite".into(), Value::Object(record));

    // Join requests: admitted by an admin, by an invite, and three open
    // ones, which a batch authorizes.
    let join = |s: &mut Sampler, index: usize, admission: Option<&Admission>| {
        let keys = Keys::draw(s);
        let (init_seed, init_key) = s.kem();
        let rnd = s.seed();
        let (encryption_key, card) = keys.leaf_keys();
        let request = replay(&[&rnd], |rng| {
            JoinRequest::sign(
                &gid,
                &cast.joiners[index],
                LeafKeys {
                    encryption_key: &encryption_key,
                    card,
                },
                &init_key.public_key(),
                NOT_AFTER,
                admission,
                rng,
            )
        })
        .unwrap();
        let mut record = signed(&format!("joiner_{}", index + 1), &rnd, request.encoded());
        keys.json(&mut record);
        insert(
            &mut record,
            vec![
                ("init_seed", hex(&init_seed)),
                ("init_key", hex(&init_key.public_key())),
                ("not_after_epoch", json!(NOT_AFTER)),
                ("admission", optional_hex(admission.map(Admission::encoded))),
                ("reference", hex(&request.reference())),
                ("token", hex(&request.token())),
            ],
        );
        (request, keys, init_seed, Value::Object(record))
    };
    let (_, _, _, admitted) = join(s, 0, Some(&by_admin));
    let (_, _, _, invited) = join(s, 1, Some(&with_invite));
    let mut open_joins = Vec::new();
    let mut open_records = Vec::new();
    let mut open_inits = Vec::new();
    for index in 0..3 {
        let (request, _, init_seed, record) = join(s, index, None);
        open_joins.push(request);
        open_records.push(record);
        open_inits.push(init_seed);
    }
    out.insert(
        "join_requests".into(),
        json!({"admitted": admitted, "invited": invited, "open": open_records}),
    );

    // Removals.
    let removals = [
        (
            "remove_proposal_self",
            Some(MEMBER),
            Urgency::Ordinary,
            "member",
            &cast.member,
        ),
        (
            "remove_proposal_admin",
            Some(CREATOR),
            Urgency::Urgent,
            "creator",
            &cast.creator,
        ),
        (
            "remove_proposal_authorizer",
            None,
            Urgency::Urgent,
            "authorizer",
            &cast.authorizer,
        ),
    ];
    for (name, proposer, urgency, signer, identity) in removals {
        let rnd = s.seed();
        let proposal = replay(&[&rnd], |rng| {
            RemoveProposal::sign(&gid, MEMBER, proposer, urgency, identity, rng)
        })
        .unwrap();
        let mut record = signed(signer, &rnd, proposal.encoded());
        insert(
            &mut record,
            vec![
                ("target", occupancy(MEMBER)),
                ("proposer", proposer.map_or(Value::Null, occupancy)),
                ("urgency", json!(urgency as u64)),
            ],
        );
        out.insert(name.into(), Value::Object(record));
    }

    // Policies and an eviction.
    let policies = [
        (
            "group_policy_closed",
            PolicyTerms {
                admission: AdmissionMode::Closed,
                max_idle_epochs: Some(100),
                authorizer_pk: None,
            },
        ),
        ("group_policy_open", PolicyTerms::open()),
        (
            "group_policy_authorized",
            PolicyTerms::authorized(cast.authorizer.public_key().to_vec()),
        ),
    ];
    let mut closed_policy = None;
    for (name, terms) in policies {
        let rnd = s.seed();
        let policy = replay(&[&rnd], |rng| {
            GroupPolicy::sign(&gid, &terms, CREATOR, &cast.creator, rng)
        })
        .unwrap();
        let mut record = signed("creator", &rnd, policy.encoded());
        insert(
            &mut record,
            vec![
                ("admission_mode", json!(terms.admission.code())),
                (
                    "max_idle_epochs",
                    terms.max_idle_epochs.map_or(Value::Null, |n| json!(n)),
                ),
                (
                    "authorizer_pk",
                    optional_hex(terms.authorizer_pk.as_deref()),
                ),
                ("admin", occupancy(CREATOR)),
                ("hash", hex(&policy.hash())),
            ],
        );
        out.insert(name.into(), Value::Object(record));
        if name == "group_policy_closed" {
            closed_policy = Some(policy);
        }
    }
    let closed_policy = closed_policy.unwrap();
    let eviction = Eviction::new(&gid, MEMBER, &closed_policy.hash()).unwrap();
    out.insert(
        "eviction".into(),
        json!({
            "target": occupancy(MEMBER),
            "policy_hash": hex(&closed_policy.hash()),
            "encoded": hex(eviction.encoded()),
        }),
    );

    // The member's requests.
    let (current_seed, current_key) = s.kem();
    let current_pk = current_key.public_key();
    let keys = Keys::draw(s);
    let rnd = s.seed();
    let (encryption_key, card) = keys.leaf_keys();
    let update = replay(&[&rnd], |rng| {
        UpdateRequest::sign(
            &gid,
            MEMBER,
            &current_pk,
            LeafKeys {
                encryption_key: &encryption_key,
                card,
            },
            &cast.member,
            rng,
        )
    })
    .unwrap();
    let mut record = signed("member", &rnd, update.encoded());
    keys.json(&mut record);
    insert(
        &mut record,
        vec![
            ("member", occupancy(MEMBER)),
            ("current_key_seed", hex(&current_seed)),
            ("current_key", hex(&current_pk)),
            ("replaces", hex(&update.replaces)),
        ],
    );
    out.insert("update_request".into(), Value::Object(record));

    let prev_interim = s.seed();
    let (init_seed, init_key) = s.kem();
    let rnd = s.seed();
    let catch_up = replay(&[&rnd], |rng| {
        CatchUpRequest::sign(
            &gid,
            MEMBER,
            &prev_interim,
            &init_key.public_key(),
            &cast.member,
            rng,
        )
    })
    .unwrap();
    let mut record = signed("member", &rnd, catch_up.encoded());
    insert(
        &mut record,
        vec![
            ("member", occupancy(MEMBER)),
            ("prev_interim", hex(&prev_interim)),
            ("init_seed", hex(&init_seed)),
            ("init_key", hex(&init_key.public_key())),
            ("reference", hex(&catch_up.reference())),
        ],
    );
    out.insert("catch_up_request".into(), Value::Object(record));

    let keys = Keys::draw(s);
    let (init_seed, init_key) = s.kem();
    let rnd = s.seed();
    let (encryption_key, card) = keys.leaf_keys();
    let re_entry = replay(&[&rnd], |rng| {
        ReEntryRequest::sign(
            &gid,
            MEMBER,
            &current_pk,
            LeafKeys {
                encryption_key: &encryption_key,
                card,
            },
            &init_key.public_key(),
            &cast.member,
            rng,
        )
    })
    .unwrap();
    let mut record = signed("member", &rnd, re_entry.encoded());
    keys.json(&mut record);
    insert(
        &mut record,
        vec![
            ("member", occupancy(MEMBER)),
            ("current_key", hex(&current_pk)),
            ("replaces", hex(&re_entry.replaces)),
            ("init_seed", hex(&init_seed)),
            ("init_key", hex(&init_key.public_key())),
            ("reference", hex(&re_entry.reference())),
        ],
    );
    out.insert("re_entry_request".into(), Value::Object(record));

    let seal_hash = s.seed();
    let rnd = s.seed();
    let repair_request = replay(&[&rnd], |rng| {
        RepairRequest::sign(&gid, 4, &seal_hash, MEMBER, 2, &cast.member, rng)
    })
    .unwrap();
    let mut record = signed("member", &rnd, repair_request.encoded());
    insert(
        &mut record,
        vec![
            ("epoch", json!(4)),
            ("seal_hash", hex(&seal_hash)),
            ("member", occupancy(MEMBER)),
            ("level", json!(2)),
        ],
    );
    out.insert("repair_request".into(), Value::Object(record));

    // An admin's checkpoint.
    let content = CheckpointContent {
        epoch: 4,
        interim: s.seed(),
        tree_hash: s.seed(),
        registry_hash: s.seed(),
        height: 3,
        district_bits: 2,
        island_bits: 1,
        subcity_bits: 1,
        external_pk_hash: s.seed(),
        time_ms: 60_000,
    };
    let rnd = s.seed();
    let checkpoint = replay(&[&rnd], |rng| {
        Checkpoint::sign(&gid, &content, CREATOR, &cast.creator, rng)
    })
    .unwrap();
    let mut record = signed("creator", &rnd, checkpoint.encoded());
    insert(
        &mut record,
        vec![
            ("epoch", json!(content.epoch)),
            ("interim", hex(&content.interim)),
            ("tree_hash", hex(&content.tree_hash)),
            ("registry_hash", hex(&content.registry_hash)),
            ("height", json!(content.height)),
            ("district_bits", json!(content.district_bits)),
            ("island_bits", json!(content.island_bits)),
            ("subcity_bits", json!(content.subcity_bits)),
            ("external_pk_hash", hex(&content.external_pk_hash)),
            ("time_ms", json!(content.time_ms)),
            ("admin", occupancy(CREATOR)),
        ],
    );
    out.insert("checkpoint".into(), Value::Object(record));

    // The authorizer's batch over the open joins.
    let rnd = s.seed();
    let authorized = replay(&[&rnd], |rng| {
        Authorizer::new(gid, cast.authorizer.clone()).authorize(EPOCH, open_joins.clone(), rng)
    })
    .unwrap();
    let batch = Arc::clone(&authorized[0].authorization.as_ref().unwrap().batch);
    let mut record = signed("authorizer", &rnd, batch.encoded());
    insert(
        &mut record,
        vec![
            ("epoch", json!(batch.epoch)),
            ("requests", Value::Array(open_joins.iter().map(|join| hex(&join.reference())).collect())),
            ("root", hex(&batch.root)),
            ("count", json!(batch.count)),
            (
                "authorizations",
                Value::Array(
                    authorized
                        .iter()
                        .map(|join| {
                            let authorization = join.authorization.as_ref().unwrap();
                            json!({
                                "index": authorization.index,
                                "path": authorization.path.iter().map(|digest| hex(digest)).collect::<Vec<_>>(),
                            })
                        })
                        .collect(),
                ),
            ),
        ],
    );
    out.insert("authorization_batch".into(), Value::Object(record));

    // Welcomes: a joiner's, and a catch-up's to the member's leaf key too.
    let joiner_secret = s.seed();
    let hedge = s.seed();
    let random = s.seed();
    let request = open_joins[0].reference();
    let init_key = KemSecret::from_seed(open_inits[0]).public_key();
    let welcome = replay(&[&random], |rng| {
        Welcome::seal(
            &gid,
            EPOCH,
            &request,
            &init_key,
            None,
            &joiner_secret,
            &hedge,
            rng,
        )
    })
    .unwrap();
    out.insert(
        "welcome".into(),
        welcome_json(
            &gid,
            EPOCH,
            &request,
            &open_inits[0],
            None,
            &joiner_secret,
            &hedge,
            &[random],
            &welcome,
        ),
    );
    let (leaf_seed, leaf_key) = s.kem();
    let catch_up_secret = s.seed();
    let hedge = s.seed();
    let randoms = [s.seed(), s.seed()];
    let request = catch_up.reference();
    let welcome = replay(&[&randoms[0], &randoms[1]], |rng| {
        Welcome::seal(
            &gid,
            EPOCH,
            &request,
            &KemSecret::from_seed(init_seed).public_key(),
            Some(&leaf_key.public_key()),
            &catch_up_secret,
            &hedge,
            rng,
        )
    })
    .unwrap();
    out.insert(
        "welcome_catch_up".into(),
        welcome_json(
            &gid,
            EPOCH,
            &request,
            &init_seed,
            Some(&leaf_seed),
            &catch_up_secret,
            &hedge,
            &randoms,
            &welcome,
        ),
    );

    // A relay element, a flat element and a repair, all carrying a root
    // secret.
    let root_secret = s.seed();
    let island_secret = s.seed();
    let context = RelayContext {
        gid,
        epoch: EPOCH,
        island_bits: 8,
        island: 3,
        interim: s.seed(),
    };
    let element = RelayElement::seal(&context, &island_secret, &root_secret).unwrap();
    let context_encoded = relay_context_encoding(&context);
    let key: [u8; 32] = expand_label(&island_secret, "relay key", &context_encoded, 32)
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = expand_label(&island_secret, "relay nonce", &context_encoded, 12)
        .try_into()
        .unwrap();
    assert_eq!(
        aead_open(&key, &nonce, &context_encoded, &element.sealed),
        root_secret
    );
    out.insert(
        "relay_element".into(),
        json!({
            "epoch": EPOCH,
            "island_bits": context.island_bits,
            "island": context.island,
            "interim": hex(&context.interim),
            "context": hex(&context_encoded),
            "island_secret": hex(&island_secret),
            "root_secret": hex(&root_secret),
            "key": hex(&key),
            "nonce": hex(&nonce),
            "sealed": hex(&element.sealed),
            "encoded": hex(&element.encode().unwrap()),
        }),
    );

    let shape = Shape::new(9, Divisions::new(8, 8, 8).unwrap()).unwrap();
    let island_pk = node_key(&island_secret).unwrap().public_key();
    let hedge = s.seed();
    let random = s.seed();
    let flat = replay(&[&random], |rng| {
        flat_element(&gid, EPOCH, shape, 1, &island_pk, &root_secret, &hedge, rng)
    })
    .unwrap();
    let mut record = wrap_record(
        &gid,
        EPOCH,
        None,
        &island_pk,
        &root_secret,
        &hedge,
        &random,
        &flat,
    );
    insert(
        &mut record,
        vec![
            ("height", json!(shape.height)),
            (
                "divisions",
                json!({"district_bits": 8, "island_bits": 8, "subcity_bits": 8}),
            ),
            ("island", json!(1)),
            ("island_secret", hex(&island_secret)),
        ],
    );
    out.insert("flat_element".into(), Value::Object(record));

    let shape = Shape::new(3, Divisions::new(2, 1, 1).unwrap()).unwrap();
    let (leaf_seed, leaf_key) = s.kem();
    let leaf_pk = leaf_key.public_key();
    let hedge = s.seed();
    let random = s.seed();
    let repair = replay(&[&random], |rng| {
        Repair::make(&gid, EPOCH, shape, 5, &leaf_pk, &root_secret, &hedge, rng)
    })
    .unwrap();
    let mut record = wrap_record(
        &gid,
        EPOCH,
        Some(&leaf_seed),
        &leaf_pk,
        &root_secret,
        &hedge,
        &random,
        &repair.wrap,
    );
    insert(
        &mut record,
        vec![
            ("height", json!(shape.height)),
            (
                "divisions",
                json!({"district_bits": 2, "island_bits": 1, "subcity_bits": 1}),
            ),
            ("leaf", json!(repair.leaf)),
            ("repair", hex(&repair.encode().unwrap())),
        ],
    );
    out.insert("repair".into(), Value::Object(record));

    // A district commit and city tasks over synthetic nodes: their
    // encodings and signatures, not a window that applies.
    let node_secrets = [s.seed(), s.seed()];
    let node_pks: Vec<Vec<u8>> = node_secrets
        .iter()
        .map(|secret| node_key(secret).unwrap().public_key())
        .collect();
    let (target_seed, target_key) = s.kem();
    let target_pk = target_key.public_key();
    let hedge = s.seed();
    let random = s.seed();
    let wrapped = replay(&[&random], |rng| {
        crypto::wrap(
            &gid,
            EPOCH,
            NodeId { level: 1, index: 0 },
            NodeId { level: 0, index: 0 },
            &target_pk,
            &node_secrets[0],
            &hedge,
            rng,
        )
    })
    .unwrap();
    let wrap_json = wrap_record(
        &gid,
        EPOCH,
        Some(&target_seed),
        &target_pk,
        &node_secrets[0],
        &hedge,
        &random,
        &wrapped,
    );
    let changes = vec![
        Change {
            leaf: 1,
            kind: ChangeKind::Join,
            request: open_joins[0].reference(),
        },
        Change {
            leaf: 3,
            kind: ChangeKind::Removal,
            request: s.seed(),
        },
    ];
    let updates = vec![
        NodeUpdate {
            node: NodeId { level: 1, index: 0 },
            public_key: Some(node_pks[0].clone()),
        },
        NodeUpdate {
            node: NodeId { level: 1, index: 1 },
            public_key: None,
        },
        NodeUpdate {
            node: NodeId { level: 2, index: 0 },
            public_key: Some(node_pks[1].clone()),
        },
    ];
    let content = DistrictCommitContent {
        gid,
        epoch: EPOCH,
        district: 0,
        height: 2,
        prev_district_hash: s.seed(),
        committer: CREATOR,
        changes: changes.clone(),
        updates: updates.clone(),
        wraps: vec![wrapped.clone()],
        district_hash: s.seed(),
    };
    let rnd = s.seed();
    let commit = replay(&[&rnd], |rng| {
        DistrictCommit::sign(content.clone(), &cast.creator, rng)
    })
    .unwrap();
    let mut record = signed("creator", &rnd, commit.encoded());
    insert(
        &mut record,
        vec![
            ("epoch", json!(EPOCH)),
            ("district", json!(content.district)),
            ("height", json!(content.height)),
            ("prev_district_hash", hex(&content.prev_district_hash)),
            ("committer", occupancy(CREATOR)),
            ("changes", changes_json(&changes)),
            (
                "node_secrets",
                Value::Array(node_secrets.iter().map(|secret| hex(secret)).collect()),
            ),
            ("nodes", updates_json(&updates)),
            ("wraps", json!([wrap_json])),
            ("district_hash", hex(&content.district_hash)),
            ("hash", hex(&commit.hash())),
        ],
    );
    out.insert("district_commit".into(), Value::Object(record));

    let mut tasks = Vec::new();
    for part in [CityPart::SubCity(0), CityPart::Top] {
        let content = CityTaskContent {
            gid,
            epoch: EPOCH,
            part,
            height: 20,
            prev_part_hash: s.seed(),
            performer: MEMBER,
            updates: updates.clone(),
            wraps: vec![wrapped.clone()],
            part_hash: s.seed(),
        };
        let rnd = s.seed();
        let task = replay(&[&rnd], |rng| {
            CityTask::sign(content.clone(), &cast.member, rng)
        })
        .unwrap();
        let mut record = signed("member", &rnd, task.encoded());
        insert(
            &mut record,
            vec![
                ("epoch", json!(EPOCH)),
                (
                    "part",
                    match part {
                        CityPart::SubCity(subcity) => json!(subcity),
                        CityPart::Top => Value::Null,
                    },
                ),
                ("height", json!(content.height)),
                ("prev_part_hash", hex(&content.prev_part_hash)),
                ("performer", occupancy(MEMBER)),
                ("nodes", updates_json(&updates)),
                ("wraps", json!([wrap_json])),
                ("part_hash", hex(&content.part_hash)),
                ("hash", hex(&task.hash())),
            ],
        );
        tasks.push(Value::Object(record));
    }
    out.insert("city_tasks".into(), Value::Array(tasks));

    // A dispute of that wrap.
    let statement = DisputeStatement::new(
        &gid,
        EPOCH,
        &wrapped,
        &target_pk,
        &node_pks[0],
        DisputeKind::KeyDiffers,
    )
    .unwrap();
    let dispute_content = DisputeContent {
        gid,
        epoch: EPOCH,
        seal_hash: s.seed(),
        member: MEMBER,
        task: commit.hash(),
        wrap_index: 0,
        kind: DisputeKind::KeyDiffers,
        proof: s.bytes(8),
    };
    let rnd = s.seed();
    let dispute = replay(&[&rnd], |rng| {
        Dispute::sign(dispute_content.clone(), &cast.member, rng)
    })
    .unwrap();
    let mut record = signed("member", &rnd, dispute.encoded());
    insert(
        &mut record,
        vec![
            ("epoch", json!(EPOCH)),
            ("seal_hash", hex(&dispute_content.seal_hash)),
            ("member", occupancy(MEMBER)),
            ("task", hex(&dispute_content.task)),
            ("wrap_index", json!(0)),
            ("kind", json!(DisputeKind::KeyDiffers.code())),
            ("proof", hex(&dispute_content.proof)),
            ("node_key", hex(&node_pks[0])),
            ("statement", hex(&statement.encode().unwrap())),
        ],
    );
    out.insert("dispute".into(), Value::Object(record));

    // Genesis seals, closed and open.
    out.insert("genesis_closed".into(), genesis(s, &cast, false));
    out.insert("genesis_open".into(), genesis(s, &cast, true));
    Value::Object(out)
}

fn changes_json(changes: &[Change]) -> Value {
    Value::Array(
        changes
            .iter()
            .map(|change| json!({"kind": change.kind.code(), "leaf": change.leaf, "request": hex(&change.request)}))
            .collect(),
    )
}

fn updates_json(updates: &[NodeUpdate]) -> Value {
    Value::Array(
        updates
            .iter()
            .map(|update| json!({"node": node(update.node), "public_key": optional_hex(update.public_key.as_deref())}))
            .collect(),
    )
}

fn relay_context_encoding(context: &RelayContext) -> Vec<u8> {
    cbor::encode(&cbor::array(vec![
        cbor::bytes(&context.gid),
        cbor::uint(context.epoch),
        cbor::uint(u64::from(context.island_bits)),
        cbor::uint(u64::from(context.island)),
        cbor::bytes(&context.interim),
    ]))
    .unwrap()
}

fn welcome_context(
    gid: &[u8; 32],
    epoch: u64,
    request: &[u8; 32],
    init_key: &[u8],
    leaf_key: Option<&[u8]>,
) -> Vec<u8> {
    cbor::encode(&cbor::array(vec![
        cbor::bytes(gid),
        cbor::uint(epoch),
        cbor::bytes(request),
        cbor::bytes(&kem_pk_hash(init_key).unwrap()),
        leaf_key.map_or(ciborium::value::Value::Null, |key| {
            cbor::bytes(&kem_pk_hash(key).unwrap())
        }),
    ]))
    .unwrap()
}

/// The vector of a welcome: its inputs, both encapsulations and the keys of
/// its seal, checked against the definitions.
#[allow(clippy::too_many_arguments)]
fn welcome_json(
    gid: &[u8; 32],
    epoch: u64,
    request: &[u8; 32],
    init_seed: &[u8; 32],
    leaf_seed: Option<&[u8; 32]>,
    joiner_secret: &[u8; 32],
    hedge: &[u8; 32],
    randoms: &[[u8; 32]],
    welcome: &Welcome,
) -> Value {
    let init_key = KemSecret::from_seed(*init_seed).public_key();
    let leaf_key = leaf_seed.map(|seed| KemSecret::from_seed(*seed).public_key());
    let context = welcome_context(gid, epoch, request, &init_key, leaf_key.as_deref());
    let init = hedged_coins(hedge, &context, &init_key, &randoms[0]);
    assert_eq!(bytes(&init, "kem_ciphertext"), welcome.kem_ciphertext);
    let mut welcome_secret = digest(&init, "shared_secret");
    let leaf = leaf_key.as_ref().map(|leaf_key| {
        let leaf = hedged_coins(hedge, &context, leaf_key, &randoms[1]);
        assert_eq!(
            Some(bytes(&leaf, "kem_ciphertext")),
            welcome.leaf_ciphertext
        );
        welcome_secret = *extract(&welcome_secret, &digest(&leaf, "shared_secret"));
        leaf
    });
    let key: [u8; 32] = expand_label(&welcome_secret, "welcome key", &context, 32)
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = expand_label(&welcome_secret, "welcome nonce", &context, 12)
        .try_into()
        .unwrap();
    assert_eq!(
        aead_open(&key, &nonce, &context, &welcome.sealed),
        joiner_secret
    );
    json!({
        "epoch": epoch,
        "request": hex(request),
        "init_seed": hex(init_seed),
        "init_key": hex(&init_key),
        "leaf_seed": optional_hex(leaf_seed.map(|seed| &seed[..])),
        "leaf_key": optional_hex(leaf_key.as_deref()),
        "joiner_secret": hex(joiner_secret),
        "hedge": hex(hedge),
        "context": hex(&context),
        "init_encapsulation": init,
        "leaf_encapsulation": leaf.unwrap_or(Value::Null),
        "welcome_secret": hex(&welcome_secret),
        "key": hex(&key),
        "nonce": hex(&nonce),
        "sealed": hex(&welcome.sealed),
        "encoded": hex(&welcome.encode().unwrap()),
    })
}

/// A genesis seal from recorded randomness, with the secrets of epoch 0.
fn genesis(s: &mut Sampler, cast: &Cast, open: bool) -> Value {
    let nonce = if open { s.seed() } else { cast.nonce };
    let gid = group_id(cast.creator.public_key(), &nonce).unwrap();
    let divisions = Divisions::new(2, 1, 1).unwrap();
    let policy_rnd = open.then(|| s.seed());
    let leaf_seed = s.seed();
    let card_seed = s.seed();
    let root_random = s.seed();
    let seal_rnd = s.seed();
    let mut parts: Vec<&[u8]> = policy_rnd.iter().map(|rnd| &rnd[..]).collect();
    parts.extend([
        &leaf_seed[..],
        &card_seed[..],
        &root_random[..],
        &seal_rnd[..],
    ]);
    let (member, seal) = replay(&parts, |rng| {
        Member::create(cast.creator.clone(), nonce, divisions, open, TIME_MS, rng)
    })
    .unwrap();
    assert_eq!(seal.header.gid, gid);
    let hedge = task_hedge(&leaf_seed, &gid, 0).unwrap();
    let root_secret = replay(&[&root_random], |rng| fresh_secret(&hedge, rng)).unwrap();
    let genesis = seal.body.genesis.as_ref().unwrap();
    assert_eq!(
        genesis.root_pk,
        node_key(&root_secret).unwrap().public_key()
    );
    assert_eq!(
        genesis.encryption_key,
        KemSecret::from_seed(leaf_seed).public_key()
    );
    assert_eq!(
        genesis.card.public_key,
        DeviceIdentity::from_seed(&card_seed).public_key()
    );
    let commit = commit_secret(&root_secret).unwrap();
    let seal_hash = seal.header.hash().unwrap();
    let confirmed = confirmed_transcript_hash(&ZERO32, &seal_hash).unwrap();
    let context = GroupContext::of_seal(&seal.header).unwrap();
    assert_eq!(context.confirmed_transcript_hash, confirmed);
    let secrets = EpochSecrets::derive(&ZERO32, &commit, &context).unwrap();
    assert_eq!(secrets.confirmation_tag(&confirmed).unwrap(), seal.tag);
    assert_eq!(
        secrets.external_key().unwrap().public_key(),
        seal.external_pk
    );
    let interim = interim_transcript_hash(&confirmed, &seal.tag).unwrap();
    let header = member.header();
    assert_eq!(header.interim, interim);
    let msg_secret = *secrets.msg_secret().unwrap();
    let epoch_secret = derive(secrets.joiner_secret(), "epoch");
    assert_eq!(
        derive(&msg_secret, "authenticator"),
        *member.epoch_authenticator()
    );
    json!({
        "open": open,
        "group_nonce": hex(&nonce),
        "gid": hex(&gid),
        "divisions": {"district_bits": 2, "island_bits": 1, "subcity_bits": 1},
        "time_ms": TIME_MS,
        "policy_rnd": optional_hex(policy_rnd.as_ref().map(|rnd| &rnd[..])),
        "policy": optional_hex(seal.body.policy.as_deref()),
        "leaf_seed": hex(&leaf_seed),
        "encryption_key": hex(&genesis.encryption_key),
        "card_seed": hex(&card_seed),
        "card": hex(&cbor::encode(&genesis.card.value()).unwrap()),
        "root_random": hex(&root_random),
        "hedge": hex(&*hedge),
        "root_secret": hex(&*root_secret),
        "root_pk": hex(&genesis.root_pk),
        "seal_rnd": hex(&seal_rnd),
        "seal": hex(&seal.encode().unwrap()),
        "seal_proof": hex(&seal.proof().encode().unwrap()),
        "seal_hash": hex(&seal_hash),
        "body_hash": hex(&seal.header.body_hash),
        "tree_hash": hex(&seal.header.tree_hash),
        "registry_header": header_json(&header.registry),
        "membership_log": {"count": seal.header.membership_log.count, "root": hex(&seal.header.membership_log.root)},
        "message_log": {"count": seal.header.message_log.count, "root": hex(&seal.header.message_log.root)},
        "group_context": hex(&context.encode().unwrap()),
        "confirmed_transcript_hash": hex(&confirmed),
        "commit_secret": hex(&*commit),
        "joiner_secret": hex(secrets.joiner_secret()),
        "epoch_secret": hex(&epoch_secret),
        "init_secret": hex(secrets.init_secret()),
        "msg_secret": hex(&msg_secret),
        "confirm_key": hex(&derive(&epoch_secret, "confirm")),
        "external_secret": hex(&derive(&epoch_secret, "external")),
        "confirmation_tag": hex(&seal.tag),
        "external_pk": hex(&seal.external_pk),
        "interim_transcript_hash": hex(&interim),
        "epoch_authenticator": hex(member.epoch_authenticator()),
    })
}

/// The public keys of the cast, by name.
fn public_keys(v: &Value) -> BTreeMap<String, Vec<u8>> {
    get(v, "devices")
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, device)| {
            let identity = DeviceIdentity::from_seed(&digest(device, "seed"));
            assert_eq!(identity.public_key(), bytes(device, "public_key"));
            (name.clone(), identity.public_key().to_vec())
        })
        .collect()
}

fn keys_of(record: &Value) -> (Vec<u8>, Card) {
    let encryption_key = KemSecret::from_seed(digest(record, "leaf_seed")).public_key();
    assert_eq!(encryption_key, bytes(record, "encryption_key"));
    let card = Card::from_value(
        cbor::decode(&bytes(record, "card"), 4096, "card").unwrap(),
        "card",
    )
    .unwrap();
    assert_eq!(
        card.public_key,
        DeviceIdentity::from_seed(&digest(record, "card_seed")).public_key()
    );
    (encryption_key, card)
}

/// Check the file as a verifier would: every object decodes to its fields,
/// re-encodes to the same bytes and verifies under its signer's key.
pub fn check(v: &Value) {
    assert_eq!(text(v, "profile"), PROFILE);
    let gid = digest(v, "gid");
    let keys = public_keys(v);
    let pk = |name: &str| keys[name].as_slice();
    let signer_pk = |record: &Value| keys[text(record, "signer")].clone();
    for (name, device) in get(v, "devices").as_object().unwrap() {
        assert_eq!(
            labelled("device-id", vec![cbor::bytes(&gid), cbor::bytes(pk(name))]).1,
            digest(device, "device_id")
        );
    }
    assert_eq!(
        labelled(
            "group-id",
            vec![
                cbor::bytes(pk("creator")),
                cbor::bytes(&digest(v, "group_nonce"))
            ]
        )
        .1,
        gid
    );
    let admins: BTreeMap<Occupancy, Vec<u8>> = BTreeMap::from([(CREATOR, pk("creator").to_vec())]);

    let record = get(v, "invite");
    let invite = Invite::decode(&bytes(record, "encoded")).unwrap();
    assert_eq!(
        invite.invite_pk,
        DeviceIdentity::from_seed(&digest(record, "invite_seed")).public_key()
    );
    assert_eq!(invite.invite_pk, bytes(record, "invite_pk"));
    assert_eq!(
        (invite.expires_at_ms, invite.max_uses),
        (uint(record, "expires_at_ms"), uint(record, "max_uses"))
    );
    assert_eq!(invite.inviter, occupancy_of(get(record, "inviter")));
    assert_eq!(invite.inviter_pk, signer_pk(record));
    invite.verify(&gid, &admins).unwrap();
    assert_eq!(invite.id().unwrap(), digest(record, "id"));
    assert_eq!(
        labelled("invite-id", vec![cbor::bytes(&invite.invite_pk)]).1,
        digest(record, "id")
    );

    for name in ["admission_by_admin", "admission_with_invite"] {
        let record = get(v, name);
        let admission = Admission::decode(&bytes(record, "encoded")).unwrap();
        assert_eq!(admission.encoded(), bytes(record, "encoded"));
        let device = digest(record, "device_id");
        assert_eq!(
            device,
            digest(get(get(v, "devices"), text(record, "device")), "device_id")
        );
        assert_eq!(admission.device_id, device);
        assert_eq!(admission.not_after_epoch, uint(record, "not_after_epoch"));
        admission.verify(&gid, &device, NOT_AFTER, &admins).unwrap();
        assert_eq!(admission.hash(), digest(record, "hash"));
        assert_eq!(h(admission.encoded()), digest(record, "hash"));
        if name == "admission_with_invite" {
            assert_eq!(admission.authorizer_pk, invite.invite_pk);
        } else {
            assert_eq!(admission.authorizer_pk, signer_pk(record));
        }
    }

    let joins = get(v, "join_requests");
    let closed = Admitters::new(&admins, AdmissionMode::Closed, None, None).unwrap();
    let open = Admitters::new(&admins, AdmissionMode::Open, None, None).unwrap();
    let check_join = |record: &Value, admitters: &Admitters<'_>| -> JoinRequest {
        let request = JoinRequest::decode(&bytes(record, "encoded")).unwrap();
        assert_eq!(request.encoded(), bytes(record, "encoded"));
        assert_eq!(request.device_pk, signer_pk(record));
        let (encryption_key, card) = keys_of(record);
        assert_eq!(
            (request.encryption_key.clone(), request.card.clone()),
            (encryption_key, card)
        );
        assert_eq!(
            request.init_key,
            KemSecret::from_seed(digest(record, "init_seed")).public_key()
        );
        assert_eq!(request.init_key, bytes(record, "init_key"));
        assert_eq!(request.not_after_epoch, uint(record, "not_after_epoch"));
        assert_eq!(
            request
                .admission
                .as_ref()
                .map(|admission| admission.encoded().to_vec()),
            optional_bytes(record, "admission")
        );
        request.verify(&gid, NOT_AFTER, admitters).unwrap();
        assert_eq!(request.reference(), digest(record, "reference"));
        assert_eq!(h(request.encoded()), digest(record, "reference"));
        assert_eq!(request.token(), digest(record, "token"));
        request
    };
    check_join(get(joins, "admitted"), &closed);
    check_join(get(joins, "invited"), &closed);
    let open_joins: Vec<JoinRequest> = list(joins, "open")
        .iter()
        .map(|record| check_join(record, &open))
        .collect();
    for join in &open_joins {
        assert_eq!(join.token(), join.reference());
    }

    let authorizer_hash = authorizer_pk_hash(pk("authorizer")).unwrap();
    let authorized = Admitters::new(
        &admins,
        AdmissionMode::Authorized,
        Some(&authorizer_hash),
        Some(pk("authorizer")),
    )
    .unwrap();
    for (name, admitters) in [
        ("remove_proposal_self", &closed),
        ("remove_proposal_admin", &closed),
        ("remove_proposal_authorizer", &authorized),
    ] {
        let record = get(v, name);
        let proposal = RemoveProposal::decode(&bytes(record, "encoded")).unwrap();
        assert_eq!(proposal.encoded(), bytes(record, "encoded"));
        assert_eq!(proposal.target, occupancy_of(get(record, "target")));
        assert_eq!(
            proposal.proposer,
            match get(record, "proposer") {
                Value::Null => None,
                value => Some(occupancy_of(value)),
            }
        );
        assert_eq!(proposal.urgency as u64, uint(record, "urgency"));
        proposal.verify(&gid, admitters, pk("member")).unwrap();
    }

    let mut closed_policy = None;
    for name in [
        "group_policy_closed",
        "group_policy_open",
        "group_policy_authorized",
    ] {
        let record = get(v, name);
        let policy = GroupPolicy::decode(&bytes(record, "encoded")).unwrap();
        assert_eq!(policy.encoded(), bytes(record, "encoded"));
        assert_eq!(policy.admission().code(), uint(record, "admission_mode"));
        assert_eq!(
            policy.max_idle_epochs(),
            get(record, "max_idle_epochs").as_u64()
        );
        assert_eq!(
            policy.authorizer_pk().map(<[u8]>::to_vec),
            optional_bytes(record, "authorizer_pk")
        );
        assert_eq!(policy.admin, occupancy_of(get(record, "admin")));
        policy.verify_signature(&gid, &signer_pk(record)).unwrap();
        policy.verify(&gid, &admins).unwrap();
        assert_eq!(policy.hash(), digest(record, "hash"));
        if name == "group_policy_closed" {
            closed_policy = Some(policy);
        }
    }
    let closed_policy = closed_policy.unwrap();
    let record = get(v, "eviction");
    let eviction = Eviction::decode(&bytes(record, "encoded")).unwrap();
    assert_eq!(eviction.target, occupancy_of(get(record, "target")));
    assert_eq!(eviction.policy_hash, digest(record, "policy_hash"));
    assert_eq!(eviction.policy_hash, closed_policy.hash());
    eviction.verify(&gid, &closed_policy, 0, 200).unwrap();

    let record = get(v, "update_request");
    let update = UpdateRequest::decode(&bytes(record, "encoded")).unwrap();
    assert_eq!(update.encoded(), bytes(record, "encoded"));
    assert_eq!(update.member, occupancy_of(get(record, "member")));
    let current_key = KemSecret::from_seed(digest(record, "current_key_seed")).public_key();
    assert_eq!(current_key, bytes(record, "current_key"));
    assert_eq!(
        update.replaces,
        labelled("kem-pk", vec![cbor::bytes(&current_key)]).1
    );
    assert_eq!(update.replaces, digest(record, "replaces"));
    let (encryption_key, card) = keys_of(record);
    assert_eq!(
        (update.encryption_key.clone(), update.card.clone()),
        (encryption_key, card)
    );
    update.verify(&gid, &signer_pk(record)).unwrap();

    let record = get(v, "catch_up_request");
    let catch_up = CatchUpRequest::decode(&bytes(record, "encoded")).unwrap();
    assert_eq!(catch_up.encoded(), bytes(record, "encoded"));
    assert_eq!(catch_up.member, occupancy_of(get(record, "member")));
    assert_eq!(catch_up.prev_interim, digest(record, "prev_interim"));
    assert_eq!(
        catch_up.init_key,
        KemSecret::from_seed(digest(record, "init_seed")).public_key()
    );
    catch_up
        .verify(&gid, &catch_up.prev_interim, &signer_pk(record))
        .unwrap();
    assert_eq!(catch_up.reference(), digest(record, "reference"));

    let record = get(v, "re_entry_request");
    let re_entry = ReEntryRequest::decode(&bytes(record, "encoded")).unwrap();
    assert_eq!(re_entry.encoded(), bytes(record, "encoded"));
    assert_eq!(re_entry.member, occupancy_of(get(record, "member")));
    assert_eq!(
        re_entry.replaces,
        labelled("kem-pk", vec![cbor::bytes(&bytes(record, "current_key"))]).1
    );
    let (encryption_key, card) = keys_of(record);
    assert_eq!(
        (re_entry.encryption_key.clone(), re_entry.card.clone()),
        (encryption_key, card)
    );
    assert_eq!(
        re_entry.init_key,
        KemSecret::from_seed(digest(record, "init_seed")).public_key()
    );
    re_entry.verify(&gid, &signer_pk(record)).unwrap();
    assert_eq!(re_entry.reference(), digest(record, "reference"));

    let record = get(v, "repair_request");
    let repair_request = RepairRequest::decode(&bytes(record, "encoded")).unwrap();
    assert_eq!(repair_request.encoded(), bytes(record, "encoded"));
    assert_eq!(
        (
            repair_request.epoch,
            repair_request.seal_hash,
            repair_request.member,
            repair_request.level
        ),
        (
            uint(record, "epoch"),
            digest(record, "seal_hash"),
            occupancy_of(get(record, "member")),
            u8_of(record, "level")
        )
    );
    repair_request.verify(&gid, &signer_pk(record)).unwrap();

    let record = get(v, "checkpoint");
    let checkpoint = Checkpoint::decode(&bytes(record, "encoded")).unwrap();
    assert_eq!(checkpoint.encoded(), bytes(record, "encoded"));
    let content = &checkpoint.content;
    assert_eq!(content.epoch, uint(record, "epoch"));
    assert_eq!(content.interim, digest(record, "interim"));
    assert_eq!(content.tree_hash, digest(record, "tree_hash"));
    assert_eq!(content.registry_hash, digest(record, "registry_hash"));
    assert_eq!(
        (
            content.height,
            content.district_bits,
            content.island_bits,
            content.subcity_bits
        ),
        (
            u8_of(record, "height"),
            u8_of(record, "district_bits"),
            u8_of(record, "island_bits"),
            u8_of(record, "subcity_bits")
        )
    );
    assert_eq!(content.external_pk_hash, digest(record, "external_pk_hash"));
    assert_eq!(content.time_ms, uint(record, "time_ms"));
    assert_eq!(checkpoint.admin, occupancy_of(get(record, "admin")));
    checkpoint.verify(&gid, &signer_pk(record)).unwrap();

    let record = get(v, "authorization_batch");
    let batch = Arc::new(AuthorizationBatch::decode(&bytes(record, "encoded")).unwrap());
    assert_eq!(batch.encoded(), bytes(record, "encoded"));
    assert_eq!(
        (batch.epoch, batch.root, batch.count),
        (
            uint(record, "epoch"),
            digest(record, "root"),
            uint(record, "count")
        )
    );
    batch.verify(&gid, &signer_pk(record)).unwrap();
    let requests = digest_list(record, "requests");
    assert_eq!(
        requests,
        open_joins
            .iter()
            .map(JoinRequest::reference)
            .collect::<Vec<_>>()
    );
    assert_eq!(batch.root, crate::merkle::mth("authorized", &requests));
    for (request, listed) in requests.iter().zip(list(record, "authorizations")) {
        let authorization = Authorization {
            batch: Arc::clone(&batch),
            index: uint(listed, "index"),
            path: digest_list(listed, "path"),
        };
        authorization
            .verify(&gid, batch.epoch, request, &signer_pk(record))
            .unwrap();
        assert!(
            authorization
                .verify(&gid, batch.epoch + 1, request, &signer_pk(record))
                .is_err()
        );
    }

    for name in ["welcome", "welcome_catch_up"] {
        check_welcome(&gid, get(v, name));
    }

    let record = get(v, "relay_element");
    let element = RelayElement::decode(&bytes(record, "encoded")).unwrap();
    assert_eq!(element.encode().unwrap(), bytes(record, "encoded"));
    let context = RelayContext {
        gid,
        epoch: uint(record, "epoch"),
        island_bits: u8_of(record, "island_bits"),
        island: u32_of(record, "island"),
        interim: digest(record, "interim"),
    };
    assert_eq!(
        (element.epoch, element.island),
        (context.epoch, context.island)
    );
    let context_encoded = relay_context_encoding(&context);
    assert_eq!(context_encoded, bytes(record, "context"));
    let island_secret = digest(record, "island_secret");
    let key: [u8; 32] = expand_label(&island_secret, "relay key", &context_encoded, 32)
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = expand_label(&island_secret, "relay nonce", &context_encoded, 12)
        .try_into()
        .unwrap();
    assert_eq!(
        (key, nonce.to_vec()),
        (digest(record, "key"), bytes(record, "nonce"))
    );
    assert_eq!(
        aead_open(&key, &nonce, &context_encoded, &bytes(record, "sealed")),
        digest(record, "root_secret")
    );
    assert_eq!(
        *element.open(&context, &island_secret).unwrap(),
        digest(record, "root_secret")
    );

    let record = get(v, "flat_element");
    let wrapped = check_wrap_record(record, &gid);
    let island_secret = digest(record, "island_secret");
    assert_eq!(
        bytes(record, "target_pk"),
        node_key(&island_secret).unwrap().public_key()
    );
    let shape = shape_of(record);
    assert_eq!(
        (wrapped.node, wrapped.target),
        (shape.root(), shape.island_root(u32_of(record, "island")))
    );
    assert_eq!(
        *open_flat(
            &gid,
            uint(record, "epoch"),
            shape,
            u32_of(record, "island"),
            &wrapped,
            &island_secret
        )
        .unwrap(),
        digest(record, "secret")
    );

    let record = get(v, "repair");
    let wrapped = check_wrap_record(record, &gid);
    let repair = Repair::decode(&bytes(record, "repair")).unwrap();
    assert_eq!(repair.encode().unwrap(), bytes(record, "repair"));
    assert_eq!(
        (repair.epoch, repair.leaf, repair.wrap.clone()),
        (uint(record, "epoch"), u32_of(record, "leaf"), wrapped)
    );
    let shape = shape_of(record);
    let leaf_key = KemSecret::from_seed(digest(record, "target_seed"));
    assert_eq!(
        *repair
            .open(
                &gid,
                repair.epoch,
                shape,
                repair.leaf,
                &leaf_key,
                &leaf_key.public_key()
            )
            .unwrap(),
        digest(record, "secret")
    );

    let record = get(v, "district_commit");
    let commit = DistrictCommit::decode(&bytes(record, "encoded")).unwrap();
    assert_eq!(commit.encoded(), bytes(record, "encoded"));
    assert_eq!(
        (
            commit.epoch,
            commit.district,
            commit.height,
            commit.prev_district_hash,
            commit.committer,
            commit.district_hash
        ),
        (
            uint(record, "epoch"),
            u32_of(record, "district"),
            u8_of(record, "height"),
            digest(record, "prev_district_hash"),
            occupancy_of(get(record, "committer")),
            digest(record, "district_hash")
        )
    );
    assert_eq!(changes_json(&commit.changes), *get(record, "changes"));
    assert_eq!(updates_json(&commit.updates), *get(record, "nodes"));
    check_node_secrets(record, &commit.updates);
    assert_eq!(commit.wraps, wraps_of(record, &gid));
    commit.verify_signature(&signer_pk(record)).unwrap();
    assert_eq!(commit.hash(), digest(record, "hash"));
    assert_eq!(h(commit.encoded()), digest(record, "hash"));

    for record in list(v, "city_tasks") {
        let task = CityTask::decode(&bytes(record, "encoded")).unwrap();
        assert_eq!(task.encoded(), bytes(record, "encoded"));
        let part = match get(record, "part") {
            Value::Null => CityPart::Top,
            value => CityPart::SubCity(u32::try_from(value.as_u64().unwrap()).unwrap()),
        };
        assert_eq!(
            (
                task.epoch,
                task.part,
                task.height,
                task.prev_part_hash,
                task.performer,
                task.part_hash
            ),
            (
                uint(record, "epoch"),
                part,
                u8_of(record, "height"),
                digest(record, "prev_part_hash"),
                occupancy_of(get(record, "performer")),
                digest(record, "part_hash")
            )
        );
        assert_eq!(updates_json(&task.updates), *get(record, "nodes"));
        assert_eq!(task.wraps, wraps_of(record, &gid));
        task.verify_signature(&signer_pk(record)).unwrap();
        assert_eq!(task.hash(), digest(record, "hash"));
    }

    let record = get(v, "dispute");
    let dispute = Dispute::decode(&bytes(record, "encoded")).unwrap();
    assert_eq!(dispute.encoded(), bytes(record, "encoded"));
    let content = &dispute.content;
    assert_eq!(
        (
            content.epoch,
            content.seal_hash,
            content.member,
            content.task,
            content.wrap_index
        ),
        (
            uint(record, "epoch"),
            digest(record, "seal_hash"),
            occupancy_of(get(record, "member")),
            digest(record, "task"),
            u32_of(record, "wrap_index")
        )
    );
    assert_eq!(content.kind.code(), uint(record, "kind"));
    assert_eq!(content.proof, bytes(record, "proof"));
    assert_eq!(content.task, commit.hash());
    dispute.verify(&gid, &signer_pk(record)).unwrap();
    let wrap_record = &list(get(v, "district_commit"), "wraps")[0];
    let statement = DisputeStatement::new(
        &gid,
        content.epoch,
        &commit.wraps[0],
        &bytes(wrap_record, "target_pk"),
        &bytes(record, "node_key"),
        content.kind,
    )
    .unwrap();
    assert_eq!(statement.encode().unwrap(), bytes(record, "statement"));
    assert_eq!(statement.context, bytes(wrap_record, "context"));

    for name in ["genesis_closed", "genesis_open"] {
        check_genesis(get(v, name), pk("creator"));
    }
}

fn shape_of(record: &Value) -> Shape {
    let divisions = get(record, "divisions");
    Shape::new(
        u8_of(record, "height"),
        Divisions::new(
            u8_of(divisions, "district_bits"),
            u8_of(divisions, "island_bits"),
            u8_of(divisions, "subcity_bits"),
        )
        .unwrap(),
    )
    .unwrap()
}

fn wraps_of(record: &Value, gid: &[u8; 32]) -> Vec<crypto::Wrap> {
    list(record, "wraps")
        .iter()
        .map(|wrapped| check_wrap_record(wrapped, gid))
        .collect()
}

/// The keyed nodes of a task derive their keys from the secrets listed.
fn check_node_secrets(record: &Value, updates: &[NodeUpdate]) {
    let secrets = digest_list(record, "node_secrets");
    let keyed: Vec<&NodeUpdate> = updates
        .iter()
        .filter(|update| update.public_key.is_some())
        .collect();
    assert_eq!(keyed.len(), secrets.len());
    for (update, secret) in keyed.iter().zip(&secrets) {
        assert_eq!(
            update.public_key.as_deref(),
            Some(node_key(secret).unwrap().public_key().as_slice())
        );
    }
}

fn check_welcome(gid: &[u8; 32], record: &Value) {
    let welcome = Welcome::decode(&bytes(record, "encoded")).unwrap();
    assert_eq!(welcome.encode().unwrap(), bytes(record, "encoded"));
    let init_key = KemSecret::from_seed(digest(record, "init_seed"));
    assert_eq!(init_key.public_key(), bytes(record, "init_key"));
    let leaf_key = optional_bytes(record, "leaf_seed")
        .map(|seed| KemSecret::from_seed(seed.try_into().unwrap()));
    assert_eq!(
        leaf_key.as_ref().map(KemSecret::public_key),
        optional_bytes(record, "leaf_key")
    );
    let request = digest(record, "request");
    assert_eq!(
        (welcome.epoch, welcome.request),
        (uint(record, "epoch"), request)
    );
    let context = welcome_context(
        gid,
        welcome.epoch,
        &request,
        &init_key.public_key(),
        optional_bytes(record, "leaf_key").as_deref(),
    );
    assert_eq!(context, bytes(record, "context"));
    let init = get(record, "init_encapsulation");
    let mut with_key = init.clone();
    with_key
        .as_object_mut()
        .unwrap()
        .insert("public_key".into(), get(record, "init_key").clone());
    with_key
        .as_object_mut()
        .unwrap()
        .insert("hedge".into(), get(record, "hedge").clone());
    check_hedged(&with_key, &context);
    assert_eq!(bytes(init, "kem_ciphertext"), welcome.kem_ciphertext);
    let mut welcome_secret = digest(init, "shared_secret");
    match (get(record, "leaf_encapsulation"), &welcome.leaf_ciphertext) {
        (Value::Null, None) => {}
        (leaf, Some(leaf_ciphertext)) => {
            let mut with_key = leaf.clone();
            with_key
                .as_object_mut()
                .unwrap()
                .insert("public_key".into(), get(record, "leaf_key").clone());
            with_key
                .as_object_mut()
                .unwrap()
                .insert("hedge".into(), get(record, "hedge").clone());
            check_hedged(&with_key, &context);
            assert_eq!(bytes(leaf, "kem_ciphertext"), *leaf_ciphertext);
            welcome_secret = extract_raw(&welcome_secret, &digest(leaf, "shared_secret"));
        }
        _ => panic!("a leaf encapsulation without a leaf ciphertext, or the reverse"),
    }
    assert_eq!(welcome_secret, digest(record, "welcome_secret"));
    let key: [u8; 32] = expand_label(&welcome_secret, "welcome key", &context, 32)
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = expand_label(&welcome_secret, "welcome nonce", &context, 12)
        .try_into()
        .unwrap();
    assert_eq!(
        (key, nonce.to_vec()),
        (digest(record, "key"), bytes(record, "nonce"))
    );
    let joiner_secret = digest(record, "joiner_secret");
    assert_eq!(
        aead_open(&key, &nonce, &context, &welcome.sealed),
        joiner_secret
    );
    assert_eq!(
        *welcome.open(&init_key, leaf_key.as_ref()).unwrap(),
        joiner_secret
    );
}

fn check_genesis(record: &Value, creator_pk: &[u8]) {
    let seal = Seal::decode(&bytes(record, "seal")).unwrap();
    assert_eq!(seal.encode().unwrap(), bytes(record, "seal"));
    assert_eq!(seal.proof().encode().unwrap(), bytes(record, "seal_proof"));
    seal.proof().verify_signature(creator_pk).unwrap();
    let gid = digest(record, "gid");
    assert_eq!(seal.header.gid, gid);
    assert_eq!(
        labelled(
            "group-id",
            vec![
                cbor::bytes(creator_pk),
                cbor::bytes(&digest(record, "group_nonce"))
            ]
        )
        .1,
        gid
    );
    let state = PublicState::from_genesis(&seal).unwrap();
    let header = state.header().unwrap();
    assert_eq!(header.tree_hash, digest(record, "tree_hash"));
    assert_eq!(header.registry, header_of(get(record, "registry_header")));
    assert_eq!(header.registry.hash().unwrap(), seal.header.registry_hash);
    assert_eq!(header.interim, digest(record, "interim_transcript_hash"));
    assert_eq!(header.external_pk, bytes(record, "external_pk"));
    let genesis = seal.body.genesis.as_ref().unwrap();
    assert_eq!(genesis.creator_pk, creator_pk);
    assert_eq!(
        seal.body.policy.as_deref().map(<[u8]>::to_vec),
        optional_bytes(record, "policy")
    );
    assert_eq!(
        seal.body.policy.is_some(),
        get(record, "open").as_bool().unwrap()
    );
    if let Some(policy) = &seal.body.policy {
        let policy = GroupPolicy::decode(policy).unwrap();
        assert!(policy.is_open());
        policy.verify_signature(&gid, creator_pk).unwrap();
    }
    let leaf_seed = digest(record, "leaf_seed");
    assert_eq!(
        genesis.encryption_key,
        KemSecret::from_seed(leaf_seed).public_key()
    );
    assert_eq!(genesis.encryption_key, bytes(record, "encryption_key"));
    assert_eq!(
        cbor::encode(&genesis.card.value()).unwrap(),
        bytes(record, "card")
    );
    assert_eq!(
        genesis.card.public_key,
        DeviceIdentity::from_seed(&digest(record, "card_seed")).public_key()
    );
    // The root secret, from the creator's hedge and randomness.
    let hedge_context = cbor::encode(&cbor::array(vec![cbor::bytes(&gid), cbor::uint(0)])).unwrap();
    let hedge: [u8; 32] = expand_label(&leaf_seed, "task hedge", &hedge_context, 32)
        .try_into()
        .unwrap();
    assert_eq!(hedge, digest(record, "hedge"));
    let root_secret = derive(
        &extract_raw(&hedge, &digest(record, "root_random")),
        "fresh node",
    );
    assert_eq!(root_secret, digest(record, "root_secret"));
    assert_eq!(
        genesis.root_pk,
        KemSecret::from_seed(derive(&root_secret, "tree node key")).public_key()
    );
    assert_eq!(genesis.root_pk, bytes(record, "root_pk"));
    // The key schedule of epoch 0.
    let seal_hash = h(&seal.header.encode().unwrap());
    assert_eq!(seal_hash, digest(record, "seal_hash"));
    assert_eq!(seal.header.body_hash, digest(record, "body_hash"));
    assert_eq!(
        h(&cbor::encode(
            &cbor::decode(&bytes(record, "seal"), 1 << 20, "seal")
                .unwrap()
                .as_array()
                .unwrap()[1]
        )
        .unwrap()),
        seal.header.body_hash
    );
    let confirmed = labelled(
        "confirmed-transcript",
        vec![cbor::bytes(&ZERO32), cbor::bytes(&seal_hash)],
    )
    .1;
    assert_eq!(confirmed, digest(record, "confirmed_transcript_hash"));
    let context = GroupContext::of_seal(&seal.header).unwrap();
    assert_eq!(context.confirmed_transcript_hash, confirmed);
    let encoded_context = context_encoding(&context);
    assert_eq!(encoded_context, bytes(record, "group_context"));
    let commit = derive(&root_secret, "commit");
    assert_eq!(commit, digest(record, "commit_secret"));
    let joiner: [u8; 32] = expand_label(
        &extract_raw(&ZERO32, &commit),
        "joiner",
        &h(&encoded_context),
        32,
    )
    .try_into()
    .unwrap();
    assert_eq!(joiner, digest(record, "joiner_secret"));
    let epoch_secret = derive(&joiner, "epoch");
    assert_eq!(epoch_secret, digest(record, "epoch_secret"));
    assert_eq!(derive(&epoch_secret, "init"), digest(record, "init_secret"));
    let msg_secret = derive(&epoch_secret, "msg");
    assert_eq!(msg_secret, digest(record, "msg_secret"));
    let confirm_key = derive(&epoch_secret, "confirm");
    assert_eq!(confirm_key, digest(record, "confirm_key"));
    let external_secret = derive(&epoch_secret, "external");
    assert_eq!(external_secret, digest(record, "external_secret"));
    assert_eq!(mac_raw(&confirm_key, &confirmed), seal.tag);
    assert_eq!(seal.tag, digest(record, "confirmation_tag"));
    assert_eq!(
        KemSecret::from_seed(derive(&external_secret, "external kem")).public_key(),
        seal.external_pk
    );
    assert_eq!(
        labelled(
            "interim-transcript",
            vec![cbor::bytes(&confirmed), cbor::bytes(&seal.tag)]
        )
        .1,
        digest(record, "interim_transcript_hash")
    );
    assert_eq!(
        derive(&msg_secret, "authenticator"),
        digest(record, "epoch_authenticator")
    );
    let logs = (get(record, "membership_log"), get(record, "message_log"));
    assert_eq!(
        (
            seal.header.membership_log.count,
            seal.header.membership_log.root
        ),
        (uint(logs.0, "count"), digest(logs.0, "root"))
    );
    assert_eq!(
        (seal.header.message_log.count, seal.header.message_log.root),
        (uint(logs.1, "count"), digest(logs.1, "root"))
    );
    assert_eq!(
        seal.header.message_log.root,
        crate::merkle::mth("msg-log", &[])
    );
    let creator_card = labelled("card", vec![genesis.card.value()]).1;
    let record_encoding = cbor::encode(&cbor::array(vec![
        cbor::uint(ChangeKind::Join.code()),
        cbor::uint(0),
        cbor::bytes(
            &labelled(
                "device-id",
                vec![cbor::bytes(&gid), cbor::bytes(creator_pk)],
            )
            .1,
        ),
        cbor::bytes(&creator_card[..8]),
    ]))
    .unwrap();
    assert_eq!(
        seal.header.membership_log.root,
        crate::merkle::mth("membership-log", &[h(&record_encoding)])
    );
    assert_eq!(seal.header.time_ms, uint(record, "time_ms"));
}
