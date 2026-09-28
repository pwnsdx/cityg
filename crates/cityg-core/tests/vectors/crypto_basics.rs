//! `crypto-basics.json`: the hash, derivation and identifier functions of
//! docs/specs.md sections 3 and 4, and the wrap of section 7.2, under the
//! framing of docs/specs-v0.5-draft.md section 5.

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use ciborium::value::Value as Cbor;
use cityg_core::authorizer::authorizer_pk_hash;
use cityg_core::card::CardKey;
use cityg_core::cbor;
use cityg_core::crypto::{
    self, PROFILE, ZERO32, chain, commit_secret, derive_secret, encaps_coins, expand_label_into,
    extract, fresh_secret, h, h_l, hedged_encapsulate, kem_pk_hash, mac, node_key, task_hedge,
    unwrap,
};
use cityg_core::identity::DeviceIdentity;
use cityg_core::kem::{KemSecret, encapsulate_derand};
use cityg_core::objects::{device_id, group_id};
use cityg_core::tree::{NodeId, leaf_key_hash};
use cityg_pqc::SignatureContext;
use serde_json::{Map, Value, json};

use crate::support::{
    Sampler, bytes, digest, digest_of, get, hex, list, node, node_of, replay, text, uint, unhex,
};

pub const FILE: &str = "crypto-basics.json";

const EXPAND_TAG: &str = "city-g/v0.5-draft expand";
const MAC_TAG: &str = "city-g/v0.5-draft mac";

/// `ExpandLabel(secret, label, context, L)` recomputed from its definition.
pub fn expand_label(secret: &[u8; 32], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let info = expand_info(label, context, length);
    let mut out = vec![0u8; length];
    blake3::Hasher::new_keyed(secret)
        .update(&info)
        .finalize_xof()
        .fill(&mut out);
    out
}

fn expand_info(label: &str, context: &[u8], length: usize) -> Vec<u8> {
    cbor::encode(&cbor::array(vec![
        cbor::text(EXPAND_TAG),
        cbor::text(label),
        cbor::bytes(context),
        cbor::uint(length as u64),
    ]))
    .unwrap()
}

/// `DeriveSecret(secret, label)` recomputed from its definition.
pub fn derive(secret: &[u8; 32], label: &str) -> [u8; 32] {
    expand_label(secret, label, &[], 32).try_into().unwrap()
}

/// `Extract(salt, ikm)` recomputed from its definition.
pub fn extract_raw(salt: &[u8; 32], ikm: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(salt, ikm).as_bytes()
}

/// `MAC(key, data)` recomputed from its definition.
pub fn mac_raw(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let framed = cbor::encode(&cbor::array(vec![cbor::text(MAC_TAG), cbor::bytes(data)])).unwrap();
    *blake3::keyed_hash(key, &framed).as_bytes()
}

/// `H_L(label, args)` recomputed from its definition; returns the preimage
/// too.
pub fn labelled(label: &str, args: Vec<Cbor>) -> (Vec<u8>, [u8; 32]) {
    let preimage = cbor::encode(&cbor::array(vec![
        cbor::text(PROFILE),
        cbor::text(label),
        cbor::array(args),
    ]))
    .unwrap();
    (preimage.clone(), h(&preimage))
}

/// The context of a wrap (docs/specs.md section 7.2).
pub fn wrap_context(
    gid: &[u8; 32],
    epoch: u64,
    node: NodeId,
    target: NodeId,
    target_pk: &[u8],
) -> Vec<u8> {
    cbor::encode(&cbor::array(vec![
        cbor::bytes(gid),
        cbor::uint(epoch),
        cbor::uint(u64::from(node.level)),
        cbor::uint(u64::from(node.index)),
        cbor::uint(u64::from(target.level)),
        cbor::uint(u64::from(target.index)),
        cbor::bytes(&kem_pk_hash(target_pk).unwrap()),
    ]))
    .unwrap()
}

/// The wire form of a wrap, `[level, index, target_level, target_index,
/// kem_ciphertext, sealed]`.
pub fn wrap_encoding(wrapped: &crypto::Wrap) -> Vec<u8> {
    cbor::encode(&cbor::array(vec![
        cbor::uint(u64::from(wrapped.node.level)),
        cbor::uint(u64::from(wrapped.node.index)),
        cbor::uint(u64::from(wrapped.target.level)),
        cbor::uint(u64::from(wrapped.target.index)),
        cbor::bytes(&wrapped.kem_ciphertext),
        cbor::bytes(&wrapped.sealed),
    ]))
    .unwrap()
}

/// Decrypt with ChaCha20-Poly1305.
pub fn aead_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .unwrap()
}

/// Encrypt with ChaCha20-Poly1305.
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .unwrap()
}

/// The vector of a wrap: its inputs, the hedged encapsulation and the keys
/// of its seal, checked against the definitions.
#[allow(clippy::too_many_arguments)]
pub fn wrap_record(
    gid: &[u8; 32],
    epoch: u64,
    target_seed: Option<&[u8; 32]>,
    target_pk: &[u8],
    secret: &[u8; 32],
    hedge: &[u8; 32],
    random: &[u8; 32],
    wrapped: &crypto::Wrap,
) -> Map<String, Value> {
    let context = wrap_context(gid, epoch, wrapped.node, wrapped.target, target_pk);
    let case = hedged_coins(hedge, &context, target_pk, random);
    let mut object = case.as_object().unwrap().clone();
    assert_eq!(unhex(&object["kem_ciphertext"]), wrapped.kem_ciphertext);
    let shared = digest_of(&object["shared_secret"]);
    let key: [u8; 32] = expand_label(&shared, "wrap key", &context, 32)
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = expand_label(&shared, "wrap nonce", &context, 12)
        .try_into()
        .unwrap();
    assert_eq!(aead_seal(&key, &nonce, &context, secret), wrapped.sealed);
    object.insert("epoch".into(), json!(epoch));
    object.insert("node".into(), node(wrapped.node));
    object.insert("target".into(), node(wrapped.target));
    if let Some(seed) = target_seed {
        object.insert("target_seed".into(), hex(seed));
    }
    object.insert("target_pk".into(), hex(target_pk));
    object.insert("secret".into(), hex(secret));
    object.insert("hedge".into(), hex(hedge));
    object.insert("context".into(), hex(&context));
    object.insert("key".into(), hex(&key));
    object.insert("nonce".into(), hex(&nonce));
    object.insert("sealed".into(), hex(&wrapped.sealed));
    object.insert("encoded".into(), hex(&wrap_encoding(wrapped)));
    object
}

/// Check the vector of a wrap of group `gid` against the definitions, and
/// return the wrap; with a `target_seed`, also open it.
pub fn check_wrap_record(case: &Value, gid: &[u8; 32]) -> crypto::Wrap {
    let epoch = uint(case, "epoch");
    let (node, target) = (node_of(get(case, "node")), node_of(get(case, "target")));
    let target_pk = bytes(case, "target_pk");
    let context = wrap_context(gid, epoch, node, target, &target_pk);
    assert_eq!(context, bytes(case, "context"));
    check_hedged(case, &context);
    let shared = digest(case, "shared_secret");
    let key: [u8; 32] = expand_label(&shared, "wrap key", &context, 32)
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = expand_label(&shared, "wrap nonce", &context, 12)
        .try_into()
        .unwrap();
    assert_eq!(key, digest(case, "key"));
    assert_eq!(nonce.to_vec(), bytes(case, "nonce"));
    let sealed = bytes(case, "sealed");
    let secret = digest(case, "secret");
    assert_eq!(aead_open(&key, &nonce, &context, &sealed), secret);
    let wrapped = crypto::Wrap {
        node,
        target,
        kem_ciphertext: bytes(case, "kem_ciphertext"),
        sealed,
    };
    assert_eq!(wrap_encoding(&wrapped), bytes(case, "encoded"));
    if let Some(seed) = case.get("target_seed").map(digest_of) {
        let opened = unwrap(
            gid,
            epoch,
            &wrapped,
            &KemSecret::from_seed(seed),
            &target_pk,
        )
        .unwrap();
        assert_eq!(*opened, secret);
    }
    wrapped
}

/// The hedged coins of an encapsulation and what they derive from
/// (docs/specs-v0.5-draft.md section 3.3).
pub fn hedged_coins(
    hedge: &[u8; 32],
    context: &[u8],
    public_key: &[u8],
    random: &[u8; 32],
) -> Value {
    let prk = extract_raw(hedge, random);
    let info = cbor::encode(&cbor::array(vec![
        cbor::bytes(context),
        cbor::bytes(&kem_pk_hash(public_key).unwrap()),
    ]))
    .unwrap();
    let coins = expand_label(&prk, "encaps coins", &info, 64);
    let (ciphertext, shared) =
        encapsulate_derand(public_key, &coins.clone().try_into().unwrap()).unwrap();
    json!({
        "random": hex(random),
        "prk": hex(&prk),
        "info": hex(&info),
        "coins": hex(&coins),
        "kem_ciphertext": hex(&ciphertext),
        "shared_secret": hex(&*shared),
    })
}

pub fn generate(s: &mut Sampler) -> Value {
    json!({
        "profile": PROFILE,
        "hash": hash_cases(s),
        "labelled_hash": labelled_hash_cases(s),
        "extract": extract_cases(s),
        "expand_label": expand_label_cases(s),
        "derive_secret": derive_secret_cases(s),
        "mac": mac_cases(s),
        "identifiers": identifiers(s),
        "ml_dsa_65": ml_dsa_cases(s),
        "x_wing": x_wing_cases(s),
        "hedged_encapsulation": hedged_cases(s),
        "wrap": wrap_cases(s),
        "task_hedge": task_hedge_cases(s),
        "fresh_secret": fresh_secret_cases(s),
        "node_key": node_key_cases(s),
        "chain": chain_cases(s),
        "commit_secret": commit_secret_cases(s),
    })
}

fn hash_cases(s: &mut Sampler) -> Value {
    let inputs = [Vec::new(), b"abc".to_vec(), s.bytes(100)];
    Value::Array(
        inputs
            .iter()
            .map(|input| json!({"input": hex(input), "output": hex(&h(input))}))
            .collect(),
    )
}

fn labelled_hash_cases(s: &mut Sampler) -> Value {
    let cases = [
        (
            "example",
            vec![
                cbor::bytes(&s.bytes(3)),
                cbor::uint(7),
                cbor::text("t"),
                Cbor::Null,
            ],
        ),
        (
            "tree/parent",
            vec![Cbor::Null, cbor::bytes(&s.seed()), cbor::bytes(&s.seed())],
        ),
        (
            "smm/node",
            vec![cbor::bytes(&ZERO32), cbor::bytes(&s.seed())],
        ),
    ];
    Value::Array(
        cases
            .into_iter()
            .map(|(label, args)| {
                let (preimage, output) = labelled(label, args.clone());
                assert_eq!(h_l(label, args.clone()).unwrap(), output);
                json!({
                    "label": label,
                    "args": hex(&cbor::encode(&cbor::array(args)).unwrap()),
                    "preimage": hex(&preimage),
                    "output": hex(&output),
                })
            })
            .collect(),
    )
}

fn extract_cases(s: &mut Sampler) -> Value {
    let salt = s.seed();
    let ikms = [Vec::new(), s.bytes(32), s.bytes(50)];
    Value::Array(
        ikms.iter()
            .map(|ikm| {
                let output = extract(&salt, ikm);
                assert_eq!(*output, extract_raw(&salt, ikm));
                json!({"salt": hex(&salt), "ikm": hex(ikm), "output": hex(&*output)})
            })
            .collect(),
    )
}

fn expand_label_cases(s: &mut Sampler) -> Value {
    let secret = s.seed();
    let contexts = [Vec::new(), s.bytes(16)];
    let mut cases = Vec::new();
    for context in &contexts {
        for length in [12usize, 32, 64] {
            let mut output = vec![0u8; length];
            expand_label_into(&secret, "example", context, &mut output).unwrap();
            assert_eq!(output, expand_label(&secret, "example", context, length));
            cases.push(json!({
                "secret": hex(&secret),
                "label": "example",
                "context": hex(context),
                "length": length,
                "info": hex(&expand_info("example", context, length)),
                "output": hex(&output),
            }));
        }
    }
    Value::Array(cases)
}

fn derive_secret_cases(s: &mut Sampler) -> Value {
    let secret = s.seed();
    Value::Array(
        ["epoch", "init", "msg", "confirm", "external"]
            .iter()
            .map(|label| {
                let output = derive_secret(&secret, label).unwrap();
                assert_eq!(*output, derive(&secret, label));
                json!({"secret": hex(&secret), "label": label, "output": hex(&*output)})
            })
            .collect(),
    )
}

fn mac_cases(s: &mut Sampler) -> Value {
    let key = s.seed();
    let data = [s.seed().to_vec(), Vec::new()];
    Value::Array(
        data.iter()
            .map(|data| {
                let framed =
                    cbor::encode(&cbor::array(vec![cbor::text(MAC_TAG), cbor::bytes(data)]))
                        .unwrap();
                let output = mac(&key, data).unwrap();
                assert_eq!(output, mac_raw(&key, data));
                json!({"key": hex(&key), "data": hex(data), "framed": hex(&framed), "output": hex(&output)})
            })
            .collect(),
    )
}

fn identifiers(s: &mut Sampler) -> Value {
    let (creator_seed, creator) = s.device();
    let nonce = s.seed();
    let gid = group_id(creator.public_key(), &nonce).unwrap();
    let (device_seed, device) = s.device();
    let (kem_seed, kem) = s.kem();
    let kem_pk = kem.public_key();
    let card_seed = s.seed();
    let card = replay(&[&card_seed], CardKey::generate).card();
    let (authorizer_seed, authorizer) = s.device();
    json!({
        "creator_seed": hex(&creator_seed),
        "creator_pk": hex(creator.public_key()),
        "group_nonce": hex(&nonce),
        "gid": hex(&gid),
        "device_seed": hex(&device_seed),
        "device_pk": hex(device.public_key()),
        "device_id": hex(&device_id(&gid, device.public_key()).unwrap()),
        "kem_seed": hex(&kem_seed),
        "kem_pk": hex(&kem_pk),
        "kem_pk_hash": hex(&kem_pk_hash(&kem_pk).unwrap()),
        "leaf_key_hash": hex(&leaf_key_hash(&kem_pk).unwrap()),
        "card_seed": hex(&card_seed),
        "card": hex(&cbor::encode(&card.value()).unwrap()),
        "card_hash": hex(&card.hash().unwrap()),
        "authorizer_seed": hex(&authorizer_seed),
        "authorizer_pk": hex(authorizer.public_key()),
        "authorizer_pk_hash": hex(&authorizer_pk_hash(authorizer.public_key()).unwrap()),
    })
}

fn context_name(context: SignatureContext) -> &'static str {
    core::str::from_utf8(context.as_bytes()).unwrap()
}

fn ml_dsa_cases(s: &mut Sampler) -> Value {
    let long = s.bytes(100);
    let cases = [
        (SignatureContext::JOIN_REQUEST, b"abc".to_vec(), s.seed()),
        (SignatureContext::MESSAGE, long, ZERO32),
    ];
    Value::Array(
        cases
            .into_iter()
            .map(|(context, message, rnd)| {
                let (seed, identity) = s.device();
                let signature =
                    replay(&[&rnd], |rng| identity.sign(context, &message, rng)).unwrap();
                json!({
                    "seed": hex(&seed),
                    "public_key": hex(identity.public_key()),
                    "context": context_name(context),
                    "message": hex(&message),
                    "rnd": hex(&rnd),
                    "signature": hex(&signature),
                })
            })
            .collect(),
    )
}

fn x_wing_cases(s: &mut Sampler) -> Value {
    Value::Array(
        (0..2)
            .map(|_| {
                let (seed, key) = s.kem();
                let public_key = key.public_key();
                let coins: [u8; 64] = s.bytes(64).try_into().unwrap();
                let (ciphertext, shared) = encapsulate_derand(&public_key, &coins).unwrap();
                json!({
                    "seed": hex(&seed),
                    "public_key": hex(&public_key),
                    "coins": hex(&coins),
                    "ciphertext": hex(&ciphertext),
                    "shared_secret": hex(&*shared),
                })
            })
            .collect(),
    )
}

fn hedged_cases(s: &mut Sampler) -> Value {
    let (seed, key) = s.kem();
    let public_key = key.public_key();
    let context = s.bytes(24);
    let hedge = s.seed();
    let random = s.seed();
    let coins = replay(&[&random], |rng| {
        encaps_coins(&hedge, &context, &public_key, rng)
    })
    .unwrap();
    let (ciphertext, shared) = replay(&[&random], |rng| {
        hedged_encapsulate(&public_key, &context, &hedge, rng)
    })
    .unwrap();
    let mut case = hedged_coins(&hedge, &context, &public_key, &random);
    assert_eq!(unhex(get(&case, "coins")), coins.to_vec());
    assert_eq!(unhex(get(&case, "kem_ciphertext")), ciphertext);
    assert_eq!(unhex(get(&case, "shared_secret")), shared.to_vec());
    let object = case.as_object_mut().unwrap();
    object.insert("seed".into(), hex(&seed));
    object.insert("public_key".into(), hex(&public_key));
    object.insert("context".into(), hex(&context));
    object.insert("hedge".into(), hex(&hedge));
    json!([case])
}

fn wrap_cases(s: &mut Sampler) -> Value {
    let gid = s.seed();
    let epoch = 5;
    let node = NodeId { level: 2, index: 1 };
    let target = NodeId { level: 1, index: 3 };
    let (target_seed, target_key) = s.kem();
    let target_pk = target_key.public_key();
    let secret = s.seed();
    let hedge = s.seed();
    let random = s.seed();
    let wrapped = replay(&[&random], |rng| {
        crypto::wrap(&gid, epoch, node, target, &target_pk, &secret, &hedge, rng)
    })
    .unwrap();
    let mut record = wrap_record(
        &gid,
        epoch,
        Some(&target_seed),
        &target_pk,
        &secret,
        &hedge,
        &random,
        &wrapped,
    );
    record.insert("gid".into(), hex(&gid));
    json!([record])
}

fn task_hedge_cases(s: &mut Sampler) -> Value {
    let leaf_seed = s.seed();
    let gid = s.seed();
    Value::Array(
        [0u64, 12]
            .iter()
            .map(|epoch| {
                let context =
                    cbor::encode(&cbor::array(vec![cbor::bytes(&gid), cbor::uint(*epoch)])).unwrap();
                let output = task_hedge(&leaf_seed, &gid, *epoch).unwrap();
                assert_eq!(output.to_vec(), expand_label(&leaf_seed, "task hedge", &context, 32));
                json!({"leaf_seed": hex(&leaf_seed), "gid": hex(&gid), "epoch": epoch, "context": hex(&context), "output": hex(&*output)})
            })
            .collect(),
    )
}

fn fresh_secret_cases(s: &mut Sampler) -> Value {
    let hedge = s.seed();
    let random = s.seed();
    let output = replay(&[&random], |rng| fresh_secret(&hedge, rng)).unwrap();
    let prk = extract_raw(&hedge, &random);
    assert_eq!(*output, derive(&prk, "fresh node"));
    json!([{"hedge": hex(&hedge), "random": hex(&random), "prk": hex(&prk), "output": hex(&*output)}])
}

fn node_key_cases(s: &mut Sampler) -> Value {
    let secret = s.seed();
    let key = node_key(&secret).unwrap();
    let seed = derive(&secret, "tree node key");
    assert_eq!(*key.seed(), seed);
    json!([{"secret": hex(&secret), "seed": hex(&seed), "public_key": hex(&key.public_key())}])
}

fn chain_cases(s: &mut Sampler) -> Value {
    let child = s.seed();
    let output = chain(&child).unwrap();
    assert_eq!(*output, derive(&child, "tree path"));
    json!([{"child_secret": hex(&child), "output": hex(&*output)}])
}

fn commit_secret_cases(s: &mut Sampler) -> Value {
    let root = s.seed();
    let output = commit_secret(&root).unwrap();
    assert_eq!(*output, derive(&root, "commit"));
    json!([{"root_secret": hex(&root), "output": hex(&*output)}])
}

/// Check the file as a verifier would: every output follows from the
/// inputs it lists.
pub fn check(v: &Value) {
    assert_eq!(text(v, "profile"), PROFILE);
    for case in list(v, "hash") {
        assert_eq!(h(&bytes(case, "input")), digest(case, "output"));
    }
    for case in list(v, "labelled_hash") {
        let preimage = bytes(case, "preimage");
        assert_eq!(h(&preimage), digest(case, "output"));
        let args = cbor::decode(&bytes(case, "args"), 4096, "args").unwrap();
        let framed = cbor::encode(&cbor::array(vec![
            cbor::text(PROFILE),
            cbor::text(text(case, "label")),
            args,
        ]))
        .unwrap();
        assert_eq!(framed, preimage);
    }
    for case in list(v, "extract") {
        assert_eq!(
            extract_raw(&digest(case, "salt"), &bytes(case, "ikm")),
            digest(case, "output")
        );
    }
    for case in list(v, "expand_label") {
        let length = usize::try_from(uint(case, "length")).unwrap();
        assert_eq!(
            expand_info(text(case, "label"), &bytes(case, "context"), length),
            bytes(case, "info")
        );
        assert_eq!(
            expand_label(
                &digest(case, "secret"),
                text(case, "label"),
                &bytes(case, "context"),
                length
            ),
            bytes(case, "output")
        );
    }
    for case in list(v, "derive_secret") {
        assert_eq!(
            derive(&digest(case, "secret"), text(case, "label")),
            digest(case, "output")
        );
    }
    for case in list(v, "mac") {
        let framed = cbor::encode(&cbor::array(vec![
            cbor::text(MAC_TAG),
            cbor::bytes(&bytes(case, "data")),
        ]))
        .unwrap();
        assert_eq!(framed, bytes(case, "framed"));
        assert_eq!(
            *blake3::keyed_hash(&digest(case, "key"), &framed).as_bytes(),
            digest(case, "output")
        );
    }
    check_identifiers(get(v, "identifiers"));
    for case in list(v, "ml_dsa_65") {
        let (public_key, secret_key) = cityg_pqc::keypair_from_seed(&digest(case, "seed"));
        assert_eq!(public_key, bytes(case, "public_key"));
        let context = context_of(text(case, "context"));
        let message = bytes(case, "message");
        let signature = bytes(case, "signature");
        assert_eq!(
            cityg_pqc::sign_with_randomness(&secret_key, context, &message, &digest(case, "rnd"))
                .unwrap(),
            signature
        );
        cityg_pqc::verify(&public_key, context, &message, &signature).unwrap();
    }
    for case in list(v, "x_wing") {
        let key = KemSecret::from_seed(digest(case, "seed"));
        assert_eq!(key.public_key(), bytes(case, "public_key"));
        let coins: [u8; 64] = bytes(case, "coins").try_into().unwrap();
        let (ciphertext, shared) = encapsulate_derand(&key.public_key(), &coins).unwrap();
        assert_eq!(ciphertext, bytes(case, "ciphertext"));
        assert_eq!(*shared, digest(case, "shared_secret"));
        assert_eq!(
            *key.decapsulate(&ciphertext).unwrap(),
            digest(case, "shared_secret")
        );
    }
    for case in list(v, "hedged_encapsulation") {
        check_hedged(case, &bytes(case, "context"));
        let key = KemSecret::from_seed(digest(case, "seed"));
        assert_eq!(
            *key.decapsulate(&bytes(case, "kem_ciphertext")).unwrap(),
            digest(case, "shared_secret")
        );
    }
    for case in list(v, "wrap") {
        check_wrap_record(case, &digest(case, "gid"));
    }
    for case in list(v, "task_hedge") {
        assert_eq!(
            expand_label(
                &digest(case, "leaf_seed"),
                "task hedge",
                &bytes(case, "context"),
                32
            ),
            bytes(case, "output")
        );
        let context = cbor::encode(&cbor::array(vec![
            cbor::bytes(&digest(case, "gid")),
            cbor::uint(uint(case, "epoch")),
        ]))
        .unwrap();
        assert_eq!(context, bytes(case, "context"));
    }
    for case in list(v, "fresh_secret") {
        let prk = extract_raw(&digest(case, "hedge"), &bytes(case, "random"));
        assert_eq!(prk, digest(case, "prk"));
        assert_eq!(derive(&prk, "fresh node"), digest(case, "output"));
    }
    for case in list(v, "node_key") {
        let seed = derive(&digest(case, "secret"), "tree node key");
        assert_eq!(seed, digest(case, "seed"));
        assert_eq!(
            KemSecret::from_seed(seed).public_key(),
            bytes(case, "public_key")
        );
    }
    for case in list(v, "chain") {
        assert_eq!(
            derive(&digest(case, "child_secret"), "tree path"),
            digest(case, "output")
        );
    }
    for case in list(v, "commit_secret") {
        assert_eq!(
            derive(&digest(case, "root_secret"), "commit"),
            digest(case, "output")
        );
    }
}

fn check_identifiers(v: &Value) {
    let creator = DeviceIdentity::from_seed(&digest(v, "creator_seed"));
    assert_eq!(creator.public_key(), bytes(v, "creator_pk"));
    let (_, gid) = labelled(
        "group-id",
        vec![
            cbor::bytes(creator.public_key()),
            cbor::bytes(&digest(v, "group_nonce")),
        ],
    );
    assert_eq!(gid, digest(v, "gid"));
    let device = DeviceIdentity::from_seed(&digest(v, "device_seed"));
    assert_eq!(device.public_key(), bytes(v, "device_pk"));
    let (_, id) = labelled(
        "device-id",
        vec![cbor::bytes(&gid), cbor::bytes(device.public_key())],
    );
    assert_eq!(id, digest(v, "device_id"));
    let kem_pk = KemSecret::from_seed(digest(v, "kem_seed")).public_key();
    assert_eq!(kem_pk, bytes(v, "kem_pk"));
    assert_eq!(
        labelled("kem-pk", vec![cbor::bytes(&kem_pk)]).1,
        digest(v, "kem_pk_hash")
    );
    assert_eq!(
        labelled("tree/leaf-key", vec![cbor::bytes(&kem_pk)]).1,
        digest(v, "leaf_key_hash")
    );
    let card_pk = DeviceIdentity::from_seed(&digest(v, "card_seed"))
        .public_key()
        .to_vec();
    let card = cbor::encode(&cbor::array(vec![cbor::uint(1), cbor::bytes(&card_pk)])).unwrap();
    assert_eq!(card, bytes(v, "card"));
    let card_value = cbor::decode(&card, 4096, "card").unwrap();
    assert_eq!(labelled("card", vec![card_value]).1, digest(v, "card_hash"));
    let authorizer_pk = DeviceIdentity::from_seed(&digest(v, "authorizer_seed"))
        .public_key()
        .to_vec();
    assert_eq!(authorizer_pk, bytes(v, "authorizer_pk"));
    assert_eq!(
        labelled("authorizer", vec![cbor::bytes(&authorizer_pk)]).1,
        digest(v, "authorizer_pk_hash")
    );
}

/// Check the coins of a hedged encapsulation case against its context.
pub fn check_hedged(case: &Value, context: &[u8]) {
    let public_key = bytes(
        case,
        if case.get("target_pk").is_some() {
            "target_pk"
        } else {
            "public_key"
        },
    );
    let prk = extract_raw(&digest(case, "hedge"), &digest(case, "random"));
    assert_eq!(prk, digest(case, "prk"));
    let info = cbor::encode(&cbor::array(vec![
        cbor::bytes(context),
        cbor::bytes(&labelled("kem-pk", vec![cbor::bytes(&public_key)]).1),
    ]))
    .unwrap();
    assert_eq!(info, bytes(case, "info"));
    let coins = expand_label(&prk, "encaps coins", &info, 64);
    assert_eq!(coins, bytes(case, "coins"));
    let (ciphertext, shared) = encapsulate_derand(&public_key, &coins.try_into().unwrap()).unwrap();
    assert_eq!(ciphertext, bytes(case, "kem_ciphertext"));
    assert_eq!(*shared, digest(case, "shared_secret"));
}

/// The signature context named `name`.
pub fn context_of(name: &str) -> SignatureContext {
    [
        SignatureContext::DISTRICT_COMMIT,
        SignatureContext::CITY_TASK,
        SignatureContext::SEAL,
        SignatureContext::JOIN_REQUEST,
        SignatureContext::ADMISSION,
        SignatureContext::INVITE,
        SignatureContext::REMOVE_PROPOSAL,
        SignatureContext::UPDATE_REQUEST,
        SignatureContext::CATCH_UP,
        SignatureContext::RE_ENTRY,
        SignatureContext::REPAIR_REQUEST,
        SignatureContext::DISPUTE,
        SignatureContext::MESSAGE,
        SignatureContext::CHECKPOINT,
        SignatureContext::GROUP_POLICY,
        SignatureContext::AUTHORIZATION_BATCH,
        SignatureContext::AUTHORIZER_CHECKPOINT,
    ]
    .into_iter()
    .find(|context| context_name(*context) == name)
    .unwrap_or_else(|| panic!("unknown signature context {name}"))
}
