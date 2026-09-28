//! `message-protection.json`: the messages of one sender in an epoch, from
//! their definitions (docs/specs-v0.5-draft.md sections 4.5 to 4.8), and
//! the log a seal commits.

use cityg_core::card::{Card, CardKey};
use cityg_core::cbor;
use cityg_core::crypto::{PROFILE, ZERO32, h};
use cityg_core::identity::DeviceIdentity;
use cityg_core::message::{EpochMessages, Message, MessageLog, T_BURST_MS};
use cityg_pqc::SignatureContext;
use serde_json::{Map, Value, json};

use crate::crypto_basics::{aead_open, aead_seal, derive, expand_label, labelled};
use crate::secret_tree::{generation_keys, ratchet_0};
use crate::support::{
    Sampler, bytes, digest, get, hex, list, optional_bytes, optional_hex, replay, text, u8_of,
    u32_of, uint,
};

pub const FILE: &str = "message-protection.json";

const LABEL: &str = "city-g/message/v5";
const EPOCH: u64 = 3;
const HEIGHT: u8 = 2;
const LEAF: u32 = 1;
const READER: u32 = 0;
/// The messages sent, and when: the first signs at once, the second waits
/// unsigned, the third signs the burst of both.
const PLAN: [(&[u8], u64); 3] = [
    (b"hello", 0),
    (b"a second message, unsigned", 100),
    (b"a third, which signs the burst", 2_500),
];
/// `MIN_CIPHERTEXT_BYTES - TAG_BYTES`: the content is padded up to it.
const MIN_CONTENT_BYTES: usize = 16;

fn aad(gid: &[u8; 32], epoch: u64) -> Vec<u8> {
    cbor::encode(&cbor::array(vec![
        cbor::text(LABEL),
        cbor::bytes(gid),
        cbor::uint(epoch),
    ]))
    .unwrap()
}

fn content_encoding(
    application_data: &[u8],
    first_generation: u32,
    signature: Option<&[u8]>,
    padding: usize,
) -> Vec<u8> {
    cbor::encode(&cbor::array(vec![
        cbor::bytes(application_data),
        cbor::uint(u64::from(first_generation)),
        signature.map_or(ciborium::value::Value::Null, cbor::bytes),
        cbor::bytes(&vec![0; padding]),
    ]))
    .unwrap()
}

fn chain_step(previous: &[u8; 32], application_data: &[u8], first_generation: u32) -> [u8; 32] {
    let entry = cbor::encode(&cbor::array(vec![
        cbor::bytes(application_data),
        cbor::uint(u64::from(first_generation)),
    ]))
    .unwrap();
    labelled(
        "msg-chain",
        vec![cbor::bytes(previous), cbor::bytes(&h(&entry))],
    )
    .1
}

fn signed_burst(
    gid: &[u8; 32],
    epoch: u64,
    leaf: u32,
    first_generation: u32,
    generation: u32,
    chain: &[u8; 32],
) -> Vec<u8> {
    cbor::encode(&cbor::array(vec![
        cbor::bytes(gid),
        cbor::uint(epoch),
        cbor::uint(u64::from(leaf)),
        cbor::uint(u64::from(first_generation)),
        cbor::uint(u64::from(generation)),
        cbor::bytes(chain),
    ]))
    .unwrap()
}

fn guarded(nonce: &[u8; 12], reuse_guard: &[u8; 4]) -> [u8; 12] {
    let mut out = *nonce;
    for (byte, guard) in out.iter_mut().zip(reuse_guard) {
        *byte ^= guard;
    }
    out
}

fn sender_data(leaf: u32, generation: u32, reuse_guard: &[u8; 4]) -> Vec<u8> {
    [
        &leaf.to_be_bytes()[..],
        &generation.to_be_bytes()[..],
        reuse_guard,
    ]
    .concat()
}

fn message_encoding(
    gid: &[u8; 32],
    epoch: u64,
    sender_data: &[u8],
    ciphertext: &[u8],
    commitment: &[u8; 32],
) -> Vec<u8> {
    cbor::encode(&cbor::array(vec![
        cbor::text(LABEL),
        cbor::bytes(gid),
        cbor::uint(epoch),
        cbor::bytes(sender_data),
        cbor::bytes(ciphertext),
        cbor::bytes(commitment),
    ]))
    .unwrap()
}

pub fn generate(s: &mut Sampler) -> Value {
    let gid = s.seed();
    let msg_secret = s.seed();
    let card_seed = s.seed();
    let card_key = replay(&[&card_seed], CardKey::generate);
    let card = card_key.card();
    let card_identity = DeviceIdentity::from_seed(&card_seed);
    let sender_data_secret = derive(&msg_secret, "sender data");
    let encryption_secret = derive(&msg_secret, "encryption");
    let mut plane = EpochMessages::new(&gid, EPOCH, HEIGHT, LEAF, &msg_secret).unwrap();
    let ratchet_start = ratchet_0(&encryption_secret, HEIGHT, LEAF);
    let mut ratchet = ratchet_start;
    let mut chain = ZERO32;
    let mut burst_start = 0u32;
    let mut unsigned_since: Option<u64> = None;
    let mut last_signed: Option<u64> = None;
    let aad = aad(&gid, EPOCH);
    let mut messages = Vec::new();
    let mut hashes = Vec::new();
    for (generation, (data, time_ms)) in PLAN.iter().enumerate() {
        let generation = u32::try_from(generation).unwrap();
        let sign = last_signed.is_none_or(|at| *time_ms >= at + T_BURST_MS)
            || unsigned_since.is_some_and(|since| *time_ms >= since + T_BURST_MS);
        let first_generation = burst_start;
        let next_chain = chain_step(&chain, data, first_generation);
        let mut record = Map::new();
        let mut signature = None;
        let mut rnd = None;
        if sign {
            let tbs = signed_burst(&gid, EPOCH, LEAF, first_generation, generation, &next_chain);
            let drawn = s.seed();
            let signed = replay(&[&drawn], |rng| {
                card_identity.sign(SignatureContext::MESSAGE, &tbs, rng)
            })
            .unwrap();
            record.insert("signed_burst".into(), hex(&tbs));
            record.insert("rnd".into(), hex(&drawn));
            signature = Some(signed);
            rnd = Some(drawn);
        }
        let reuse_guard: [u8; 4] = s.bytes(4).try_into().unwrap();
        let unpadded = content_encoding(data, first_generation, signature.as_deref(), 0);
        let padding = MIN_CONTENT_BYTES.saturating_sub(unpadded.len());
        let content = content_encoding(data, first_generation, signature.as_deref(), padding);
        let (key, nonce, next_secret) = generation_keys(&ratchet, generation);
        let guarded_nonce = guarded(&nonce, &reuse_guard);
        let ciphertext = aead_seal(&key, &guarded_nonce, &aad, &content);
        let commitment = labelled(
            "msg-commit",
            vec![
                cbor::bytes(&key),
                cbor::bytes(&guarded_nonce),
                cbor::bytes(&h(&ciphertext)),
            ],
        )
        .1;
        let plain_sender_data = sender_data(LEAF, generation, &reuse_guard);
        let sample = &ciphertext[..32];
        let sender_data_key: [u8; 32] =
            expand_label(&sender_data_secret, "sender data key", sample, 32)
                .try_into()
                .unwrap();
        let sender_data_nonce: [u8; 12] =
            expand_label(&sender_data_secret, "sender data nonce", sample, 12)
                .try_into()
                .unwrap();
        let encrypted_sender_data = aead_seal(
            &sender_data_key,
            &sender_data_nonce,
            &aad,
            &plain_sender_data,
        );
        let encoded = message_encoding(
            &gid,
            EPOCH,
            &encrypted_sender_data,
            &ciphertext,
            &commitment,
        );
        // The implementation produces the same message from the same
        // randomness.
        let parts: Vec<&[u8]> = rnd
            .iter()
            .map(|rnd| &rnd[..])
            .chain([&reuse_guard[..]])
            .collect();
        let message = replay(&parts, |rng| plane.send(data, &card_key, *time_ms, rng)).unwrap();
        assert_eq!(message.encode().unwrap(), encoded);
        let hash = message.hash().unwrap();
        hashes.push(hash);
        record.extend([
            ("application_data".to_string(), hex(data)),
            ("time_ms".to_string(), json!(time_ms)),
            ("generation".to_string(), json!(generation)),
            ("first_generation".to_string(), json!(first_generation)),
            ("chain".to_string(), hex(&next_chain)),
            ("signature".to_string(), optional_hex(signature.as_deref())),
            ("padding".to_string(), json!(padding)),
            ("content".to_string(), hex(&content)),
            ("key".to_string(), hex(&key)),
            ("nonce".to_string(), hex(&nonce)),
            ("reuse_guard".to_string(), hex(&reuse_guard)),
            ("guarded_nonce".to_string(), hex(&guarded_nonce)),
            ("ciphertext".to_string(), hex(&ciphertext)),
            ("commitment".to_string(), hex(&commitment)),
            ("sender_data".to_string(), hex(&plain_sender_data)),
            ("sender_data_key".to_string(), hex(&sender_data_key)),
            ("sender_data_nonce".to_string(), hex(&sender_data_nonce)),
            (
                "encrypted_sender_data".to_string(),
                hex(&encrypted_sender_data),
            ),
            ("message".to_string(), hex(&encoded)),
            ("hash".to_string(), hex(&hash)),
        ]);
        messages.push(Value::Object(record));
        ratchet = next_secret;
        chain = next_chain;
        if sign {
            burst_start = generation + 1;
            unsigned_since = None;
            last_signed = Some(*time_ms);
        } else if unsigned_since.is_none() {
            unsigned_since = Some(*time_ms);
        }
    }
    let log = MessageLog::of(&hashes).unwrap();
    json!({
        "profile": PROFILE,
        "gid": hex(&gid),
        "epoch": EPOCH,
        "height": HEIGHT,
        "leaf": LEAF,
        "msg_secret": hex(&msg_secret),
        "sender_data_secret": hex(&sender_data_secret),
        "encryption_secret": hex(&encryption_secret),
        "ratchet_0": hex(&ratchet_start),
        "card_seed": hex(&card_seed),
        "card": hex(&cbor::encode(&card.value()).unwrap()),
        "aad": hex(&aad),
        "messages": messages,
        "message_log": {
            "count": log.count,
            "root": hex(&log.root),
            "encoded": hex(&cbor::encode(&log.value()).unwrap()),
        },
    })
}

/// Check the file: each message follows from its inputs, and a reader of
/// the epoch opens and delivers them.
pub fn check(v: &Value) {
    assert_eq!(text(v, "profile"), PROFILE);
    let gid = digest(v, "gid");
    let epoch = uint(v, "epoch");
    let height = u8_of(v, "height");
    let leaf = u32_of(v, "leaf");
    let msg_secret = digest(v, "msg_secret");
    let sender_data_secret = derive(&msg_secret, "sender data");
    assert_eq!(sender_data_secret, digest(v, "sender_data_secret"));
    let encryption_secret = derive(&msg_secret, "encryption");
    assert_eq!(encryption_secret, digest(v, "encryption_secret"));
    let mut ratchet = ratchet_0(&encryption_secret, height, leaf);
    assert_eq!(ratchet, digest(v, "ratchet_0"));
    let card = Card::from_value(
        cbor::decode(&bytes(v, "card"), 4096, "card").unwrap(),
        "card",
    )
    .unwrap();
    assert_eq!(
        card.public_key,
        DeviceIdentity::from_seed(&digest(v, "card_seed")).public_key()
    );
    let aad = aad(&gid, epoch);
    assert_eq!(aad, bytes(v, "aad"));
    let mut reader = EpochMessages::new(&gid, epoch, height, READER, &msg_secret).unwrap();
    let mut chain = ZERO32;
    let mut delivered = Vec::new();
    let mut messages = Vec::new();
    for (record, generation) in list(v, "messages").iter().zip(0u32..) {
        assert_eq!(uint(record, "generation"), u64::from(generation));
        let data = bytes(record, "application_data");
        let first_generation = u32_of(record, "first_generation");
        chain = chain_step(&chain, &data, first_generation);
        assert_eq!(chain, digest(record, "chain"));
        let signature = optional_bytes(record, "signature");
        if let Some(signature) = &signature {
            let tbs = signed_burst(&gid, epoch, leaf, first_generation, generation, &chain);
            assert_eq!(tbs, bytes(record, "signed_burst"));
            card.verify(&tbs, signature).unwrap();
        }
        let padding = usize::try_from(uint(record, "padding")).unwrap();
        let content = content_encoding(&data, first_generation, signature.as_deref(), padding);
        assert_eq!(content, bytes(record, "content"));
        assert_eq!(
            padding,
            MIN_CONTENT_BYTES.saturating_sub(
                content_encoding(&data, first_generation, signature.as_deref(), 0).len()
            )
        );
        let (key, nonce, next) = generation_keys(&ratchet, generation);
        assert_eq!(
            (key, nonce.to_vec()),
            (digest(record, "key"), bytes(record, "nonce"))
        );
        let reuse_guard: [u8; 4] = bytes(record, "reuse_guard").try_into().unwrap();
        let guarded_nonce = guarded(&nonce, &reuse_guard);
        assert_eq!(guarded_nonce.to_vec(), bytes(record, "guarded_nonce"));
        let ciphertext = bytes(record, "ciphertext");
        assert_eq!(aead_open(&key, &guarded_nonce, &aad, &ciphertext), content);
        let commitment = labelled(
            "msg-commit",
            vec![
                cbor::bytes(&key),
                cbor::bytes(&guarded_nonce),
                cbor::bytes(&h(&ciphertext)),
            ],
        )
        .1;
        assert_eq!(commitment, digest(record, "commitment"));
        let sender_data_key: [u8; 32] = expand_label(
            &sender_data_secret,
            "sender data key",
            &ciphertext[..32],
            32,
        )
        .try_into()
        .unwrap();
        let sender_data_nonce: [u8; 12] = expand_label(
            &sender_data_secret,
            "sender data nonce",
            &ciphertext[..32],
            12,
        )
        .try_into()
        .unwrap();
        assert_eq!(sender_data_key, digest(record, "sender_data_key"));
        assert_eq!(
            sender_data_nonce.to_vec(),
            bytes(record, "sender_data_nonce")
        );
        let encrypted_sender_data = bytes(record, "encrypted_sender_data");
        assert_eq!(
            aead_open(
                &sender_data_key,
                &sender_data_nonce,
                &aad,
                &encrypted_sender_data
            ),
            sender_data(leaf, generation, &reuse_guard)
        );
        let encoded = bytes(record, "message");
        assert_eq!(
            message_encoding(
                &gid,
                epoch,
                &encrypted_sender_data,
                &ciphertext,
                &commitment
            ),
            encoded
        );
        assert_eq!(h(&encoded), digest(record, "hash"));
        // A reader of the epoch opens it, and delivers it once signed.
        let message = Message::decode(&encoded).unwrap();
        assert_eq!(message.encode().unwrap(), encoded);
        let received = reader.open(&message, uint(record, "time_ms")).unwrap();
        assert_eq!((received.leaf, received.generation), (leaf, generation));
        if received.ready {
            delivered.extend(
                reader
                    .authenticate(leaf, &card)
                    .unwrap()
                    .into_iter()
                    .map(|delivered| (delivered.generation, delivered.application_data)),
            );
        }
        messages.push(message);
        ratchet = next;
    }
    let expected: Vec<(u32, Vec<u8>)> = list(v, "messages")
        .iter()
        .zip(0u32..)
        .map(|(record, generation)| (generation, bytes(record, "application_data")))
        .collect();
    assert_eq!(delivered, expected);
    let log = get(v, "message_log");
    let sealed = MessageLog {
        count: uint(log, "count"),
        root: digest(log, "root"),
    };
    assert_eq!(
        cbor::encode(&sealed.value()).unwrap(),
        bytes(log, "encoded")
    );
    sealed.check(&messages).unwrap();
}
