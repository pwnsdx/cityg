//! `key-schedule.json`: the key schedule of docs/specs.md section 9 with
//! the group context of the draft, over three epochs, the last of which an
//! entrant seals, and the secrets of the message plane
//! (docs/specs-v0.5-draft.md section 4.3).

use cityg_core::cbor;
use cityg_core::crypto::{PROFILE, ZERO32, commit_secret, h};
use cityg_core::kem::KemSecret;
use cityg_core::message::EpochMessages;
use cityg_core::schedule::{
    EpochSecrets, GroupContext, confirmed_transcript_hash, external_init, interim_transcript_hash,
    joiner_secret,
};
use serde_json::{Map, Value, json};

use crate::crypto_basics::{
    check_hedged, derive, expand_label, extract_raw, hedged_coins, labelled, mac_raw,
};
use crate::support::{Sampler, bytes, digest, get, hex, list, replay, text, u8_of, uint, unhex};

pub const FILE: &str = "key-schedule.json";

const CONTEXT_LABEL: &str = "city-g/group-context/v5";
const BITS: u8 = 8;

/// The exports every epoch's vector records: label, context, length.
const EXPORTS: [(&str, &[u8], usize); 2] = [("vector", b"context", 16), ("another label", b"", 32)];

/// The encoding of a group context from its definition.
pub fn context_encoding(context: &GroupContext) -> Vec<u8> {
    cbor::encode(&cbor::array(vec![
        cbor::text(CONTEXT_LABEL),
        cbor::bytes(&context.gid),
        cbor::uint(context.epoch),
        cbor::bytes(&context.tree_hash),
        cbor::bytes(&context.registry_hash),
        cbor::uint(u64::from(context.height)),
        cbor::uint(u64::from(context.district_bits)),
        cbor::uint(u64::from(context.island_bits)),
        cbor::uint(u64::from(context.subcity_bits)),
        cbor::text(PROFILE),
        cbor::bytes(&context.confirmed_transcript_hash),
    ]))
    .unwrap()
}

/// The secrets of the message plane of an epoch, and the exports, from
/// `msg_secret` by the definitions.
fn message_plane(gid: &[u8; 32], epoch: u64, height: u8, msg_secret: &[u8; 32]) -> Value {
    let plane = EpochMessages::new(gid, epoch, height, 0, msg_secret).unwrap();
    let exporter = derive(msg_secret, "exporter");
    let authenticator = derive(msg_secret, "authenticator");
    assert_eq!(*plane.authenticator(), authenticator);
    let exports: Vec<Value> = EXPORTS
        .iter()
        .map(|(label, context, length)| {
            let output = plane.export(label, context, *length).unwrap();
            assert_eq!(
                *output,
                expand_label(&derive(&exporter, label), "exported", &h(context), *length)
            );
            json!({"label": label, "context": hex(context), "length": length, "output": hex(&output)})
        })
        .collect();
    json!({
        "sender_data_secret": hex(&derive(msg_secret, "sender data")),
        "encryption_secret": hex(&derive(msg_secret, "encryption")),
        "exporter_secret": hex(&exporter),
        "epoch_authenticator": hex(&authenticator),
        "exports": exports,
    })
}

pub fn generate(s: &mut Sampler) -> Value {
    let gid = s.seed();
    let mut prev_init = ZERO32;
    let mut prev_interim = ZERO32;
    let mut previous: Option<(EpochSecrets, Vec<u8>)> = None;
    let mut epochs = Vec::new();
    for epoch in 0..3u64 {
        let height = u8::try_from(epoch + 1).unwrap();
        let tree_hash = s.seed();
        let registry_hash = s.seed();
        let seal_hash = s.seed();
        let root_secret = s.seed();
        let mut record = Map::new();
        record.insert("epoch".into(), json!(epoch));
        record.insert(
            "sealed_by".into(),
            json!(if epoch == 2 { "entrant" } else { "member" }),
        );
        if let Some((prev_secrets, prev_external_pk)) = previous.as_ref().filter(|_| epoch == 2) {
            // An entrant's external init replaces the init chain.
            let hedge = s.seed();
            let random = s.seed();
            let (kem_output, init) = replay(&[&random], |rng| {
                external_init(&gid, epoch, prev_external_pk, &hedge, rng)
            })
            .unwrap();
            let context =
                cbor::encode(&cbor::array(vec![cbor::bytes(&gid), cbor::uint(epoch)])).unwrap();
            let mut external = hedged_coins(&hedge, &context, prev_external_pk, &random);
            let shared = digest(&external, "shared_secret");
            assert_eq!(unhex(get(&external, "kem_ciphertext")), kem_output);
            assert_eq!(
                init.to_vec(),
                expand_label(
                    &extract_raw(&ZERO32, &shared),
                    "external init",
                    &h(&kem_output),
                    32
                )
            );
            assert_eq!(
                *prev_secrets.external_init_secret(&kem_output).unwrap(),
                *init
            );
            let fields = external.as_object_mut().unwrap();
            fields.remove("kem_ciphertext");
            fields.insert("kem_output".into(), hex(&kem_output));
            fields.insert("external_pk".into(), hex(prev_external_pk));
            fields.insert("context".into(), hex(&context));
            fields.insert("hedge".into(), hex(&hedge));
            fields.insert("external_init_secret".into(), hex(&*init));
            record.insert("external_init".into(), external);
            prev_init = *init;
        }
        let commit = commit_secret(&root_secret).unwrap();
        let confirmed = confirmed_transcript_hash(&prev_interim, &seal_hash).unwrap();
        let context = GroupContext {
            gid,
            epoch,
            tree_hash,
            registry_hash,
            height,
            district_bits: BITS,
            island_bits: BITS,
            subcity_bits: BITS,
            confirmed_transcript_hash: confirmed,
        };
        let encoded = context.encode().unwrap();
        assert_eq!(encoded, context_encoding(&context));
        let context_hash = context.hash().unwrap();
        let joiner = joiner_secret(&prev_init, &commit, &context).unwrap();
        assert_eq!(
            joiner.to_vec(),
            expand_label(
                &extract_raw(&prev_init, &*commit),
                "joiner",
                &context_hash,
                32
            )
        );
        let secrets = EpochSecrets::derive(&prev_init, &commit, &context).unwrap();
        let epoch_secret = derive(&joiner, "epoch");
        let msg_secret = *secrets.msg_secret().unwrap();
        assert_eq!(*secrets.init_secret(), derive(&epoch_secret, "init"));
        assert_eq!(msg_secret, derive(&epoch_secret, "msg"));
        let confirm_key = derive(&epoch_secret, "confirm");
        let external_secret = derive(&epoch_secret, "external");
        let tag = secrets.confirmation_tag(&confirmed).unwrap();
        assert_eq!(tag, mac_raw(&confirm_key, &confirmed));
        let external_key = secrets.external_key().unwrap();
        assert_eq!(
            *external_key.seed(),
            derive(&external_secret, "external kem")
        );
        let external_pk = external_key.public_key();
        let interim = interim_transcript_hash(&confirmed, &tag).unwrap();
        record.extend([
            ("prev_init".to_string(), hex(&prev_init)),
            ("prev_interim".to_string(), hex(&prev_interim)),
            ("root_secret".to_string(), hex(&root_secret)),
            ("commit_secret".to_string(), hex(&*commit)),
            ("seal_hash".to_string(), hex(&seal_hash)),
            ("confirmed_transcript_hash".to_string(), hex(&confirmed)),
            (
                "group_context".to_string(),
                json!({
                    "tree_hash": hex(&tree_hash),
                    "registry_hash": hex(&registry_hash),
                    "height": height,
                    "district_bits": BITS,
                    "island_bits": BITS,
                    "subcity_bits": BITS,
                    "encoded": hex(&encoded),
                    "hash": hex(&context_hash),
                }),
            ),
            ("joiner_secret".to_string(), hex(&*joiner)),
            ("epoch_secret".to_string(), hex(&epoch_secret)),
            ("init_secret".to_string(), hex(secrets.init_secret())),
            ("msg_secret".to_string(), hex(&msg_secret)),
            ("confirm_key".to_string(), hex(&confirm_key)),
            ("external_secret".to_string(), hex(&external_secret)),
            ("external_kem_seed".to_string(), hex(external_key.seed())),
            ("external_pk".to_string(), hex(&external_pk)),
            ("confirmation_tag".to_string(), hex(&tag)),
            ("interim_transcript_hash".to_string(), hex(&interim)),
            (
                "message_plane".to_string(),
                message_plane(&gid, epoch, height, &msg_secret),
            ),
        ]);
        epochs.push(Value::Object(record));
        prev_init = *secrets.init_secret();
        prev_interim = interim;
        previous = Some((secrets, external_pk));
    }
    json!({"profile": PROFILE, "gid": hex(&gid), "epochs": epochs})
}

/// Check the file as a verifier would: each epoch's secrets follow from
/// its inputs and the epoch before.
pub fn check(v: &Value) {
    assert_eq!(text(v, "profile"), PROFILE);
    let gid = digest(v, "gid");
    let mut chain: Option<(Value, [u8; 32])> = None;
    for record in list(v, "epochs") {
        let epoch = uint(record, "epoch");
        let prev_init = digest(record, "prev_init");
        let prev_interim = digest(record, "prev_interim");
        match (&chain, record.get("external_init")) {
            (None, None) => {
                assert_eq!((prev_init, prev_interim), (ZERO32, ZERO32));
            }
            (Some((before, _)), None) => {
                assert_eq!(prev_init, digest(before, "init_secret"));
            }
            (Some((before, before_joiner)), Some(external)) => {
                let context =
                    cbor::encode(&cbor::array(vec![cbor::bytes(&gid), cbor::uint(epoch)])).unwrap();
                assert_eq!(context, bytes(external, "context"));
                assert_eq!(bytes(external, "external_pk"), bytes(before, "external_pk"));
                let kem_output = bytes(external, "kem_output");
                let mut hedged = external.clone();
                hedged
                    .as_object_mut()
                    .unwrap()
                    .insert("kem_ciphertext".into(), hex(&kem_output));
                hedged
                    .as_object_mut()
                    .unwrap()
                    .insert("public_key".into(), get(external, "external_pk").clone());
                check_hedged(&hedged, &context);
                let shared = digest(external, "shared_secret");
                let init = expand_label(
                    &extract_raw(&ZERO32, &shared),
                    "external init",
                    &h(&kem_output),
                    32,
                );
                assert_eq!(init, bytes(external, "external_init_secret"));
                assert_eq!(init, prev_init.to_vec());
                let before_secrets = EpochSecrets::from_joiner_secret(before_joiner).unwrap();
                assert_eq!(
                    before_secrets
                        .external_init_secret(&kem_output)
                        .unwrap()
                        .to_vec(),
                    init
                );
            }
            (None, Some(_)) => panic!("an external init in the first epoch"),
        }
        if let Some((before, _)) = &chain {
            assert_eq!(prev_interim, digest(before, "interim_transcript_hash"));
        }
        let commit = derive(&digest(record, "root_secret"), "commit");
        assert_eq!(commit, digest(record, "commit_secret"));
        let confirmed = labelled(
            "confirmed-transcript",
            vec![
                cbor::bytes(&prev_interim),
                cbor::bytes(&digest(record, "seal_hash")),
            ],
        )
        .1;
        assert_eq!(confirmed, digest(record, "confirmed_transcript_hash"));
        let gc = get(record, "group_context");
        let context = GroupContext {
            gid,
            epoch,
            tree_hash: digest(gc, "tree_hash"),
            registry_hash: digest(gc, "registry_hash"),
            height: u8_of(gc, "height"),
            district_bits: u8_of(gc, "district_bits"),
            island_bits: u8_of(gc, "island_bits"),
            subcity_bits: u8_of(gc, "subcity_bits"),
            confirmed_transcript_hash: confirmed,
        };
        let encoded = context_encoding(&context);
        assert_eq!(encoded, bytes(gc, "encoded"));
        let context_hash = h(&encoded);
        assert_eq!(context_hash, digest(gc, "hash"));
        let joiner: [u8; 32] = expand_label(
            &extract_raw(&prev_init, &commit),
            "joiner",
            &context_hash,
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
        let external_seed = derive(&external_secret, "external kem");
        assert_eq!(external_seed, digest(record, "external_kem_seed"));
        assert_eq!(
            KemSecret::from_seed(external_seed).public_key(),
            bytes(record, "external_pk")
        );
        let tag = mac_raw(&confirm_key, &confirmed);
        assert_eq!(tag, digest(record, "confirmation_tag"));
        assert_eq!(
            labelled(
                "interim-transcript",
                vec![cbor::bytes(&confirmed), cbor::bytes(&tag)]
            )
            .1,
            digest(record, "interim_transcript_hash")
        );
        // The implementation agrees with the definitions.
        let secrets = EpochSecrets::from_joiner_secret(&joiner).unwrap();
        secrets.check_confirmation_tag(&confirmed, &tag).unwrap();
        assert_eq!(
            secrets.external_key().unwrap().public_key(),
            bytes(record, "external_pk")
        );
        let plane = get(record, "message_plane");
        assert_eq!(
            derive(&msg_secret, "sender data"),
            digest(plane, "sender_data_secret")
        );
        assert_eq!(
            derive(&msg_secret, "encryption"),
            digest(plane, "encryption_secret")
        );
        let exporter = derive(&msg_secret, "exporter");
        assert_eq!(exporter, digest(plane, "exporter_secret"));
        assert_eq!(
            derive(&msg_secret, "authenticator"),
            digest(plane, "epoch_authenticator")
        );
        let messages = EpochMessages::new(&gid, epoch, context.height, 0, &msg_secret).unwrap();
        assert_eq!(
            *messages.authenticator(),
            digest(plane, "epoch_authenticator")
        );
        for export in list(plane, "exports") {
            let length = usize::try_from(uint(export, "length")).unwrap();
            let expected = bytes(export, "output");
            let context = bytes(export, "context");
            assert_eq!(
                expand_label(
                    &derive(&exporter, text(export, "label")),
                    "exported",
                    &h(&context),
                    length
                ),
                expected
            );
            assert_eq!(
                *messages
                    .export(text(export, "label"), &context, length)
                    .unwrap(),
                expected
            );
        }
        chain = Some((record.clone(), joiner));
    }
}
