//! `secret-tree.json`: the secret tree and the chains of the message plane
//! (docs/specs-v0.5-draft.md section 4.4), from their definitions.

use cityg_core::cbor;
use cityg_core::crypto::PROFILE;
use serde_json::{Value, json};

use crate::crypto_basics::{derive, expand_label};
use crate::support::{Sampler, bytes, digest, hex, list, text, u8_of, u32_of, uint};

pub const FILE: &str = "secret-tree.json";

const HEIGHT: u8 = 3;
const LEAVES: [u32; 3] = [0, 3, 7];
const GENERATIONS: u32 = 3;

/// The secrets of the secret tree from its root down to leaf `leaf`:
/// `(level, index, tree_secret(level, index))`.
pub fn tree_path(encryption_secret: &[u8; 32], height: u8, leaf: u32) -> Vec<(u8, u32, [u8; 32])> {
    let mut path = vec![(height, 0, *encryption_secret)];
    for level in (0..height).rev() {
        let parent = path.last().unwrap().2;
        let index = leaf >> level;
        let label = if index & 1 == 0 {
            "tree left"
        } else {
            "tree right"
        };
        path.push((level, index, derive(&parent, label)));
    }
    path
}

/// `ratchet_0(leaf)`.
pub fn ratchet_0(encryption_secret: &[u8; 32], height: u8, leaf: u32) -> [u8; 32] {
    derive(
        &tree_path(encryption_secret, height, leaf).last().unwrap().2,
        "application",
    )
}

/// The key and nonce of generation `generation` of a chain whose secret
/// is `ratchet`, and the secret of the next generation.
pub fn generation_keys(ratchet: &[u8; 32], generation: u32) -> ([u8; 32], [u8; 12], [u8; 32]) {
    let context = generation_context(generation);
    (
        expand_label(ratchet, "message key", &context, 32)
            .try_into()
            .unwrap(),
        expand_label(ratchet, "message nonce", &context, 12)
            .try_into()
            .unwrap(),
        expand_label(ratchet, "message secret", &context, 32)
            .try_into()
            .unwrap(),
    )
}

fn generation_context(generation: u32) -> Vec<u8> {
    cbor::encode(&cbor::uint(u64::from(generation))).unwrap()
}

pub fn generate(s: &mut Sampler) -> Value {
    let encryption_secret = s.seed();
    let leaves: Vec<Value> = LEAVES
        .iter()
        .map(|leaf| {
            let path: Vec<Value> = tree_path(&encryption_secret, HEIGHT, *leaf)
                .iter()
                .map(|(level, index, secret)| json!({"level": level, "index": index, "secret": hex(secret)}))
                .collect();
            let mut ratchet = ratchet_0(&encryption_secret, HEIGHT, *leaf);
            let ratchet_0 = ratchet;
            let generations: Vec<Value> = (0..GENERATIONS)
                .map(|generation| {
                    let (key, nonce, next) = generation_keys(&ratchet, generation);
                    let record = json!({
                        "generation": generation,
                        "context": hex(&generation_context(generation)),
                        "key": hex(&key),
                        "nonce": hex(&nonce),
                        "next_secret": hex(&next),
                    });
                    ratchet = next;
                    record
                })
                .collect();
            json!({"leaf": leaf, "path": path, "ratchet_0": hex(&ratchet_0), "generations": generations})
        })
        .collect();
    json!({
        "profile": PROFILE,
        "height": HEIGHT,
        "encryption_secret": hex(&encryption_secret),
        "leaves": leaves,
    })
}

/// Check the file: every secret follows from the encryption secret.
pub fn check(v: &Value) {
    assert_eq!(text(v, "profile"), PROFILE);
    let height = u8_of(v, "height");
    let encryption_secret = digest(v, "encryption_secret");
    for record in list(v, "leaves") {
        let leaf = u32_of(record, "leaf");
        let path = tree_path(&encryption_secret, height, leaf);
        let listed = list(record, "path");
        assert_eq!(listed.len(), path.len());
        for (step, (level, index, secret)) in listed.iter().zip(&path) {
            assert_eq!(
                (u8_of(step, "level"), u32_of(step, "index")),
                (*level, *index)
            );
            assert_eq!(digest(step, "secret"), *secret);
        }
        let mut ratchet = ratchet_0(&encryption_secret, height, leaf);
        assert_eq!(ratchet, digest(record, "ratchet_0"));
        for (expected, generation) in list(record, "generations").iter().zip(0u32..) {
            assert_eq!(uint(expected, "generation"), u64::from(generation));
            let (key, nonce, next) = generation_keys(&ratchet, generation);
            assert_eq!(key, digest(expected, "key"));
            assert_eq!(nonce.to_vec(), bytes(expected, "nonce"));
            assert_eq!(next, digest(expected, "next_secret"));
            ratchet = next;
        }
    }
}
