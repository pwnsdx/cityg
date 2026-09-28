//! The test vectors of profile `city-g/v0.5-draft` (docs/vectors/README.md).
//!
//! `vectors_match_the_files` regenerates every file from the inputs its
//! sampler draws, compares it with the committed file, and checks the
//! committed file as a verifier would, from the inputs it lists;
//! `write_vectors` (ignored) writes the files.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

mod crypto_basics;
mod key_schedule;
mod merkle;
mod message_protection;
mod objects;
mod registry;
mod secret_tree;
mod support;
mod tree;

use serde_json::Value;
use support::Sampler;

type Family = (&'static str, fn(&mut Sampler) -> Value, fn(&Value));

const FAMILIES: [Family; 8] = [
    (
        crypto_basics::FILE,
        crypto_basics::generate,
        crypto_basics::check,
    ),
    (
        key_schedule::FILE,
        key_schedule::generate,
        key_schedule::check,
    ),
    (secret_tree::FILE, secret_tree::generate, secret_tree::check),
    (
        message_protection::FILE,
        message_protection::generate,
        message_protection::check,
    ),
    (merkle::FILE, merkle::generate, merkle::check),
    (tree::FILE, tree::generate, tree::check),
    (registry::FILE, registry::generate, registry::check),
    (objects::FILE, objects::generate, objects::check),
];

#[test]
fn vectors_match_the_files() {
    for (file, generate, check) in FAMILIES {
        let generated = generate(&mut Sampler::new());
        let committed = support::read(file);
        support::assert_same(&committed, &generated);
        check(&committed);
    }
}

#[test]
#[ignore = "writes docs/vectors: run it to regenerate the files"]
fn write_vectors() {
    for (file, generate, check) in FAMILIES {
        let generated = generate(&mut Sampler::new());
        check(&generated);
        support::write(file, &generated);
    }
}
