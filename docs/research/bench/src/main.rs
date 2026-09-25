//! Micro-benchmarks of the primitives behind the CPU figures of
//! `docs/research/grands-groupes-2026-09-25.md`, through the same code paths
//! as `cityg-core`: X-Wing key generation from a seed, encapsulation and
//! decapsulation; the wrap of a 32-byte secret (X-Wing, then
//! ChaCha20-Poly1305 under keys derived with BLAKE3, as in update paths);
//! ML-DSA-65 signing and verification; one BLAKE3 derivation.
//!
//! Run: `cargo run --release --manifest-path docs/research/bench/Cargo.toml`

use std::hint::black_box;
use std::time::Instant;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use cityg_core::hash::expand_label_into;
use cityg_core::identity::{verify_signature, DeviceIdentity};
use cityg_core::kem::{encapsulate, KemSecret};
use cityg_pqc::SignatureContext;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

const CONTEXT: &[u8] = b"window 7, district 3, node 41, target 82";

/// Mean time of `f` in microseconds, after a short warm-up.
fn time(name: &str, iterations: u32, mut f: impl FnMut()) -> f64 {
    for _ in 0..(iterations / 10).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let micros = start.elapsed().as_secs_f64() * 1e6 / f64::from(iterations);
    println!("{name:<44} {micros:>9.1} us");
    micros
}

fn wrap_keys(shared: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let mut key = [0u8; 32];
    expand_label_into(shared, "tree path wrap key", CONTEXT, &mut key).expect("wrap key");
    let mut nonce = [0u8; 12];
    expand_label_into(shared, "tree path wrap nonce", CONTEXT, &mut nonce).expect("wrap nonce");
    (key, nonce)
}

/// Encapsulate to `public_key` and seal `secret` under the derived key.
fn wrap(public_key: &[u8], secret: &[u8; 32], rng: &mut ChaCha20Rng) -> (Vec<u8>, Vec<u8>) {
    let (ciphertext, shared) = encapsulate(public_key, rng).expect("encapsulate");
    let (key, nonce) = wrap_keys(&shared);
    let sealed = ChaCha20Poly1305::new((&key).into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: secret,
                aad: CONTEXT,
            },
        )
        .expect("seal");
    (ciphertext, sealed)
}

fn unwrap(key: &KemSecret, ciphertext: &[u8], sealed: &[u8]) -> Vec<u8> {
    let shared = key.decapsulate(ciphertext).expect("decapsulate");
    let (aead_key, nonce) = wrap_keys(&shared);
    ChaCha20Poly1305::new((&aead_key).into())
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: sealed,
                aad: CONTEXT,
            },
        )
        .expect("open")
}

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);

    println!("Primitive costs (one core, release build)");
    let derive = time("BLAKE3 ExpandLabel, 32 bytes", 200_000, || {
        let mut out = [0u8; 32];
        expand_label_into(black_box(&secret), "tree path", &[], &mut out).expect("derive");
        black_box(out);
    });
    let keygen = time("X-Wing node key from a secret (seed, pk)", 2_000, || {
        let key = KemSecret::derive(black_box(&secret), "tree node key").expect("derive");
        black_box(key.public_key());
    });
    let node = KemSecret::derive(&secret, "tree node key").expect("derive");
    let public_key = node.public_key();
    let encaps = time("X-Wing encapsulation", 2_000, || {
        black_box(encapsulate(black_box(&public_key), &mut rng).expect("encapsulate"));
    });
    let (ciphertext, _) = encapsulate(&public_key, &mut rng).expect("encapsulate");
    let decaps = time("X-Wing decapsulation", 2_000, || {
        black_box(
            node.decapsulate(black_box(&ciphertext))
                .expect("decapsulate"),
        );
    });
    let wrap_us = time("wrap of a 32-byte secret (X-Wing + AEAD)", 2_000, || {
        black_box(wrap(black_box(&public_key), &secret, &mut rng));
    });
    let (wrapped_ct, wrapped) = wrap(&public_key, &secret, &mut rng);
    assert_eq!(unwrap(&node, &wrapped_ct, &wrapped), secret);
    let unwrap_us = time("unwrap (X-Wing + AEAD)", 2_000, || {
        black_box(unwrap(&node, black_box(&wrapped_ct), &wrapped));
    });
    let identity = DeviceIdentity::generate(&mut rng);
    let message = vec![0x5a_u8; 1024];
    let sign = time("ML-DSA-65 signature, 1 KiB", 500, || {
        black_box(
            identity
                .sign(SignatureContext::ANCHOR, black_box(&message), &mut rng)
                .expect("sign"),
        );
    });
    let signature = identity
        .sign(SignatureContext::ANCHOR, &message, &mut rng)
        .expect("sign");
    let verify = time("ML-DSA-65 verification, 1 KiB", 2_000, || {
        verify_signature(
            identity.public_key(),
            SignatureContext::ANCHOR,
            black_box(&message),
            &signature,
            "bench",
        )
        .expect("verify");
    });

    // Machine-readable line for docs/research/rekey_sim.py.
    println!(
        "\nCPU_US = {{\"derive\": {derive:.2}, \"keygen\": {keygen:.1}, \"encaps\": {encaps:.1}, \
         \"decaps\": {decaps:.1}, \"wrap\": {wrap_us:.1}, \"unwrap\": {unwrap_us:.1}, \
         \"sign\": {sign:.1}, \"verify\": {verify:.1}}}"
    );
}
