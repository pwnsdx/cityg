//! Micro-benchmarks of the primitives behind the CPU figures of
//! `docs/research/grands-groupes-2026-09-25.md`, through the code paths of
//! `cityg-core`: one BLAKE3 derivation; the X-Wing key of a tree node from
//! its secret, encapsulation and decapsulation; the wrap of a node secret
//! to a child and its opening; ML-DSA-65 signing and verification.
//!
//! Run: `cargo run --release --manifest-path docs/research/bench/Cargo.toml`

use std::hint::black_box;
use std::time::Instant;

use cityg_core::crypto::{expand_label_into, node_key, unwrap, wrap};
use cityg_core::identity::{DeviceIdentity, verify_signature};
use cityg_core::kem::encapsulate;
use cityg_core::tree::NodeId;
use cityg_pqc::SignatureContext;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

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

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let gid = [3u8; 32];
    let node = NodeId { level: 2, index: 1 };
    let target = NodeId { level: 1, index: 3 };

    println!("Primitive costs (one core, release build)");
    let derive = time("BLAKE3 ExpandLabel, 32 bytes", 200_000, || {
        let mut out = [0u8; 32];
        expand_label_into(black_box(&secret), "tree path", &[], &mut out).expect("derive");
        black_box(out);
    });
    let keygen = time("X-Wing node key from a secret (seed, pk)", 2_000, || {
        let key = node_key(black_box(&secret)).expect("node key");
        black_box(key.public_key());
    });
    let key = node_key(&secret).expect("node key");
    let public_key = key.public_key();
    let encaps = time("X-Wing encapsulation", 2_000, || {
        black_box(encapsulate(black_box(&public_key), &mut rng).expect("encapsulate"));
    });
    let (ciphertext, _) = encapsulate(&public_key, &mut rng).expect("encapsulate");
    let decaps = time("X-Wing decapsulation", 2_000, || {
        black_box(
            key.decapsulate(black_box(&ciphertext))
                .expect("decapsulate"),
        );
    });
    let wrap_us = time("wrap of a node secret (X-Wing + AEAD)", 2_000, || {
        black_box(
            wrap(
                &gid,
                7,
                node,
                target,
                black_box(&public_key),
                &secret,
                &mut rng,
            )
            .expect("wrap"),
        );
    });
    let wrapped = wrap(&gid, 7, node, target, &public_key, &secret, &mut rng).expect("wrap");
    assert_eq!(
        *unwrap(&gid, 7, &wrapped, &key, &public_key).expect("unwrap"),
        secret
    );
    let unwrap_us = time("unwrap (X-Wing + AEAD)", 2_000, || {
        black_box(unwrap(&gid, 7, black_box(&wrapped), &key, &public_key).expect("unwrap"));
    });
    let identity = DeviceIdentity::generate(&mut rng);
    let message = vec![0x5a_u8; 1024];
    let sign = time("ML-DSA-65 signature, 1 KiB", 500, || {
        black_box(
            identity
                .sign(
                    SignatureContext::DISTRICT_COMMIT,
                    black_box(&message),
                    &mut rng,
                )
                .expect("sign"),
        );
    });
    let signature = identity
        .sign(SignatureContext::DISTRICT_COMMIT, &message, &mut rng)
        .expect("sign");
    let verify = time("ML-DSA-65 verification, 1 KiB", 2_000, || {
        verify_signature(
            identity.public_key(),
            SignatureContext::DISTRICT_COMMIT,
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
