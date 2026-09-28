//! Micro-benchmarks of the primitives behind the CPU figures of the research
//! notes in `docs/research`, through the code paths of `cityg-core`:
//!
//! * re-key (`grands-groupes-2026-09-25.md`): one BLAKE3 derivation; the
//!   X-Wing key of a tree node from its secret, encapsulation and
//!   decapsulation; the wrap of a node secret to a child and its opening;
//!   ML-DSA-65 signing and verification;
//! * message plane (`plan-de-messages-2026-09-26.md`): FN-DSA-512 and
//!   FN-DSA-1024 (the `fn-dsa` crate) signing and verification, the
//!   derivation of a sender's chain in a secret tree of 2^24 leaves,
//!   ChaCha20-Poly1305 over a short message, and the hash of an envelope.
//!
//! Run: `cargo run --release --manifest-path docs/research/bench/Cargo.toml`

use std::hint::black_box;
use std::time::Instant;

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use cityg_core::crypto::{
    derive_secret, expand_label_into, expand_label32, h, node_key, unwrap, wrap,
};
use cityg_core::identity::{DeviceIdentity, verify_signature};
use cityg_core::kem::encapsulate;
use cityg_core::tree::NodeId;
use cityg_pqc::SignatureContext;
use fn_dsa::{
    DOMAIN_NONE, FN_DSA_LOGN_512, FN_DSA_LOGN_1024, HASH_ID_RAW, KeyPairGenerator,
    KeyPairGeneratorStandard, SigningKey, SigningKeyStandard, VerifyingKey, VerifyingKeyStandard,
    sign_key_size, signature_size, vrfy_key_size,
};
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

    println!("\nMessage plane (one core, release build)");
    let (fn512_sign, fn512_verify, fn512_sig, fn512_pk) =
        fn_dsa_costs(FN_DSA_LOGN_512, "FN-DSA-512", &mut rng);
    let (fn1024_sign, fn1024_verify, fn1024_sig, fn1024_pk) =
        fn_dsa_costs(FN_DSA_LOGN_1024, "FN-DSA-1024", &mut rng);
    let chain = time(
        "sender chain in a secret tree of 2^24 leaves",
        20_000,
        || {
            let mut node = derive_secret(black_box(&secret), "msg tree").expect("derive");
            for level in 0..24u8 {
                let label = if level % 2 == 0 {
                    "msg left"
                } else {
                    "msg right"
                };
                node = derive_secret(&node, label).expect("derive");
            }
            black_box(expand_label32(&node, "msg sender", &[0; 12]).expect("derive"));
        },
    );
    let key = [7u8; 32];
    let nonce = [9u8; 12];
    let text = vec![0x41_u8; 150];
    let aad = [0x11_u8; 64];
    let aead = time("ChaCha20-Poly1305, 150-byte message", 200_000, || {
        let cipher = ChaCha20Poly1305::new((&key).into());
        black_box(
            cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: black_box(&text),
                        aad: &aad,
                    },
                )
                .expect("seal"),
        );
    });
    let envelope = vec![0x5a_u8; 300];
    let hash = time("BLAKE3 of a 300-byte envelope", 200_000, || {
        black_box(h(black_box(&envelope)));
    });
    println!(
        "\nMSG_US = {{\"fndsa512_sign\": {fn512_sign:.1}, \"fndsa512_verify\": {fn512_verify:.1}, \
         \"fndsa1024_sign\": {fn1024_sign:.1}, \"fndsa1024_verify\": {fn1024_verify:.1}, \
         \"chain24\": {chain:.2}, \"aead150\": {aead:.2}, \"hash300\": {hash:.2}}}"
    );
    println!(
        "MSG_BYTES = {{\"fndsa512_sig\": {fn512_sig}, \"fndsa512_pk\": {fn512_pk}, \
         \"fndsa1024_sig\": {fn1024_sig}, \"fndsa1024_pk\": {fn1024_pk}}}"
    );
}

/// Mean signing and verification times of FN-DSA with `2^logn`, and the
/// sizes of its signature and verifying key.
fn fn_dsa_costs(logn: u32, name: &str, rng: &mut ChaCha20Rng) -> (f64, f64, usize, usize) {
    let mut generator = KeyPairGeneratorStandard::default();
    let mut signing = vec![0u8; sign_key_size(logn)];
    let mut verifying = vec![0u8; vrfy_key_size(logn)];
    generator.keygen(logn, rng, &mut signing, &mut verifying);
    let mut key = SigningKeyStandard::decode(&signing).expect("signing key");
    let public = VerifyingKeyStandard::decode(&verifying).expect("verifying key");
    let message = vec![0x5a_u8; 1024];
    let mut signature = vec![0u8; signature_size(logn)];
    let sign = time(&format!("{name} signature, 1 KiB"), 500, || {
        key.sign(
            rng,
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            black_box(&message),
            &mut signature,
        );
    });
    key.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, &message, &mut signature);
    let verify = time(&format!("{name} verification, 1 KiB"), 2_000, || {
        assert!(public.verify(black_box(&signature), &DOMAIN_NONE, &HASH_ID_RAW, &message));
    });
    (sign, verify, signature.len(), verifying.len())
}
