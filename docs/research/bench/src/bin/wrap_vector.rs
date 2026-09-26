//! A wrap made by `cityg-core`, with its key schedule, for the C++
//! reference of the dispute proof in `docs/research/dispute-zk/longfellow/`
//! (`dispute_test.cc`, `kWrap`): fixed inputs, the wrap's context, the
//! `ExpandLabel` input, the shared secret, the wrap's key and nonce, and the
//! sealed secret.
//!
//! Run: `cargo run --release --manifest-path docs/research/bench/Cargo.toml
//! --bin wrap_vector`

use cityg_core::cbor::{array, bytes, encode, text, uint};
use cityg_core::crypto::{expand_label_into, kem_pk_hash, unwrap, wrap};
use cityg_core::kem::KemSecret;
use cityg_core::tree::NodeId;
use rand_core::{CryptoRng, RngCore};

/// Randomness source that hands out fixed bytes, in order.
struct Fixed(Vec<u8>);

impl RngCore for Fixed {
    fn next_u32(&mut self) -> u32 {
        let mut word = [0u8; 4];
        self.fill_bytes(&mut word);
        u32::from_le_bytes(word)
    }

    fn next_u64(&mut self) -> u64 {
        let mut word = [0u8; 8];
        self.fill_bytes(&mut word);
        u64::from_le_bytes(word)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let rest = self.0.split_off(dest.len());
        dest.copy_from_slice(&self.0);
        self.0 = rest;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Fixed {}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let seed: [u8; 32] = std::array::from_fn(|i| (7 * i + 1) as u8);
    let eseed: Vec<u8> = (0..64).map(|i| (13 * i + 5) as u8).collect();
    let gid: [u8; 32] = std::array::from_fn(|i| (3 * i + 2) as u8);
    let secret: [u8; 32] = std::array::from_fn(|i| (11 * i + 9) as u8);
    let epoch = 1_000_003u64;
    let node = NodeId {
        level: 3,
        index: 41,
    };
    let target = NodeId {
        level: 2,
        index: 82,
    };

    let key = KemSecret::from_seed(seed);
    let pk = key.public_key();
    let wrapped = wrap(
        &gid,
        epoch,
        node,
        target,
        &pk,
        &secret,
        &mut Fixed(eseed.clone()),
    )
    .expect("wrap");
    assert_eq!(
        *unwrap(&gid, epoch, &wrapped, &key, &pk).expect("unwrap"),
        secret
    );

    // The wrap's context and the "wrap key" input of ExpandLabel, as
    // crypto.rs builds them.
    let pk_hash = kem_pk_hash(&pk).expect("pk hash");
    let context = encode(&array(vec![
        bytes(&gid),
        uint(epoch),
        uint(u64::from(node.level)),
        uint(u64::from(node.index)),
        uint(u64::from(target.level)),
        uint(u64::from(target.index)),
        bytes(&pk_hash),
    ]))
    .expect("context");
    let info = encode(&array(vec![
        text("city-g/v0.4 expand"),
        text("wrap key"),
        bytes(&context),
        uint(32),
    ]))
    .expect("info");
    let shared = key
        .decapsulate(&wrapped.kem_ciphertext)
        .expect("decapsulate");
    let mut wrap_key = [0u8; 32];
    let mut wrap_nonce = [0u8; 12];
    expand_label_into(&shared, "wrap key", &context, &mut wrap_key).expect("key");
    expand_label_into(&shared, "wrap nonce", &context, &mut wrap_nonce).expect("nonce");

    println!("seed        {}", hex(&seed));
    println!("eseed       {}", hex(&eseed));
    println!("gid         {}", hex(&gid));
    println!("secret      {}", hex(&secret));
    println!("epoch       {epoch}");
    println!("node        {} {}", node.level, node.index);
    println!("target      {} {}", target.level, target.index);
    println!("pk_hash     {}", hex(&pk_hash));
    println!("context     {}", hex(&context));
    println!("info (key)  {}", hex(&info));
    println!("shared      {}", hex(shared.as_ref()));
    println!("wrap key    {}", hex(&wrap_key));
    println!("wrap nonce  {}", hex(&wrap_nonce));
    println!("sealed      {}", hex(&wrapped.sealed));
}
