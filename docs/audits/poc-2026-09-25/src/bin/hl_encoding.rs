//! Finding H-06: spec S2.2 defines H_L(label, args[]) over CBOR_det of an
//! ARRAY; the implementation hashes named structs, which ciborium encodes as
//! CBOR MAPS with text keys in declaration order (not RFC 8949 §4.2.1 order).
//! Shown here for TreeHash (S11.4) and fs_dev_commit (S7.4).
use msphf_core::hash::h_l;
use serde::Serialize;

// Implementation shape: crates/cityg-client/src/barrier.rs (BarrierTreeLeafHashPreimage).
#[derive(Serialize)]
struct ImplLeafPreimage<'a> {
    n_max: u64,
    node_index: u64,
    #[serde(with = "serde_bytes")]
    pk: &'a [u8],
}

// Spec S11.4: H_L("barrier/tree/leaf-hash", [N_max, i, pk_i]).
#[derive(Serialize)]
struct SpecLeafPreimage<'a>(u64, u64, #[serde(with = "serde_bytes")] &'a [u8]);

// Implementation shape: crates/msphf-orchestrator/src/lib.rs (FsDevChainV2Preimage).
#[derive(Serialize)]
struct ImplDevChain<'a> {
    #[serde(with = "serde_bytes")]
    device_pk: &'a [u8],
    fs_ec: u64,
    #[serde(with = "serde_bytes")]
    prev_commit: &'a [u8; 32],
    barrier_version: u64,
    #[serde(with = "serde_bytes")]
    barrier_update_digest: &'a [u8; 32],
}

// Spec S7.4: H_L("fs/dev/chain/v2", [header[108], header[141], header[152], header[176], digest]).
#[derive(Serialize)]
struct SpecDevChain<'a>(
    #[serde(with = "serde_bytes")] &'a [u8],
    u64,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u64,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
);

fn cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)?;
    Ok(out)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pk = vec![0x11u8; 1184];
    let implementation = ImplLeafPreimage {
        n_max: 8,
        node_index: 9,
        pk: &pk,
    };
    let spec = SpecLeafPreimage(8, 9, &pk);
    println!(
        "TreeHash leaf  impl CBOR head = {:02x?} (map)",
        &cbor(&implementation)?[..8]
    );
    println!(
        "TreeHash leaf  spec CBOR head = {:02x?} (array)",
        &cbor(&spec)?[..4]
    );
    let impl_hash = h_l("barrier/tree/leaf-hash", &implementation)?;
    let spec_hash = h_l("barrier/tree/leaf-hash", &spec)?;
    println!(
        "TreeHash leaf  impl = {}\nTreeHash leaf  spec = {}\nequal = {}",
        hex::encode(impl_hash),
        hex::encode(spec_hash),
        impl_hash == spec_hash
    );

    let device_pk = vec![0xAAu8; 2592];
    let zero = [0u8; 32];
    let impl_chain = h_l(
        "fs/dev/chain/v2",
        &ImplDevChain {
            device_pk: &device_pk,
            fs_ec: 104,
            prev_commit: &zero,
            barrier_version: 0,
            barrier_update_digest: &zero,
        },
    )?;
    let spec_chain = h_l(
        "fs/dev/chain/v2",
        &SpecDevChain(&device_pk, 104, &zero, 0, &zero),
    )?;
    println!(
        "fs_dev_commit impl = {}\nfs_dev_commit spec = {}\nequal = {}",
        hex::encode(impl_chain),
        hex::encode(spec_chain),
        impl_chain == spec_chain
    );
    let map = cbor(&implementation)?;
    println!(
        "first map key emitted: {:?} (RFC 8949 §4.2.1 order would put \"pk\" first)",
        String::from_utf8_lossy(&map[2..7])
    );
    Ok(())
}
