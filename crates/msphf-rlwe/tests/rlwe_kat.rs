use msphf_core::{
    ds,
    hash::h_l,
    instance::AnchorInstance,
    merkle::{hash_leaf, hash_node},
    params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK},
    witness::{CanonicalWitness, RawMembershipWitness, RawPathEntry, WitnessVariants},
};
use msphf_rlwe::{derive_branch_material, hash_full, hash_proj};
use serde::Serialize;

const CRS_ID: &str = RLWE_CRS_ID_DEFAULT;
const PARAMS_ID: &str = RLWE_PARAMS_ID_MOCK;

#[derive(Serialize)]
struct SeedRef<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

fn leak(bytes: [u8; 32]) -> &'static [u8] {
    Box::leak(Box::new(bytes)).as_slice()
}

fn anchor_and_witness() -> (AnchorInstance<'static>, CanonicalWitness, [u8; 32]) {
    let leaf = hash_leaf(b"leaf0");
    let sibling = hash_leaf(b"leaf1");
    let root = hash_node(&leaf, &sibling);

    let witness = CanonicalWitness {
        inner: WitnessVariants::A {
            witness: RawMembershipWitness {
                leaf_id: leaf.to_vec(),
                root: root.to_vec(),
                path: vec![RawPathEntry {
                    sibling: sibling.to_vec(),
                    dir: 0,
                }],
            },
            pop: None,
        },
    };

    let anchor = AnchorInstance {
        gid: leak([0x10; 32]),
        cat: leak([0x11; 32]),
        we_epoch_id: [0x07; 32],
        anchor_hdr_ctx: leak([0x12; 32]),
        tswe_salt_hash: leak([0x13; 32]),
        parent_root: leak(root),
        join_delta_root: leak(hash_node(&leaf, &hash_leaf(b"leafx"))),
        revoked_since_prev_root: leak(hash_node(&hash_leaf(b"leafy"), &hash_leaf(b"leafz"))),
        revoked_root: leak(hash_node(&hash_leaf(b"leafm"), &hash_leaf(b"leafn"))),
        pox_r_commit: None,
        msphf_hp_commit: None,
    };
    let xk_hash = anchor.xk_hash().expect("xk_hash");
    (anchor, witness, xk_hash)
}

fn derive_branch_seed(drbg: &[u8; 32]) -> [u8; 32] {
    h_l(ds::MSPHF_KGEN_A, &SeedRef(drbg)).expect("derive branch seed")
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn kat_eqroot_projection_matches_full() {
    let (anchor, canonical, xk_hash) = anchor_and_witness();
    let seed_drbg = [0x21u8; 32];
    let seed_a = derive_branch_seed(&seed_drbg);
    let (sk_a, _) = derive_branch_material(&seed_a, "branch-a").expect("derive branch material");
    let full = hash_full(&sk_a, "A", CRS_ID, PARAMS_ID, &anchor, &xk_hash).expect("hash_full");
    let witness = canonical
        .validate_against(&anchor)
        .expect("canonical witness validates");
    let proj = hash_proj(
        &full.projective,
        "A",
        CRS_ID,
        PARAMS_ID,
        &anchor,
        Some(&witness),
    )
    .expect("hash_proj");
    let expected = "d838cb926100bc8b4ae5aaa65b68332f5e6844c398d5f0673e5ad7e5ee1ee2ad";
    assert_eq!(to_hex(&full.y_full), expected);
    assert_eq!(full.y_full, proj);
}

#[test]
fn kat_rootflip_detects_change() {
    let (anchor, canonical, xk_hash) = anchor_and_witness();
    let seed_drbg = [0x33u8; 32];
    let seed_a = derive_branch_seed(&seed_drbg);
    let (sk_a, _) = derive_branch_material(&seed_a, "branch-a").expect("derive branch material");
    let full = hash_full(&sk_a, "A", CRS_ID, PARAMS_ID, &anchor, &xk_hash).expect("hash_full");
    let mut tampered = canonical
        .validate_against(&anchor)
        .expect("canonical witness validates");
    tampered.membership.root[0] ^= 0x80;
    let proj = hash_proj(
        &full.projective,
        "A",
        CRS_ID,
        PARAMS_ID,
        &anchor,
        Some(&tampered),
    )
    .expect("hash_proj with tampered witness");
    assert_ne!(full.y_full, proj);
}

#[test]
fn kat_missing_witness_is_smooth() {
    let (anchor, _, xk_hash) = anchor_and_witness();
    let seed_drbg = [0x44u8; 32];
    let seed_a = derive_branch_seed(&seed_drbg);
    let (sk_a, _) = derive_branch_material(&seed_a, "branch-a").expect("derive branch material");
    let full = hash_full(&sk_a, "A", CRS_ID, PARAMS_ID, &anchor, &xk_hash).expect("hash_full");
    let proj = hash_proj(&full.projective, "A", CRS_ID, PARAMS_ID, &anchor, None)
        .expect("hash_proj without witness");
    assert_eq!(full.y_full, proj);
}
