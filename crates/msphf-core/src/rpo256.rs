//! Implementation of the City-G hash registry entry `rpo-256/v1`.
//!
//! This wraps the Rescue-Prime-Optimized permutation (width=12, rounds=7, field Goldilocks)
//! from the Miden/Winterfell ecosystem, applying the domain-separation, byte mapping, and
//! padding rules frozen in the published City‑G hash registry. The code is still missing
//! official KAT binding; test vectors are generated in-tree for now.

use core::ops::AddAssign;

use core::convert::TryInto;

use winter_crypto::hashers::Rp64_256;
use winter_math::{FieldElement, fields::f64::BaseElement};

use crate::MsphfError;

// ----------------------------------------------------------------------------------------------
// Sponge parameters (normative)
// ----------------------------------------------------------------------------------------------

const STATE_WIDTH: usize = 12;
const RATE_WIDTH: usize = 8;
const RATE_OFFSET: usize = 4;
// Verify we are aligned with the registry definition.
const _: () = assert!(RATE_WIDTH == 8);

// DS tags (64-bit big-endian ASCII, zero padded) copied from the public hash registry.
const DS_MT_LEAF_U64: u64 = 0x4D54_5F4C_4541_4600; // "MT_LEAF\0"
const DS_MT_NODE_U64: u64 = 0x4D54_5F4E_4F44_4500; // "MT_NODE\0"
const DS_NONMEM_INTNODE_U64: u64 = 0x4D54_5F4E_4D49_4E54; // "MT_NMINT"
const DS_NONMEM_BIND_U64: u64 = 0x4D54_5F4E_4D42_494E; // "MT_NMBIN"
const DS_SET_HASH_U64: u64 = 0x5345_545F_4841_5348; // "SET_HASH"
#[allow(dead_code)]
const DS_GENERIC_U64: u64 = 0x4745_4E45_5249_4300; // "GENERIC\0"

// ----------------------------------------------------------------------------------------------
// Public helpers
// ----------------------------------------------------------------------------------------------

/// Hash arbitrary payload under a DS tag treated as a 64-bit value.
#[inline]
pub fn hash_with_tag(tag: u64, payload: &[u8]) -> [u8; 32] {
    rpo_hash(tag, payload)
}

/// Merkle leaf hash.
#[inline]
pub fn leaf(data: &[u8]) -> [u8; 32] {
    hash_with_tag(DS_MT_LEAF_U64, data)
}

/// Merkle internal node hash (left || right).
#[inline]
pub fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(left);
    payload[32..].copy_from_slice(right);
    hash_with_tag(DS_MT_NODE_U64, &payload)
}

/// Interval node hash for NONMEM proofs (left || right).
#[inline]
pub fn interval_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(left);
    payload[32..].copy_from_slice(right);
    hash_with_tag(DS_NONMEM_INTNODE_U64, &payload)
}

#[inline]
pub fn interval_binding(
    left_id: &[u8; 32],
    left_leaf: &[u8; 32],
    right_id: &[u8; 32],
    right_leaf: &[u8; 32],
    lca_left_height: u8,
    lca_right_height: u8,
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(32 * 4 + 2);
    payload.extend_from_slice(left_id);
    payload.extend_from_slice(left_leaf);
    payload.extend_from_slice(right_id);
    payload.extend_from_slice(right_leaf);
    payload.push(lca_left_height);
    payload.push(lca_right_height);
    hash_with_tag(DS_NONMEM_BIND_U64, &payload)
}

/// Deterministic set hashing for lexicographically sorted 32-byte items.
pub fn set_hash(items: &[[u8; 32]]) -> Result<[u8; 32], MsphfError> {
    if items.windows(2).any(|w| w[0] >= w[1]) {
        return Err(MsphfError::invalid_input(
            "set must be strict-sorted (lex asc)",
        ));
    }
    let mut payload = Vec::with_capacity(items.len() * 32);
    for item in items {
        payload.extend_from_slice(item);
    }
    Ok(hash_with_tag(DS_SET_HASH_U64, &payload))
}

/// Interpret a byte slice as a digest (must be exactly 32 bytes).
#[inline]
pub fn digest_from_slice(bytes: &[u8]) -> Result<[u8; 32], MsphfError> {
    bytes
        .try_into()
        .map_err(|_| MsphfError::invalid_input("expected 32-byte digest"))
}

// ----------------------------------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------------------------------

fn rpo_hash(ds_tag: u64, payload: &[u8]) -> [u8; 32] {
    let mut state = [BaseElement::ZERO; STATE_WIDTH];

    // Domain separation tag.
    absorb_words(&mut state, &[BaseElement::new(ds_tag)]);

    // Length in field words.
    let field_words = bytes_to_field_elements(payload);
    absorb_words(&mut state, &[BaseElement::new(field_words.len() as u64)]);

    // Payload.
    if !field_words.is_empty() {
        absorb_words(&mut state, &field_words);
    }

    // Final permutation before squeezing.
    Rp64_256::apply_permutation(&mut state);

    // Output first four rate lanes (big-endian u64).
    let mut out = [0u8; 32];
    for (i, elem) in state.iter().skip(RATE_OFFSET).take(4).enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&elem.as_int().to_be_bytes());
    }
    out
}

fn absorb_words(state: &mut [BaseElement; STATE_WIDTH], words: &[BaseElement]) {
    if words.is_empty() {
        return;
    }
    let mut lane = 0usize;
    for word in words {
        if lane == RATE_WIDTH {
            Rp64_256::apply_permutation(state);
            lane = 0;
        }
        state[RATE_OFFSET + lane].add_assign(*word);
        lane += 1;
    }
    if lane != 0 {
        Rp64_256::apply_permutation(state);
    }
}

fn bytes_to_field_elements(bytes: &[u8]) -> Vec<BaseElement> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(8));
    for chunk in bytes.chunks(8) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let value = u64::from_be_bytes(buf);
        out.push(BaseElement::new(value));
    }
    out
}

// ----------------------------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn hex_to_bytes(input: &str) -> [u8; 32] {
        assert_eq!(input.len(), 64);
        let mut out = [0u8; 32];
        for (i, chunk) in input.as_bytes().chunks(2).enumerate() {
            let chunk_str = core::str::from_utf8(chunk).expect("hex chunk");
            out[i] = u8::from_str_radix(chunk_str, 16).expect("hex decode");
        }
        out
    }

    #[test]
    fn leaf_hash_matches_self_consistency() {
        let digest = leaf(b"abc");
        assert_eq!(hex(&digest), hex(&hash_with_tag(DS_MT_LEAF_U64, b"abc")));
    }

    #[test]
    fn kat_vectors_match_expected() {
        let range: Vec<u8> = (0u8..=0x3f).collect();
        let zero32 = [0u8; 32];
        let ff32 = [0xFFu8; 32];
        let item1 = [0x01u8; 32];
        let item2 = [0x02u8; 32];

        let cases = [
            (
                "empty-generic",
                hash_with_tag(DS_GENERIC_U64, b""),
                "a824cccb29388c0be4c01a0352709275c21779029d56a5b0604706de74e57270",
            ),
            (
                "generic-00..3f",
                hash_with_tag(DS_GENERIC_U64, range.as_slice()),
                "eae68053e98dec57d2344d2ee84de50bb6e1f499e19aa234e91473d87eea0755",
            ),
            (
                "leaf-empty",
                leaf(b""),
                "8a87df85cea83e4346e583983b8b50cf4d896844c760bf33891085f62b09e570",
            ),
            (
                "leaf-abc",
                leaf(b"abc"),
                "d0d90734a4d34f27be32a691a80ba03596717700ab13dc91056cdc3cd902ff6c",
            ),
            (
                "leaf-32-zero",
                leaf(&zero32),
                "a13f7d20cb6f4cc50d8fb4e1fef4900dd1dcf0562e5dbc1b76165e29dccae591",
            ),
            (
                "node-0-0",
                node(&zero32, &zero32),
                "91694b6c3b813206f1822c989c3e74fca9354d75e3266ef829917eb84eaa38ba",
            ),
            (
                "node-0-ff",
                node(&zero32, &ff32),
                "a3df3643aaecd5db468c616143a076ea978b5bd4071729c4615306e6680175cb",
            ),
            (
                "set-empty",
                set_hash(&[]).expect("set hash empty"),
                "b544a8eb62fc5c4d587453ed33ab34c748daa52b91ad73ad6f83611da299f5e3",
            ),
            (
                "set-single",
                set_hash(&[zero32]).expect("set hash single"),
                "ba2f0508a1d23aef220c8ae91655711cdffe7af29ba53023b7be79e4912badba",
            ),
            (
                "set-three",
                set_hash(&[zero32, item1, item2]).expect("set hash triple"),
                "dc6c0bfb2c6ece179747b95b8e6b5ed49462069f0db6510dc2fad2bb50c6305e",
            ),
        ];

        for (name, digest, expected_hex) in cases {
            assert_eq!(
                hex_to_bytes(expected_hex),
                digest,
                "KAT mismatch for {name}"
            );
        }
    }

    #[test]
    #[ignore]
    fn kat_debug_print() {
        let range: Vec<u8> = (0u8..=0x3f).collect();
        let zero32 = [0u8; 32];
        let ff32 = [0xFFu8; 32];
        let node_zero = node(&zero32, &zero32);
        let node_mix = node(&zero32, &ff32);
        let set_empty = hash_with_tag(DS_SET_HASH_U64, b"");
        let set_single = set_hash(&[zero32]).expect("set hash single");
        let item1 = [0x01u8; 32];
        let item2 = [0x02u8; 32];
        let set_three = set_hash(&[zero32, item1, item2]).expect("set hash triple");

        let cases = [
            (
                "empty-generic",
                DS_GENERIC_U64,
                hash_with_tag(DS_GENERIC_U64, b""),
            ),
            (
                "generic-00..3f",
                DS_GENERIC_U64,
                hash_with_tag(DS_GENERIC_U64, range.as_slice()),
            ),
            ("leaf-empty", DS_MT_LEAF_U64, leaf(b"")),
            ("leaf-abc", DS_MT_LEAF_U64, leaf(b"abc")),
            ("leaf-32-zero", DS_MT_LEAF_U64, leaf(&zero32)),
            ("node-0-0", DS_MT_NODE_U64, node_zero),
            ("node-0-ff", DS_MT_NODE_U64, node_mix),
            ("set-empty", DS_SET_HASH_U64, set_empty),
            ("set-single", DS_SET_HASH_U64, set_single),
            ("set-three", DS_SET_HASH_U64, set_three),
        ];
        for (name, _tag, digest) in cases {
            println!("{name}: {}", hex(&digest));
        }
    }
}
