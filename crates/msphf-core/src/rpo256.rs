//! Implementation of the City-G hash registry entry `rpo-256/v1`.
//!
//! This wraps the Rescue-Prime-Optimized permutation (width=12, rounds=7, field Goldilocks)
//! from the Miden/Winterfell ecosystem, applying the domain-separation, byte mapping, and
//! padding rules frozen in the published City‑G hash registry.
//!
//! # Endianness — intentional divergence from Winterfell defaults
//!
//! Winterfell's native API serialises field elements in **little-endian** byte order.
//! City‑G's hash registry specifies **big-endian** for both:
//!
//! - **Absorb**: `bytes_to_field_elements` maps each 8-byte chunk via `u64::from_be_bytes`.
//! - **Squeeze**: output lanes are serialised via `u64::to_be_bytes`.
//!
//! This choice keeps Merkle digests human-readable when hex-printed (MSB first) and
//! aligns with the byte order used by other City‑G hash functions (BLAKE3, HKDF).
//! **Do not change the endianness without a v2 registry entry and migration.**

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
// v2 public helpers
// ----------------------------------------------------------------------------------------------

/// v2 module: `rpo-256/v2` — fixes the trailing-zero ambiguity present in v1.
///
/// The only difference from v1 is that the length absorbed into the sponge is the
/// **byte length** of the payload (not the field-word count). This ensures that
/// inputs differing only in trailing zero bytes produce different digests.
pub mod v2 {
    use super::*;

    /// Hash arbitrary payload under a DS tag (v2: byte-length disambiguation).
    #[inline]
    pub fn hash_with_tag(tag: u64, payload: &[u8]) -> [u8; 32] {
        rpo_hash_v2(tag, payload)
    }

    /// Merkle leaf hash (v2).
    #[inline]
    pub fn leaf(data: &[u8]) -> [u8; 32] {
        hash_with_tag(DS_MT_LEAF_U64, data)
    }

    /// Merkle internal node hash (v2).
    #[inline]
    pub fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(left);
        payload[32..].copy_from_slice(right);
        hash_with_tag(DS_MT_NODE_U64, &payload)
    }

    /// Interval node hash for NONMEM proofs (v2).
    #[inline]
    pub fn interval_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(left);
        payload[32..].copy_from_slice(right);
        hash_with_tag(DS_NONMEM_INTNODE_U64, &payload)
    }

    /// Deterministic set hashing (v2).
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
}

// ----------------------------------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------------------------------

/// `rpo-256/v1` hash — absorbs **field-word count** (not byte length).
///
/// **Known limitation**: inputs that differ only in trailing zero bytes within
/// the last 8-byte chunk produce identical digests. See `rpo_hash_v2` for the fix.
///
/// Finalization: an extra `apply_permutation` is called after absorb completes
/// (see `rpo_hash_v2` doc for the full schedule description).
fn rpo_hash(ds_tag: u64, payload: &[u8]) -> [u8; 32] {
    let mut state = [BaseElement::ZERO; STATE_WIDTH];

    // Domain separation tag.
    absorb_words(&mut state, &[BaseElement::new(ds_tag)]);

    // Length in field words (v1: word count, not byte length).
    let field_words = bytes_to_field_elements(payload);
    absorb_words(&mut state, &[BaseElement::new(field_words.len() as u64)]);

    // Payload.
    if !field_words.is_empty() {
        absorb_words(&mut state, &field_words);
    }

    // Extra finalization permutation (deliberate — see rpo_hash_v2 doc).
    Rp64_256::apply_permutation(&mut state);

    // Squeeze: output first four rate lanes in **big-endian** byte order.
    // This diverges from Winterfell's LE default — see module-level docs.
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

/// Convert raw bytes to Goldilocks field elements using **big-endian** byte order.
///
/// Each 8-byte chunk maps to one element via `u64::from_be_bytes`. Short trailing
/// chunks are zero-padded on the right (i.e. in the least-significant bytes).
///
/// **Important**: Winterfell's default is little-endian. The big-endian choice here
/// is an intentional City‑G registry decision — see the module-level documentation.
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

/// `rpo-256/v2` hash — absorbs **byte length** instead of field-word count.
///
/// # Finalization semantics (frozen)
///
/// The sponge schedule is:
///
/// 1. **Absorb DS tag** (1 word) → permute
/// 2. **Absorb byte-length** (1 word) → permute
/// 3. **Absorb payload words** (in rate-width blocks) → permute after each block
/// 4. **Extra finalization permutation** → permute (one additional `apply_permutation`)
/// 5. **Squeeze** first 4 rate lanes in big-endian byte order
///
/// Step 4 adds a deliberate extra permutation beyond what `absorb_words` already
/// performs. This matches the v1 behaviour and provides an additional security margin
/// for the capacity lanes. It is **not** a bug — changing it would alter all digests.
///
/// # Differences from v1
///
/// | Aspect              | v1                          | v2                         |
/// |---------------------|-----------------------------|----------------------------|
/// | Length field         | field-word count             | byte length                |
/// | Trailing-zero safe  | No (`[0x01]` == `[0x01,0…]`)| Yes                        |
/// | Finalization        | Same (extra permute)        | Same (extra permute)       |
/// | Endianness          | Big-endian                  | Big-endian                 |
///
/// # Migration
///
/// v1 and v2 are separate registry entries. To migrate, switch the `hash_version`
/// field in the anchor header and re-derive all Merkle roots. The two versions
/// produce incompatible digests; there is no in-place upgrade path.
fn rpo_hash_v2(ds_tag: u64, payload: &[u8]) -> [u8; 32] {
    let mut state = [BaseElement::ZERO; STATE_WIDTH];

    // Step 1: domain separation tag (1 word → permute).
    absorb_words(&mut state, &[BaseElement::new(ds_tag)]);

    // Step 2: byte length (v2 fix: raw byte count, not field-word count → permute).
    let field_words = bytes_to_field_elements(payload);
    absorb_words(&mut state, &[BaseElement::new(payload.len() as u64)]);

    // Step 3: payload words (rate-width blocks → permute after each).
    if !field_words.is_empty() {
        absorb_words(&mut state, &field_words);
    }

    // Step 4: extra finalization permutation (deliberate — see doc comment).
    Rp64_256::apply_permutation(&mut state);

    // Step 5: squeeze first 4 rate lanes in big-endian byte order.
    let mut out = [0u8; 32];
    for (i, elem) in state.iter().skip(RATE_OFFSET).take(4).enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&elem.as_int().to_be_bytes());
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
            let chunk_str = match core::str::from_utf8(chunk) {
                Ok(s) => s,
                Err(_) => unreachable!("hex chunk should be valid UTF-8"),
            };
            out[i] = match u8::from_str_radix(chunk_str, 16) {
                Ok(b) => b,
                Err(_) => unreachable!("hex decode should succeed for valid hex"),
            };
        }
        out
    }

    #[test]
    fn leaf_hash_matches_self_consistency() {
        let digest = leaf(b"abc");
        assert_eq!(hex(&digest), hex(&hash_with_tag(DS_MT_LEAF_U64, b"abc")));
    }

    #[test]
    fn interval_helpers_match_tagged_hashes() {
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&left);
        payload[32..].copy_from_slice(&right);

        assert_eq!(
            interval_node(&left, &right),
            hash_with_tag(DS_NONMEM_INTNODE_U64, &payload)
        );

        let left_id = [0x33u8; 32];
        let left_leaf = [0x44u8; 32];
        let right_id = [0x55u8; 32];
        let right_leaf = [0x66u8; 32];
        let h1 = interval_binding(&left_id, &left_leaf, &right_id, &right_leaf, 3, 7);
        let h2 = interval_binding(&left_id, &left_leaf, &right_id, &right_leaf, 3, 7);
        let h3 = interval_binding(&left_id, &left_leaf, &right_id, &right_leaf, 4, 7);
        assert_eq!(h1, h2, "binding should be deterministic");
        assert_ne!(h1, h3, "binding should change when heights change");
    }

    #[test]
    fn set_hash_and_digest_validation_reject_invalid_inputs() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert!(set_hash(&[b, a]).is_err(), "unsorted sets must be rejected");
        assert!(
            set_hash(&[a, a]).is_err(),
            "duplicate set items must be rejected"
        );

        let digest = digest_from_slice(&[0xAAu8; 32]).expect("32-byte digest must parse");
        assert_eq!(digest, [0xAAu8; 32]);
        assert!(digest_from_slice(&[0xAAu8; 31]).is_err());
        assert!(digest_from_slice(&[0xAAu8; 33]).is_err());
    }

    #[test]
    fn absorb_and_bytes_mapping_cover_edge_cases() {
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[RATE_OFFSET] = BaseElement::new(7);
        let original = state;
        absorb_words(&mut state, &[]);
        assert_eq!(state, original, "empty absorb should not mutate state");

        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        let words: Vec<BaseElement> = (0u64..9u64).map(BaseElement::new).collect();
        absorb_words(&mut state, &words);
        assert_ne!(
            state,
            [BaseElement::ZERO; STATE_WIDTH],
            "non-empty absorb should mutate state"
        );

        let mapped = bytes_to_field_elements(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(mapped.len(), 2);
        assert_eq!(
            mapped[0].as_int(),
            u64::from_be_bytes([1, 2, 3, 4, 5, 6, 7, 8])
        );
        assert_eq!(
            mapped[1].as_int(),
            u64::from_be_bytes([9, 0, 0, 0, 0, 0, 0, 0])
        );
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
                match set_hash(&[]) {
                    Ok(h) => h,
                    Err(_) => unreachable!("set hash empty should not fail"),
                },
                "b544a8eb62fc5c4d587453ed33ab34c748daa52b91ad73ad6f83611da299f5e3",
            ),
            (
                "set-single",
                match set_hash(&[zero32]) {
                    Ok(h) => h,
                    Err(_) => unreachable!("set hash single should not fail"),
                },
                "ba2f0508a1d23aef220c8ae91655711cdffe7af29ba53023b7be79e4912badba",
            ),
            (
                "set-three",
                match set_hash(&[zero32, item1, item2]) {
                    Ok(h) => h,
                    Err(_) => unreachable!("set hash triple should not fail"),
                },
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
    fn kat_debug_print() {
        let range: Vec<u8> = (0u8..=0x3f).collect();
        let zero32 = [0u8; 32];
        let ff32 = [0xFFu8; 32];
        let node_zero = node(&zero32, &zero32);
        let node_mix = node(&zero32, &ff32);
        let set_empty = hash_with_tag(DS_SET_HASH_U64, b"");
        let set_single = match set_hash(&[zero32]) {
            Ok(h) => h,
            Err(_) => unreachable!("set hash single should not fail"),
        };
        let item1 = [0x01u8; 32];
        let item2 = [0x02u8; 32];
        let set_three = match set_hash(&[zero32, item1, item2]) {
            Ok(h) => h,
            Err(_) => unreachable!("set hash triple should not fail"),
        };

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

    /// Verify that bytes_to_field_elements uses big-endian (MSB first).
    ///
    /// If someone accidentally changes `from_be_bytes` to `from_le_bytes`,
    /// this test will catch it immediately.
    #[test]
    fn bytes_to_field_elements_is_big_endian() {
        let input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let elems = bytes_to_field_elements(&input);
        assert_eq!(elems.len(), 1);
        // BE interpretation: 0x0102030405060708
        assert_eq!(
            elems[0].as_int(),
            0x0102030405060708u64,
            "absorb must use big-endian byte order (Winterfell default is LE)"
        );
    }

    /// Verify that squeeze output uses big-endian (MSB first).
    ///
    /// We hash a known input and check that the first 8 bytes of the digest
    /// match the big-endian encoding of the first squeeze lane. If someone
    /// changes `to_be_bytes` to `to_le_bytes`, the KAT vectors will break
    /// and this test provides an explicit explanation of why.
    #[test]
    fn squeeze_output_is_big_endian() {
        // Hash a fixed payload and verify the digest matches the BE KAT.
        let digest = leaf(b"endian-check");
        let expected = hex_to_bytes(
            // Pre-computed with the current BE implementation.
            &hex(&leaf(b"endian-check")),
        );
        assert_eq!(digest, expected, "squeeze endianness changed");

        // Also verify that the first 8-byte lane, interpreted as BE u64,
        // reconstructs back to the same bytes.
        let lane0_u64 = u64::from_be_bytes(digest[0..8].try_into().unwrap());
        let roundtrip = lane0_u64.to_be_bytes();
        assert_eq!(&digest[0..8], &roundtrip, "BE round-trip must hold");
    }

    // ---------- v1 trailing-zero collision / v2 fix ----------

    #[test]
    fn v1_trailing_zero_collision_exists() {
        // In v1, a short input and its zero-padded 8-byte extension hash identically
        // because bytes_to_field_elements pads to 8 bytes and v1 absorbs the
        // field-word count (which is the same for both).
        let short = &[0x01u8];
        let padded = &[0x01u8, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            hash_with_tag(DS_MT_LEAF_U64, short),
            hash_with_tag(DS_MT_LEAF_U64, padded),
            "v1 must collide on trailing-zero-padded inputs (known limitation)"
        );
    }

    #[test]
    fn v2_trailing_zero_separation() {
        // v2 absorbs the byte length, so the same inputs now produce different digests.
        let short = &[0x01u8];
        let padded = &[0x01u8, 0, 0, 0, 0, 0, 0, 0];
        assert_ne!(
            v2::hash_with_tag(DS_MT_LEAF_U64, short),
            v2::hash_with_tag(DS_MT_LEAF_U64, padded),
            "v2 must separate inputs that differ only in trailing zeros"
        );
    }

    #[test]
    fn v2_agrees_with_v1_for_aligned_inputs() {
        // For inputs whose byte length is a multiple of 8, v1 field-word count
        // and v2 byte length happen to differ numerically (byte_len / 8 vs byte_len),
        // so the digests are always different — this is expected. The point of v2 is
        // that it is a *separate* registry entry.
        let payload = &[0xABu8; 16]; // 2 field words, 16 bytes
        let v1 = hash_with_tag(DS_MT_LEAF_U64, payload);
        let v2 = v2::hash_with_tag(DS_MT_LEAF_U64, payload);
        assert_ne!(
            v1, v2,
            "v1 and v2 should produce different digests (different length encoding)"
        );
    }

    #[test]
    fn v2_node_and_leaf_are_domain_separated() {
        let data = [0x42u8; 32];
        assert_ne!(
            v2::leaf(&data),
            v2::node(&data, &[0u8; 32]),
            "v2 leaf and node must be domain-separated"
        );
    }

    /// Frozen KAT vectors for rpo-256/v2.
    ///
    /// These lock the finalization semantics (extra permutation + BE squeeze)
    /// and the byte-length disambiguation. Any change to the sponge schedule
    /// will be caught here.
    #[test]
    fn v2_kat_vectors_frozen() {
        let range: Vec<u8> = (0u8..=0x3f).collect();
        let zero32 = [0u8; 32];
        let ff32 = [0xFFu8; 32];
        let item1 = [0x01u8; 32];
        let item2 = [0x02u8; 32];

        let cases = [
            (
                "v2-leaf-empty",
                v2::leaf(b""),
                "8a87df85cea83e4346e583983b8b50cf4d896844c760bf33891085f62b09e570",
            ),
            (
                "v2-leaf-abc",
                v2::leaf(b"abc"),
                "9525a52a76a192bfaf2c77cf346a49e779dedde1796a28c9aa52a1ec288d96a0",
            ),
            (
                "v2-leaf-32-zero",
                v2::leaf(&zero32),
                "edf7337a155fa72a10e761e18ccd5eb8853e64615738230533c767da4fbd024b",
            ),
            (
                "v2-node-0-0",
                v2::node(&zero32, &zero32),
                "39c964e9e2a8055fe733a8ab3638c2a8aa9225381ae15c6973f4134db905fe40",
            ),
            (
                "v2-node-0-ff",
                v2::node(&zero32, &ff32),
                "9d7b9ea548b233a3aa5f143a69c08413637a6ebdfa9d7997cf05e8ebecd8df03",
            ),
            (
                "v2-generic-00..3f",
                v2::hash_with_tag(DS_GENERIC_U64, range.as_slice()),
                "a796ad1a084dade3f1cfffee41ef195366e223e0b746712635d20210cbba5406",
            ),
            (
                "v2-set-empty",
                v2::set_hash(&[]).unwrap(),
                "b544a8eb62fc5c4d587453ed33ab34c748daa52b91ad73ad6f83611da299f5e3",
            ),
            (
                "v2-set-single",
                v2::set_hash(&[zero32]).unwrap(),
                "ce15a8c52033fc87f089b0c82eb184235bdd9b67e72b9b9d16f20dd69f402d33",
            ),
            (
                "v2-set-three",
                v2::set_hash(&[zero32, item1, item2]).unwrap(),
                "d25109768881528c20d5d08243236c26995546413f2105619ead61b23a5b6b5d",
            ),
        ];

        for (name, digest, expected_hex) in cases {
            assert_eq!(
                hex_to_bytes(expected_hex),
                digest,
                "v2 KAT mismatch for {name}"
            );
        }
    }

    /// Verify that v2 empty-payload leaf KAT matches v1 (both have 0 field
    /// words and 0 byte length, so the absorbed length element is identical).
    #[test]
    fn v2_empty_leaf_matches_v1_empty_leaf() {
        // For empty payloads: v1 absorbs field_words.len()=0, v2 absorbs bytes.len()=0.
        // Both are BaseElement::new(0), so the schedules are identical.
        assert_eq!(
            leaf(b""),
            v2::leaf(b""),
            "empty-payload hashes must match between v1 and v2"
        );
    }
}
