//! Hashing and key derivation for the v0.3 profile.
//!
//! * `H(x) := BLAKE3-256(x)`.
//! * `H_L(label, args) := H(CBOR_det(["city-g/v0.3", label, args]))`, where
//!   `args` is a CBOR array. Every labelled hash of the profile uses this one
//!   array encoding (audit H-06).
//! * `Extract(salt, ikm) := BLAKE3-keyed(key = salt, ikm)`.
//! * `ExpandLabel(secret, label, context, L) := BLAKE3-keyed-XOF(key = secret,
//!   CBOR_det(["city-g/v0.3 expand", label, context, L]))[0..L]`.
//! * `DeriveSecret(secret, label) := ExpandLabel(secret, label, h'', 32)`.
//! * `MAC(key, data) := BLAKE3-keyed(key, CBOR_det(["city-g/v0.3 mac", data]))`.
//!
//! BLAKE3 in keyed mode is a PRF, and its XOF output is a PRF output of any
//! length, so Extract/Expand follow the HKDF structure with BLAKE3 in place of
//! HMAC.

use ciborium::value::Value;
use zeroize::Zeroizing;

use crate::cbor::{array, bytes, encode, text, uint};
use crate::error::{CoreError, CoreResult};

/// Profile tag bound into every labelled hash.
pub const PROFILE_TAG: &str = "city-g/v0.3";
const EXPAND_TAG: &str = "city-g/v0.3 expand";
const MAC_TAG: &str = "city-g/v0.3 mac";

/// A 32-byte digest.
pub type Digest = [u8; 32];

/// All-zero 32-byte string (`ZERO32`).
pub const ZERO32: [u8; 32] = [0u8; 32];

/// `H(x) := BLAKE3-256(x)`.
#[must_use]
pub fn h(data: &[u8]) -> Digest {
    *blake3::hash(data).as_bytes()
}

/// `H_L(label, args)` over the CBOR array `args`.
pub fn h_l(label: &str, args: Vec<Value>) -> CoreResult<Digest> {
    let encoded = encode(&array(vec![text(PROFILE_TAG), text(label), array(args)]))?;
    Ok(h(&encoded))
}

/// `Extract(salt, ikm)`: a 32-byte pseudorandom key.
#[must_use]
pub fn extract(salt: &[u8; 32], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(*blake3::keyed_hash(salt, ikm).as_bytes())
}

/// `ExpandLabel(secret, label, context, L)` into `out` (`L = out.len()`).
pub fn expand_label_into(
    secret: &[u8; 32],
    label: &str,
    context: &[u8],
    out: &mut [u8],
) -> CoreResult<()> {
    let info = encode(&array(vec![
        text(EXPAND_TAG),
        text(label),
        bytes(context),
        uint(u64::try_from(out.len()).map_err(|_| CoreError::TooLarge("expand length"))?),
    ]))?;
    let mut hasher = blake3::Hasher::new_keyed(secret);
    hasher.update(&info);
    hasher.finalize_xof().fill(out);
    Ok(())
}

/// `ExpandLabel(secret, label, context, 32)`.
pub fn expand_label32(
    secret: &[u8; 32],
    label: &str,
    context: &[u8],
) -> CoreResult<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    expand_label_into(secret, label, context, out.as_mut())?;
    Ok(out)
}

/// `DeriveSecret(secret, label)`.
pub fn derive_secret(secret: &[u8; 32], label: &str) -> CoreResult<Zeroizing<[u8; 32]>> {
    expand_label32(secret, label, &[])
}

/// `MAC(key, data)`.
pub fn mac(key: &[u8; 32], data: &[u8]) -> CoreResult<Digest> {
    let framed = encode(&array(vec![text(MAC_TAG), bytes(data)]))?;
    Ok(*blake3::keyed_hash(key, &framed).as_bytes())
}

/// Constant-time equality of two digests.
#[must_use]
pub fn digest_eq(left: &Digest, right: &Digest) -> bool {
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn labelled_hash_binds_label_and_arguments() {
        let base = h_l("test", vec![uint(1), bytes(b"a")]).unwrap();
        assert_ne!(base, h_l("test2", vec![uint(1), bytes(b"a")]).unwrap());
        assert_ne!(base, h_l("test", vec![uint(2), bytes(b"a")]).unwrap());
        assert_ne!(base, h_l("test", vec![bytes(b"a"), uint(1)]).unwrap());
        // The preimage is the array, not a map (audit H-06).
        let preimage = encode(&array(vec![
            text(PROFILE_TAG),
            text("test"),
            array(vec![uint(1), bytes(b"a")]),
        ]))
        .unwrap();
        assert_eq!(base, h(&preimage));
    }

    #[test]
    fn expand_label_separates_labels_contexts_and_lengths() {
        let secret = [7u8; 32];
        let a = expand_label32(&secret, "a", b"ctx").unwrap();
        let b = expand_label32(&secret, "b", b"ctx").unwrap();
        let c = expand_label32(&secret, "a", b"other").unwrap();
        assert_ne!(*a, *b);
        assert_ne!(*a, *c);
        let mut long = [0u8; 64];
        expand_label_into(&secret, "a", b"ctx", &mut long).unwrap();
        assert_ne!(&long[..32], a.as_slice(), "length is bound into the info");
        assert_eq!(
            *derive_secret(&secret, "x").unwrap(),
            *expand_label32(&secret, "x", &[]).unwrap()
        );
    }

    #[test]
    fn extract_and_mac_are_keyed() {
        assert_ne!(*extract(&[1; 32], b"ikm"), *extract(&[2; 32], b"ikm"));
        assert_ne!(mac(&[1; 32], b"m").unwrap(), mac(&[2; 32], b"m").unwrap());
        assert!(digest_eq(&[3; 32], &[3; 32]));
        assert!(!digest_eq(&[3; 32], &[4; 32]));
    }
}
