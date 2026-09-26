//! Hashing, key derivation and wraps.
//!
//! * `H(x) := BLAKE3-256(x)`;
//! * `H_L(label, args) := H(CBOR_det(["city-g/v0.4", label, args]))`, where
//!   `args` is a CBOR array: every labelled hash uses this one encoding;
//! * `Extract(salt, ikm) := BLAKE3-keyed(key = salt, ikm)`;
//! * `ExpandLabel(secret, label, context, L) := BLAKE3-keyed-XOF(key = secret,
//!   CBOR_det(["city-g/v0.4 expand", label, context, L]))[0..L]`;
//! * `DeriveSecret(secret, label) := ExpandLabel(secret, label, h'', 32)`;
//! * `MAC(key, data) := BLAKE3-keyed(key, CBOR_det(["city-g/v0.4 mac", data]))`.
//!
//! BLAKE3 in keyed mode is a PRF and its XOF output is a PRF output of any
//! length, so `Extract` and `ExpandLabel` follow the HKDF structure with
//! BLAKE3 in place of HMAC.
//!
//! A *wrap* carries a 32-byte node secret to the holder of an X-Wing key:
//! an X-Wing encapsulation, then ChaCha20-Poly1305 under a key and nonce
//! derived from the shared secret and a context that binds the group, the
//! epoch, the node, the target and the target's key.

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use ciborium::value::Value;
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::cbor::{array, bytes, encode, text, uint};
use crate::error::{CoreError, CoreResult};
use crate::kem::{KEM_CIPHERTEXT_BYTES, KemSecret, encapsulate};
use crate::tree::NodeId;

/// Profile identifier bound into every group context.
pub const PROFILE: &str = "city-g/v0.4";
const HASH_TAG: &str = "city-g/v0.4";
const EXPAND_TAG: &str = "city-g/v0.4 expand";
const MAC_TAG: &str = "city-g/v0.4 mac";

/// Size of a sealed 32-byte secret (ChaCha20-Poly1305 adds a 16-byte tag).
pub const SEALED_SECRET_BYTES: usize = 48;

/// Size of a wrap on the wire: X-Wing ciphertext, sealed secret, and the
/// four small integers that address it.
pub const KEM_WRAP_BYTES: usize = KEM_CIPHERTEXT_BYTES + SEALED_SECRET_BYTES + 16;

/// A 32-byte digest.
pub type Digest = [u8; 32];

/// All-zero 32-byte string (`ZERO32`).
pub const ZERO32: Digest = [0u8; 32];

/// A 32-byte secret, zeroized when dropped.
pub type Secret = Zeroizing<[u8; 32]>;

/// `H(x) := BLAKE3-256(x)`.
#[must_use]
pub fn h(data: &[u8]) -> Digest {
    *blake3::hash(data).as_bytes()
}

/// `H_L(label, args)` over the CBOR array `args`.
pub fn h_l(label: &str, args: Vec<Value>) -> CoreResult<Digest> {
    let encoded = encode(&array(vec![text(HASH_TAG), text(label), array(args)]))?;
    Ok(h(&encoded))
}

/// `Extract(salt, ikm)`: a 32-byte pseudorandom key.
#[must_use]
pub fn extract(salt: &[u8; 32], ikm: &[u8]) -> Secret {
    Zeroizing::new(*blake3::keyed_hash(salt, ikm).as_bytes())
}

/// `ExpandLabel(secret, label, context, L)` into `out` (`L = out.len()`).
pub fn expand_label_into(
    secret: &[u8; 32],
    label: &str,
    context: &[u8],
    out: &mut [u8],
) -> CoreResult<()> {
    let length = u64::try_from(out.len()).map_err(|_| CoreError::TooLarge("expand length"))?;
    let info = encode(&array(vec![
        text(EXPAND_TAG),
        text(label),
        bytes(context),
        uint(length),
    ]))?;
    let mut hasher = blake3::Hasher::new_keyed(secret);
    hasher.update(&info);
    hasher.finalize_xof().fill(out);
    Ok(())
}

/// `ExpandLabel(secret, label, context, 32)`.
pub fn expand_label32(secret: &[u8; 32], label: &str, context: &[u8]) -> CoreResult<Secret> {
    let mut out = Zeroizing::new([0u8; 32]);
    expand_label_into(secret, label, context, out.as_mut())?;
    Ok(out)
}

/// `DeriveSecret(secret, label)`.
pub fn derive_secret(secret: &[u8; 32], label: &str) -> CoreResult<Secret> {
    expand_label32(secret, label, &[])
}

/// `MAC(key, data)`.
pub fn mac(key: &[u8; 32], data: &[u8]) -> CoreResult<Digest> {
    let framed = encode(&array(vec![text(MAC_TAG), bytes(data)]))?;
    Ok(*blake3::keyed_hash(key, &framed).as_bytes())
}

/// `H_L("kem-pk", [pk])`, the hash of an X-Wing public key bound into wraps
/// and welcomes.
pub fn kem_pk_hash(public_key: &[u8]) -> CoreResult<Digest> {
    h_l("kem-pk", vec![bytes(public_key)])
}

/// X-Wing key of a tree node, from the node's 32-byte secret.
pub fn node_key(secret: &[u8; 32]) -> CoreResult<KemSecret> {
    let seed = expand_label32(secret, "tree node key", &[])?;
    Ok(KemSecret::from_seed(*seed))
}

/// One step up a chain of re-keyed nodes: `DeriveSecret(child, "tree path")`.
pub fn chain(child_secret: &[u8; 32]) -> CoreResult<Secret> {
    derive_secret(child_secret, "tree path")
}

/// Commit secret of a window, one step past the root secret.
pub fn commit_secret(root_secret: &[u8; 32]) -> CoreResult<Secret> {
    derive_secret(root_secret, "commit")
}

/// A fresh node secret: `DeriveSecret(Extract(hedge, r), "fresh node")` for
/// 32 random bytes `r`. A member hedges with its init secret, so that a weak
/// generator alone does not expose the secret to an outsider.
pub fn fresh_secret(hedge: &[u8; 32], rng: &mut impl CryptoRngCore) -> CoreResult<Secret> {
    let mut random = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(random.as_mut());
    let prk = extract(hedge, random.as_ref());
    derive_secret(&prk, "fresh node")
}

/// A node secret wrapped to one child of the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wrap {
    /// The re-keyed node whose secret is wrapped.
    pub node: NodeId,
    /// The child it is wrapped to (a leaf or a parent node).
    pub target: NodeId,
    /// X-Wing ciphertext (1120 bytes).
    pub kem_ciphertext: Vec<u8>,
    /// The secret under ChaCha20-Poly1305 (48 bytes).
    pub sealed: Vec<u8>,
}

fn wrap_context(
    gid: &Digest,
    epoch: u64,
    node: NodeId,
    target: NodeId,
    target_pk_hash: &Digest,
) -> CoreResult<Vec<u8>> {
    encode(&array(vec![
        bytes(gid),
        uint(epoch),
        uint(u64::from(node.level)),
        uint(u64::from(node.index)),
        uint(u64::from(target.level)),
        uint(u64::from(target.index)),
        bytes(target_pk_hash),
    ]))
}

fn wrap_cipher(shared: &[u8; 32], context: &[u8]) -> CoreResult<(ChaCha20Poly1305, [u8; 12])> {
    let key = expand_label32(shared, "wrap key", context)?;
    let mut nonce = [0u8; 12];
    expand_label_into(shared, "wrap nonce", context, &mut nonce)?;
    Ok((ChaCha20Poly1305::new(key.as_ref().into()), nonce))
}

/// Wrap `secret` (the new secret of `node`) to `target`, whose X-Wing key is
/// `target_pk`.
pub fn wrap(
    gid: &Digest,
    epoch: u64,
    node: NodeId,
    target: NodeId,
    target_pk: &[u8],
    secret: &[u8; 32],
    rng: &mut impl CryptoRngCore,
) -> CoreResult<Wrap> {
    let context = wrap_context(gid, epoch, node, target, &kem_pk_hash(target_pk)?)?;
    let (kem_ciphertext, shared) = encapsulate(target_pk, rng)?;
    let (cipher, nonce) = wrap_cipher(&shared, &context)?;
    let sealed = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: secret,
                aad: &context,
            },
        )
        .map_err(|_| CoreError::Crypto("wrap"))?;
    Ok(Wrap {
        node,
        target,
        kem_ciphertext,
        sealed,
    })
}

/// Open a wrap with the target's key; `target_pk` is the target's public key.
pub fn unwrap(
    gid: &Digest,
    epoch: u64,
    wrapped: &Wrap,
    key: &KemSecret,
    target_pk: &[u8],
) -> CoreResult<Secret> {
    if wrapped.kem_ciphertext.len() != KEM_CIPHERTEXT_BYTES
        || wrapped.sealed.len() != SEALED_SECRET_BYTES
    {
        return Err(CoreError::Malformed("wrap"));
    }
    let context = wrap_context(
        gid,
        epoch,
        wrapped.node,
        wrapped.target,
        &kem_pk_hash(target_pk)?,
    )?;
    let shared = key.decapsulate(&wrapped.kem_ciphertext)?;
    let (cipher, nonce) = wrap_cipher(&shared, &context)?;
    let opened = Zeroizing::new(
        cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &wrapped.sealed,
                    aad: &context,
                },
            )
            .map_err(|_| CoreError::Decrypt("wrap"))?,
    );
    let mut secret = Zeroizing::new([0u8; 32]);
    if opened.len() != 32 {
        return Err(CoreError::Malformed("wrapped secret"));
    }
    secret.copy_from_slice(&opened);
    Ok(secret)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn labelled_hash_binds_label_and_arguments() {
        let base = h_l("test", vec![uint(1), bytes(b"a")]).unwrap();
        assert_ne!(base, h_l("test2", vec![uint(1), bytes(b"a")]).unwrap());
        assert_ne!(base, h_l("test", vec![uint(2), bytes(b"a")]).unwrap());
        assert_ne!(base, h_l("test", vec![bytes(b"a"), uint(1)]).unwrap());
        let preimage = encode(&array(vec![
            text(HASH_TAG),
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
        assert_ne!(
            &long[..32],
            a.as_slice(),
            "the length is bound into the info"
        );
        assert_eq!(
            *derive_secret(&secret, "x").unwrap(),
            *expand_label32(&secret, "x", &[]).unwrap()
        );
    }

    #[test]
    fn extract_and_mac_are_keyed() {
        assert_ne!(*extract(&[1; 32], b"ikm"), *extract(&[2; 32], b"ikm"));
        assert_ne!(mac(&[1; 32], b"m").unwrap(), mac(&[2; 32], b"m").unwrap());
        assert_ne!(mac(&[1; 32], b"m").unwrap(), mac(&[1; 32], b"n").unwrap());
    }

    #[test]
    fn wrap_round_trips_and_binds_its_context() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let gid = [3u8; 32];
        let key = node_key(&[9u8; 32]).unwrap();
        let pk = key.public_key();
        let node = NodeId { level: 2, index: 1 };
        let target = NodeId { level: 1, index: 3 };
        let secret = [5u8; 32];
        let wrapped = wrap(&gid, 4, node, target, &pk, &secret, &mut rng).unwrap();
        assert_eq!(wrapped.sealed.len(), SEALED_SECRET_BYTES);
        assert_eq!(*unwrap(&gid, 4, &wrapped, &key, &pk).unwrap(), secret);
        assert!(unwrap(&gid, 5, &wrapped, &key, &pk).is_err());
        let mut moved = wrapped.clone();
        moved.target = NodeId { level: 1, index: 2 };
        assert!(unwrap(&gid, 4, &moved, &key, &pk).is_err());
        let other = node_key(&[8u8; 32]).unwrap();
        assert!(unwrap(&gid, 4, &wrapped, &other, &other.public_key()).is_err());
    }

    #[test]
    fn fresh_secrets_depend_on_randomness_and_hedge() {
        let mut a = ChaCha20Rng::seed_from_u64(2);
        let mut b = ChaCha20Rng::seed_from_u64(2);
        let first = fresh_secret(&[1u8; 32], &mut a).unwrap();
        let same = fresh_secret(&[1u8; 32], &mut b).unwrap();
        assert_eq!(*first, *same);
        let mut c = ChaCha20Rng::seed_from_u64(2);
        assert_ne!(*first, *fresh_secret(&[2u8; 32], &mut c).unwrap());
        assert_ne!(*first, *fresh_secret(&[1u8; 32], &mut a).unwrap());
    }
}
