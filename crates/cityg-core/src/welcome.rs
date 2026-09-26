//! Welcomes (docs/specs.md section 11).
//!
//! ```text
//! Welcome := ["city-g/welcome/v4", gid, epoch, request_ref, kem_ciphertext,
//!             leaf_ciphertext or null, sealed]
//! context := CBOR_det([gid, epoch, request_ref, H_L("kem-pk", [init_key]),
//!                      H_L("kem-pk", [leaf_key]) or null])
//! (ct, ss) := X-Wing.Encaps(init_key)
//! (ct_leaf, ss_leaf) := X-Wing.Encaps(leaf_key)                a catch-up only
//! welcome_secret := ss, or Extract(ss, ss_leaf) for a catch-up
//! sealed := ChaCha20-Poly1305(ExpandLabel(welcome_secret, "welcome key", context, 32),
//!                             ExpandLabel(welcome_secret, "welcome nonce", context, 12),
//!                             aad = context, joiner_secret)
//! ```
//!
//! A welcome gives the joiner secret of a window to the holder of a one-time
//! init key: a joiner, a member re-entering its leaf, or a returning member
//! that asked for a jump. A jump's welcome also needs the member's leaf key,
//! which the welcomer takes from the tree: a device key without the
//! member's state cannot obtain epochs by asking for jumps. A welcome is
//! not signed: the joiner secret must reproduce the confirmation tag that
//! the sealer signed.

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::cbor::{array, bytes, encode, text, uint};
use crate::codec::{nullable, open_unsigned};
use crate::crypto::{
    Digest, SEALED_SECRET_BYTES, Secret, expand_label_into, expand_label32, extract, kem_pk_hash,
};
use crate::error::{CoreError, CoreResult};
use crate::kem::{KEM_CIPHERTEXT_BYTES, KemSecret, encapsulate};

pub const WELCOME_LABEL: &str = "city-g/welcome/v4";
const MAX_WELCOME_BYTES: usize = 4096;

/// A welcome into epoch `epoch` for the request `request`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    pub gid: Digest,
    pub epoch: u64,
    pub request: Digest,
    pub kem_ciphertext: Vec<u8>,
    /// The encapsulation to the member's leaf key, for a catch-up only.
    pub leaf_ciphertext: Option<Vec<u8>>,
    pub sealed: Vec<u8>,
}

fn cipher(
    welcome_secret: &[u8; 32],
    gid: &Digest,
    epoch: u64,
    request: &Digest,
    init_key: &[u8],
    leaf_key: Option<&[u8]>,
) -> CoreResult<(ChaCha20Poly1305, [u8; 12], Vec<u8>)> {
    let leaf_hash = leaf_key.map(kem_pk_hash).transpose()?;
    let context = encode(&array(vec![
        bytes(gid),
        uint(epoch),
        bytes(request),
        bytes(&kem_pk_hash(init_key)?),
        nullable(leaf_hash.as_ref(), |digest| bytes(digest)),
    ]))?;
    let key = expand_label32(welcome_secret, "welcome key", &context)?;
    let mut nonce = [0u8; 12];
    expand_label_into(welcome_secret, "welcome nonce", &context, &mut nonce)?;
    Ok((ChaCha20Poly1305::new(key.as_ref().into()), nonce, context))
}

impl Welcome {
    /// Seal `joiner_secret` to `init_key`, and for a catch-up also to the
    /// member's `leaf_key` as the tree holds it.
    pub fn seal(
        gid: &Digest,
        epoch: u64,
        request: &Digest,
        init_key: &[u8],
        leaf_key: Option<&[u8]>,
        joiner_secret: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let (kem_ciphertext, shared) = encapsulate(init_key, rng)?;
        let (leaf_ciphertext, welcome_secret) = match leaf_key {
            Some(leaf_key) => {
                let (ciphertext, leaf_shared) = encapsulate(leaf_key, rng)?;
                (Some(ciphertext), extract(&shared, leaf_shared.as_ref()))
            }
            None => (None, shared),
        };
        let (cipher, nonce, context) =
            cipher(&welcome_secret, gid, epoch, request, init_key, leaf_key)?;
        let sealed = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: joiner_secret,
                    aad: &context,
                },
            )
            .map_err(|_| CoreError::Crypto("welcome"))?;
        Ok(Self {
            gid: *gid,
            epoch,
            request: *request,
            kem_ciphertext,
            leaf_ciphertext,
            sealed,
        })
    }

    /// Open the welcome with the init key, and for a catch-up with the
    /// member's leaf key.
    pub fn open(&self, init_key: &KemSecret, leaf_key: Option<&KemSecret>) -> CoreResult<Secret> {
        if self.kem_ciphertext.len() != KEM_CIPHERTEXT_BYTES
            || self.sealed.len() != SEALED_SECRET_BYTES
            || self
                .leaf_ciphertext
                .as_ref()
                .is_some_and(|ciphertext| ciphertext.len() != KEM_CIPHERTEXT_BYTES)
        {
            return Err(CoreError::Malformed("welcome"));
        }
        let init_pk = init_key.public_key();
        let shared = init_key.decapsulate(&self.kem_ciphertext)?;
        let (welcome_secret, leaf_pk) = match (&self.leaf_ciphertext, leaf_key) {
            (Some(ciphertext), Some(leaf_key)) => {
                let leaf_shared = leaf_key.decapsulate(ciphertext)?;
                (
                    extract(&shared, leaf_shared.as_ref()),
                    Some(leaf_key.public_key()),
                )
            }
            (None, None) => (shared, None),
            _ => return Err(CoreError::Invalid("welcome of another kind")),
        };
        let (cipher, nonce, context) = cipher(
            &welcome_secret,
            &self.gid,
            self.epoch,
            &self.request,
            &init_pk,
            leaf_pk.as_deref(),
        )?;
        let opened = Zeroizing::new(
            cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &self.sealed,
                        aad: &context,
                    },
                )
                .map_err(|_| CoreError::Decrypt("welcome"))?,
        );
        let mut secret = Zeroizing::new([0u8; 32]);
        if opened.len() != 32 {
            return Err(CoreError::Malformed("welcome secret"));
        }
        secret.copy_from_slice(&opened);
        Ok(secret)
    }

    /// Encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            text(WELCOME_LABEL),
            bytes(&self.gid),
            uint(self.epoch),
            bytes(&self.request),
            bytes(&self.kem_ciphertext),
            nullable(self.leaf_ciphertext.as_deref(), bytes),
            bytes(&self.sealed),
        ]))
    }

    /// Parse a welcome.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let mut fields = open_unsigned(encoded, WELCOME_LABEL, 7, MAX_WELCOME_BYTES, "welcome")?;
        Ok(Self {
            gid: fields.digest()?,
            epoch: fields.uint()?,
            request: fields.digest()?,
            kem_ciphertext: fields.bytes()?,
            leaf_ciphertext: fields.optional_bytes()?,
            sealed: fields.bytes()?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn welcomes_round_trip_and_bind_their_context() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let init = KemSecret::generate(&mut rng);
        let welcome = Welcome::seal(
            &[1; 32],
            5,
            &[2; 32],
            &init.public_key(),
            None,
            &[3; 32],
            &mut rng,
        )
        .unwrap();
        let decoded = Welcome::decode(&welcome.encode().unwrap()).unwrap();
        assert_eq!(decoded, welcome);
        assert_eq!(*decoded.open(&init, None).unwrap(), [3; 32]);
        let mut moved = decoded.clone();
        moved.epoch = 6;
        assert!(moved.open(&init, None).is_err());
        let mut retargeted = decoded.clone();
        retargeted.request = [9; 32];
        assert!(retargeted.open(&init, None).is_err());
        let other = KemSecret::generate(&mut rng);
        assert!(decoded.open(&other, None).is_err());
        assert_eq!(
            decoded.open(&init, Some(&other)).unwrap_err(),
            CoreError::Invalid("welcome of another kind")
        );
    }

    #[test]
    fn a_catch_up_welcome_needs_the_leaf_key_too() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let init = KemSecret::generate(&mut rng);
        let leaf = KemSecret::generate(&mut rng);
        let welcome = Welcome::seal(
            &[1; 32],
            5,
            &[2; 32],
            &init.public_key(),
            Some(&leaf.public_key()),
            &[3; 32],
            &mut rng,
        )
        .unwrap();
        let encoded = welcome.encode().unwrap();
        assert!(encoded.len() < MAX_WELCOME_BYTES);
        let decoded = Welcome::decode(&encoded).unwrap();
        assert_eq!(decoded, welcome);
        assert_eq!(*decoded.open(&init, Some(&leaf)).unwrap(), [3; 32]);
        // The init key alone does not open it: whoever signed the catch-up
        // with the member's device key but lacks its leaf key stays out.
        assert_eq!(
            decoded.open(&init, None).unwrap_err(),
            CoreError::Invalid("welcome of another kind")
        );
        let stolen = KemSecret::generate(&mut rng);
        assert!(decoded.open(&init, Some(&stolen)).is_err());
        assert!(decoded.open(&stolen, Some(&leaf)).is_err());
        // Nor does it open as a welcome of another kind.
        let mut stripped = decoded.clone();
        stripped.leaf_ciphertext = None;
        assert!(stripped.open(&init, None).is_err());
    }
}
