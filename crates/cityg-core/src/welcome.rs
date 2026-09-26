//! Welcomes (docs/specs.md section 11).
//!
//! ```text
//! Welcome := ["city-g/welcome/v4", gid, epoch, request_ref, kem_ciphertext, sealed]
//! context := CBOR_det([gid, epoch, request_ref, H_L("kem-pk", [init_key])])
//! (ct, ss) := X-Wing.Encaps(init_key)
//! sealed := ChaCha20-Poly1305(ExpandLabel(ss, "welcome key", context, 32),
//!                             ExpandLabel(ss, "welcome nonce", context, 12),
//!                             aad = context, joiner_secret)
//! ```
//!
//! A welcome gives the joiner secret of a window to the holder of a one-time
//! init key: a joiner, a returning member that asked for a jump, or a member
//! re-entering its leaf. It is not signed: the joiner secret must reproduce
//! the confirmation tag that the sealer signed.

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::cbor::{array, bytes, encode, text, uint};
use crate::codec::open_unsigned;
use crate::crypto::{
    Digest, SEALED_SECRET_BYTES, Secret, expand_label_into, expand_label32, kem_pk_hash,
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
    pub sealed: Vec<u8>,
}

fn cipher(
    shared: &[u8; 32],
    gid: &Digest,
    epoch: u64,
    request: &Digest,
    init_key: &[u8],
) -> CoreResult<(ChaCha20Poly1305, [u8; 12], Vec<u8>)> {
    let context = encode(&array(vec![
        bytes(gid),
        uint(epoch),
        bytes(request),
        bytes(&kem_pk_hash(init_key)?),
    ]))?;
    let key = expand_label32(shared, "welcome key", &context)?;
    let mut nonce = [0u8; 12];
    expand_label_into(shared, "welcome nonce", &context, &mut nonce)?;
    Ok((ChaCha20Poly1305::new(key.as_ref().into()), nonce, context))
}

impl Welcome {
    /// Seal `joiner_secret` to `init_key`.
    pub fn seal(
        gid: &Digest,
        epoch: u64,
        request: &Digest,
        init_key: &[u8],
        joiner_secret: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let (kem_ciphertext, shared) = encapsulate(init_key, rng)?;
        let (cipher, nonce, context) = cipher(&shared, gid, epoch, request, init_key)?;
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
            sealed,
        })
    }

    /// Open the welcome with the init key.
    pub fn open(&self, init_key: &KemSecret) -> CoreResult<Secret> {
        if self.kem_ciphertext.len() != KEM_CIPHERTEXT_BYTES
            || self.sealed.len() != SEALED_SECRET_BYTES
        {
            return Err(CoreError::Malformed("welcome"));
        }
        let init_pk = init_key.public_key();
        let shared = init_key.decapsulate(&self.kem_ciphertext)?;
        let (cipher, nonce, context) =
            cipher(&shared, &self.gid, self.epoch, &self.request, &init_pk)?;
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
            bytes(&self.sealed),
        ]))
    }

    /// Parse a welcome.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let mut fields = open_unsigned(encoded, WELCOME_LABEL, 6, MAX_WELCOME_BYTES, "welcome")?;
        Ok(Self {
            gid: fields.digest()?,
            epoch: fields.uint()?,
            request: fields.digest()?,
            kem_ciphertext: fields.bytes()?,
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
            &[3; 32],
            &mut rng,
        )
        .unwrap();
        let decoded = Welcome::decode(&welcome.encode().unwrap()).unwrap();
        assert_eq!(*decoded.open(&init).unwrap(), [3; 32]);
        let mut moved = decoded.clone();
        moved.epoch = 6;
        assert!(moved.open(&init).is_err());
        let mut retargeted = decoded.clone();
        retargeted.request = [9; 32];
        assert!(retargeted.open(&init).is_err());
        let other = KemSecret::generate(&mut rng);
        assert!(decoded.open(&other).is_err());
    }
}
