//! Cards (docs/specs-v0.5-draft.md section 4.1).
//!
//! ```text
//! Card := [algorithm, public_key]      algorithm 1: ML-DSA-65 (2, FN-DSA-512, is reserved)
//! ```
//!
//! A card is the key a member signs its messages with, and nothing else:
//! the device key keeps signing requests, tasks and seals. A member draws a
//! fresh card with each leaf key, so that a stolen card stops signing for
//! it at its next update.

use ciborium::value::Value;
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::cbor::{array, bytes, expect_array, expect_bytes, expect_uint, uint};
use crate::crypto::{Digest, h_l};
use crate::error::{CoreError, CoreResult};
use crate::identity::{DeviceIdentity, check_device_key, verify_signature};

/// ML-DSA-65, the card algorithm this draft implements.
pub const CARD_ML_DSA_65: u64 = 1;

/// A member's card: the algorithm and the public key it signs messages
/// with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    pub algorithm: u64,
    pub public_key: Vec<u8>,
}

impl Card {
    /// CBOR `[algorithm, public_key]`.
    #[must_use]
    pub fn value(&self) -> Value {
        array(vec![uint(self.algorithm), bytes(&self.public_key)])
    }

    /// Read a card; only ML-DSA-65 cards are accepted.
    pub fn from_value(value: Value, what: &'static str) -> CoreResult<Self> {
        let mut items = expect_array(value, 2, what)?.into_iter();
        let mut next = || items.next().ok_or(CoreError::Malformed(what));
        let card = Self {
            algorithm: expect_uint(&next()?, what)?,
            public_key: expect_bytes(next()?, what)?,
        };
        card.check(what)?;
        Ok(card)
    }

    /// Check the algorithm and the key's length.
    pub fn check(&self, what: &'static str) -> CoreResult<()> {
        if self.algorithm != CARD_ML_DSA_65 {
            return Err(CoreError::Malformed(what));
        }
        check_device_key(&self.public_key, what)
    }

    /// `H_L("card", [card])`, which the registry's map of keys holds.
    pub fn hash(&self) -> CoreResult<Digest> {
        h_l("card", vec![self.value()])
    }

    /// Check a signature of `message` by the card, under the context of
    /// messages.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CoreResult<()> {
        self.check("card")?;
        verify_signature(
            &self.public_key,
            SignatureContext::MESSAGE,
            message,
            signature,
            "card signature",
        )
    }
}

/// The private key of a card.
#[derive(Clone)]
pub struct CardKey {
    identity: DeviceIdentity,
}

impl CardKey {
    /// Draw a fresh card.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            identity: DeviceIdentity::generate(rng),
        }
    }

    /// The public card.
    #[must_use]
    pub fn card(&self) -> Card {
        Card {
            algorithm: CARD_ML_DSA_65,
            public_key: self.identity.public_key().to_vec(),
        }
    }

    /// Sign `message` with the card, under the context of messages.
    pub fn sign(&self, message: &[u8], rng: &mut impl CryptoRngCore) -> CoreResult<Vec<u8>> {
        self.identity.sign(SignatureContext::MESSAGE, message, rng)
    }
}

impl core::fmt::Debug for CardKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CardKey(..)")
    }
}

/// The keys a request sets in a leaf: the leaf key and the card.
#[derive(Clone, Copy, Debug)]
pub struct LeafKeys<'a> {
    pub encryption_key: &'a [u8],
    pub card: &'a Card,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::cbor::{decode, encode};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn a_card_signs_messages_only() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let key = CardKey::generate(&mut rng);
        let card = key.card();
        let signature = key.sign(b"burst", &mut rng).unwrap();
        card.verify(b"burst", &signature).unwrap();
        assert!(card.verify(b"other", &signature).is_err());
        // A card signature is not a device signature, and the reverse.
        let device = DeviceIdentity::generate(&mut rng);
        let by_device = device
            .sign(SignatureContext::JOIN_REQUEST, b"burst", &mut rng)
            .unwrap();
        let as_card = Card {
            algorithm: CARD_ML_DSA_65,
            public_key: device.public_key().to_vec(),
        };
        assert!(as_card.verify(b"burst", &by_device).is_err());
        // A card round-trips, and an unknown algorithm is refused.
        let encoded = encode(&card.value()).unwrap();
        let decoded = Card::from_value(decode(&encoded, 4096, "card").unwrap(), "card").unwrap();
        assert_eq!(decoded, card);
        let other = Card {
            algorithm: 2,
            public_key: card.public_key.clone(),
        };
        let encoded = encode(&other.value()).unwrap();
        assert!(Card::from_value(decode(&encoded, 4096, "card").unwrap(), "card").is_err());
        assert_ne!(card.hash().unwrap(), key_hash_of_other(&mut rng));
    }

    fn key_hash_of_other(rng: &mut ChaCha20Rng) -> Digest {
        CardKey::generate(rng).card().hash().unwrap()
    }
}
