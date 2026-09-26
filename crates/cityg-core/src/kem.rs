//! X-Wing hybrid KEM (ML-KEM-768 and X25519, draft-connolly-cfrg-xwing-kem).
//!
//! A private key is its 32-byte X-Wing decapsulation key (a seed that
//! SHAKE256 expands into the ML-KEM-768 seed and the X25519 scalar); the
//! expanded keys are re-derived when needed. Encapsulation takes its 64 bytes
//! of randomness (32 for ML-KEM, 32 for the X25519 ephemeral key) from the
//! caller's generator, so that every random input of the protocol comes from
//! one injectable source.

use rand_core::CryptoRngCore;
use x_wing::{
    Ciphertext, Decapsulate, DecapsulationKey, Decapsulator, EncapsulationKey, KeyExport,
    TryKeyInit,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CoreError, CoreResult};

/// Encoded X-Wing encapsulation key size (ML-KEM-768 key, then X25519 key).
pub const KEM_PUBLIC_KEY_BYTES: usize = x_wing::ENCAPSULATION_KEY_SIZE;
/// X-Wing ciphertext size (ML-KEM-768 ciphertext, then X25519 ephemeral key).
pub const KEM_CIPHERTEXT_BYTES: usize = x_wing::CIPHERTEXT_SIZE;
/// X-Wing decapsulation key (seed) size.
pub const KEM_SEED_BYTES: usize = x_wing::DECAPSULATION_KEY_SIZE;

/// Private X-Wing key held as its 32-byte decapsulation key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KemSecret {
    seed: [u8; KEM_SEED_BYTES],
}

impl KemSecret {
    /// Wrap a 32-byte decapsulation key.
    #[must_use]
    pub fn from_seed(seed: [u8; KEM_SEED_BYTES]) -> Self {
        Self { seed }
    }

    /// Sample a fresh key.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut seed = [0u8; KEM_SEED_BYTES];
        rng.fill_bytes(&mut seed);
        let key = Self { seed };
        seed.zeroize();
        key
    }

    /// The seed bytes (for persistence by the key owner only).
    #[must_use]
    pub fn seed(&self) -> &[u8; KEM_SEED_BYTES] {
        &self.seed
    }

    fn decapsulation_key(&self) -> DecapsulationKey {
        DecapsulationKey::from(self.seed)
    }

    /// Encoded encapsulation (public) key.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.decapsulation_key()
            .encapsulation_key()
            .to_bytes()
            .as_slice()
            .to_vec()
    }

    /// Recover the shared secret of `ciphertext`.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> CoreResult<Zeroizing<[u8; 32]>> {
        let ciphertext = Ciphertext::try_from(ciphertext)
            .map_err(|_| CoreError::Malformed("X-Wing ciphertext"))?;
        let shared = self.decapsulation_key().decapsulate(&ciphertext);
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(shared.as_slice());
        Ok(out)
    }
}

impl core::fmt::Debug for KemSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemSecret(..)")
    }
}

fn encapsulation_key(public_key: &[u8]) -> CoreResult<EncapsulationKey> {
    if public_key.len() != KEM_PUBLIC_KEY_BYTES {
        return Err(CoreError::Malformed("X-Wing public key"));
    }
    EncapsulationKey::new_from_slice(public_key)
        .map_err(|_| CoreError::Malformed("X-Wing public key"))
}

/// Encapsulate to `public_key`: returns `(ciphertext, shared_secret)`.
pub fn encapsulate(
    public_key: &[u8],
    rng: &mut impl CryptoRngCore,
) -> CoreResult<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let key = encapsulation_key(public_key)?;
    let mut randomness = Zeroizing::new([0u8; x_wing::ENCAPSULATION_RANDOMNESS_SIZE]);
    rng.fill_bytes(randomness.as_mut());
    let (ciphertext, shared) = key.encapsulate_deterministic(&(*randomness).into());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(shared.as_slice());
    Ok((ciphertext.as_slice().to_vec(), out))
}

/// Check that `public_key` is a valid X-Wing encapsulation key (its ML-KEM
/// half passes the FIPS 203 modulus check).
pub fn validate_public_key(public_key: &[u8]) -> CoreResult<()> {
    encapsulation_key(public_key).map(|_| ())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn seeded_keys_round_trip_and_are_deterministic() {
        let a = KemSecret::from_seed([5u8; 32]);
        let b = KemSecret::from_seed([5u8; 32]);
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(a.public_key(), KemSecret::from_seed([6u8; 32]).public_key());
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let pk = a.public_key();
        assert_eq!(pk.len(), KEM_PUBLIC_KEY_BYTES);
        validate_public_key(&pk).unwrap();
        let (ct, ss) = encapsulate(&pk, &mut rng).unwrap();
        assert_eq!(ct.len(), KEM_CIPHERTEXT_BYTES);
        assert_eq!(*a.decapsulate(&ct).unwrap(), *ss);
        assert_ne!(
            *KemSecret::generate(&mut rng).decapsulate(&ct).unwrap(),
            *ss,
            "another key yields an unrelated secret"
        );
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        assert!(encapsulate(&[0u8; 10], &mut rng).is_err());
        assert!(validate_public_key(&[0u8; 10]).is_err());
        // An ML-KEM half whose coefficients exceed the modulus fails the
        // FIPS 203 input check.
        assert!(validate_public_key(&[0xffu8; KEM_PUBLIC_KEY_BYTES]).is_err());
        let key = KemSecret::generate(&mut rng);
        assert!(key.decapsulate(&[0u8; 10]).is_err());
        assert_eq!(format!("{key:?}"), "KemSecret(..)");
        assert_eq!(
            KemSecret::from_seed(*key.seed()).public_key(),
            key.public_key()
        );
    }

    /// Randomness source that hands out fixed bytes, in order.
    struct Fixed(Vec<u8>);

    impl rand_core::RngCore for Fixed {
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

    impl rand_core::CryptoRng for Fixed {}

    /// Test vector 1 of the X-Wing draft (shipped with the `x-wing` crate):
    /// seed, encapsulation randomness, and the expected public key and
    /// ciphertext (through BLAKE3 digests) and shared secret.
    #[test]
    fn x_wing_draft_vector() {
        let seed: [u8; 32] =
            hex::decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
                .unwrap()
                .try_into()
                .unwrap();
        let key = KemSecret::from_seed(seed);
        let public_key = key.public_key();
        assert_eq!(
            hex::encode(blake3::hash(&public_key).as_bytes()),
            "feef93be794a93e4e5e9ea6b57c0cb74477e7624a4a5cc269372392b8cb49ca2"
        );
        let mut eseed = Fixed(
            hex::decode(
                "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2\
                 35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
            )
            .unwrap(),
        );
        let (ciphertext, shared) = encapsulate(&public_key, &mut eseed).unwrap();
        assert_eq!(
            hex::encode(blake3::hash(&ciphertext).as_bytes()),
            "ad7464c3f36f257dfe3369a82fef9f60f84fd14fffc232ec50568de4511e0ff3"
        );
        let expected = "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384";
        assert_eq!(hex::encode(*shared), expected);
        assert_eq!(
            hex::encode(*key.decapsulate(&ciphertext).unwrap()),
            expected
        );
    }
}
