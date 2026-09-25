//! ML-KEM-768 (FIPS 203) wrappers.
//!
//! Private keys are kept as their 64-byte FIPS 203 seed `(d, z)`; the
//! decapsulation key is re-derived with `KeyGen_internal` when needed.
//! Encapsulation takes its 32-byte message `m` from the caller's RNG so
//! that every random input of the protocol comes from one injectable source.

use ml_kem::kem::{Decapsulate, KeyExport, TryKeyInit};
use ml_kem::{B32, Seed, ml_kem_768};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cbor::bytes;
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, expand_label_into, h_l};

/// Encoded ML-KEM-768 encapsulation key size.
pub const KEM_PUBLIC_KEY_BYTES: usize = 1184;
/// ML-KEM-768 ciphertext size.
pub const KEM_CIPHERTEXT_BYTES: usize = 1088;
/// ML-KEM-768 seed size (`d || z`).
pub const KEM_SEED_BYTES: usize = 64;

/// Private ML-KEM-768 key held as its FIPS 203 seed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KemSecret {
    seed: [u8; KEM_SEED_BYTES],
}

impl KemSecret {
    /// Wrap a 64-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; KEM_SEED_BYTES]) -> Self {
        Self { seed }
    }

    /// Derive a key seed from a 32-byte secret: `ExpandLabel(secret, label, h'', 64)`.
    pub fn derive(secret: &[u8; 32], label: &str) -> CoreResult<Self> {
        let mut seed = [0u8; KEM_SEED_BYTES];
        expand_label_into(secret, label, &[], &mut seed)?;
        let key = Self { seed };
        seed.zeroize();
        Ok(key)
    }

    /// Sample a fresh key seed.
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

    fn decapsulation_key(&self) -> ml_kem_768::DecapsulationKey {
        ml_kem_768::DecapsulationKey::from_seed(Seed::from(self.seed))
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
        if ciphertext.len() != KEM_CIPHERTEXT_BYTES {
            return Err(CoreError::Malformed("ML-KEM ciphertext"));
        }
        let shared = self
            .decapsulation_key()
            .decapsulate_slice(ciphertext)
            .map_err(|_| CoreError::Malformed("ML-KEM ciphertext"))?;
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

/// Encapsulate to `public_key`: returns `(ciphertext, shared_secret)`.
pub fn encapsulate(
    public_key: &[u8],
    rng: &mut impl CryptoRngCore,
) -> CoreResult<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    if public_key.len() != KEM_PUBLIC_KEY_BYTES {
        return Err(CoreError::Malformed("ML-KEM public key"));
    }
    let ek = ml_kem_768::EncapsulationKey::new_from_slice(public_key)
        .map_err(|_| CoreError::Malformed("ML-KEM public key"))?;
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);
    let (ciphertext, shared) = ek.encapsulate_deterministic(&B32::from(m));
    m.zeroize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(shared.as_slice());
    Ok((ciphertext.as_slice().to_vec(), out))
}

/// Check that `public_key` is a valid ML-KEM-768 encapsulation key.
pub fn validate_public_key(public_key: &[u8]) -> CoreResult<()> {
    if public_key.len() != KEM_PUBLIC_KEY_BYTES {
        return Err(CoreError::Malformed("ML-KEM public key"));
    }
    ml_kem_768::EncapsulationKey::new_from_slice(public_key)
        .map(|_| ())
        .map_err(|_| CoreError::Malformed("ML-KEM public key"))
}

/// `H_pk(pk) := H_L("kem-pk", [pk])`.
pub fn pk_hash(public_key: &[u8]) -> CoreResult<Digest> {
    h_l("kem-pk", vec![bytes(public_key)])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn derived_keys_round_trip_and_are_deterministic() {
        let secret = [5u8; 32];
        let a = KemSecret::derive(&secret, "node").unwrap();
        let b = KemSecret::derive(&secret, "node").unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(
            a.public_key(),
            KemSecret::derive(&secret, "leaf").unwrap().public_key()
        );
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
            "implicit rejection yields an unrelated secret"
        );
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        assert!(encapsulate(&[0u8; 10], &mut rng).is_err());
        assert!(validate_public_key(&[0u8; 10]).is_err());
        let key = KemSecret::generate(&mut rng);
        assert!(key.decapsulate(&[0u8; 10]).is_err());
        assert_eq!(format!("{key:?}"), "KemSecret(..)");
        assert_eq!(
            KemSecret::from_seed(*key.seed()).public_key(),
            key.public_key()
        );
        assert_ne!(pk_hash(&key.public_key()).unwrap(), [0u8; 32]);
    }
}
