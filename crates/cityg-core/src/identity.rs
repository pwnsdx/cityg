//! Device identities (ML-DSA-65).
//!
//! A device key signs everything its device does in one group: its join
//! request, its update, catch-up and re-entry requests, and the district
//! commits and seals it produces. Members are named by their occupancy
//! `[leaf, since]` (see [`crate::tree::Occupancy`]); the registry maps each
//! `device_id` to it.

use cityg_pqc::{SecretKey, SignatureContext};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};

/// A device signing identity (ML-DSA-65).
pub struct DeviceIdentity {
    public_key: Vec<u8>,
    secret_key: SecretKey,
}

impl DeviceIdentity {
    /// Generate a fresh identity: the FIPS 204 key-generation seed `xi` is
    /// drawn from `rng`.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(seed.as_mut());
        Self::from_seed(&seed)
    }

    /// Deterministic identity from a 32-byte FIPS 204 seed `xi`.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (public_key, secret_key) = cityg_pqc::keypair_from_seed(seed);
        Self {
            public_key,
            secret_key,
        }
    }

    /// Restore an identity from its serialized secret key.
    pub fn from_secret_key_bytes(secret_key: &[u8]) -> CoreResult<Self> {
        let secret_key = SecretKey::from_bytes(secret_key)
            .map_err(|_| CoreError::Malformed("ML-DSA-65 secret key"))?;
        Ok(Self {
            public_key: secret_key.public_key(),
            secret_key,
        })
    }

    /// Encoded ML-DSA-65 public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Serialized secret key (for persistence by the owner only).
    #[must_use]
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }

    /// Hedged ML-DSA-65 signature under `context`; the 32-byte `rnd` input
    /// of FIPS 204 is drawn from `rng`.
    pub fn sign(
        &self,
        context: SignatureContext,
        message: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Vec<u8>> {
        let mut rnd = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(rnd.as_mut());
        cityg_pqc::sign_with_randomness(&self.secret_key, context, message, &rnd)
            .map_err(|_| CoreError::Crypto("ML-DSA-65 signing"))
    }
}

impl Clone for DeviceIdentity {
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key.clone(),
            secret_key: self.secret_key.clone(),
        }
    }
}

impl core::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("public_key_len", &self.public_key.len())
            .finish_non_exhaustive()
    }
}

/// Verify an ML-DSA-65 signature; `what` names the signed object.
pub fn verify_signature(
    public_key: &[u8],
    context: SignatureContext,
    message: &[u8],
    signature: &[u8],
    what: &'static str,
) -> CoreResult<()> {
    cityg_pqc::verify(public_key, context, message, signature)
        .map_err(|_| CoreError::BadSignature(what))
}

/// Check that `public_key` has the length of an ML-DSA-65 public key.
pub fn check_device_key(public_key: &[u8], what: &'static str) -> CoreResult<()> {
    if cityg_pqc::is_public_key_length(public_key) {
        Ok(())
    } else {
        Err(CoreError::Malformed(what))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn signatures_round_trip_through_serialized_keys() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let alice = DeviceIdentity::from_seed(&[3; 32]);
        let restored = DeviceIdentity::from_secret_key_bytes(alice.secret_key_bytes()).unwrap();
        assert_eq!(restored.public_key(), alice.public_key());
        let signature = restored
            .sign(SignatureContext::SEAL, b"m", &mut rng)
            .unwrap();
        verify_signature(
            alice.public_key(),
            SignatureContext::SEAL,
            b"m",
            &signature,
            "m",
        )
        .unwrap();
        assert_eq!(
            verify_signature(
                alice.public_key(),
                SignatureContext::DISTRICT_COMMIT,
                b"m",
                &signature,
                "m"
            ),
            Err(CoreError::BadSignature("m"))
        );
        assert!(DeviceIdentity::from_secret_key_bytes(&[0; 3]).is_err());
        assert!(format!("{alice:?}").contains("DeviceIdentity"));
        let generated = DeviceIdentity::generate(&mut rng);
        assert_eq!(generated.public_key().len(), cityg_pqc::PUBLIC_KEY_BYTES);
        assert_eq!(generated.clone().public_key(), generated.public_key());
        check_device_key(generated.public_key(), "device key").unwrap();
        assert!(check_device_key(&[0; 5], "device key").is_err());
    }

    #[test]
    fn signing_randomness_comes_from_the_rng() {
        let alice = DeviceIdentity::from_seed(&[4; 32]);
        let sign = |seed| {
            alice
                .sign(
                    SignatureContext::SEAL,
                    b"m",
                    &mut ChaCha20Rng::seed_from_u64(seed),
                )
                .unwrap()
        };
        assert_eq!(sign(5), sign(5));
        assert_ne!(sign(5), sign(6));
    }
}
