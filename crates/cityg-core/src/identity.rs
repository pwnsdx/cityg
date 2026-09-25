//! Device identities (ML-DSA-87) and the identifiers derived from them.

use cityg_pqc::{SecretKey, SignatureContext};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::cbor::bytes;
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, h_l};

/// `leaf_id := H_L("leaf-id", [gid, device_pk])`.
pub fn leaf_id(gid: &[u8; 32], device_pk: &[u8]) -> CoreResult<Digest> {
    h_l("leaf-id", vec![bytes(gid), bytes(device_pk)])
}

/// `gid := H_L("group-id", [creator_device_pk, nonce])`.
///
/// Binding the creator key into the group identifier makes the creator the
/// verifiable first admin of the group.
pub fn group_id(creator_device_pk: &[u8], nonce: &[u8; 32]) -> CoreResult<Digest> {
    h_l("group-id", vec![bytes(creator_device_pk), bytes(nonce)])
}

/// A device signing identity (ML-DSA-87).
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
            .map_err(|_| CoreError::Malformed("ML-DSA-87 secret key"))?;
        Ok(Self {
            public_key: secret_key.public_key(),
            secret_key,
        })
    }

    /// Encoded ML-DSA-87 public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Serialized secret key (for persistence by the owner only).
    #[must_use]
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }

    /// Hedged ML-DSA-87 signature under `context`; the 32-byte `rnd` input
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
            .map_err(|_| CoreError::Crypto("ML-DSA-87 signing"))
    }

    /// `leaf_id` of this device in group `gid`.
    pub fn leaf_id(&self, gid: &[u8; 32]) -> CoreResult<Digest> {
        leaf_id(gid, &self.public_key)
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

/// Verify an ML-DSA-87 signature; `what` names the signed object.
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

/// Check that `public_key` has the length of an ML-DSA-87 public key.
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
    fn identifiers_bind_group_and_key() {
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let gid = group_id(alice.public_key(), &[9; 32]).unwrap();
        assert_ne!(gid, group_id(bob.public_key(), &[9; 32]).unwrap());
        assert_ne!(gid, group_id(alice.public_key(), &[8; 32]).unwrap());
        let leaf = alice.leaf_id(&gid).unwrap();
        assert_eq!(leaf, leaf_id(&gid, alice.public_key()).unwrap());
        assert_ne!(leaf, bob.leaf_id(&gid).unwrap());
        assert_ne!(leaf, alice.leaf_id(&[0; 32]).unwrap());
    }

    #[test]
    fn signatures_round_trip_through_serialized_keys() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let alice = DeviceIdentity::from_seed(&[3; 32]);
        let restored = DeviceIdentity::from_secret_key_bytes(alice.secret_key_bytes()).unwrap();
        assert_eq!(restored.public_key(), alice.public_key());
        let signature = restored
            .sign(SignatureContext::ANCHOR, b"m", &mut rng)
            .unwrap();
        verify_signature(
            alice.public_key(),
            SignatureContext::ANCHOR,
            b"m",
            &signature,
            "m",
        )
        .unwrap();
        assert_eq!(
            verify_signature(
                alice.public_key(),
                SignatureContext::INVITE,
                b"m",
                &signature,
                "m"
            ),
            Err(CoreError::BadSignature("m"))
        );
        assert!(DeviceIdentity::from_secret_key_bytes(&[0; 3]).is_err());
        assert!(format!("{alice:?}").contains("DeviceIdentity"));
        let generated = DeviceIdentity::generate(&mut rng);
        assert_eq!(generated.public_key().len(), 2592);
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
                    SignatureContext::ANCHOR,
                    b"m",
                    &mut ChaCha20Rng::seed_from_u64(seed),
                )
                .unwrap()
        };
        assert_eq!(sign(5), sign(5));
        assert_ne!(sign(5), sign(6));
    }
}
