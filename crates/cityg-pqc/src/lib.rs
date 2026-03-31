#![forbid(unsafe_code)]

use thiserror::Error;

/// Historical City-G wire label for POP/admin signatures.
///
/// The repository currently emits Dilithium5-compatible key/signature sizes
/// while carrying the `"ML-DSA-65"` label in protocol payloads. This crate
/// preserves that wire compatibility behind one adapter surface.
pub const CITYG_POP_SIGNATURE_ALGORITHM: &str = "ML-DSA-65";
pub const CITYG_POP_PUBLIC_KEY_BYTES: usize = 2592;
pub const CITYG_POP_SIGNATURE_BYTES: usize = 4627;

pub const ML_DSA_65_ALGORITHM: &str = CITYG_POP_SIGNATURE_ALGORITHM;
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = CITYG_POP_PUBLIC_KEY_BYTES;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = CITYG_POP_SIGNATURE_BYTES;

pub struct MlDsa65SecretKey(backend::SecretKey);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MlDsa65VerifyError {
    #[error("invalid ML-DSA-65 public key length")]
    InvalidPublicKeyLength,
    #[error("invalid ML-DSA-65 signature length")]
    InvalidSignatureLength,
    #[error("invalid ML-DSA-65 public key")]
    InvalidPublicKey,
    #[error("invalid ML-DSA-65 signature")]
    InvalidSignature,
    #[error("ML-DSA-65 verification failed")]
    VerificationFailed,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MlDsa65SecretKeyError {
    #[error("invalid ML-DSA-65 secret key length")]
    InvalidSecretKeyLength,
    #[error("invalid ML-DSA-65 secret key")]
    InvalidSecretKey,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MlDsa65SignError {
    #[error("invalid ML-DSA-65 secret key length")]
    InvalidSecretKeyLength,
    #[error("invalid ML-DSA-65 secret key")]
    InvalidSecretKey,
    #[error("ML-DSA-65 signing failed")]
    SigningFailed,
}

impl MlDsa65SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlDsa65SecretKeyError> {
        backend::secret_key_from_bytes(bytes).map(Self)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        backend::secret_key_into_bytes(self.0)
    }
}

pub fn verify_cityg_pop_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), MlDsa65VerifyError> {
    if public_key.len() != CITYG_POP_PUBLIC_KEY_BYTES {
        return Err(MlDsa65VerifyError::InvalidPublicKeyLength);
    }
    if signature.len() != CITYG_POP_SIGNATURE_BYTES {
        return Err(MlDsa65VerifyError::InvalidSignatureLength);
    }

    backend::verify(public_key, message, signature)
}

pub fn verify_ml_dsa_65_detached_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), MlDsa65VerifyError> {
    verify_cityg_pop_signature(public_key, message, signature)
}

pub fn sign_ml_dsa_65_detached_signature(
    secret_key: &MlDsa65SecretKey,
    message: &[u8],
) -> Result<Vec<u8>, MlDsa65SignError> {
    backend::sign(&secret_key.0, message)
}

pub fn ml_dsa_65_keypair() -> Result<(Vec<u8>, MlDsa65SecretKey), MlDsa65SignError> {
    let (public_key, secret_key) = backend::keypair()?;
    Ok((public_key, MlDsa65SecretKey(secret_key)))
}

#[cfg(not(target_arch = "wasm32"))]
mod backend {
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::{
        DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
        SecretKey as SecretKeyTrait,
    };

    use crate::{MlDsa65SecretKeyError, MlDsa65SignError, MlDsa65VerifyError};

    pub type SecretKey = dilithium5::SecretKey;

    pub fn secret_key_from_bytes(bytes: &[u8]) -> Result<SecretKey, MlDsa65SecretKeyError> {
        <dilithium5::SecretKey as SecretKeyTrait>::from_bytes(bytes).map_err(|_| {
            if bytes.len() == dilithium5::secret_key_bytes() {
                MlDsa65SecretKeyError::InvalidSecretKey
            } else {
                MlDsa65SecretKeyError::InvalidSecretKeyLength
            }
        })
    }

    pub fn secret_key_into_bytes(secret_key: SecretKey) -> Vec<u8> {
        secret_key.as_bytes().to_vec()
    }

    pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<Vec<u8>, MlDsa65SignError> {
        Ok(dilithium5::detached_sign(message, secret_key)
            .as_bytes()
            .to_vec())
    }

    pub fn keypair() -> Result<(Vec<u8>, SecretKey), MlDsa65SignError> {
        let (public_key, secret_key) = dilithium5::keypair();
        Ok((public_key.as_bytes().to_vec(), secret_key))
    }

    pub fn verify(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), MlDsa65VerifyError> {
        let public_key = <dilithium5::PublicKey as PublicKeyTrait>::from_bytes(public_key)
            .map_err(|_| MlDsa65VerifyError::InvalidPublicKey)?;
        let signature =
            <dilithium5::DetachedSignature as DetachedSignatureTrait>::from_bytes(signature)
                .map_err(|_| MlDsa65VerifyError::InvalidSignature)?;

        dilithium5::verify_detached_signature(&signature, message, &public_key)
            .map_err(|_| MlDsa65VerifyError::VerificationFailed)
    }
}

#[cfg(target_arch = "wasm32")]
mod backend {
    use fips204::{
        ml_dsa_87,
        traits::{SerDes, Signer, Verifier},
    };
    use rand_core::OsRng;

    use crate::{MlDsa65SecretKeyError, MlDsa65SignError, MlDsa65VerifyError};

    pub type SecretKey = ml_dsa_87::PrivateKey;

    pub fn secret_key_from_bytes(bytes: &[u8]) -> Result<SecretKey, MlDsa65SecretKeyError> {
        let bytes = <[u8; ml_dsa_87::SK_LEN]>::try_from(bytes)
            .map_err(|_| MlDsa65SecretKeyError::InvalidSecretKeyLength)?;
        ml_dsa_87::PrivateKey::try_from_bytes(bytes)
            .map_err(|_| MlDsa65SecretKeyError::InvalidSecretKey)
    }

    pub fn secret_key_into_bytes(secret_key: SecretKey) -> Vec<u8> {
        secret_key.into_bytes().to_vec()
    }

    pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<Vec<u8>, MlDsa65SignError> {
        let mut rng = OsRng;
        secret_key
            .try_sign_with_rng(&mut rng, message, &[])
            .map(|signature| signature.to_vec())
            .map_err(|_| MlDsa65SignError::SigningFailed)
    }

    pub fn keypair() -> Result<(Vec<u8>, SecretKey), MlDsa65SignError> {
        let mut rng = OsRng;
        ml_dsa_87::try_keygen_with_rng(&mut rng)
            .map(|(public_key, secret_key)| (public_key.into_bytes().to_vec(), secret_key))
            .map_err(|_| MlDsa65SignError::SigningFailed)
    }

    pub fn verify(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), MlDsa65VerifyError> {
        let public_key = <[u8; ml_dsa_87::PK_LEN]>::try_from(public_key)
            .map_err(|_| MlDsa65VerifyError::InvalidPublicKeyLength)?;
        let signature = <[u8; ml_dsa_87::SIG_LEN]>::try_from(signature)
            .map_err(|_| MlDsa65VerifyError::InvalidSignatureLength)?;
        let public_key = ml_dsa_87::PublicKey::try_from_bytes(public_key)
            .map_err(|_| MlDsa65VerifyError::InvalidPublicKey)?;

        if public_key.verify(message, &signature, &[]) {
            Ok(())
        } else {
            Err(MlDsa65VerifyError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

    use super::{
        CITYG_POP_PUBLIC_KEY_BYTES, CITYG_POP_SIGNATURE_BYTES, MlDsa65SecretKey,
        MlDsa65VerifyError, ml_dsa_65_keypair, sign_ml_dsa_65_detached_signature,
        verify_cityg_pop_signature,
    };

    #[test]
    fn host_backend_verifies_native_signature() {
        let (public_key, secret_key) = dilithium5::keypair();
        let message = b"cityg-mldsa";
        let signature = dilithium5::detached_sign(message, &secret_key);

        verify_cityg_pop_signature(public_key.as_bytes(), message, signature.as_bytes())
            .expect("signature should verify");
    }

    #[test]
    fn host_backend_rejects_invalid_lengths() {
        let error = verify_cityg_pop_signature(&[], b"msg", &[]).expect_err("lengths should fail");
        assert_eq!(error, MlDsa65VerifyError::InvalidPublicKeyLength);

        let public_key = vec![0u8; CITYG_POP_PUBLIC_KEY_BYTES];
        let short_signature = vec![0u8; CITYG_POP_SIGNATURE_BYTES - 1];
        let error = verify_cityg_pop_signature(&public_key, b"msg", &short_signature)
            .expect_err("signature length should fail");
        assert_eq!(error, MlDsa65VerifyError::InvalidSignatureLength);
    }

    #[test]
    fn host_wrapper_signs_and_verifies() {
        let (public_key, secret_key) = ml_dsa_65_keypair().expect("keypair");
        let signature =
            sign_ml_dsa_65_detached_signature(&secret_key, b"cityg-wrapper").expect("sign");

        verify_cityg_pop_signature(&public_key, b"cityg-wrapper", &signature)
            .expect("signature should verify");
    }

    #[test]
    fn host_secret_key_round_trips_from_bytes() {
        let (_, secret_key) = dilithium5::keypair();
        let secret_key = MlDsa65SecretKey::from_bytes(secret_key.as_bytes()).expect("secret key");
        let signature = sign_ml_dsa_65_detached_signature(&secret_key, b"roundtrip")
            .expect("sign with round-tripped key");
        assert_eq!(signature.len(), CITYG_POP_SIGNATURE_BYTES);
    }
}
