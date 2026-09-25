#![forbid(unsafe_code)]
//! FIPS 204 ML-DSA-87 signatures for City-G.
//!
//! Every City-G signature (anchor proof of possession, bootstrap CA, barrier
//! receipts, history-authority attestations, room-admin proofs, identity
//! bindings, chat messages, removal proposals) uses FIPS 204 ML-DSA-87 through
//! this crate. The same pure-Rust backend (`fips204`) runs on native and wasm32
//! targets, so signatures produced by one build verify on every other build.
//!
//! Each signed object type has its own FIPS 204 context string
//! ([`SignatureContext`]). A signature produced for one usage therefore never
//! verifies for another, even when the signed byte strings coincide.

use fips204::{
    ml_dsa_87,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use rand_core::OsRng;
use thiserror::Error;
use zeroize::Zeroizing;

/// Wire label carried in anchors (header key 107) and API payloads.
pub const SIGNATURE_ALGORITHM: &str = "ML-DSA-87";
pub const ML_DSA_87_PUBLIC_KEY_BYTES: usize = ml_dsa_87::PK_LEN;
pub const ML_DSA_87_SECRET_KEY_BYTES: usize = ml_dsa_87::SK_LEN;
pub const ML_DSA_87_SIGNATURE_BYTES: usize = ml_dsa_87::SIG_LEN;

/// FIPS 204 context string (`ctx`) naming the usage of a signature.
///
/// The set is closed: callers pick one of the associated constants, so a
/// context cannot be forged from arbitrary bytes at a call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignatureContext(&'static [u8]);

impl SignatureContext {
    /// Proof of possession carried by JOIN anchors (header key 109).
    pub const ANCHOR_POP: Self = Self(b"city-g/anchor/pop/v1");
    /// Signature over a whole anchor header (profile v0.2, header key 109).
    pub const ANCHOR: Self = Self(b"city-g/anchor/v2");
    /// Bootstrap certificate-authority signature (header key 171).
    pub const ANCHOR_BOOTSTRAP: Self = Self(b"city-g/anchor/bootstrap/v1");
    /// Author receipt over a barrier update (header key 181).
    pub const BARRIER_RECEIPT: Self = Self(b"city-g/barrier/receipt/v1");
    /// History-authority attestations, witnesses and helper responses.
    pub const HISTORY_AUTHORITY: Self = Self(b"city-g/history-authority/v1");
    /// Room-admin authorization proofs.
    pub const ROOM_ADMIN: Self = Self(b"city-g/room-admin/v1");
    /// Alias to device-key identity bindings.
    pub const IDENTITY_BINDING: Self = Self(b"city-g/identity-binding/v1");
    /// Authenticated chat message content.
    pub const MESSAGE: Self = Self(b"city-g/msg/v2");
    /// Removal proposal (voluntary leave or admin removal).
    pub const REMOVE_PROPOSAL: Self = Self(b"city-g/remove/v1");
    /// Group information published with an epoch (profile v0.2).
    pub const GROUP_INFO: Self = Self(b"city-g/group-info/v2");
    /// Admission of a joining device (profile v0.2).
    pub const ADMISSION: Self = Self(b"city-g/admission/v1");
    /// Report that a barrier update did not cover a member (profile v0.2).
    pub const COVER_FAILURE: Self = Self(b"city-g/cover-failure/v1");
    /// Signed deployment policy documents.
    pub const POLICY: Self = Self(b"city-g/policy/v1");

    /// Context bytes passed to FIPS 204 as `ctx`.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        self.0
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("invalid ML-DSA-87 public key length")]
    InvalidPublicKeyLength,
    #[error("invalid ML-DSA-87 signature length")]
    InvalidSignatureLength,
    #[error("invalid ML-DSA-87 public key")]
    InvalidPublicKey,
    #[error("ML-DSA-87 verification failed")]
    VerificationFailed,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretKeyError {
    #[error("invalid ML-DSA-87 secret key length")]
    InvalidSecretKeyLength,
    #[error("invalid ML-DSA-87 secret key")]
    InvalidSecretKey,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignError {
    #[error("ML-DSA-87 key generation failed")]
    KeyGenerationFailed,
    #[error("ML-DSA-87 signing failed")]
    SigningFailed,
}

/// ML-DSA-87 signing key.
///
/// Holds the expanded key and its FIPS 204 encoding; both are zeroized on drop.
/// The expanded key (~24 KiB) lives on the heap so that values and async
/// futures holding a key stay small.
#[derive(Clone)]
pub struct SecretKey {
    expanded: Box<ml_dsa_87::PrivateKey>,
    encoded: Zeroizing<Vec<u8>>,
}

impl SecretKey {
    fn from_expanded(expanded: ml_dsa_87::PrivateKey) -> Self {
        let encoded = Zeroizing::new(expanded.clone().into_bytes().to_vec());
        Self {
            expanded: Box::new(expanded),
            encoded,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SecretKeyError> {
        let array = <[u8; ML_DSA_87_SECRET_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| SecretKeyError::InvalidSecretKeyLength)?;
        let expanded = ml_dsa_87::PrivateKey::try_from_bytes(array)
            .map_err(|_| SecretKeyError::InvalidSecretKey)?;
        Ok(Self {
            expanded: Box::new(expanded),
            encoded: Zeroizing::new(bytes.to_vec()),
        })
    }

    /// FIPS 204 encoding of the secret key (4896 bytes).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.encoded.as_slice()
    }

    /// Owned copy of the FIPS 204 encoding; callers own its zeroization.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encoded.to_vec()
    }

    /// Serialized public key matching this secret key.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.expanded.get_public_key().into_bytes().to_vec()
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(ML-DSA-87, redacted)")
    }
}

/// Generate a fresh key pair from the operating-system RNG.
pub fn keypair() -> Result<(Vec<u8>, SecretKey), SignError> {
    let mut rng = OsRng;
    ml_dsa_87::try_keygen_with_rng(&mut rng)
        .map(|(public_key, secret_key)| {
            (
                public_key.into_bytes().to_vec(),
                SecretKey::from_expanded(secret_key),
            )
        })
        .map_err(|_| SignError::KeyGenerationFailed)
}

/// Derive a key pair from a 32-byte seed (FIPS 204 `ML-DSA.KeyGen_internal`).
///
/// Only for deterministic fixtures and test vectors: production keys come
/// from [`keypair`].
#[must_use]
pub fn keypair_from_seed(seed: &[u8; 32]) -> (Vec<u8>, SecretKey) {
    let (public_key, secret_key) = ml_dsa_87::KG::keygen_from_seed(seed);
    (
        public_key.into_bytes().to_vec(),
        SecretKey::from_expanded(secret_key),
    )
}

/// Hedged FIPS 204 signature (fresh randomness per signature).
pub fn sign(
    secret_key: &SecretKey,
    context: SignatureContext,
    message: &[u8],
) -> Result<Vec<u8>, SignError> {
    let mut rng = OsRng;
    secret_key
        .expanded
        .try_sign_with_rng(&mut rng, message, context.as_bytes())
        .map(|signature| signature.to_vec())
        .map_err(|_| SignError::SigningFailed)
}

/// Deterministic FIPS 204 signature (`rnd = 0^256`), for test vectors only.
pub fn sign_deterministic(
    secret_key: &SecretKey,
    context: SignatureContext,
    message: &[u8],
) -> Result<Vec<u8>, SignError> {
    secret_key
        .expanded
        .try_sign_with_seed(&[0u8; 32], message, context.as_bytes())
        .map(|signature| signature.to_vec())
        .map_err(|_| SignError::SigningFailed)
}

/// Sign with a secret key given as serialized bytes.
pub fn sign_with_secret_key_bytes(
    secret_key: &[u8],
    context: SignatureContext,
    message: &[u8],
) -> Result<Vec<u8>, SignError> {
    let secret_key = SecretKey::from_bytes(secret_key).map_err(|_| SignError::SigningFailed)?;
    sign(&secret_key, context, message)
}

/// Verify a FIPS 204 ML-DSA-87 signature under the given usage context.
pub fn verify(
    public_key: &[u8],
    context: SignatureContext,
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let public_key = <[u8; ML_DSA_87_PUBLIC_KEY_BYTES]>::try_from(public_key)
        .map_err(|_| VerifyError::InvalidPublicKeyLength)?;
    let signature = <[u8; ML_DSA_87_SIGNATURE_BYTES]>::try_from(signature)
        .map_err(|_| VerifyError::InvalidSignatureLength)?;
    let public_key = ml_dsa_87::PublicKey::try_from_bytes(public_key)
        .map_err(|_| VerifyError::InvalidPublicKey)?;
    if public_key.verify(message, &signature, context.as_bytes()) {
        Ok(())
    } else {
        Err(VerifyError::VerificationFailed)
    }
}

/// Check the length of a serialized public key without parsing it.
#[must_use]
pub fn is_public_key_length(bytes: &[u8]) -> bool {
    bytes.len() == ML_DSA_87_PUBLIC_KEY_BYTES
}

/// Check the length of a serialized signature without parsing it.
#[must_use]
pub fn is_signature_length(bytes: &[u8]) -> bool {
    bytes.len() == ML_DSA_87_SIGNATURE_BYTES
}

/// Helpers for test suites of dependent crates (feature `test-utils`).
///
/// They never fail: key generation falls back to a counter-derived seed if the
/// OS RNG is unavailable, and signing falls back to the deterministic variant.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use super::{SecretKey, SignatureContext};
    use core::sync::atomic::{AtomicU64, Ordering};

    static FALLBACK_COUNTER: AtomicU64 = AtomicU64::new(1);

    /// `as_bytes()` on serialized keys and signatures, so test code written
    /// against byte-array wrapper types keeps reading naturally.
    pub trait AsBytes {
        fn as_bytes(&self) -> &[u8];
    }

    impl AsBytes for Vec<u8> {
        fn as_bytes(&self) -> &[u8] {
            self.as_slice()
        }
    }

    /// Fresh random key pair (infallible).
    #[must_use]
    pub fn keypair() -> (Vec<u8>, SecretKey) {
        super::keypair().unwrap_or_else(|_| {
            let counter = FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut seed = [0x5au8; 32];
            seed[..8].copy_from_slice(&counter.to_le_bytes());
            super::keypair_from_seed(&seed)
        })
    }

    /// Hedged signature, or deterministic signature if the RNG fails (infallible).
    #[must_use]
    pub fn sign(secret_key: &SecretKey, context: SignatureContext, message: &[u8]) -> Vec<u8> {
        super::sign(secret_key, context, message)
            .or_else(|_| super::sign_deterministic(secret_key, context, message))
            .unwrap_or_default()
    }

    /// Deterministic FIPS 204 signature (empty signature on failure), for
    /// signers whose statements are re-derived and compared byte for byte.
    #[must_use]
    pub fn sign_deterministic(
        secret_key: &SecretKey,
        context: SignatureContext,
        message: &[u8],
    ) -> Vec<u8> {
        super::sign_deterministic(secret_key, context, message).unwrap_or_default()
    }

    /// Deterministic signature with serialized secret key bytes (empty
    /// signature on malformed key).
    #[must_use]
    pub fn sign_deterministic_with_secret_key_bytes(
        secret_key: &[u8],
        context: SignatureContext,
        message: &[u8],
    ) -> Vec<u8> {
        SecretKey::from_bytes(secret_key)
            .map(|secret_key| sign_deterministic(&secret_key, context, message))
            .unwrap_or_default()
    }

    /// Sign with serialized secret key bytes (empty signature on malformed key).
    #[must_use]
    pub fn sign_with_secret_key_bytes(
        secret_key: &[u8],
        context: SignatureContext,
        message: &[u8],
    ) -> Vec<u8> {
        SecretKey::from_bytes(secret_key)
            .map(|secret_key| sign(&secret_key, context, message))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;

    const ALL_CONTEXTS: [SignatureContext; 13] = [
        SignatureContext::ANCHOR_POP,
        SignatureContext::ANCHOR,
        SignatureContext::ANCHOR_BOOTSTRAP,
        SignatureContext::BARRIER_RECEIPT,
        SignatureContext::HISTORY_AUTHORITY,
        SignatureContext::ROOM_ADMIN,
        SignatureContext::IDENTITY_BINDING,
        SignatureContext::MESSAGE,
        SignatureContext::REMOVE_PROPOSAL,
        SignatureContext::GROUP_INFO,
        SignatureContext::ADMISSION,
        SignatureContext::COVER_FAILURE,
        SignatureContext::POLICY,
    ];

    #[test]
    fn sizes_match_fips204_ml_dsa_87() {
        assert_eq!(ML_DSA_87_PUBLIC_KEY_BYTES, 2592);
        assert_eq!(ML_DSA_87_SECRET_KEY_BYTES, 4896);
        assert_eq!(ML_DSA_87_SIGNATURE_BYTES, 4627);
        assert_eq!(SIGNATURE_ALGORITHM, "ML-DSA-87");
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (public_key, secret_key) = keypair().expect("keypair");
        assert_eq!(secret_key.public_key(), public_key);
        let signature = sign(&secret_key, SignatureContext::MESSAGE, b"hello").expect("sign");
        assert_eq!(signature.len(), ML_DSA_87_SIGNATURE_BYTES);
        verify(&public_key, SignatureContext::MESSAGE, b"hello", &signature).expect("verify");
        assert_eq!(
            verify(&public_key, SignatureContext::MESSAGE, b"hellp", &signature),
            Err(VerifyError::VerificationFailed)
        );
    }

    #[test]
    fn contexts_are_distinct_and_bind_signatures() {
        let unique: std::collections::BTreeSet<&[u8]> = ALL_CONTEXTS
            .iter()
            .map(|context| context.as_bytes())
            .collect();
        assert_eq!(unique.len(), ALL_CONTEXTS.len());
        for context in ALL_CONTEXTS {
            assert!(context.as_bytes().len() <= 255, "FIPS 204 ctx limit");
        }

        let (public_key, secret_key) = keypair_from_seed(&[7u8; 32]);
        let signature =
            sign(&secret_key, SignatureContext::REMOVE_PROPOSAL, b"payload").expect("sign");
        for context in ALL_CONTEXTS {
            let outcome = verify(&public_key, context, b"payload", &signature);
            if context == SignatureContext::REMOVE_PROPOSAL {
                assert_eq!(outcome, Ok(()));
            } else {
                assert_eq!(outcome, Err(VerifyError::VerificationFailed));
            }
        }
    }

    #[test]
    fn seeded_keys_and_deterministic_signatures_are_reproducible() {
        let (pk_a, sk_a) = keypair_from_seed(&[1u8; 32]);
        let (pk_b, sk_b) = keypair_from_seed(&[1u8; 32]);
        assert_eq!(pk_a, pk_b);
        let sig_a = sign_deterministic(&sk_a, SignatureContext::ANCHOR, b"m").expect("sign");
        let sig_b = sign_deterministic(&sk_b, SignatureContext::ANCHOR, b"m").expect("sign");
        assert_eq!(sig_a, sig_b);
        verify(&pk_a, SignatureContext::ANCHOR, b"m", &sig_a).expect("verify");

        let hedged_a = sign(&sk_a, SignatureContext::ANCHOR, b"m").expect("sign");
        let hedged_b = sign(&sk_a, SignatureContext::ANCHOR, b"m").expect("sign");
        assert_ne!(hedged_a, hedged_b, "hedged signatures use fresh randomness");
    }

    #[test]
    fn secret_key_round_trips_through_bytes() {
        let (public_key, secret_key) = keypair().expect("keypair");
        let bytes = secret_key.to_bytes();
        assert_eq!(bytes.len(), ML_DSA_87_SECRET_KEY_BYTES);
        assert_eq!(secret_key.as_bytes(), bytes.as_slice());
        let restored = SecretKey::from_bytes(&bytes).expect("parse");
        assert_eq!(restored.public_key(), public_key);
        let signature = sign_with_secret_key_bytes(&bytes, SignatureContext::ROOM_ADMIN, b"x")
            .expect("sign with bytes");
        verify(&public_key, SignatureContext::ROOM_ADMIN, b"x", &signature).expect("verify");
        assert_eq!(format!("{secret_key:?}"), "SecretKey(ML-DSA-87, redacted)");
    }

    #[test]
    fn test_utils_never_fail_and_verify() {
        let (public_key, secret_key) = test_utils::keypair();
        let signature = test_utils::sign(&secret_key, SignatureContext::MESSAGE, b"t");
        verify(&public_key, SignatureContext::MESSAGE, b"t", &signature).expect("verify");
        let from_bytes = test_utils::sign_with_secret_key_bytes(
            &secret_key.to_bytes(),
            SignatureContext::MESSAGE,
            b"t",
        );
        verify(&public_key, SignatureContext::MESSAGE, b"t", &from_bytes).expect("verify");
        assert!(
            test_utils::sign_with_secret_key_bytes(&[0u8; 2], SignatureContext::MESSAGE, b"t")
                .is_empty()
        );
        let first = test_utils::sign_deterministic_with_secret_key_bytes(
            &secret_key.to_bytes(),
            SignatureContext::HISTORY_AUTHORITY,
            b"t",
        );
        let second =
            test_utils::sign_deterministic(&secret_key, SignatureContext::HISTORY_AUTHORITY, b"t");
        assert_eq!(first, second);
        verify(
            &public_key,
            SignatureContext::HISTORY_AUTHORITY,
            b"t",
            &first,
        )
        .expect("verify");
        assert!(
            test_utils::sign_deterministic_with_secret_key_bytes(
                &[0u8; 2],
                SignatureContext::MESSAGE,
                b"t"
            )
            .is_empty()
        );
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        assert_eq!(
            SecretKey::from_bytes(&[0u8; 12]).err(),
            Some(SecretKeyError::InvalidSecretKeyLength)
        );
        assert_eq!(
            verify(&[], SignatureContext::MESSAGE, b"m", &[]),
            Err(VerifyError::InvalidPublicKeyLength)
        );
        let (public_key, _) = keypair_from_seed(&[3u8; 32]);
        assert_eq!(
            verify(
                &public_key,
                SignatureContext::MESSAGE,
                b"m",
                &[0u8; ML_DSA_87_SIGNATURE_BYTES - 1]
            ),
            Err(VerifyError::InvalidSignatureLength)
        );
        assert_eq!(
            verify(
                &public_key,
                SignatureContext::MESSAGE,
                b"m",
                &[0u8; ML_DSA_87_SIGNATURE_BYTES]
            ),
            Err(VerifyError::VerificationFailed)
        );
        assert!(sign_with_secret_key_bytes(&[1u8; 3], SignatureContext::MESSAGE, b"m").is_err());
        assert!(is_public_key_length(&public_key));
        assert!(!is_public_key_length(&public_key[1..]));
        assert!(is_signature_length(&[0u8; ML_DSA_87_SIGNATURE_BYTES]));
        assert!(!is_signature_length(&[0u8; 4]));
    }

    /// FIPS 204 final and the pre-standard Dilithium5 are not interoperable
    /// (audit H-05): pin one known-answer signature so a backend swap is caught.
    #[test]
    fn deterministic_known_answer_is_stable() {
        let (public_key, secret_key) = keypair_from_seed(&[0x42u8; 32]);
        let signature =
            sign_deterministic(&secret_key, SignatureContext::ANCHOR, b"city-g kat").expect("sign");
        verify(
            &public_key,
            SignatureContext::ANCHOR,
            b"city-g kat",
            &signature,
        )
        .expect("verify");
        assert_eq!(
            hex_digest(blake3::hash(&public_key).as_bytes()),
            "9feb4643cb4e7e1643415c8f57f56a6a522ee559a5be6b8f06989ab98c772553"
        );
        assert_eq!(
            hex_digest(blake3::hash(&signature).as_bytes()),
            "340192246112cd6a49f9ee3cbf3a673f09d8af656ee10f5d1e777d9cb1611a2e"
        );
    }

    fn hex_digest(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
