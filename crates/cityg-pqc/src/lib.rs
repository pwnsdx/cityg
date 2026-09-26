#![forbid(unsafe_code)]
//! FIPS 204 ML-DSA-65 signatures for City-G.
//!
//! Every City-G v0.3 signature (commits and key rotations, group
//! information, join requests, admissions, invitations and their
//! revocations, removal proposals, cover-failure reports, framed messages,
//! alias bindings, session requests, policy documents) uses FIPS 204
//! ML-DSA-65 through this crate. ML-DSA-65 is NIST security category 3, the
//! category of the ML-KEM-768 half of the X-Wing KEM the protocol pairs it
//! with. The same pure-Rust backend (`fips204`) runs on native and wasm32
//! targets, so signatures produced by one build verify on every other build.
//!
//! Each signed object type has its own FIPS 204 context string
//! ([`SignatureContext`]). A signature produced for one usage therefore never
//! verifies for another, even when the signed byte strings coincide.

use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use rand_core::OsRng;
use thiserror::Error;
use zeroize::Zeroizing;

/// Name of the signature algorithm.
pub const SIGNATURE_ALGORITHM: &str = "ML-DSA-65";
/// Encoded public key size (1952 bytes).
pub const PUBLIC_KEY_BYTES: usize = ml_dsa_65::PK_LEN;
/// Encoded secret key size (4032 bytes).
pub const SECRET_KEY_BYTES: usize = ml_dsa_65::SK_LEN;
/// Signature size (3309 bytes).
pub const SIGNATURE_BYTES: usize = ml_dsa_65::SIG_LEN;

/// FIPS 204 context string (`ctx`) naming the usage of a signature.
///
/// The set is closed: callers pick one of the associated constants, so a
/// context cannot be forged from arbitrary bytes at a call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignatureContext(&'static [u8]);

impl SignatureContext {
    /// Commit, signed by its author over `anchor_tbs` (header key 109).
    pub const ANCHOR: Self = Self(b"city-g/anchor/v3");
    /// Commit, signed by the author's new device key when the commit rotates
    /// it (header key 111).
    pub const KEY_ROTATION: Self = Self(b"city-g/key-rotation/v1");
    /// Alias to device-key identity bindings.
    pub const IDENTITY_BINDING: Self = Self(b"city-g/identity-binding/v1");
    /// Removal proposal (voluntary leave or admin removal).
    pub const REMOVE_PROPOSAL: Self = Self(b"city-g/remove/v3");
    /// Request of a device to join a group.
    pub const JOIN_REQUEST: Self = Self(b"city-g/join-request/v1");
    /// Group information published with an epoch.
    pub const GROUP_INFO: Self = Self(b"city-g/group-info/v3");
    /// Admission of a joining device.
    pub const ADMISSION: Self = Self(b"city-g/admission/v2");
    /// Report that a commit could not be processed.
    pub const COVER_FAILURE: Self = Self(b"city-g/cover-failure/v2");
    /// Signed deployment policy documents.
    pub const POLICY: Self = Self(b"city-g/policy/v1");
    /// Framed message content (message plane v4).
    pub const MESSAGE: Self = Self(b"city-g/msg/v4");
    /// Invitation delegating admission to an invite key.
    pub const INVITE: Self = Self(b"city-g/invite/v2");
    /// Revocation of an invitation by an admin.
    pub const INVITE_REVOCATION: Self = Self(b"city-g/invite-revocation/v1");
    /// Request for a delivery-service session token (deployment binding).
    pub const SESSION_AUTH: Self = Self(b"city-g/session-auth/v1");
    /// Draft profile v0.4: district commit, signed by its committer.
    pub const DISTRICT_COMMIT: Self = Self(b"city-g/district-commit/v4");
    /// Draft profile v0.4: seal of a window, signed by its sealer.
    pub const SEAL: Self = Self(b"city-g/seal/v4");
    /// Draft profile v0.4: request of a member to replace its leaf key.
    pub const UPDATE_REQUEST: Self = Self(b"city-g/update/v4");
    /// Draft profile v0.4: request of a member to jump to the present.
    pub const CATCH_UP: Self = Self(b"city-g/catch-up/v4");
    /// Draft profile v0.4: request of a member to re-enter its own leaf.
    pub const RE_ENTRY: Self = Self(b"city-g/re-entry/v4");
    /// Draft profile v0.4: checkpoint of an epoch, signed by an admin.
    pub const CHECKPOINT: Self = Self(b"city-g/checkpoint/v4");

    /// Context bytes passed to FIPS 204 as `ctx`.
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        self.0
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("invalid ML-DSA-65 public key length")]
    InvalidPublicKeyLength,
    #[error("invalid ML-DSA-65 signature length")]
    InvalidSignatureLength,
    #[error("invalid ML-DSA-65 public key")]
    InvalidPublicKey,
    #[error("ML-DSA-65 verification failed")]
    VerificationFailed,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretKeyError {
    #[error("invalid ML-DSA-65 secret key length")]
    InvalidSecretKeyLength,
    #[error("invalid ML-DSA-65 secret key")]
    InvalidSecretKey,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignError {
    #[error("ML-DSA-65 key generation failed")]
    KeyGenerationFailed,
    #[error("ML-DSA-65 signing failed")]
    SigningFailed,
}

/// ML-DSA-65 signing key.
///
/// Holds the expanded key and its FIPS 204 encoding; both are zeroized on drop.
/// The expanded key (~20 KiB) lives on the heap so that values and async
/// futures holding a key stay small.
#[derive(Clone)]
pub struct SecretKey {
    expanded: Box<ml_dsa_65::PrivateKey>,
    encoded: Zeroizing<Vec<u8>>,
}

impl SecretKey {
    fn from_expanded(expanded: ml_dsa_65::PrivateKey) -> Self {
        let encoded = Zeroizing::new(expanded.clone().into_bytes().to_vec());
        Self {
            expanded: Box::new(expanded),
            encoded,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SecretKeyError> {
        let array = <[u8; SECRET_KEY_BYTES]>::try_from(bytes)
            .map_err(|_| SecretKeyError::InvalidSecretKeyLength)?;
        let expanded = ml_dsa_65::PrivateKey::try_from_bytes(array)
            .map_err(|_| SecretKeyError::InvalidSecretKey)?;
        Ok(Self {
            expanded: Box::new(expanded),
            encoded: Zeroizing::new(bytes.to_vec()),
        })
    }

    /// FIPS 204 encoding of the secret key (4032 bytes).
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
        f.write_str("SecretKey(ML-DSA-65, redacted)")
    }
}

/// Generate a fresh key pair from the operating-system RNG.
pub fn keypair() -> Result<(Vec<u8>, SecretKey), SignError> {
    let mut rng = OsRng;
    ml_dsa_65::try_keygen_with_rng(&mut rng)
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
    let (public_key, secret_key) = ml_dsa_65::KG::keygen_from_seed(seed);
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

/// FIPS 204 signature with caller-provided randomness `rnd` (hedged mode
/// when `rnd` is fresh). Protocol cores that take an injectable RNG use this
/// so that every random input comes from one source.
pub fn sign_with_randomness(
    secret_key: &SecretKey,
    context: SignatureContext,
    message: &[u8],
    rnd: &[u8; 32],
) -> Result<Vec<u8>, SignError> {
    secret_key
        .expanded
        .try_sign_with_seed(rnd, message, context.as_bytes())
        .map(|signature| signature.to_vec())
        .map_err(|_| SignError::SigningFailed)
}

/// Verify a FIPS 204 ML-DSA-65 signature under the given usage context.
pub fn verify(
    public_key: &[u8],
    context: SignatureContext,
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let public_key = <[u8; PUBLIC_KEY_BYTES]>::try_from(public_key)
        .map_err(|_| VerifyError::InvalidPublicKeyLength)?;
    let signature = <[u8; SIGNATURE_BYTES]>::try_from(signature)
        .map_err(|_| VerifyError::InvalidSignatureLength)?;
    let public_key = ml_dsa_65::PublicKey::try_from_bytes(public_key)
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
    bytes.len() == PUBLIC_KEY_BYTES
}

/// Check the length of a serialized signature without parsing it.
#[must_use]
pub fn is_signature_length(bytes: &[u8]) -> bool {
    bytes.len() == SIGNATURE_BYTES
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;

    const ALL_CONTEXTS: [SignatureContext; 19] = [
        SignatureContext::ANCHOR,
        SignatureContext::KEY_ROTATION,
        SignatureContext::IDENTITY_BINDING,
        SignatureContext::REMOVE_PROPOSAL,
        SignatureContext::JOIN_REQUEST,
        SignatureContext::GROUP_INFO,
        SignatureContext::ADMISSION,
        SignatureContext::COVER_FAILURE,
        SignatureContext::POLICY,
        SignatureContext::MESSAGE,
        SignatureContext::INVITE,
        SignatureContext::INVITE_REVOCATION,
        SignatureContext::SESSION_AUTH,
        SignatureContext::DISTRICT_COMMIT,
        SignatureContext::SEAL,
        SignatureContext::UPDATE_REQUEST,
        SignatureContext::CATCH_UP,
        SignatureContext::RE_ENTRY,
        SignatureContext::CHECKPOINT,
    ];

    #[test]
    fn sizes_match_fips204_ml_dsa_65() {
        assert_eq!(SIGNATURE_ALGORITHM, "ML-DSA-65");
        assert_eq!(PUBLIC_KEY_BYTES, 1952);
        assert_eq!(SECRET_KEY_BYTES, 4032);
        assert_eq!(SIGNATURE_BYTES, 3309);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (public_key, secret_key) = keypair().expect("keypair");
        assert_eq!(secret_key.public_key(), public_key);
        let signature = sign(&secret_key, SignatureContext::MESSAGE, b"hello").expect("sign");
        assert_eq!(signature.len(), SIGNATURE_BYTES);
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
        let sig_a =
            sign_with_randomness(&sk_a, SignatureContext::ANCHOR, b"m", &[0u8; 32]).expect("sign");
        let sig_b =
            sign_with_randomness(&sk_b, SignatureContext::ANCHOR, b"m", &[0u8; 32]).expect("sign");
        assert_eq!(sig_a, sig_b);
        verify(&pk_a, SignatureContext::ANCHOR, b"m", &sig_a).expect("verify");

        let hedged_a = sign(&sk_a, SignatureContext::ANCHOR, b"m").expect("sign");
        let hedged_b = sign(&sk_a, SignatureContext::ANCHOR, b"m").expect("sign");
        assert_ne!(hedged_a, hedged_b, "hedged signatures use fresh randomness");

        let with_rnd = sign_with_randomness(&sk_a, SignatureContext::ANCHOR, b"m", &[7u8; 32])
            .expect("sign with randomness");
        assert_ne!(with_rnd, sig_a);
        verify(&pk_a, SignatureContext::ANCHOR, b"m", &with_rnd).expect("verify");
    }

    #[test]
    fn secret_key_round_trips_through_bytes() {
        let (public_key, secret_key) = keypair().expect("keypair");
        let bytes = secret_key.to_bytes();
        assert_eq!(bytes.len(), SECRET_KEY_BYTES);
        assert_eq!(secret_key.as_bytes(), bytes.as_slice());
        let restored = SecretKey::from_bytes(&bytes).expect("parse");
        assert_eq!(restored.public_key(), public_key);
        let signature = sign(&restored, SignatureContext::POLICY, b"x").expect("sign");
        verify(&public_key, SignatureContext::POLICY, b"x", &signature).expect("verify");
        assert_eq!(format!("{secret_key:?}"), "SecretKey(ML-DSA-65, redacted)");
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
                &[0u8; SIGNATURE_BYTES - 1]
            ),
            Err(VerifyError::InvalidSignatureLength)
        );
        assert_eq!(
            verify(
                &public_key,
                SignatureContext::MESSAGE,
                b"m",
                &[0u8; SIGNATURE_BYTES]
            ),
            Err(VerifyError::VerificationFailed)
        );
        assert!(is_public_key_length(&public_key));
        assert!(!is_public_key_length(&public_key[1..]));
        assert!(is_signature_length(&[0u8; SIGNATURE_BYTES]));
        assert!(!is_signature_length(&[0u8; 4]));
    }

    /// FIPS 204 final and the pre-standard Dilithium are not interoperable
    /// (audit H-05): pin one known-answer key and signature so a backend swap
    /// is caught. Both values were cross-checked with an independent
    /// implementation (dilithium-py, `ML_DSA_65.key_derive` and
    /// `_sign_internal` with `rnd = 0^32` over `0 || len(ctx) || ctx || m`).
    #[test]
    fn deterministic_known_answer_is_stable() {
        let (public_key, secret_key) = keypair_from_seed(&[0x42u8; 32]);
        let signature = sign_with_randomness(
            &secret_key,
            SignatureContext::ANCHOR,
            b"city-g kat",
            &[0u8; 32],
        )
        .expect("sign");
        verify(
            &public_key,
            SignatureContext::ANCHOR,
            b"city-g kat",
            &signature,
        )
        .expect("verify");
        assert_eq!(
            hex_digest(blake3::hash(&public_key).as_bytes()),
            "3a46d0b0835485ef0558d7ef2a3be17f2fceb9ae3d80fe45265084d17f5a5ad3"
        );
        assert_eq!(
            hex_digest(blake3::hash(&signature).as_bytes()),
            "096a177ffcc50e9619ed592a7bd689f08bd061f73b25acc683b34337a803d740"
        );
    }

    fn hex_digest(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
