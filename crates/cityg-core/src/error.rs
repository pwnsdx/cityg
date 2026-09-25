//! Error type shared by every City-G v0.2 core operation.

use thiserror::Error;

/// Why a City-G v0.2 object or transition was rejected.
///
/// Variants carry static context only: errors may be logged or returned to
/// peers and must never embed secret material.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    /// The encoding of an object does not follow its wire definition.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// The bytes decode, but are not deterministic CBOR (RFC 8949 §4.2.1).
    #[error("non-deterministic CBOR in {0}")]
    NonDeterministic(&'static str),
    /// A well-formed object violates a protocol rule.
    #[error("invalid {0}")]
    Invalid(&'static str),
    /// The author of an object is not allowed to perform it.
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
    /// A signature does not verify under the expected key and context.
    #[error("bad signature on {0}")]
    BadSignature(&'static str),
    /// A commit does not build on the current epoch.
    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },
    /// A commit does not extend the current transcript.
    #[error("transcript mismatch")]
    TranscriptMismatch,
    /// Authenticated decryption failed.
    #[error("decryption failed: {0}")]
    Decrypt(&'static str),
    /// A message was already received or falls outside the replay window.
    #[error("replayed or expired message")]
    Replay,
    /// An object exceeds a profile size bound.
    #[error("too large: {0}")]
    TooLarge(&'static str),
    /// A cryptographic primitive failed (key generation, KEM, signature).
    #[error("crypto failure: {0}")]
    Crypto(&'static str),
}

/// Result alias for core operations.
pub type CoreResult<T> = Result<T, CoreError>;
