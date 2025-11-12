use std::io;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("serialization error: {0}")]
    Serialization(#[from] io::Error),
    #[error("norm violation at polynomial {poly} coefficient {coeff}")]
    NormViolation { poly: usize, coeff: usize },
    #[error("invalid key payload: {0}")]
    InvalidKey(&'static str),
    #[error("invalid proof payload: {0}")]
    InvalidProof(&'static str),
    #[error("invalid domain: {0}")]
    Domain(&'static str),
    #[error("challenge generation failed")]
    ChallengeFailure,
    #[error("rng error")]
    Rng,
    #[error("unexpected state: {0}")]
    Internal(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
