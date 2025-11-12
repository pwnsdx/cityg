use std::{error::Error, fmt};

use thiserror::Error;

/// Structured error codes for witness validation failures (mapped to Freeze 907.x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessValidationError {
    CborMalformed,
    NonCanonical,
    LeafBindMismatch,
    ProjEvalFail,
    PathOversize,
}

impl WitnessValidationError {
    pub fn code(self) -> u16 {
        match self {
            WitnessValidationError::CborMalformed => 9071,
            WitnessValidationError::NonCanonical => 9072,
            WitnessValidationError::LeafBindMismatch => 9073,
            WitnessValidationError::ProjEvalFail => 9074,
            WitnessValidationError::PathOversize => 9075,
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            WitnessValidationError::CborMalformed => "cbor_malformed",
            WitnessValidationError::NonCanonical => "nonmem_noncanonical",
            WitnessValidationError::LeafBindMismatch => "leaf_bind_mismatch",
            WitnessValidationError::ProjEvalFail => "proj_eval_fail",
            WitnessValidationError::PathOversize => "path_oversize",
        }
    }
}

impl fmt::Display for WitnessValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason())
    }
}

impl Error for WitnessValidationError {}

/// Common error type for the msphf-we stack.
#[derive(Debug, Error)]
pub enum MsphfError {
    /// Placeholder for functionality that has not been implemented yet.
    #[error("feature not implemented: {0}")]
    Unimplemented(&'static str),
    /// Wrapper around serialization errors.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// Wrapper around invalid inputs (e.g. malformed witnesses, headers).
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Deterministic witness replay diverged from the recorded proof material.
    #[error("witness replay mismatch ({0})")]
    WitnessReplayMismatch(WitnessReplayField),
    /// Structured witness validation error.
    #[error("witness validation error: {0}")]
    Witness(#[from] WitnessValidationError),
}

/// Identifies which component diverged during strict witness replay.
///
/// Add new variants here when the strict rebuild checks additional inputs
/// (e.g. seed context hash, seed commit) so that higher layers can keep
/// matching on an exhaustively typed error rather than falling back to
/// string comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessReplayField {
    XkHash,
    RhoCommit,
}

impl std::fmt::Display for WitnessReplayField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            WitnessReplayField::XkHash => "xk_hash",
            WitnessReplayField::RhoCommit => "rho_commit",
        };
        f.write_str(label)
    }
}

impl MsphfError {
    pub fn serialization<E: std::fmt::Display>(err: E) -> Self {
        MsphfError::Serialization(err.to_string())
    }
    pub fn invalid_input<E: std::fmt::Display>(err: E) -> Self {
        MsphfError::InvalidInput(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // WitnessValidationError tests
    #[test]
    fn witness_validation_error_codes() {
        assert_eq!(WitnessValidationError::CborMalformed.code(), 9071);
        assert_eq!(WitnessValidationError::NonCanonical.code(), 9072);
        assert_eq!(WitnessValidationError::LeafBindMismatch.code(), 9073);
        assert_eq!(WitnessValidationError::ProjEvalFail.code(), 9074);
        assert_eq!(WitnessValidationError::PathOversize.code(), 9075);
    }

    #[test]
    fn witness_validation_error_reasons() {
        assert_eq!(
            WitnessValidationError::CborMalformed.reason(),
            "cbor_malformed"
        );
        assert_eq!(
            WitnessValidationError::NonCanonical.reason(),
            "nonmem_noncanonical"
        );
        assert_eq!(
            WitnessValidationError::LeafBindMismatch.reason(),
            "leaf_bind_mismatch"
        );
        assert_eq!(
            WitnessValidationError::ProjEvalFail.reason(),
            "proj_eval_fail"
        );
        assert_eq!(
            WitnessValidationError::PathOversize.reason(),
            "path_oversize"
        );
    }

    #[test]
    fn witness_validation_error_display() {
        assert_eq!(
            format!("{}", WitnessValidationError::CborMalformed),
            "cbor_malformed"
        );
        assert_eq!(
            format!("{}", WitnessValidationError::NonCanonical),
            "nonmem_noncanonical"
        );
        assert_eq!(
            format!("{}", WitnessValidationError::LeafBindMismatch),
            "leaf_bind_mismatch"
        );
        assert_eq!(
            format!("{}", WitnessValidationError::ProjEvalFail),
            "proj_eval_fail"
        );
        assert_eq!(
            format!("{}", WitnessValidationError::PathOversize),
            "path_oversize"
        );
    }

    #[test]
    fn witness_validation_error_is_error() {
        let err: &dyn Error = &WitnessValidationError::CborMalformed;
        assert_eq!(err.to_string(), "cbor_malformed");
    }

    #[test]
    fn witness_validation_error_clone_eq() {
        let err1 = WitnessValidationError::CborMalformed;
        let err2 = err1;
        assert_eq!(err1, err2);

        let err3 = WitnessValidationError::NonCanonical;
        assert_ne!(err1, err3);
    }

    #[test]
    fn witness_validation_error_debug() {
        let err = WitnessValidationError::ProjEvalFail;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("ProjEvalFail"));
    }

    // WitnessReplayField tests
    #[test]
    fn witness_replay_field_display() {
        assert_eq!(format!("{}", WitnessReplayField::XkHash), "xk_hash");
        assert_eq!(format!("{}", WitnessReplayField::RhoCommit), "rho_commit");
    }

    #[test]
    fn witness_replay_field_clone_eq() {
        let field1 = WitnessReplayField::XkHash;
        let field2 = field1;
        assert_eq!(field1, field2);

        let field3 = WitnessReplayField::RhoCommit;
        assert_ne!(field1, field3);
    }

    #[test]
    fn witness_replay_field_debug() {
        let field = WitnessReplayField::XkHash;
        let debug_str = format!("{:?}", field);
        assert!(debug_str.contains("XkHash"));
    }

    // MsphfError tests
    #[test]
    fn msphf_error_unimplemented_display() {
        let err = MsphfError::Unimplemented("some feature");
        assert_eq!(err.to_string(), "feature not implemented: some feature");
    }

    #[test]
    fn msphf_error_serialization_helper() {
        let err = MsphfError::serialization("invalid format");
        assert_eq!(err.to_string(), "serialization error: invalid format");
    }

    #[test]
    fn msphf_error_serialization_direct() {
        let err = MsphfError::Serialization("test error".to_string());
        assert_eq!(err.to_string(), "serialization error: test error");
    }

    #[test]
    fn msphf_error_invalid_input_helper() {
        let err = MsphfError::invalid_input("bad data");
        assert_eq!(err.to_string(), "invalid input: bad data");
    }

    #[test]
    fn msphf_error_invalid_input_direct() {
        let err = MsphfError::InvalidInput("malformed".to_string());
        assert_eq!(err.to_string(), "invalid input: malformed");
    }

    #[test]
    fn msphf_error_witness_replay_mismatch() {
        let err = MsphfError::WitnessReplayMismatch(WitnessReplayField::XkHash);
        assert_eq!(err.to_string(), "witness replay mismatch (xk_hash)");

        let err2 = MsphfError::WitnessReplayMismatch(WitnessReplayField::RhoCommit);
        assert_eq!(err2.to_string(), "witness replay mismatch (rho_commit)");
    }

    #[test]
    fn msphf_error_from_witness_validation_error() {
        let witness_err = WitnessValidationError::LeafBindMismatch;
        let msphf_err: MsphfError = witness_err.into();
        assert_eq!(
            msphf_err.to_string(),
            "witness validation error: leaf_bind_mismatch"
        );
    }

    #[test]
    fn msphf_error_witness_direct() {
        let err = MsphfError::Witness(WitnessValidationError::PathOversize);
        assert_eq!(err.to_string(), "witness validation error: path_oversize");
    }

    #[test]
    fn msphf_error_is_error_trait() {
        let err: Box<dyn Error> = Box::new(MsphfError::Unimplemented("test"));
        assert!(err.to_string().contains("not implemented"));
    }

    #[test]
    fn msphf_error_debug() {
        let err = MsphfError::InvalidInput("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("InvalidInput"));
    }

    #[test]
    fn helper_methods_accept_different_types() {
        // Test that helpers work with different Display types
        let err1 = MsphfError::serialization(42);
        assert_eq!(err1.to_string(), "serialization error: 42");

        let err2 = MsphfError::invalid_input(true);
        assert_eq!(err2.to_string(), "invalid input: true");

        let err3 = MsphfError::serialization("string literal");
        assert_eq!(err3.to_string(), "serialization error: string literal");
    }
}
