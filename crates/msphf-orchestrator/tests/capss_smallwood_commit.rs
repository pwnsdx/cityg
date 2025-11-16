use capss::field::BaseField;
use capss::smallwood::commit::{commit, open, recompute_commitment};

fn bf(value: u64) -> BaseField {
    BaseField::from(value)
}

#[test]
fn hash_commit_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let polynomials = vec![vec![bf(1), bf(2), bf(3)], vec![bf(4), bf(5)]];
    let salt = b"commit-roundtrip";
    let (digest, state) = commit(salt, &polynomials)?;
    let queries = vec![bf(2), bf(3)];
    let (responses, proof) = open(&state, &[], &[], &[], &queries, b"")?;
    let recomputed = recompute_commitment(salt, &[], &[], &[], &queries, &responses, &proof, b"")?;
    assert_eq!(digest, recomputed);
    Ok(())
}

#[test]
fn recompute_commitment_catches_length_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let polynomials = vec![vec![bf(1), bf(0)]];
    let (_digest, state) = commit(b"salt", &polynomials)?;
    let queries = vec![bf(1), bf(2)];
    let (responses, proof) = open(&state, &[], &[], &[], &queries, b"bind")?;
    let err = match recompute_commitment(
        b"salt",
        &[],
        &[],
        &[],
        &queries[..1],
        &responses,
        &proof,
        b"bind",
    ) {
        Err(e) => e,
        Ok(_) => return Err("expected length mismatch error".into()),
    };
    assert!(err.to_string().contains("length mismatch"));
    Ok(())
}

#[test]
fn recompute_commitment_detects_truncated_proof() -> Result<(), Box<dyn std::error::Error>> {
    let polynomials = vec![vec![bf(5), bf(6)]];
    let (_digest, state) = commit(b"salt", &polynomials)?;
    let queries = vec![bf(3)];
    let (responses, proof) = open(&state, &[], &[], &[], &queries, b"bind")?;
    let truncated = &proof[..proof.len() - 1];
    let err = match recompute_commitment(
        b"salt",
        &[],
        &[],
        &[],
        &queries,
        &responses,
        truncated,
        b"bind",
    ) {
        Err(e) => e,
        Ok(_) => return Err("expected truncated proof error".into()),
    };
    assert!(err.to_string().contains("truncated"));
    Ok(())
}

#[test]
fn recompute_commitment_detects_bad_evaluations() -> Result<(), Box<dyn std::error::Error>> {
    let polynomials = vec![vec![bf(1), bf(1)]]; // x + 1
    let (_digest, state) = commit(b"salt", &polynomials)?;
    let queries = vec![bf(0)];
    let (mut responses, proof) = open(&state, &[], &[], &[], &queries, b"bind")?;
    responses[0][0] += bf(1); // corrupt evaluation
    let err = match recompute_commitment(
        b"salt",
        &[],
        &[],
        &[],
        &queries,
        &responses,
        &proof,
        b"bind",
    ) {
        Err(e) => e,
        Ok(_) => return Err("expected evaluation mismatch error".into()),
    };
    assert!(err.to_string().contains("evaluation mismatch"));
    Ok(())
}

#[test]
fn recompute_commitment_changes_with_binding() -> Result<(), Box<dyn std::error::Error>> {
    let polynomials = vec![vec![bf(1), bf(1)]]; // x + 1
    let (digest, state) = commit(b"salt", &polynomials)?;
    let queries = vec![bf(2)];
    let (responses, proof) = open(&state, &[], &[], &[], &queries, b"")?;
    let recomputed =
        recompute_commitment(b"salt", &[], &[], &[], &queries, &responses, &proof, b"")?;
    assert_eq!(digest, recomputed);

    let recomputed_with_binding = recompute_commitment(
        b"salt",
        &[],
        &[],
        &[],
        &queries,
        &responses,
        &proof,
        b"binding",
    )?;
    assert_ne!(digest, recomputed_with_binding);
    Ok(())
}
