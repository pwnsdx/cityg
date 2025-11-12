use capss::field::BaseField;
use capss::smallwood::commit::{commit, open, recompute_commitment};

fn bf(value: u64) -> BaseField {
    BaseField::from(value)
}

#[test]
fn hash_commit_roundtrip() {
    let polynomials = vec![vec![bf(1), bf(2), bf(3)], vec![bf(4), bf(5)]];
    let salt = b"commit-roundtrip";
    let (digest, state) = commit(salt, &polynomials).expect("commit");
    let queries = vec![bf(2), bf(3)];
    let (responses, proof) = open(&state, &[], &[], &[], &queries, b"").expect("open");
    let recomputed = recompute_commitment(salt, &[], &[], &[], &queries, &responses, &proof, b"")
        .expect("recompute");
    assert_eq!(digest, recomputed);
}

#[test]
fn recompute_commitment_catches_length_mismatch() {
    let polynomials = vec![vec![bf(1), bf(0)]];
    let (_digest, state) = commit(b"salt", &polynomials).expect("commit");
    let queries = vec![bf(1), bf(2)];
    let (responses, proof) = open(&state, &[], &[], &[], &queries, b"bind").expect("open");
    let err = recompute_commitment(
        b"salt",
        &[],
        &[],
        &[],
        &queries[..1],
        &responses,
        &proof,
        b"bind",
    )
    .expect_err("length mismatch");
    assert!(err.to_string().contains("length mismatch"));
}

#[test]
fn recompute_commitment_detects_truncated_proof() {
    let polynomials = vec![vec![bf(5), bf(6)]];
    let (_digest, state) = commit(b"salt", &polynomials).expect("commit");
    let queries = vec![bf(3)];
    let (responses, proof) = open(&state, &[], &[], &[], &queries, b"bind").expect("open");
    let truncated = &proof[..proof.len() - 1];
    let err = recompute_commitment(
        b"salt",
        &[],
        &[],
        &[],
        &queries,
        &responses,
        truncated,
        b"bind",
    )
    .expect_err("truncated");
    assert!(err.to_string().contains("truncated"));
}

#[test]
fn recompute_commitment_detects_bad_evaluations() {
    let polynomials = vec![vec![bf(1), bf(1)]]; // x + 1
    let (_digest, state) = commit(b"salt", &polynomials).expect("commit");
    let queries = vec![bf(0)];
    let (mut responses, proof) = open(&state, &[], &[], &[], &queries, b"bind").expect("open");
    responses[0][0] += bf(1); // corrupt evaluation
    let err = recompute_commitment(
        b"salt",
        &[],
        &[],
        &[],
        &queries,
        &responses,
        &proof,
        b"bind",
    )
    .expect_err("evaluation mismatch");
    assert!(err.to_string().contains("evaluation mismatch"));
}

#[test]
fn recompute_commitment_changes_with_binding() {
    let polynomials = vec![vec![bf(1), bf(1)]]; // x + 1
    let (digest, state) = commit(b"salt", &polynomials).expect("commit");
    let queries = vec![bf(2)];
    let (responses, proof) = open(&state, &[], &[], &[], &queries, b"").expect("open");
    let recomputed =
        recompute_commitment(b"salt", &[], &[], &[], &queries, &responses, &proof, b"")
            .expect("recompute");
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
    )
    .expect("recompute alt binding");
    assert_ne!(digest, recomputed_with_binding);
}
