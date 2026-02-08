use anyhow::{Result, anyhow, bail};
use ark_ff::{BigInteger, PrimeField};
use blake3::Hasher;

use super::{
    decs::{DecsCommitment as InnerDecs, DecsConfig, DecsState},
    polynomial::eval,
    rng::RoundSeeder,
};
use crate::field::BaseField;

/// Abstraction over the polynomial commitment scheme used by SmallWood.
pub trait PolynomialCommitment {
    type State;

    fn commit(
        &self,
        salt: &[u8],
        polynomials: &[Vec<BaseField>],
        round_seeder: Option<&RoundSeeder>,
    ) -> Result<(Vec<u8>, Self::State)>;

    fn open(
        &self,
        state: &Self::State,
        piop_queries: &[BaseField],
        lvcs_queries: &[Vec<BaseField>],
        fullrank_cols: &[usize],
        decs_queries: &[BaseField],
        binding: &[u8],
    ) -> Result<(Vec<Vec<BaseField>>, Vec<u8>)>;

    #[allow(clippy::too_many_arguments)]
    fn recompute_commitment(
        &self,
        salt: &[u8],
        piop_queries: &[BaseField],
        lvcs_queries: &[Vec<BaseField>],
        fullrank_cols: &[usize],
        decs_queries: &[BaseField],
        responses: &[Vec<BaseField>],
        opening_proof: &[u8],
        binding: &[u8],
    ) -> Result<Vec<u8>>;
}

#[derive(Clone, Debug)]
pub struct CommitmentState {
    polynomials: Vec<Vec<BaseField>>,
}

/// Deterministic Blake3-based commitment scheme used as a stand-in for the real DECS PCS.
#[derive(Clone, Debug, Default)]
pub struct HashCommitment;

#[derive(Clone, Debug)]
pub struct DecsCommitment {
    inner: InnerDecs,
}

#[derive(Clone, Debug)]
pub struct DecsStateWrapper {
    state: DecsState,
}

impl PolynomialCommitment for HashCommitment {
    type State = CommitmentState;

    fn commit(
        &self,
        salt: &[u8],
        polynomials: &[Vec<BaseField>],
        _round_seeder: Option<&RoundSeeder>,
    ) -> Result<(Vec<u8>, Self::State)> {
        commit_impl(salt, polynomials)
    }

    fn open(
        &self,
        state: &Self::State,
        _piop_queries: &[BaseField],
        _lvcs_queries: &[Vec<BaseField>],
        _fullrank_cols: &[usize],
        queries: &[BaseField],
        binding: &[u8],
    ) -> Result<(Vec<Vec<BaseField>>, Vec<u8>)> {
        open_impl(state, queries, binding)
    }

    #[allow(clippy::too_many_arguments)]
    fn recompute_commitment(
        &self,
        salt: &[u8],
        _piop_queries: &[BaseField],
        _lvcs_queries: &[Vec<BaseField>],
        _fullrank_cols: &[usize],
        queries: &[BaseField],
        responses: &[Vec<BaseField>],
        opening_proof: &[u8],
        binding: &[u8],
    ) -> Result<Vec<u8>> {
        recompute_commitment_impl(salt, queries, responses, opening_proof, binding)
    }
}

impl DecsCommitment {
    pub fn new(config: DecsConfig) -> Self {
        Self {
            inner: InnerDecs::new(config),
        }
    }

    pub fn sample_query_points(
        &self,
        fs_domain: &str,
        statement_bytes: &[u8],
        commitment: &[u8],
        nb_queries: usize,
    ) -> Vec<BaseField> {
        self.inner
            .sample_query_points(fs_domain, statement_bytes, commitment, nb_queries)
    }

    pub fn config(&self) -> &DecsConfig {
        &self.inner.config
    }
}

impl PolynomialCommitment for DecsCommitment {
    type State = DecsStateWrapper;

    fn commit(
        &self,
        salt: &[u8],
        polynomials: &[Vec<BaseField>],
        round_seeder: Option<&RoundSeeder>,
    ) -> Result<(Vec<u8>, Self::State)> {
        let (commitment, state) = self.inner.commit(salt, polynomials, round_seeder)?;
        Ok((commitment, DecsStateWrapper { state }))
    }

    fn open(
        &self,
        state: &Self::State,
        _piop_queries: &[BaseField],
        _lvcs_queries: &[Vec<BaseField>],
        _fullrank_cols: &[usize],
        queries: &[BaseField],
        _binding: &[u8],
    ) -> Result<(Vec<Vec<BaseField>>, Vec<u8>)> {
        self.inner.open(&state.state, queries)
    }

    fn recompute_commitment(
        &self,
        salt: &[u8],
        _piop_queries: &[BaseField],
        _lvcs_queries: &[Vec<BaseField>],
        _fullrank_cols: &[usize],
        queries: &[BaseField],
        responses: &[Vec<BaseField>],
        opening_proof: &[u8],
        _binding: &[u8],
    ) -> Result<Vec<u8>> {
        self.inner
            .recompute_commitment(salt, queries, responses, opening_proof)
    }
}

pub fn field_to_bytes(f: &BaseField) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let repr = f.into_bigint();
    let repr_bytes = repr.to_bytes_le();
    bytes[..repr_bytes.len()].copy_from_slice(&repr_bytes);
    bytes
}

pub fn bytes_to_field(bytes: &[u8]) -> BaseField {
    BaseField::from_le_bytes_mod_order(bytes)
}

fn compute_digest(salt: &[u8], binding: &[u8], polynomials: &[Vec<BaseField>]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(salt);
    hasher.update(binding);
    for poly in polynomials {
        for coeff in poly {
            hasher.update(&field_to_bytes(coeff));
        }
    }
    hasher.finalize().as_bytes().to_vec()
}

fn commit_impl(salt: &[u8], polynomials: &[Vec<BaseField>]) -> Result<(Vec<u8>, CommitmentState)> {
    let digest = compute_digest(salt, &[], polynomials);
    Ok((
        digest,
        CommitmentState {
            polynomials: polynomials.to_vec(),
        },
    ))
}

fn open_impl(
    state: &CommitmentState,
    queries: &[BaseField],
    _binding: &[u8],
) -> Result<(Vec<Vec<BaseField>>, Vec<u8>)> {
    let mut responses = Vec::with_capacity(queries.len());
    for query in queries {
        let evals = state
            .polynomials
            .iter()
            .map(|poly| eval(poly, *query))
            .collect();
        responses.push(evals);
    }

    let mut proof = Vec::new();
    proof.extend_from_slice(&(state.polynomials.len() as u64).to_le_bytes());
    for poly in &state.polynomials {
        proof.extend_from_slice(&(poly.len() as u64).to_le_bytes());
        for coeff in poly {
            proof.extend_from_slice(&field_to_bytes(coeff));
        }
    }

    Ok((responses, proof))
}

fn recompute_commitment_impl(
    salt: &[u8],
    queries: &[BaseField],
    responses: &[Vec<BaseField>],
    opening_proof: &[u8],
    binding: &[u8],
) -> Result<Vec<u8>> {
    let mut cursor = opening_proof;
    const U64_LEN: usize = std::mem::size_of::<u64>();
    if cursor.len() < U64_LEN {
        bail!("opening proof truncated");
    }
    let nb_polys = u64::from_le_bytes(
        cursor[..U64_LEN]
            .try_into()
            .map_err(|_| anyhow!("opening proof row count malformed"))?,
    ) as usize;
    cursor = &cursor[U64_LEN..];
    let mut polynomials = Vec::with_capacity(nb_polys);
    for _ in 0..nb_polys {
        if cursor.len() < U64_LEN {
            bail!("opening proof truncated (poly len)");
        }
        let degree = u64::from_le_bytes(
            cursor[..U64_LEN]
                .try_into()
                .map_err(|_| anyhow!("opening proof poly length malformed"))?,
        ) as usize;
        cursor = &cursor[U64_LEN..];
        let required = degree * 32;
        if cursor.len() < required {
            bail!("opening proof truncated (coeffs)");
        }
        let mut coeffs = Vec::with_capacity(degree);
        for chunk in cursor[..required].chunks(32) {
            coeffs.push(bytes_to_field(chunk));
        }
        cursor = &cursor[required..];
        polynomials.push(coeffs);
    }

    if responses.len() != queries.len() {
        bail!("response/query length mismatch");
    }
    for (round, (query, evals)) in queries.iter().zip(responses.iter()).enumerate() {
        let expected: Vec<BaseField> = polynomials.iter().map(|poly| eval(poly, *query)).collect();
        if expected != *evals {
            bail!("evaluation mismatch at query {round}");
        }
    }

    Ok(compute_digest(salt, binding, &polynomials))
}

// Helper wrappers to maintain the previous free-function API while callers migrate to the trait.
pub fn commit(salt: &[u8], polynomials: &[Vec<BaseField>]) -> Result<(Vec<u8>, CommitmentState)> {
    HashCommitment.commit(salt, polynomials, None)
}

pub fn open(
    state: &CommitmentState,
    piop_queries: &[BaseField],
    lvcs_queries: &[Vec<BaseField>],
    fullrank_cols: &[usize],
    queries: &[BaseField],
    binding: &[u8],
) -> Result<(Vec<Vec<BaseField>>, Vec<u8>)> {
    HashCommitment.open(
        state,
        piop_queries,
        lvcs_queries,
        fullrank_cols,
        queries,
        binding,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn recompute_commitment(
    salt: &[u8],
    piop_queries: &[BaseField],
    lvcs_queries: &[Vec<BaseField>],
    fullrank_cols: &[usize],
    queries: &[BaseField],
    responses: &[Vec<BaseField>],
    opening_proof: &[u8],
    binding: &[u8],
) -> Result<Vec<u8>> {
    HashCommitment.recompute_commitment(
        salt,
        piop_queries,
        lvcs_queries,
        fullrank_cols,
        queries,
        responses,
        opening_proof,
        binding,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smallwood::decs::DecsChallengeFormat;
    use crate::smallwood::rng::SmallwoodSeeder;

    fn sample_polynomials() -> Vec<Vec<BaseField>> {
        vec![
            vec![
                BaseField::from(1u64),
                BaseField::from(2u64),
                BaseField::from(3u64),
            ],
            vec![
                BaseField::from(4u64),
                BaseField::from(5u64),
                BaseField::from(6u64),
            ],
        ]
    }

    #[test]
    fn field_encoding_roundtrip() {
        let value = BaseField::from(123_456u64);
        let encoded = field_to_bytes(&value);
        let decoded = bytes_to_field(&encoded);
        assert_eq!(decoded, value);
    }

    #[test]
    fn hash_commitment_roundtrip_and_binding_effect() -> Result<()> {
        let salt = b"fixed-salt";
        let polynomials = sample_polynomials();
        let (commitment, state) = commit(salt, &polynomials)?;
        let queries = vec![BaseField::from(0u64), BaseField::from(1u64)];
        let (responses, opening) = open(&state, &[], &[], &[], &queries, b"unused")?;

        let recomputed =
            recompute_commitment(salt, &[], &[], &[], &queries, &responses, &opening, &[])?;
        assert_eq!(commitment, recomputed);

        let rebound = recompute_commitment(
            salt,
            &[],
            &[],
            &[],
            &queries,
            &responses,
            &opening,
            b"binding",
        )?;
        assert_ne!(
            commitment, rebound,
            "binding should domain-separate commitment recomputation"
        );
        Ok(())
    }

    #[test]
    fn recompute_commitment_reports_truncation_and_mismatch_errors() -> Result<()> {
        let salt = b"fixed-salt";
        let polynomials = sample_polynomials();
        let (_commitment, state) = commit(salt, &polynomials)?;
        let queries = vec![BaseField::from(0u64), BaseField::from(1u64)];
        let (responses, opening) = open(&state, &[], &[], &[], &queries, &[])?;

        let err = recompute_commitment(salt, &[], &[], &[], &queries, &responses, &[], &[])
            .expect_err("empty proof must fail");
        assert!(err.to_string().contains("truncated"));

        let mut truncated_poly_len = opening.clone();
        truncated_poly_len.truncate(8);
        let err = recompute_commitment(
            salt,
            &[],
            &[],
            &[],
            &queries,
            &responses,
            &truncated_poly_len,
            &[],
        )
        .expect_err("proof without poly lengths must fail");
        assert!(err.to_string().contains("truncated"));

        let mut truncated_coeffs = opening.clone();
        truncated_coeffs.pop();
        let err = recompute_commitment(
            salt,
            &[],
            &[],
            &[],
            &queries,
            &responses,
            &truncated_coeffs,
            &[],
        )
        .expect_err("proof without coefficients must fail");
        assert!(err.to_string().contains("truncated"));

        let err = recompute_commitment(
            salt,
            &[],
            &[],
            &[],
            &queries[..1],
            &responses,
            &opening,
            &[],
        )
        .expect_err("query/response mismatch must fail");
        assert!(err.to_string().contains("response/query length mismatch"));

        let mut bad_responses = responses.clone();
        bad_responses[0][0] += BaseField::from(1u64);
        let err =
            recompute_commitment(salt, &[], &[], &[], &queries, &bad_responses, &opening, &[])
                .expect_err("evaluation mismatch must fail");
        assert!(err.to_string().contains("evaluation mismatch"));
        Ok(())
    }

    #[test]
    fn decs_commitment_wrapper_accessors_and_roundtrip() -> Result<()> {
        let config = DecsConfig {
            nb_polys: 1,
            degree: 2,
            eta: 1,
            nb_queries: 1,
            nb_evals: 4,
            format_challenge: DecsChallengeFormat::Uniform,
            pow_opening_bits: 0,
            use_commitment_tapes: false,
            digest_bytes: 16,
            salt_bytes: 8,
            tree_arity: vec![2, 2],
            tree_truncation: None,
        };
        let pcs = DecsCommitment::new(config.clone());
        assert_eq!(pcs.config().nb_polys, 1);

        let seeder = SmallwoodSeeder::new("decs/test", b"statement");
        let round = seeder.round(0);
        let salt = round.salt(config.salt_bytes);
        let polynomials = vec![vec![
            BaseField::from(1u64),
            BaseField::from(2u64),
            BaseField::from(3u64),
        ]];

        let err = pcs
            .commit(&salt, &polynomials, None)
            .expect_err("missing round seeder should fail");
        assert!(err.to_string().contains("round seeder"));

        let (commitment, state) = pcs.commit(&salt, &polynomials, Some(&round))?;
        let queries = pcs.sample_query_points("decs/test", b"statement", &commitment, 1);
        let (responses, opening) = pcs.open(&state, &[], &[], &[], &queries, &[])?;
        let recomputed =
            pcs.recompute_commitment(&salt, &[], &[], &[], &queries, &responses, &opening, &[])?;
        assert_eq!(recomputed, commitment);
        Ok(())
    }
}
