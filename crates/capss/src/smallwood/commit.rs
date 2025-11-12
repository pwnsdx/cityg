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
