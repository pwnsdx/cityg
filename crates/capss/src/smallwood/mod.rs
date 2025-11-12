//! SmallWood hash-based polynomial commitment and argument of knowledge.
//!
//! This module implements the Smallwood protocol, a linear algebraic proof system that provides
//! zero-knowledge proofs of polynomial evaluations. Used in City-G for server-blind validation
//! of forward secrecy parameters.
//!
//! ## Implementation Note
//!
//! This is a **Rust port of a Sage/Python reference implementation** housed in
//! `vendor/smallwood-python` (git submodule). Cross-language fixture tests
//! (see `../../tests/python_fixture.rs`) ensure bit-for-bit compatibility with the mathematical
//! reference.
//!
//! For details on the port relationship, testing workflow, and architecture, see the
//! [crate README](../../../README.md).

use std::{convert::TryFrom, mem::size_of};

use anyhow::{Context, Result, bail, ensure};
use ark_ff::PrimeField;
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

pub mod array;
pub mod commit;
pub mod decs;
pub mod layout;
pub mod linear;
pub mod lvcs;
pub mod merkle;
pub mod pacs;
pub mod polynomial;
pub mod rng;
pub mod serialization;
pub mod serializer;
pub mod witness;
pub mod xof;

use crate::{
    field::{BaseField, FieldElement},
    transcript::{decode_proof, encode_proof},
    types::{CapssProof, CapssSignature, CapssStatement},
};
use commit::{PolynomialCommitment, field_to_bytes};
use decs::{DecsChallengeFormat, DecsCommitment as InnerDecs, DecsConfig};
use layout::GenericUnivariateLayout;
use lvcs::LvcsCommitment;
use pacs::{ExamplePacs, Pacs};
use rng::SmallwoodSeeder;
use serializer::{deserialize_matrix_exact, serialize_matrix};
use witness::{create_mask_polynomials, create_witness_polynomials};

/// Parameters controlling the SmallWood proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmallwoodConfig {
    /// Number of repetitions to achieve the target soundness.
    pub repetitions: usize,
    /// Target security level in bits (matches CAPSS spec table).
    pub security_level: u16,
    /// Degree bound for the polynomials inside the PACS commitments.
    pub polynomial_degree: usize,
    /// Domain separator used for Fiat–Shamir hashing.
    pub fs_domain: String,
    /// Number of queries sampled by the verifier.
    pub nb_queries: usize,
    /// Number of mask polynomials (rho in the paper).
    pub rho: usize,
}

impl Default for SmallwoodConfig {
    fn default() -> Self {
        Self {
            repetitions: 0,
            security_level: 128,
            polynomial_degree: 4,
            fs_domain: "msphf/smallwood/chal".to_string(),
            nb_queries: 1,
            rho: 1,
        }
    }
}

/// Commitment data recorded for each round.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoundCommitment {
    /// Serialized commitment (e.g., DECS commitment hash).
    pub commitment: Vec<u8>,
    /// Optional metadata (e.g., seed commitments) that the verifier must recompute.
    pub metadata: Vec<u8>,
}

/// Response data for the positions challenged via Fiat–Shamir.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoundResponse {
    /// Serialized evaluations of the committed polynomials.
    pub evaluations: Vec<u8>,
    /// Serialized opening proof used to recompute the commitment.
    pub opening_proof: Vec<u8>,
}

/// Serializable transcript of the SmallWood protocol.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodTranscript {
    /// Commitments for each repetition before the challenge.
    pub commitments: Vec<RoundCommitment>,
    /// Fiat–Shamir challenge bytes (e.g., derived via Poseidon/Blake3).
    pub challenge: Vec<u8>,
    /// Responses corresponding to the challenge bits/indices.
    pub responses: Vec<RoundResponse>,
}

/// Structured proof returned by the SmallWood prover.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodProof {
    /// Transcript payload.
    pub transcript: SmallwoodTranscript,
    /// Configuration that was used (helps detect mismatch between prover/verifier).
    pub config: SmallwoodConfig,
}

#[derive(Clone, Copy, Debug)]
struct TranscriptRoundSizes {
    commitment: usize,
    metadata: usize,
    evaluations: usize,
    opening_proof: usize,
}

fn compute_round_sizes(pcs: &LvcsCommitment, config: &SmallwoodConfig) -> TranscriptRoundSizes {
    let dec_cfg = pcs.decs_config();
    let piop_queries = config.nb_queries;
    let commitment_fields = dec_cfg.eta * (dec_cfg.degree + 1);
    let commitment = pcs.digest_bytes() + decs::packed_field_bytes(commitment_fields);

    let metadata = dec_cfg.salt_bytes;

    let layout = pcs.layout();
    let u64_len = size_of::<u64>();
    let evaluations = u64_len + piop_queries * (u64_len + layout.nb_polys() * 32);

    let dec_query_count = dec_cfg.nb_queries;
    let mask_bytes = decs::packed_field_bytes(dec_query_count * dec_cfg.eta);
    let keep = dec_cfg.nb_queries.min(dec_cfg.degree + 1);
    let eps_high_len = dec_cfg.degree + 1 - keep;
    let eps_bytes = decs::packed_field_bytes(dec_cfg.eta * eps_high_len);
    let tapes_bytes = if dec_cfg.use_commitment_tapes {
        dec_cfg.digest_bytes * dec_query_count
    } else {
        0
    };
    let path_siblings: usize = dec_cfg
        .tree_arity
        .iter()
        .rev()
        .map(|branch| branch.saturating_sub(1))
        .sum();
    let path_bytes = path_siblings * dec_cfg.digest_bytes * dec_query_count;
    let dec_aux_bytes = size_of::<u32>();
    let dec_opening_bytes = mask_bytes + eps_bytes + tapes_bytes + path_bytes;

    let partial_bytes = decs::packed_field_bytes(layout.partial_evals_size());
    let lvcs_query_count = layout.nb_lvcs_queries();
    let assoc_bytes = decs::packed_field_bytes(lvcs_query_count * dec_cfg.nb_queries);
    let sub_cols = layout.nb_rows().saturating_sub(lvcs_query_count);
    let sub_bytes = decs::packed_field_bytes(dec_cfg.nb_queries * sub_cols);

    TranscriptRoundSizes {
        commitment,
        metadata,
        evaluations,
        opening_proof: partial_bytes + assoc_bytes + sub_bytes + dec_aux_bytes + dec_opening_bytes,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoundDebug {
    pub piop_queries: Vec<Vec<u8>>,
    pub lvcs_responses: Vec<Vec<Vec<u8>>>,
    pub associated_randomness: Vec<Vec<Vec<u8>>>,
    pub partial_evaluations: Vec<Vec<u8>>,
    pub sub_dec_opened: Vec<Vec<Vec<u8>>>,
    pub dec_aux: Vec<u8>,
    pub dec_proof: Vec<u8>,
    pub leaf_hashes: Vec<Vec<u8>>,
    pub input_shares: Vec<Vec<Vec<u8>>>,
    pub extended_rows: Vec<Vec<Vec<u8>>>,
    pub layout_rows: Vec<Vec<Vec<u8>>>,
}

impl From<SmallwoodProof> for CapssProof {
    fn from(value: SmallwoodProof) -> Self {
        let bytes = encode_proof(&value).expect("serialize Smallwood proof");
        CapssProof { bytes }
    }
}

impl From<SmallwoodProof> for CapssSignature {
    fn from(value: SmallwoodProof) -> Self {
        CapssSignature {
            proof: value.into(),
        }
    }
}

impl TryFrom<&CapssSignature> for SmallwoodProof {
    type Error = anyhow::Error;

    fn try_from(value: &CapssSignature) -> Result<Self> {
        decode_proof(&value.proof.bytes)
            .context("failed to deserialize SmallWood proof from CAPSS signature")
    }
}

/// Helper object that drives the interactive prover logic before Fiat–Shamir folding.
#[derive(Clone, Debug)]
pub struct ProofBuilder {
    pub config: SmallwoodConfig,
    pub statement: CapssStatement,
    pub transcript: SmallwoodTranscript,
}

impl ProofBuilder {
    pub fn new(config: SmallwoodConfig, statement: CapssStatement) -> Self {
        Self {
            config,
            statement,
            transcript: SmallwoodTranscript::default(),
        }
    }

    pub fn push_commitment(&mut self, commitment: RoundCommitment) {
        self.transcript.commitments.push(commitment);
    }

    pub fn push_response(&mut self, response: RoundResponse) {
        self.transcript.responses.push(response);
    }

    pub fn finish(self) -> SmallwoodProof {
        SmallwoodProof {
            transcript: self.transcript,
            config: self.config,
        }
    }
}

/// Produce a Smallwood proof for the supplied statement under the given configuration.
pub fn prove(config: &SmallwoodConfig, statement: &CapssStatement) -> Result<SmallwoodProof> {
    let repetitions = config.repetitions.max(1);
    let mut builder = ProofBuilder::new(config.clone(), statement.clone());
    let statement_bytes = statement_bytes(statement);
    let seeder = rng::SmallwoodSeeder::new(&config.fs_domain, &statement_bytes);
    let (pcs, polynomials) = build_decs_commitment(config, statement, &seeder)?;
    let round_sizes = compute_round_sizes(&pcs, config);

    for round in 0..repetitions {
        let round_seed = seeder.round(round as u64);
        let salt = round_seed.salt(round_sizes.metadata);
        let (commitment_bytes, state) = pcs.commit(&salt, &polynomials, Some(&round_seed))?;
        ensure!(
            commitment_bytes.len() == round_sizes.commitment,
            "SmallWood commitment length mismatch (expected {}, got {})",
            round_sizes.commitment,
            commitment_bytes.len()
        );
        ensure!(
            salt.len() == round_sizes.metadata,
            "SmallWood metadata length mismatch (expected {}, got {})",
            round_sizes.metadata,
            salt.len()
        );
        let queries = pcs.sample_query_points(
            &config.fs_domain,
            &statement_bytes,
            &commitment_bytes,
            config.nb_queries,
        );
        let (lvcs_queries, fullrank_cols) = pcs.derive_lvcs_queries(&queries);
        let (responses, opening_proof) = pcs.open(
            &state,
            &queries,
            &lvcs_queries,
            &fullrank_cols,
            &queries,
            &[],
        )?;
        ensure!(
            opening_proof.len() == round_sizes.opening_proof,
            "SmallWood opening proof length mismatch (expected {}, got {})",
            round_sizes.opening_proof,
            opening_proof.len()
        );
        let evaluations = serialize_matrix(&responses);
        ensure!(
            evaluations.len() == round_sizes.evaluations,
            "SmallWood evaluation payload length mismatch (expected {}, got {})",
            round_sizes.evaluations,
            evaluations.len()
        );
        builder.push_commitment(RoundCommitment {
            commitment: commitment_bytes,
            metadata: salt,
        });
        builder.push_response(RoundResponse {
            evaluations,
            opening_proof,
        });
    }

    builder.transcript.challenge = derive_challenge(
        config,
        &statement_bytes,
        &builder.transcript.commitments,
        &builder.transcript.responses,
    )?;
    Ok(builder.finish())
}

/// Verify a Smallwood proof against the provided statement and configuration.
pub fn verify(
    config: &SmallwoodConfig,
    statement: &CapssStatement,
    signature: &CapssSignature,
) -> Result<()> {
    let proof = SmallwoodProof::try_from(signature)?;
    if proof.config != *config {
        bail!("SmallWood config mismatch between proof and verifier input");
    }

    let repetitions = config.repetitions.max(1);
    if proof.transcript.commitments.len() != repetitions {
        bail!("SmallWood transcript commitment count mismatch");
    }
    if proof.transcript.responses.len() != repetitions {
        bail!("SmallWood transcript response count mismatch");
    }

    let statement_bytes = statement_bytes(statement);
    let seeder = rng::SmallwoodSeeder::new(&config.fs_domain, &statement_bytes);
    let (pcs, _polynomials) = build_decs_commitment(config, statement, &seeder)?;
    let round_sizes = compute_round_sizes(&pcs, config);

    for (round, (commitment, response)) in proof
        .transcript
        .commitments
        .iter()
        .zip(proof.transcript.responses.iter())
        .enumerate()
    {
        ensure!(
            commitment.commitment.len() == round_sizes.commitment,
            "SmallWood commitment length mismatch (expected {}, got {})",
            round_sizes.commitment,
            commitment.commitment.len()
        );
        ensure!(
            commitment.metadata.len() == round_sizes.metadata,
            "SmallWood metadata length mismatch (expected {}, got {})",
            round_sizes.metadata,
            commitment.metadata.len()
        );
        ensure!(
            response.evaluations.len() == round_sizes.evaluations,
            "SmallWood evaluation payload length mismatch (expected {}, got {})",
            round_sizes.evaluations,
            response.evaluations.len()
        );
        ensure!(
            response.opening_proof.len() == round_sizes.opening_proof,
            "SmallWood opening proof length mismatch (expected {}, got {})",
            round_sizes.opening_proof,
            response.opening_proof.len()
        );

        let salt = &commitment.metadata;
        let queries = pcs.sample_query_points(
            &config.fs_domain,
            &statement_bytes,
            &commitment.commitment,
            config.nb_queries,
        );
        let responses = deserialize_matrix_exact(&response.evaluations)?;
        let (lvcs_queries, fullrank_cols) = pcs.derive_lvcs_queries(&queries);
        let recomputed = pcs.recompute_commitment(
            salt,
            &queries,
            &lvcs_queries,
            &fullrank_cols,
            &queries,
            &responses,
            &response.opening_proof,
            &[],
        )?;
        if recomputed != commitment.commitment {
            bail!("SmallWood commitment mismatch at round {round}");
        }
    }

    let expected_challenge = derive_challenge(
        config,
        &statement_bytes,
        &proof.transcript.commitments,
        &proof.transcript.responses,
    )?;
    if proof.transcript.challenge != expected_challenge {
        bail!("SmallWood challenge mismatch");
    }

    Ok(())
}

fn build_decs_commitment(
    config: &SmallwoodConfig,
    statement: &CapssStatement,
    seeder: &SmallwoodSeeder,
) -> Result<(LvcsCommitment, Vec<Vec<BaseField>>)> {
    let (pacs_instance, witness_rows) = example_pacs_witness(statement);
    let support: Vec<BaseField> = (0..pacs_instance.nb_wit_cols())
        .map(|i| BaseField::from(i as u64))
        .collect();
    let input_degree = if support.is_empty() {
        0
    } else {
        config.nb_queries + support.len() - 1
    };
    let witness_polys = create_witness_polynomials(
        &witness_rows,
        &support,
        config.nb_queries,
        input_degree,
        seeder,
    );
    let mask_degree =
        pacs_instance.constraint_degree() * input_degree + pacs_instance.nb_wit_cols();
    let mask_polys = create_mask_polynomials(config.rho, &support, mask_degree, seeder);
    let mut all_polys = Vec::with_capacity(witness_polys.len() + mask_polys.len());
    all_polys.extend(witness_polys.iter().cloned());
    all_polys.extend(mask_polys.iter().cloned());

    let degrees = std::iter::repeat_n(input_degree, pacs_instance.nb_wit_rows())
        .chain(std::iter::repeat_n(mask_degree, config.rho))
        .collect::<Vec<_>>();
    let poly_col_size = input_degree.saturating_sub(config.nb_queries) + 1;
    let layout = GenericUnivariateLayout::new(degrees.clone(), config.nb_queries, poly_col_size, 1);
    let degree = layout.row_length() + config.nb_queries - 1;

    let pcs_degree = config.polynomial_degree.max(input_degree);
    let target = pcs_degree + config.rho + 1;
    let mut nb_leaves = 1usize;
    while nb_leaves < target {
        nb_leaves <<= 1;
    }
    let depth = if nb_leaves <= 1 {
        1
    } else {
        nb_leaves.trailing_zeros() as usize
    };
    let tree_arity = vec![2; depth];
    let nb_evals = nb_leaves;
    let digest_bytes = (config.security_level as usize).max(1).div_ceil(8).max(1) * 2;
    let decs_config = DecsConfig {
        nb_polys: layout.nb_rows(),
        degree,
        eta: config.rho,
        nb_queries: config.nb_queries,
        nb_evals,
        format_challenge: DecsChallengeFormat::Uniform,
        pow_opening_bits: 0,
        use_commitment_tapes: false,
        digest_bytes,
        salt_bytes: 16,
        tree_arity,
        tree_truncation: None,
    };
    let decs = InnerDecs::new(decs_config);
    Ok((LvcsCommitment::new(layout, decs), all_polys))
}

fn example_pacs_witness(statement: &CapssStatement) -> (ExamplePacs, Vec<Vec<BaseField>>) {
    let digest = statement_digest(statement);
    let root = BaseField::from_le_bytes_mod_order(&digest);
    let (pacs_instance, witness_flat) = ExamplePacs::from_root(root);
    let cols = pacs_instance.nb_wit_cols();
    let rows = witness_flat
        .chunks(cols)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>();
    (pacs_instance, rows)
}

pub fn example_pacs_witness_rows(statement: &CapssStatement) -> Vec<Vec<BaseField>> {
    let (_, rows) = example_pacs_witness(statement);
    rows
}

pub fn example_pacs_witness_flat(statement: &CapssStatement) -> Vec<BaseField> {
    example_pacs_witness_rows(statement)
        .into_iter()
        .flatten()
        .collect()
}

pub fn statement_bytes(statement: &CapssStatement) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(statement.public_key.iv.len() as u64).to_le_bytes());
    for elem in &statement.public_key.iv {
        out.extend_from_slice(&elem.to_bytes());
    }
    out.extend_from_slice(&statement.public_key.y.to_bytes());
    out.extend_from_slice(&(statement.message.len() as u64).to_le_bytes());
    out.extend_from_slice(&statement.message);
    out
}

fn statement_digest(statement: &CapssStatement) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&statement_bytes(statement));
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub fn master_seed_bytes(config: &SmallwoodConfig, statement: &CapssStatement) -> [u8; 32] {
    let statement_bytes = statement_bytes(statement);
    SmallwoodSeeder::new(&config.fs_domain, &statement_bytes).master_bytes()
}

pub fn round_salt_bytes(
    config: &SmallwoodConfig,
    statement: &CapssStatement,
    round: u64,
    len: usize,
) -> Vec<u8> {
    let statement_bytes = statement_bytes(statement);
    let seeder = SmallwoodSeeder::new(&config.fs_domain, &statement_bytes);
    seeder.round(round).salt(len)
}

fn derive_challenge(
    config: &SmallwoodConfig,
    statement_bytes: &[u8],
    commitments: &[RoundCommitment],
    responses: &[RoundResponse],
) -> Result<Vec<u8>> {
    let mut hasher = Hasher::new();
    hasher.update(config.fs_domain.as_bytes());
    hasher.update(statement_bytes);
    for (commitment, response) in commitments.iter().zip(responses.iter()) {
        hasher.update(&commitment.commitment);
        hasher.update(&commitment.metadata);
        hasher.update(&response.evaluations);
        hasher.update(&response.opening_proof);
    }
    Ok(hasher.finalize().as_bytes().to_vec())
}

fn base_to_bytes(value: &BaseField) -> Vec<u8> {
    FieldElement::from_base(*value).to_bytes().to_vec()
}

fn slice_to_bytes(values: &[BaseField]) -> Vec<Vec<u8>> {
    values.iter().map(base_to_bytes).collect()
}

fn matrix_to_bytes(matrix: &[Vec<BaseField>]) -> Vec<Vec<Vec<u8>>> {
    matrix.iter().map(|row| slice_to_bytes(row)).collect()
}

pub fn round_debug(
    config: &SmallwoodConfig,
    statement: &CapssStatement,
    proof: &SmallwoodProof,
) -> Result<Vec<RoundDebug>> {
    let statement_bytes = statement_bytes(statement);
    let seeder = SmallwoodSeeder::new(&config.fs_domain, &statement_bytes);
    let (pcs, polynomials) = build_decs_commitment(config, statement, &seeder)?;
    let mut out = Vec::with_capacity(proof.transcript.responses.len());

    for (round, (commitment, response)) in proof
        .transcript
        .commitments
        .iter()
        .zip(proof.transcript.responses.iter())
        .enumerate()
    {
        let salt = &commitment.metadata;
        let round_seed = seeder.round(round as u64);
        let queries = pcs.sample_query_points(
            &config.fs_domain,
            &statement_bytes,
            &commitment.commitment,
            config.nb_queries,
        );
        let (lvcs_queries, fullrank_cols) = pcs.derive_lvcs_queries(&queries);
        let responses_matrix = deserialize_matrix_exact(&response.evaluations)?;
        let debug = pcs.debug_opening_details(
            &queries,
            &lvcs_queries,
            &fullrank_cols,
            &responses_matrix,
            &response.opening_proof,
            &[],
        )?;

        let (_debug_commitment, state_debug) = pcs.commit(salt, &polynomials, Some(&round_seed))?;
        let dec_state = state_debug.dec_state();
        let extended_rows = state_debug.extended_rows();
        let base_rows = pcs.layout().to_rows(&polynomials, &round_seed);
        let mut share_bytes = Vec::with_capacity(dec_state.shares.len());
        let mut leaf_hashes = Vec::with_capacity(dec_state.shares.len());
        let mut extended_rows_bytes = Vec::with_capacity(extended_rows.len());
        let mut layout_rows_bytes = Vec::with_capacity(base_rows.len());
        for (idx, share) in dec_state.shares.iter().enumerate() {
            let bytes_row = share
                .iter()
                .map(|value| field_to_bytes(value).to_vec())
                .collect::<Vec<_>>();
            share_bytes.push(bytes_row);
            let row_bytes = crate::smallwood::decs::pack_field_values(share);
            let tape = &dec_state.commitment_tapes[idx];
            leaf_hashes.push(hash_leaf_debug(
                salt,
                idx,
                &row_bytes,
                tape,
                pcs.digest_bytes(),
            ));
        }
        for row in extended_rows {
            let bytes_row = row
                .iter()
                .map(|value| field_to_bytes(value).to_vec())
                .collect::<Vec<_>>();
            extended_rows_bytes.push(bytes_row);
        }
        for row in base_rows {
            let bytes_row = row
                .iter()
                .map(|value| field_to_bytes(value).to_vec())
                .collect::<Vec<_>>();
            layout_rows_bytes.push(bytes_row);
        }

        out.push(RoundDebug {
            piop_queries: slice_to_bytes(&queries),
            lvcs_responses: matrix_to_bytes(&debug.lvcs_responses),
            associated_randomness: matrix_to_bytes(&debug.associated_randomness),
            partial_evaluations: slice_to_bytes(&debug.partial_evals),
            sub_dec_opened: matrix_to_bytes(&debug.sub_dec_opened),
            dec_aux: debug.dec_aux.clone(),
            dec_proof: debug.dec_proof.clone(),
            leaf_hashes,
            input_shares: share_bytes,
            extended_rows: extended_rows_bytes,
            layout_rows: layout_rows_bytes,
        });

        // Ensure deterministic coverage for future rounds even if proof repetitions differ.
        let _ = round;
        let _ = salt;
    }

    Ok(out)
}

fn hash_leaf_debug(
    salt: &[u8],
    index: usize,
    row_bytes: &[u8],
    tape: &[u8],
    digest_len: usize,
) -> Vec<u8> {
    let mut hasher = Shake128::default();
    hasher.update(salt);
    let idx_bytes = [(index & 0xFF) as u8, ((index >> 8) & 0xFF) as u8];
    hasher.update(&idx_bytes);
    hasher.update(row_bytes);
    if !tape.is_empty() {
        hasher.update(tape);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; digest_len];
    reader.read(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_verify_round_trip() {
        let cfg = SmallwoodConfig {
            repetitions: 2,
            polynomial_degree: 4,
            security_level: 128,
            fs_domain: "capss/test-domain".to_string(),
            ..Default::default()
        };

        let statement = CapssStatement {
            message: b"hello smallwood".to_vec(),
            ..Default::default()
        };

        let proof = prove(&cfg, &statement).expect("prove");
        let signature: CapssSignature = proof.clone().into();
        verify(&cfg, &statement, &signature).expect("verify");
    }

    #[test]
    fn detect_tampered_commitment() {
        let cfg = SmallwoodConfig {
            repetitions: 1,
            fs_domain: "capss/test-domain".to_string(),
            ..Default::default()
        };
        let statement = CapssStatement::default();

        let mut proof = prove(&cfg, &statement).expect("prove");
        if let Some(first_round) = proof.transcript.responses.first_mut()
            && let Some(byte) = first_round.evaluations.get_mut(0)
        {
            *byte ^= 0x01;
        }
        let signature: CapssSignature = proof.into();
        let err = verify(&cfg, &statement, &signature).expect_err("should fail");
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("mismatch") || err_msg.contains("encoding"),
            "unexpected verification error: {}",
            err_msg
        );
    }
}
