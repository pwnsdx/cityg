use anyhow::{Result, anyhow};
use ark_ff::{One, PrimeField, Zero};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::field::BaseField;

use super::{
    PolynomialCommitment,
    decs::{DecsCommitment, DecsConfig, DecsState, pack_field_values, unpack_field_values},
    layout::GenericUnivariateLayout,
    linear,
    polynomial::{self, eval as eval_poly},
    rng::RoundSeeder,
};

pub struct LvcsCommitment {
    layout: GenericUnivariateLayout,
    decs: DecsCommitment,
}

pub struct LvcsState {
    dec_state: DecsState,
    extended_rows: Vec<Vec<BaseField>>,
}

impl LvcsState {
    pub fn dec_state(&self) -> &DecsState {
        &self.dec_state
    }

    pub fn extended_rows(&self) -> &[Vec<BaseField>] {
        &self.extended_rows
    }
}

struct OpeningSegments {
    partial_evals: Vec<BaseField>,
    associated_rnd: Vec<Vec<BaseField>>,
    sub_dec_opened: Vec<Vec<BaseField>>,
    dec_aux: Vec<u8>,
    dec_proof: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct LvcsOpeningDebug {
    pub partial_evals: Vec<BaseField>,
    pub lvcs_responses: Vec<Vec<BaseField>>,
    pub associated_randomness: Vec<Vec<BaseField>>,
    pub sub_dec_opened: Vec<Vec<BaseField>>,
    pub dec_queries: Vec<BaseField>,
    pub dec_opened_values: Vec<Vec<BaseField>>,
    pub dec_aux: Vec<u8>,
    pub dec_proof: Vec<u8>,
}

impl LvcsCommitment {
    pub fn new(layout: GenericUnivariateLayout, decs: DecsCommitment) -> Self {
        Self { layout, decs }
    }

    pub fn decs_config(&self) -> &DecsConfig {
        &self.decs.config
    }

    pub(crate) fn digest_bytes(&self) -> usize {
        self.decs.config.digest_bytes
    }

    pub(crate) fn layout(&self) -> &GenericUnivariateLayout {
        &self.layout
    }

    pub fn sample_query_points(
        &self,
        fs_domain: &str,
        statement_bytes: &[u8],
        commitment: &[u8],
        nb_queries: usize,
    ) -> Vec<BaseField> {
        self.decs
            .sample_query_points(fs_domain, statement_bytes, commitment, nb_queries)
    }

    pub fn derive_lvcs_queries(
        &self,
        piop_queries: &[BaseField],
    ) -> (Vec<Vec<BaseField>>, Vec<usize>) {
        self.layout.to_lvcs_queries(piop_queries)
    }

    fn extend_rows(
        &self,
        rows: &[Vec<BaseField>],
        round_seeder: &RoundSeeder,
    ) -> Vec<Vec<BaseField>> {
        rows.iter()
            .enumerate()
            .map(|(idx, row)| {
                let mut extended = row.clone();
                extended.extend(self.sample_extended_values(idx, round_seeder));
                extended
            })
            .collect()
    }

    fn sample_extended_values(&self, row_idx: usize, round_seeder: &RoundSeeder) -> Vec<BaseField> {
        let extra = self.decs.config.nb_queries;
        if extra == 0 {
            return Vec::new();
        }
        let context = row_idx.to_le_bytes();
        let branch = round_seeder.branch(b"lvcs/extended", &context);
        (0..extra)
            .map(|pos| branch.field(b"lvcs/extended/value", &(pos as u64).to_le_bytes()))
            .collect()
    }

    fn interpolation_points(&self) -> Vec<BaseField> {
        let total = self.layout.row_length() + self.decs.config.nb_queries;
        (0..total)
            .map(|i| {
                if i == 0 {
                    BaseField::zero()
                } else {
                    -BaseField::from(i as u64)
                }
            })
            .collect()
    }

    fn hash_challenge_opening_decs(
        &self,
        binding: &[u8],
        lvcs_responses: &[Vec<BaseField>],
        associated_rnd: &[Vec<BaseField>],
    ) -> Vec<u8> {
        let mut hasher = Shake128::default();
        hasher.update(binding);
        for response in lvcs_responses {
            hasher.update(&pack_field_values(response));
        }
        for rnd in associated_rnd {
            hasher.update(&pack_field_values(rnd));
        }
        let mut digest = vec![0u8; self.decs.config.digest_bytes];
        hasher.finalize_xof().read(&mut digest);
        digest
    }

    fn decode_opening_segments(
        &self,
        opening_proof: &[u8],
        lvcs_queries_len: usize,
        fullrank_cols_len: usize,
        nb_rows: usize,
    ) -> Result<OpeningSegments> {
        let bits_per = BaseField::MODULUS_BIT_SIZE as usize;

        let partial_count = self.layout.partial_evals_size();
        let partial_bytes = (partial_count * bits_per).div_ceil(8);
        if opening_proof.len() < partial_bytes {
            return Err(anyhow!("partial eval segment truncated"));
        }
        let partial_evals = unpack_field_values(&opening_proof[..partial_bytes], partial_count)?;
        let mut cursor = &opening_proof[partial_bytes..];

        let assoc_rows = lvcs_queries_len;
        let assoc_cols = self.decs.config.nb_queries;
        let assoc_count = assoc_rows * assoc_cols;
        let assoc_bytes = (assoc_count * bits_per).div_ceil(8);
        if cursor.len() < assoc_bytes {
            return Err(anyhow!("associated randomness segment truncated"));
        }
        let assoc_flat = unpack_field_values(&cursor[..assoc_bytes], assoc_count)?;
        cursor = &cursor[assoc_bytes..];
        let mut associated_rnd = Vec::with_capacity(assoc_rows);
        for chunk in assoc_flat.chunks(assoc_cols) {
            associated_rnd.push(chunk.to_vec());
        }
        if associated_rnd.len() != assoc_rows
            || associated_rnd.first().map_or(0, |row| row.len()) != assoc_cols
        {
            return Err(anyhow!("associated randomness shape mismatch"));
        }

        let sub_rows = self.decs.config.nb_queries;
        let sub_cols = nb_rows.saturating_sub(fullrank_cols_len);
        let sub_count = sub_rows * sub_cols;
        let sub_bytes = (sub_count * bits_per).div_ceil(8);
        if cursor.len() < sub_bytes {
            return Err(anyhow!("LVCS sub segment truncated"));
        }
        let sub_flat = unpack_field_values(&cursor[..sub_bytes], sub_count)?;
        cursor = &cursor[sub_bytes..];
        let mut sub_dec_opened = Vec::with_capacity(sub_rows);
        for chunk in sub_flat.chunks(sub_cols) {
            sub_dec_opened.push(chunk.to_vec());
        }
        if sub_dec_opened.len() != sub_rows
            || sub_dec_opened.first().map_or(0, |row| row.len()) != sub_cols
        {
            return Err(anyhow!("LVCS sub decoded values shape mismatch"));
        }

        if cursor.len() < std::mem::size_of::<u32>() {
            return Err(anyhow!("DEC aux truncated"));
        }
        let (dec_aux, dec_proof) = cursor.split_at(std::mem::size_of::<u32>());

        Ok(OpeningSegments {
            partial_evals,
            associated_rnd,
            sub_dec_opened,
            dec_aux: dec_aux.to_vec(),
            dec_proof: dec_proof.to_vec(),
        })
    }

    pub(crate) fn debug_opening_details(
        &self,
        piop_queries: &[BaseField],
        lvcs_queries: &[Vec<BaseField>],
        fullrank_cols: &[usize],
        responses: &[Vec<BaseField>],
        opening_proof: &[u8],
        binding: &[u8],
    ) -> Result<LvcsOpeningDebug> {
        let nb_rows = self.layout.nb_rows();
        let segments = self.decode_opening_segments(
            opening_proof,
            lvcs_queries.len(),
            fullrank_cols.len(),
            nb_rows,
        )?;

        let lvcs_responses =
            self.layout
                .to_lvcs_responses(piop_queries, responses, &segments.partial_evals)?;

        let binding_bytes =
            self.hash_challenge_opening_decs(binding, &lvcs_responses, &segments.associated_rnd);
        let dec_queries = self
            .decs
            .recompute_random_opening(&segments.dec_aux, &binding_bytes)?;

        let dec_opened_values = self.restore_dec_opened_values(
            lvcs_queries,
            fullrank_cols,
            &segments.associated_rnd,
            &segments.sub_dec_opened,
            &lvcs_responses,
            &dec_queries,
        )?;

        Ok(LvcsOpeningDebug {
            partial_evals: segments.partial_evals,
            lvcs_responses,
            associated_randomness: segments.associated_rnd,
            sub_dec_opened: segments.sub_dec_opened,
            dec_queries,
            dec_opened_values,
            dec_aux: segments.dec_aux,
            dec_proof: segments.dec_proof,
        })
    }
}

impl PolynomialCommitment for LvcsCommitment {
    type State = LvcsState;

    fn commit(
        &self,
        salt: &[u8],
        polynomials: &[Vec<BaseField>],
        round_seeder: Option<&RoundSeeder>,
    ) -> Result<(Vec<u8>, Self::State)> {
        let seeder =
            round_seeder.ok_or_else(|| anyhow!("lvcs commitment requires round seeder"))?;
        let rows = self.layout.to_rows(polynomials, seeder);
        let extended_rows = self.extend_rows(&rows, seeder);
        let interpolation_points = self.interpolation_points();
        let interpolated = extended_rows
            .iter()
            .map(|row| interpolate_row(row, &interpolation_points))
            .collect::<Vec<_>>();
        let (commitment, dec_state) = self.decs.commit(salt, &interpolated, round_seeder)?;
        Ok((
            commitment,
            LvcsState {
                dec_state,
                extended_rows,
            },
        ))
    }

    fn open(
        &self,
        state: &Self::State,
        piop_queries: &[BaseField],
        lvcs_queries: &[Vec<BaseField>],
        fullrank_cols: &[usize],
        _decs_queries: &[BaseField],
        binding: &[u8],
    ) -> Result<(Vec<Vec<BaseField>>, Vec<u8>)> {
        let nb_queries = lvcs_queries.len();
        let row_length = self.layout.row_length();
        let dec_nb_queries = self.decs.config.nb_queries;

        let mut lvcs_responses = Vec::with_capacity(nb_queries);
        let mut associated_rnd = Vec::with_capacity(nb_queries);
        for query in lvcs_queries.iter() {
            let mut extended = vec![BaseField::zero(); row_length + dec_nb_queries];
            for (coeff, row) in query.iter().zip(state.extended_rows.iter()) {
                for (idx, value) in row.iter().enumerate() {
                    extended[idx] += *coeff * *value;
                }
            }
            let (resp, rnd) = extended.split_at(row_length);
            lvcs_responses.push(resp.to_vec());
            associated_rnd.push(rnd.to_vec());
        }

        let binding_bytes =
            self.hash_challenge_opening_decs(binding, &lvcs_responses, &associated_rnd);
        let (dec_queries, dec_aux) = self.decs.get_random_opening(&binding_bytes);
        let (dec_opened_values, dec_proof) = self.decs.open(&state.dec_state, &dec_queries)?;
        let sub_dec_opened = strip_fullrank_columns(&dec_opened_values, fullrank_cols);

        let (iop_responses, partial_evals) =
            self.layout.to_iop_responses(piop_queries, &lvcs_responses);

        let mut proof_bytes = Vec::new();
        proof_bytes.extend(pack_field_values(&partial_evals));
        let assoc_flat: Vec<BaseField> = associated_rnd.iter().flatten().cloned().collect();
        proof_bytes.extend(pack_field_values(&assoc_flat));
        let sub_flat: Vec<BaseField> = sub_dec_opened.iter().flatten().cloned().collect();
        proof_bytes.extend(pack_field_values(&sub_flat));
        proof_bytes.extend_from_slice(&dec_aux);
        proof_bytes.extend_from_slice(&dec_proof);

        Ok((iop_responses, proof_bytes))
    }

    fn recompute_commitment(
        &self,
        salt: &[u8],
        piop_queries: &[BaseField],
        lvcs_queries: &[Vec<BaseField>],
        fullrank_cols: &[usize],
        _decs_queries: &[BaseField],
        responses: &[Vec<BaseField>],
        opening_proof: &[u8],
        binding: &[u8],
    ) -> Result<Vec<u8>> {
        let details = self.debug_opening_details(
            piop_queries,
            lvcs_queries,
            fullrank_cols,
            responses,
            opening_proof,
            binding,
        )?;

        self.decs.recompute_commitment(
            salt,
            &details.dec_queries,
            &details.dec_opened_values,
            &details.dec_proof,
        )
    }
}

impl LvcsCommitment {
    fn restore_dec_opened_values(
        &self,
        lvcs_queries: &[Vec<BaseField>],
        fullrank_cols: &[usize],
        associated_rnd: &[Vec<BaseField>],
        sub_dec_opened: &[Vec<BaseField>],
        lvcs_responses: &[Vec<BaseField>],
        dec_queries: &[BaseField],
    ) -> Result<Vec<Vec<BaseField>>> {
        let nb_queries = lvcs_responses.len();
        if lvcs_queries.len() != nb_queries || associated_rnd.len() != nb_queries {
            return Err(anyhow!("inconsistent query/response counts"));
        }

        let dec_nb_queries = self.decs.config.nb_queries;
        let nb_rows = self.layout.nb_rows();

        let interpolation_points = self.interpolation_points();
        let polys = lvcs_responses
            .iter()
            .zip(associated_rnd.iter())
            .map(|(resp, rnd)| {
                let mut extended = resp.clone();
                extended.extend(rnd.clone());
                interpolate_row(&extended, &interpolation_points)
            })
            .collect::<Vec<_>>();

        let mut v_values = Vec::with_capacity(dec_nb_queries);
        for query in dec_queries {
            let mut row = Vec::with_capacity(nb_queries);
            for poly in &polys {
                row.push(eval_poly(poly, *query));
            }
            v_values.push(row);
        }

        let coeffs_part1 = build_coeffs_part1(lvcs_queries, fullrank_cols, nb_rows)?;
        let coeffs_part2 = build_coeffs_part2(lvcs_queries, fullrank_cols, nb_rows)?;
        let coeffs_part1_inv = invert_matrix(&coeffs_part1)?;

        let mut dec_opened = Vec::with_capacity(dec_nb_queries);
        for (row_idx, sub_row) in sub_dec_opened.iter().enumerate() {
            let pivot = solve_pivot_values(
                &coeffs_part1_inv,
                &coeffs_part2,
                &v_values[row_idx],
                sub_row,
            );
            dec_opened.push(merge_columns(&pivot, sub_row, fullrank_cols, nb_rows));
        }

        Ok(dec_opened)
    }
}

fn interpolate_row(values: &[BaseField], points: &[BaseField]) -> Vec<BaseField> {
    let relations = values
        .iter()
        .zip(points.iter())
        .map(|(value, point)| (*value, vec![*point]))
        .collect::<Vec<_>>();
    polynomial::restore_only_from_relation(&relations, values.len() - 1)
}

fn strip_fullrank_columns(
    dec_opened_values: &[Vec<BaseField>],
    fullrank_cols: &[usize],
) -> Vec<Vec<BaseField>> {
    let total_cols = dec_opened_values.first().map_or(0, |row| row.len());
    dec_opened_values
        .iter()
        .map(|row| {
            let mut out = Vec::with_capacity(total_cols.saturating_sub(fullrank_cols.len()));
            let mut pivot_iter = fullrank_cols.iter().copied().peekable();
            for (idx, value) in row.iter().enumerate() {
                if matches!(pivot_iter.peek(), Some(&col) if col == idx) {
                    pivot_iter.next();
                } else {
                    out.push(*value);
                }
            }
            out
        })
        .collect()
}

fn build_coeffs_part1(
    lvcs_queries: &[Vec<BaseField>],
    fullrank_cols: &[usize],
    nb_rows: usize,
) -> Result<Vec<Vec<BaseField>>> {
    let nb_queries = lvcs_queries.len();
    if fullrank_cols.len() != nb_queries {
        return Err(anyhow!("unsupported beta configuration"));
    }
    let mut matrix = vec![vec![BaseField::zero(); nb_queries]; nb_queries];
    for (row_idx, query) in lvcs_queries.iter().enumerate() {
        let mut pivot_iter = fullrank_cols.iter().copied().peekable();
        let mut pivot_pos = 0;
        for (col_idx, coeff) in query.iter().enumerate().take(nb_rows) {
            if matches!(pivot_iter.peek(), Some(&pivot) if pivot == col_idx) {
                matrix[row_idx][pivot_pos] = *coeff;
                pivot_pos += 1;
                pivot_iter.next();
            }
        }
    }
    Ok(matrix)
}

fn build_coeffs_part2(
    lvcs_queries: &[Vec<BaseField>],
    fullrank_cols: &[usize],
    nb_rows: usize,
) -> Result<Vec<Vec<BaseField>>> {
    let nb_queries = lvcs_queries.len();
    let remainder = nb_rows.saturating_sub(fullrank_cols.len());
    let mut matrix = vec![vec![BaseField::zero(); remainder]; nb_queries];
    for (row_idx, query) in lvcs_queries.iter().enumerate() {
        let mut pivot_iter = fullrank_cols.iter().copied().peekable();
        let mut remainder_idx = 0;
        for (col_idx, coeff) in query.iter().enumerate().take(nb_rows) {
            if matches!(pivot_iter.peek(), Some(&pivot) if pivot == col_idx) {
                pivot_iter.next();
            } else {
                matrix[row_idx][remainder_idx] = *coeff;
                remainder_idx += 1;
            }
        }
    }
    Ok(matrix)
}

fn solve_pivot_values(
    coeffs_part1_inv: &[Vec<BaseField>],
    coeffs_part2: &[Vec<BaseField>],
    v_row: &[BaseField],
    sub_row: &[BaseField],
) -> Vec<BaseField> {
    let part2_mul = mat_vec_mul(coeffs_part2, sub_row);
    let mut rhs = Vec::with_capacity(v_row.len());
    for (a, b) in v_row.iter().zip(part2_mul.iter()) {
        rhs.push(*a - *b);
    }
    mat_vec_mul(coeffs_part1_inv, &rhs)
}

fn mat_vec_mul(matrix: &[Vec<BaseField>], vector: &[BaseField]) -> Vec<BaseField> {
    matrix
        .iter()
        .map(|row| {
            row.iter()
                .zip(vector.iter())
                .fold(BaseField::zero(), |acc, (a, b)| acc + *a * *b)
        })
        .collect()
}

fn merge_columns(
    pivot: &[BaseField],
    remainder: &[BaseField],
    fullrank_cols: &[usize],
    total_cols: usize,
) -> Vec<BaseField> {
    let mut out = vec![BaseField::zero(); total_cols];
    let mut pivot_iter = pivot.iter();
    let mut remainder_iter = remainder.iter();
    let mut next_pivot = fullrank_cols.iter().copied().peekable();
    for (idx, slot) in out.iter_mut().enumerate() {
        if matches!(next_pivot.peek(), Some(&col) if col == idx) {
            *slot = *pivot_iter.next().expect("pivot length mismatch");
            next_pivot.next();
        } else {
            *slot = *remainder_iter.next().expect("remainder length mismatch");
        }
    }
    out
}

fn invert_matrix(matrix: &[Vec<BaseField>]) -> Result<Vec<Vec<BaseField>>> {
    let n = matrix.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    for row in matrix {
        if row.len() != n {
            return Err(anyhow!("matrix not square"));
        }
    }

    let base = matrix.to_vec();
    let mut columns = Vec::with_capacity(n);
    for col in 0..n {
        let mut rhs = vec![BaseField::zero(); n];
        rhs[col] = BaseField::one();
        let solution = linear::solve_linear_system(base.clone(), rhs)
            .map_err(|_| anyhow!("matrix not invertible"))?;
        columns.push(solution);
    }

    let mut inverse = vec![vec![BaseField::zero(); n]; n];
    for (col_idx, column) in columns.into_iter().enumerate() {
        for (row_idx, value) in column.into_iter().enumerate() {
            inverse[row_idx][col_idx] = value;
        }
    }
    Ok(inverse)
}
