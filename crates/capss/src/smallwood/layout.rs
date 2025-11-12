use crate::field::BaseField;
use anyhow::{Result, anyhow};
use ark_ff::{Field, Zero};

use super::rng::RoundSeeder;

fn shift_poly(coeffs: &mut [BaseField], shift: usize) {
    if shift == 0 {
        return;
    }
    let len = coeffs.len();
    for idx in (0..len).rev() {
        if idx >= shift {
            coeffs[idx] = coeffs[idx - shift];
        } else {
            coeffs[idx] = BaseField::zero();
        }
    }
}

fn add_shifted(target: &mut [BaseField], values: &[BaseField], shift: usize) {
    for (idx, value) in values.iter().enumerate() {
        let pos = idx + shift;
        if pos < target.len() {
            target[pos] += *value;
        }
    }
}

#[derive(Clone, Debug)]
pub struct GenericUnivariateLayout {
    degrees: Vec<usize>,
    nb_queries: usize,
    poly_col_size: usize,
    beta: usize,
    split_factors: Vec<usize>,
    unstacked_row_length: usize,
    unstacked_nb_rows: usize,
    row_length: usize,
    nb_rows: usize,
}

impl GenericUnivariateLayout {
    pub fn new(degrees: Vec<usize>, nb_queries: usize, poly_col_size: usize, beta: usize) -> Self {
        assert_ne!(beta, 0);
        let split_factors = degrees
            .iter()
            .map(|deg| {
                let numerator = deg + 1 - nb_queries;
                if numerator == 0 {
                    1
                } else {
                    numerator.div_ceil(poly_col_size)
                }
            })
            .collect::<Vec<_>>();
        let unstacked_row_length = split_factors.iter().copied().sum::<usize>();
        let unstacked_nb_rows = poly_col_size + nb_queries;
        let row_length = unstacked_row_length.div_ceil(beta).max(1);
        let nb_rows = beta * unstacked_nb_rows;
        Self {
            degrees,
            nb_queries,
            poly_col_size,
            beta,
            split_factors,
            unstacked_row_length,
            unstacked_nb_rows,
            row_length,
            nb_rows,
        }
    }

    pub fn row_length(&self) -> usize {
        self.row_length
    }

    pub fn nb_rows(&self) -> usize {
        self.nb_rows
    }

    pub fn nb_polys(&self) -> usize {
        self.degrees.len()
    }

    pub fn nb_lvcs_queries(&self) -> usize {
        self.nb_queries * self.beta
    }

    pub fn to_rows(
        &self,
        polynomials: &[Vec<BaseField>],
        seeder: &RoundSeeder,
    ) -> Vec<Vec<BaseField>> {
        assert_eq!(polynomials.len(), self.nb_polys());
        let mut unit_polys = Vec::with_capacity(self.unstacked_row_length);
        for (poly_idx, poly) in polynomials.iter().enumerate() {
            let mut remaining = poly.clone();
            remaining.resize(self.unstacked_nb_rows, BaseField::zero());
            let split_factor = self.split_factors[poly_idx];
            let mut previous_leading: Option<Vec<BaseField>> = None;
            for chunk_idx in 0..split_factor {
                let mut unit_poly = vec![BaseField::zero(); self.unstacked_nb_rows];
                if chunk_idx < split_factor - 1 {
                    for (idx, slot) in unit_poly.iter_mut().enumerate().take(self.poly_col_size) {
                        *slot = *remaining.get(idx).unwrap_or(&BaseField::zero());
                    }
                    remaining = remaining
                        .iter()
                        .skip(self.poly_col_size)
                        .cloned()
                        .collect::<Vec<_>>();
                    if let Some(prev) = &previous_leading {
                        for (slot, coeff) in unit_poly.iter_mut().zip(prev.iter()) {
                            *slot -= *coeff;
                        }
                    }
                    let leading = self.sample_leading(poly_idx, chunk_idx, seeder);
                    add_shifted(&mut unit_poly, &leading, self.poly_col_size);
                    previous_leading = Some(leading);
                } else {
                    let last = remaining.clone();
                    let last_degree = self.degrees[poly_idx]
                        - (self.split_factors[poly_idx] - 1) * self.poly_col_size;
                    for (idx, slot) in unit_poly.iter_mut().enumerate().take(last_degree + 1) {
                        *slot = *last.get(idx).unwrap_or(&BaseField::zero());
                    }
                    if let Some(prev) = &previous_leading {
                        for (slot, coeff) in unit_poly.iter_mut().zip(prev.iter()) {
                            *slot -= *coeff;
                        }
                    }
                    let shift = self.unstacked_nb_rows - 1 - last_degree;
                    shift_poly(&mut unit_poly, shift);
                }
                unit_polys.push(unit_poly);
            }
        }

        let mut unstacked_rows =
            vec![vec![BaseField::zero(); self.unstacked_row_length]; self.unstacked_nb_rows];
        for (col_idx, unit_poly) in unit_polys.iter().enumerate() {
            for (row_idx, row) in unstacked_rows.iter_mut().enumerate() {
                row[col_idx] = unit_poly[row_idx];
            }
        }

        let mut rows = vec![vec![BaseField::zero(); self.row_length]; self.nb_rows];
        for unstacked_col in 0..self.unstacked_row_length {
            let block = unstacked_col / self.row_length;
            let col = unstacked_col % self.row_length;
            for (row_idx, unstacked_row) in unstacked_rows.iter().enumerate() {
                let dest_row = block * self.unstacked_nb_rows + row_idx;
                rows[dest_row][col] = unstacked_row[unstacked_col];
            }
        }
        rows
    }

    pub fn split_factors(&self) -> &[usize] {
        &self.split_factors
    }

    pub fn partial_evals_size(&self) -> usize {
        let per_poly: usize = self.split_factors.iter().map(|sf| sf - 1).sum();
        per_poly * self.nb_queries
    }

    pub fn to_iop_responses(
        &self,
        queries: &[BaseField],
        lvcs_responses: &[Vec<BaseField>],
    ) -> (Vec<Vec<BaseField>>, Vec<BaseField>) {
        assert_eq!(queries.len(), self.nb_queries);
        assert_eq!(lvcs_responses.len(), self.nb_lvcs_queries());

        let exponents = self.exponents();
        let mut partial_evals = Vec::with_capacity(self.partial_evals_size());
        let mut iop_responses = Vec::with_capacity(self.nb_queries);

        for query_idx in 0..self.nb_queries {
            let mut concatenated = Vec::with_capacity(self.row_length * self.beta);
            for k in 0..self.beta {
                concatenated.extend_from_slice(&lvcs_responses[query_idx * self.beta + k]);
            }
            // Trim to the unstacked portion and assert trailing zeros.
            let unstacked = concatenated[..self.unstacked_row_length].to_vec();
            if cfg!(debug_assertions) {
                for value in concatenated[self.unstacked_row_length..].iter() {
                    debug_assert!(value.is_zero());
                }
            }

            let mut iop_row = Vec::with_capacity(self.nb_polys());
            let mut offset = 0;
            for (poly_idx, split) in self.split_factors.iter().enumerate() {
                let chunk = &unstacked[offset..offset + split];
                offset += split;
                let mut value = BaseField::zero();
                for (k, coeff) in chunk.iter().enumerate() {
                    value += *coeff * queries[query_idx].pow([exponents[poly_idx][k] as u64]);
                }
                iop_row.push(value);
                if *split > 1 {
                    partial_evals.extend_from_slice(&chunk[1..]);
                }
            }
            iop_responses.push(iop_row);
        }

        (iop_responses, partial_evals)
    }

    pub fn to_lvcs_responses(
        &self,
        queries: &[BaseField],
        iop_responses: &[Vec<BaseField>],
        partial_evals: &[BaseField],
    ) -> Result<Vec<Vec<BaseField>>> {
        assert_eq!(queries.len(), self.nb_queries);
        assert_eq!(iop_responses.len(), self.nb_queries);

        let exponents = self.exponents();
        let expected_partials = self.partial_evals_size();
        if partial_evals.len() != expected_partials {
            return Err(anyhow!(
                "partial eval size mismatch (got {}, expected {})",
                partial_evals.len(),
                expected_partials
            ));
        }

        let mut partial_iter = partial_evals.iter();
        let mut lvcs_responses = Vec::with_capacity(self.nb_lvcs_queries());

        for query_idx in 0..self.nb_queries {
            let mut unstacked = Vec::with_capacity(self.unstacked_row_length);
            for (poly_idx, split) in self.split_factors.iter().enumerate() {
                let mut value = iop_responses[query_idx][poly_idx];
                let mut extras = Vec::with_capacity(split.saturating_sub(1));
                for exponent in exponents[poly_idx].iter().take(*split).skip(1) {
                    let coeff = *partial_iter
                        .next()
                        .ok_or_else(|| anyhow!("partial eval underflow"))?;
                    value -= coeff * queries[query_idx].pow([*exponent as u64]);
                    extras.push(coeff);
                }
                unstacked.push(value);
                unstacked.extend(extras);
            }

            // Pad with zeros to align with row layout and split across beta blocks.
            let mut padded = unstacked;
            padded.extend(std::iter::repeat_n(
                BaseField::zero(),
                self.row_length * self.beta - padded.len(),
            ));
            for k in 0..self.beta {
                let start = k * self.row_length;
                lvcs_responses.push(padded[start..start + self.row_length].to_vec());
            }
        }

        if partial_iter.next().is_some() {
            return Err(anyhow!("partial eval trailing data"));
        }

        Ok(lvcs_responses)
    }

    pub fn exponents(&self) -> Vec<Vec<usize>> {
        let mut exponents = vec![Vec::new(); self.nb_polys()];
        for (poly_idx, split) in self.split_factors.iter().enumerate() {
            let mut poly_exponents = Vec::with_capacity(*split);
            for k in 0..*split {
                if k < split - 1 {
                    poly_exponents.push(k * self.poly_col_size);
                } else {
                    let last_degree = self.degrees[poly_idx]
                        - (self.split_factors[poly_idx] - 1) * self.poly_col_size;
                    poly_exponents.push(
                        (self.split_factors[poly_idx] - 1) * self.poly_col_size
                            - (self.unstacked_nb_rows - 1 - last_degree),
                    );
                }
            }
            exponents[poly_idx] = poly_exponents;
        }
        exponents
    }

    pub fn to_lvcs_queries(&self, queries: &[BaseField]) -> (Vec<Vec<BaseField>>, Vec<usize>) {
        assert_eq!(queries.len(), self.nb_queries);
        let mut lvcs_queries = Vec::with_capacity(self.nb_lvcs_queries());
        for query in queries {
            let mut powers = Vec::with_capacity(self.unstacked_nb_rows);
            for exp in 0..self.unstacked_nb_rows {
                powers.push(query.pow([exp as u64]));
            }
            for k in 0..self.beta {
                let mut vec = vec![BaseField::zero(); self.nb_rows];
                let offset = k * self.unstacked_nb_rows;
                for (idx, value) in powers.iter().enumerate() {
                    vec[offset + idx] = *value;
                }
                lvcs_queries.push(vec);
            }
        }
        let mut fullrank_cols = Vec::with_capacity(self.nb_queries * self.beta);
        for k in 0..self.beta {
            for j in 0..self.nb_queries {
                fullrank_cols.push(k * self.unstacked_nb_rows + j);
            }
        }
        (lvcs_queries, fullrank_cols)
    }

    fn sample_leading(
        &self,
        poly_idx: usize,
        chunk_idx: usize,
        seeder: &RoundSeeder,
    ) -> Vec<BaseField> {
        if self.nb_queries == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(self.nb_queries);
        let mut context = Vec::with_capacity(16);
        context.extend_from_slice(&(poly_idx as u64).to_le_bytes());
        context.extend_from_slice(&(chunk_idx as u64).to_le_bytes());
        let branch = seeder.branch(b"layout/leading", &context);
        for coeff_idx in 0..self.nb_queries {
            out.push(branch.field(b"layout/leading/coeff", &(coeff_idx as u64).to_le_bytes()));
        }
        out
    }
}
