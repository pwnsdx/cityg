use ark_ff::{Field, One, Zero};

use crate::field::BaseField;

use super::Pacs;

/// Example PACS used by the Sage reference implementation.
///
/// It models the relation “I know `x` such that `x^{2^4} = y`” for a public `y`.
/// The witness matrix is
///
/// ```text
/// [ x      x^4  ]
/// [ x^2    x^8  ]
/// [ x^4   x^16 ]
/// ```
///
/// flattened row-major when exported.
#[derive(Clone, Debug)]
pub struct ExamplePacs {
    y: BaseField,
}

impl ExamplePacs {
    /// Construct the PACS instance from the public value `y = x^{16}`.
    pub fn new(y: BaseField) -> Self {
        Self { y }
    }

    /// Return the number of witness rows used by the example system.
    pub fn witness_rows(&self) -> usize {
        3
    }

    /// Return the number of witness columns used by the example system.
    pub fn witness_cols(&self) -> usize {
        2
    }

    /// Produce the witness matrix (flattened row-major) for a secret root `x`.
    pub fn witness_from_root(x: BaseField) -> Vec<BaseField> {
        let x2 = x.square();
        let x4 = x2.square();
        let x8 = x4.square();
        let x16 = x8.square();

        vec![x, x4, x2, x8, x4, x16]
    }

    /// Instantiate the example PACS from a secret root `x`, returning the instance
    /// together with the flattened witness.
    pub fn from_root(x: BaseField) -> (Self, Vec<BaseField>) {
        let witness = Self::witness_from_root(x);
        let y = witness.last().copied().unwrap_or_else(BaseField::zero);
        (Self::new(y), witness)
    }
}

impl Pacs for ExamplePacs {
    fn nb_wit_rows(&self) -> usize {
        self.witness_rows()
    }

    fn nb_wit_cols(&self) -> usize {
        self.witness_cols()
    }

    fn constraint_degree(&self) -> usize {
        2
    }

    fn nb_parallel_constraints(&self) -> usize {
        self.nb_wit_rows().saturating_sub(1)
    }

    fn nb_aggregated_constraints(&self) -> usize {
        self.nb_wit_cols()
    }

    fn theta(&self) -> Vec<Vec<Vec<BaseField>>> {
        vec![Vec::<Vec<BaseField>>::new(); self.nb_parallel_constraints()]
    }

    fn theta_prime(&self) -> Vec<Vec<Vec<BaseField>>> {
        let cols = self.nb_wit_cols();
        let mut theta = Vec::with_capacity(cols);

        for j in 0..(cols - 1) {
            let mut first = vec![BaseField::zero(); cols];
            first[j] = BaseField::one();
            let mut second = vec![BaseField::zero(); cols];
            second[j + 1] = BaseField::one();
            theta.push(vec![first, second]);
        }

        let mut last_first = vec![BaseField::zero(); cols];
        last_first[cols - 1] = BaseField::one();
        let mut last_second = vec![BaseField::zero(); cols];
        last_second[cols - 1] = self.y;
        theta.push(vec![last_first, last_second]);

        theta
    }

    fn evaluate_parallel_constraints(
        &self,
        witness: &[BaseField],
        theta: &[Vec<BaseField>],
    ) -> Vec<BaseField> {
        debug_assert_eq!(theta.len(), self.nb_parallel_constraints());
        let mut values = Vec::with_capacity(self.nb_parallel_constraints());
        for (theta_entry, window) in theta
            .iter()
            .zip(witness.windows(2))
            .take(self.nb_parallel_constraints())
        {
            // theta entries are unused (empty vectors) for this example PACS.
            debug_assert!(theta_entry.is_empty());
            let lhs = window[0].square();
            let rhs = window[1];
            values.push(lhs - rhs);
        }
        values
    }

    fn evaluate_aggregated_constraints(
        &self,
        witness: &[BaseField],
        theta: &[Vec<BaseField>],
    ) -> Vec<BaseField> {
        debug_assert_eq!(theta.len(), self.nb_aggregated_constraints());
        let mut values = Vec::with_capacity(self.nb_aggregated_constraints());

        for coeffs in theta
            .iter()
            .take(self.nb_aggregated_constraints().saturating_sub(1))
        {
            debug_assert!(coeffs.len() >= 2);
            let alpha = coeffs[0];
            let beta = coeffs[1];
            values.push(witness[2] * alpha - witness[0] * beta);
        }

        let last = theta
            .last()
            .expect("theta should have at least one aggregated constraint");
        debug_assert!(last.len() >= 2);
        let alpha = last[0];
        let beta = last[1];
        values.push(witness[2] * alpha - beta);

        values
    }
}

#[cfg(test)]
mod tests {
    use super::super::format_theta;
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn witness_relations_hold() {
        let x = BaseField::from(5u64);
        let (pacs, witness_flat) = ExamplePacs::from_root(x);

        let rows = pacs.nb_wit_rows();
        let cols = pacs.nb_wit_cols();
        let mut matrix = vec![vec![BaseField::zero(); cols]; rows];
        for r in 0..rows {
            for c in 0..cols {
                matrix[r][c] = witness_flat[r * cols + c];
            }
        }
        let mut columns: Vec<Vec<BaseField>> = vec![Vec::with_capacity(rows); cols];
        for row in &matrix {
            for (col_idx, value) in row.iter().enumerate() {
                columns[col_idx].push(*value);
            }
        }

        // Parallel constraints: x_{j}^2 - x_{j+1} = 0 for each column.
        let theta_parallel = pacs.theta();
        for (col, column) in columns.iter().enumerate() {
            let theta_col = format_theta(&theta_parallel, |entry| {
                entry.get(col).copied().unwrap_or_else(BaseField::zero)
            });
            let evals = pacs.evaluate_parallel_constraints(column, &theta_col);
            assert!(evals.into_iter().all(|v| v.is_zero()));
        }

        // Aggregated constraints summed over columns must vanish.
        let theta_prime = pacs.theta_prime();
        let mut sums = vec![BaseField::zero(); pacs.nb_aggregated_constraints()];
        for (col, column) in columns.iter().enumerate() {
            let theta_col = format_theta(&theta_prime, |entry| {
                entry.get(col).copied().unwrap_or_else(BaseField::zero)
            });
            let evals = pacs.evaluate_aggregated_constraints(column, &theta_col);
            for (acc, val) in sums.iter_mut().zip(evals) {
                *acc += val;
            }
        }
        assert!(sums.into_iter().all(|v| v.is_zero()));
    }
}
