use ark_ff::{Field, One, Zero};

use crate::field::BaseField;

/// Result alias used by the linear solver implementations.
pub type LinearResult = Result<Vec<BaseField>, &'static str>;

/// Trait capturing the behaviour of a linear-system solver over `BaseField`.
pub trait LinearSolver {
    fn solve(matrix: Vec<Vec<BaseField>>, rhs: Vec<BaseField>) -> LinearResult;
}

/// Baseline Gaussian elimination implementation. This mirrors the original code
/// that shipped with the initial Smallwood port.
pub struct GaussianSolver;

impl LinearSolver for GaussianSolver {
    fn solve(mut matrix: Vec<Vec<BaseField>>, mut rhs: Vec<BaseField>) -> LinearResult {
        let n = rhs.len();
        for i in 0..n {
            // Pivot selection: find the first row at or below `i` with a non-zero entry.
            let mut pivot = i;
            while pivot < n && matrix[pivot][i].is_zero() {
                pivot += 1;
            }
            if pivot == n {
                return Err("singular matrix");
            }
            if pivot != i {
                matrix.swap(i, pivot);
                rhs.swap(i, pivot);
            }

            // Normalize the pivot row.
            let inv = matrix[i][i].inverse().ok_or("non invertible pivot")?;
            for value in matrix[i].iter_mut().skip(i) {
                *value *= inv;
            }
            rhs[i] *= inv;
            let row_i = matrix[i].clone();
            let rhs_i = rhs[i];

            // Eliminate the column from the remaining rows.
            for (row_idx, row) in matrix.iter_mut().enumerate() {
                if row_idx == i {
                    continue;
                }
                let factor = row[i];
                if factor.is_zero() {
                    continue;
                }
                for (entry, pivot_entry) in row.iter_mut().zip(row_i.iter()).skip(i) {
                    *entry -= factor * *pivot_entry;
                }
                rhs[row_idx] -= factor * rhs_i;
            }
        }
        Ok(rhs)
    }
}

/// Constant-time solver that mirrors Gauss-Jordan elimination while avoiding
/// data-dependent branches on the matrix values. It performs conditional row
/// swaps and eliminations using field arithmetic masks so every iteration
/// touches the same rows/columns regardless of the secret witness.
pub struct ConstantTimeSolver;

impl ConstantTimeSolver {
    fn bool_mask(flag: u8) -> BaseField {
        debug_assert!(flag <= 1);
        BaseField::from(flag as u64)
    }

    fn conditional_swap(
        matrix: &mut [Vec<BaseField>],
        rhs: &mut [BaseField],
        a: usize,
        b: usize,
        swap: u8,
    ) {
        let mask = Self::bool_mask(swap);
        let inv = BaseField::one() - mask;

        if a == b {
            // Swapping a row with itself is a no-op, so we can return early.
            return;
        }

        let (row_a, row_b) = if a < b {
            let (head, tail) = matrix.split_at_mut(b);
            (&mut head[a], &mut tail[0])
        } else {
            let (head, tail) = matrix.split_at_mut(a);
            (&mut tail[0], &mut head[b])
        };

        for (val_a, val_b) in row_a.iter_mut().zip(row_b.iter_mut()) {
            let original_a = *val_a;
            let original_b = *val_b;
            *val_a = original_a * inv + original_b * mask;
            *val_b = original_a * mask + original_b * inv;
        }

        let rhs_a = rhs[a];
        let rhs_b = rhs[b];
        rhs[a] = rhs_a * inv + rhs_b * mask;
        rhs[b] = rhs_a * mask + rhs_b * inv;
    }
}

impl LinearSolver for ConstantTimeSolver {
    fn solve(mut matrix: Vec<Vec<BaseField>>, mut rhs: Vec<BaseField>) -> LinearResult {
        let n = rhs.len();
        if matrix.len() != n {
            return Err("non square matrix");
        }
        for row in &matrix {
            if row.len() != n {
                return Err("non square matrix");
            }
        }

        for col in 0..n {
            let mut pivot_found: u8 = 0;
            for row in col..n {
                let nz = (!matrix[row][col].is_zero()) as u8;
                let select = nz & (1u8.wrapping_sub(pivot_found));
                pivot_found |= select;
                Self::conditional_swap(&mut matrix, &mut rhs, col, row, select);
            }

            if pivot_found == 0 {
                return Err("singular matrix");
            }

            let pivot = matrix[col][col];
            let inv = pivot.inverse().ok_or("non invertible pivot")?;

            for value in matrix[col].iter_mut() {
                *value *= inv;
            }
            rhs[col] *= inv;

            let pivot_row = matrix[col].clone();
            let pivot_rhs = rhs[col];

            for row in 0..n {
                let factor = matrix[row][col];
                let mask = Self::bool_mask((row != col) as u8);
                let adjusted = factor * mask;
                for (entry, &pivot_entry) in matrix[row].iter_mut().zip(pivot_row.iter()) {
                    *entry -= adjusted * pivot_entry;
                }
                rhs[row] -= adjusted * pivot_rhs;
            }
        }

        Ok(rhs)
    }
}

/// Default entry point used by the rest of the module. Callers always receive the
/// constant-time implementation without having to know about the underlying
/// solver choice.
pub fn solve_linear_system(matrix: Vec<Vec<BaseField>>, rhs: Vec<BaseField>) -> LinearResult {
    ConstantTimeSolver::solve(matrix, rhs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn constant_time_solver_matches_gaussian() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = test_rng();
        for dimension in 1..=5 {
            for _ in 0..16 {
                let mut matrix = vec![vec![BaseField::zero(); dimension]; dimension];
                let mut rhs = vec![BaseField::zero(); dimension];
                for row in matrix.iter_mut().take(dimension) {
                    for entry in row.iter_mut() {
                        *entry = BaseField::rand(&mut rng);
                    }
                }
                for value in rhs.iter_mut().take(dimension) {
                    *value = BaseField::rand(&mut rng);
                }

                // Ensure matrix is non-singular by adding identity component.
                for (i, row) in matrix.iter_mut().enumerate().take(dimension) {
                    row[i] += BaseField::one();
                }

                let gaussian = GaussianSolver::solve(matrix.clone(), rhs.clone())?;
                let constant = ConstantTimeSolver::solve(matrix, rhs)?;
                assert_eq!(gaussian, constant);
            }
        }
        Ok(())
    }
}
