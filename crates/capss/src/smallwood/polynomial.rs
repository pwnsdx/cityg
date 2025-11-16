use ark_ff::{Field, Zero};
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};

use super::linear;
use crate::field::BaseField;

/// Evaluate coefficients at a point.
pub fn eval(coeffs: &[BaseField], point: BaseField) -> BaseField {
    coeffs
        .iter()
        .enumerate()
        .fold(BaseField::zero(), |acc, (i, coeff)| {
            acc + *coeff * point.pow([i as u64])
        })
}

/// Return the last `nb` coefficients of a polynomial of given degree.
pub fn get_high_coeffs(coeffs: &[BaseField], degree: usize, nb: usize) -> Vec<BaseField> {
    assert_eq!(coeffs.len(), degree + 1);
    assert!(nb <= coeffs.len());
    coeffs[coeffs.len() - nb..].to_vec()
}

/// Restore coefficients given relations of the form sum_{v in vs} P(v) = alpha.
pub fn restore_only_from_relation(
    relations: &[(BaseField, Vec<BaseField>)],
    degree: usize,
) -> Vec<BaseField> {
    assert_eq!(relations.len(), degree + 1);
    let mut matrix = Vec::with_capacity(degree + 1);
    let mut rhs = Vec::with_capacity(degree + 1);
    for (alpha, vs) in relations {
        rhs.push(*alpha);
        let mut row = Vec::with_capacity(degree + 1);
        for pow in 0..=degree {
            let mut sum = BaseField::zero();
            for v in vs {
                sum += v.pow([pow as u64]);
            }
            row.push(sum);
        }
        matrix.push(row);
    }
    match linear::solve_linear_system(matrix, rhs) {
        Ok(solution) => solution,
        Err(_) => {
            // This should not fail if the matrix is well-conditioned
            unreachable!("failed to solve linear system for polynomial restoration")
        }
    }
}

/// Restore coefficients given high-degree coefficients and relations.
pub fn restore_from_relations(
    relations: &[(BaseField, Vec<BaseField>)],
    high_coeffs: &[BaseField],
    degree: usize,
) -> Vec<BaseField> {
    let high_len = high_coeffs.len();
    let degree_l = degree - high_len;
    assert_eq!(relations.len(), degree_l + 1);

    let mut adjusted_relations = Vec::with_capacity(relations.len());
    for (alpha, vs) in relations {
        let mut value = *alpha;
        for v in vs {
            let mut term = BaseField::zero();
            let mut pow = v.pow([degree_l as u64 + 1]);
            for coeff in high_coeffs {
                term += *coeff * pow;
                pow *= *v;
            }
            value -= term;
        }
        adjusted_relations.push((value, vs.clone()));
    }

    let mut coeffs = restore_only_from_relation(&adjusted_relations, degree_l);
    coeffs.extend_from_slice(high_coeffs);
    coeffs
}

/// Convert coefficients into DensePolynomial.
pub fn polynomial_from_coeffs(coeffs: &[BaseField]) -> DensePolynomial<BaseField> {
    DensePolynomial::from_coefficients_vec(coeffs.to_vec())
}

/// Convert `DensePolynomial` into coefficient list of size `degree + 1`.
pub fn to_list(poly: &DensePolynomial<BaseField>, degree: usize) -> Vec<BaseField> {
    let mut coeffs = poly.coeffs.clone();
    coeffs.resize(degree + 1, BaseField::zero());
    coeffs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bf(val: u64) -> BaseField {
        BaseField::from(val)
    }

    #[test]
    fn eval_basic() {
        let coeffs = vec![bf(1), bf(2), bf(1)]; // 1 + 2x + x^2
        let point = bf(3);
        let value = eval(&coeffs, point);
        assert_eq!(value, bf(16));
    }

    #[test]
    fn restore_only_from_single_points() {
        // polynomial P(x) = 2 + 3x + x^2
        let relations = vec![
            (bf(2), vec![bf(0)]),
            (bf(6), vec![bf(1)]),
            (bf(12), vec![bf(2)]),
        ];
        let coeffs = restore_only_from_relation(&relations, 2);
        assert_eq!(coeffs, vec![bf(2), bf(3), bf(1)]);
    }

    #[test]
    fn restore_with_high_coeffs() {
        // polynomial P(x) = 4 + 5x + 7x^2 + 11x^3
        let high_coeffs = vec![bf(7), bf(11)];
        let relations = vec![(bf(4), vec![bf(0)]), (bf(27), vec![bf(1)])];
        let coeffs = restore_from_relations(&relations, &high_coeffs, 3);
        assert_eq!(coeffs, vec![bf(4), bf(5), bf(7), bf(11)]);
    }
}
