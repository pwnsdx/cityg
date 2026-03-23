use anyhow::{Result, anyhow, ensure};
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
) -> Result<Vec<BaseField>> {
    ensure!(
        relations.len() == degree + 1,
        "polynomial relation count mismatch: expected {}, got {}",
        degree + 1,
        relations.len()
    );
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
    linear::solve_linear_system(matrix, rhs)
        .map_err(|err| anyhow!("failed to solve linear system for polynomial restoration: {err}"))
}

/// Restore coefficients given high-degree coefficients and relations.
pub fn restore_from_relations(
    relations: &[(BaseField, Vec<BaseField>)],
    high_coeffs: &[BaseField],
    degree: usize,
) -> Result<Vec<BaseField>> {
    let high_len = high_coeffs.len();
    ensure!(
        high_len <= degree,
        "high coefficient count {} exceeds degree {}",
        high_len,
        degree
    );
    let degree_l = degree - high_len;

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

    let mut coeffs = restore_only_from_relation(&adjusted_relations, degree_l)?;
    coeffs.extend_from_slice(high_coeffs);
    Ok(coeffs)
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
    fn eval_empty_polynomial_is_zero() {
        assert_eq!(eval(&[], bf(7)), BaseField::zero());
    }

    #[test]
    fn get_high_coeffs_returns_suffix() {
        let coeffs = vec![bf(1), bf(2), bf(3), bf(4)];
        assert_eq!(get_high_coeffs(&coeffs, 3, 2), vec![bf(3), bf(4)]);
        assert_eq!(get_high_coeffs(&coeffs, 3, 0), Vec::<BaseField>::new());
        assert_eq!(get_high_coeffs(&coeffs, 3, 4), coeffs);
    }

    #[test]
    #[should_panic]
    fn get_high_coeffs_rejects_degree_mismatch() {
        let coeffs = vec![bf(1), bf(2)];
        let _ = get_high_coeffs(&coeffs, 2, 1);
    }

    #[test]
    #[should_panic]
    fn get_high_coeffs_rejects_too_many_coeffs() {
        let coeffs = vec![bf(1), bf(2), bf(3)];
        let _ = get_high_coeffs(&coeffs, 2, 4);
    }

    #[test]
    fn restore_only_from_single_points() {
        // polynomial P(x) = 2 + 3x + x^2
        let relations = vec![
            (bf(2), vec![bf(0)]),
            (bf(6), vec![bf(1)]),
            (bf(12), vec![bf(2)]),
        ];
        let coeffs = restore_only_from_relation(&relations, 2).expect("relations restore");
        assert_eq!(coeffs, vec![bf(2), bf(3), bf(1)]);
    }

    #[test]
    fn restore_only_from_relation_rejects_wrong_relation_count() {
        let relations = vec![(bf(1), vec![bf(0)])];
        assert!(restore_only_from_relation(&relations, 1).is_err());
    }

    #[test]
    fn restore_only_from_relation_rejects_singular_system() {
        let relations = vec![(bf(1), vec![bf(0)]), (bf(1), vec![bf(0)])];
        assert!(restore_only_from_relation(&relations, 1).is_err());
    }

    #[test]
    fn restore_with_high_coeffs() {
        // polynomial P(x) = 4 + 5x + 7x^2 + 11x^3
        let high_coeffs = vec![bf(7), bf(11)];
        let relations = vec![(bf(4), vec![bf(0)]), (bf(27), vec![bf(1)])];
        let coeffs = restore_from_relations(&relations, &high_coeffs, 3)
            .expect("relations restore with high coeffs");
        assert_eq!(coeffs, vec![bf(4), bf(5), bf(7), bf(11)]);
    }

    #[test]
    fn restore_from_relations_without_high_coeffs_roundtrips() {
        let relations = vec![(bf(3), vec![bf(0)]), (bf(5), vec![bf(1)])];
        let coeffs =
            restore_from_relations(&relations, &[], 1).expect("relations restore without high");
        assert_eq!(coeffs, vec![bf(3), bf(2)]);
    }

    #[test]
    fn polynomial_conversions_roundtrip_and_pad() {
        let coeffs = vec![bf(9), bf(4)];
        let poly = polynomial_from_coeffs(&coeffs);
        assert_eq!(poly.coeffs, coeffs);
        assert_eq!(
            to_list(&poly, 4),
            vec![
                bf(9),
                bf(4),
                BaseField::zero(),
                BaseField::zero(),
                BaseField::zero()
            ]
        );
    }
}
