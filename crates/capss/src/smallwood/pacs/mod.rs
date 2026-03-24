use anyhow::Result;
use ark_ff::Zero;
use blake3::Hasher;

use crate::{
    field::BaseField,
    smallwood::{
        commit::{bytes_to_field, field_to_bytes},
        polynomial::{eval as poly_eval, restore_only_from_relation},
    },
};

pub mod example;
pub use example::ExamplePacs;

pub trait Pacs {
    fn nb_wit_rows(&self) -> usize;
    fn nb_wit_cols(&self) -> usize;
    fn constraint_degree(&self) -> usize;
    fn nb_parallel_constraints(&self) -> usize;
    fn nb_aggregated_constraints(&self) -> usize;
    fn theta(&self) -> Vec<Vec<Vec<BaseField>>>;
    fn theta_prime(&self) -> Vec<Vec<Vec<BaseField>>>;
    fn evaluate_parallel_constraints(
        &self,
        witness: &[BaseField],
        theta: &[Vec<BaseField>],
    ) -> Vec<BaseField>;
    fn evaluate_aggregated_constraints(
        &self,
        witness: &[BaseField],
        theta: &[Vec<BaseField>],
    ) -> Vec<BaseField>;
}
/// Format θ data using callback over each inner vector (matches Python utility).
pub fn format_theta<F>(thetas: &[Vec<Vec<BaseField>>], mut f: F) -> Vec<Vec<BaseField>>
where
    F: FnMut(&[BaseField]) -> BaseField,
{
    thetas
        .iter()
        .map(|theta| theta.iter().map(|sub| f(sub)).collect())
        .collect()
}

/// Evaluate parallel constraints over witness polynomials by interpolating from point samples.
///
/// Each returned polynomial is a deterministic linear combination of the input polynomials
/// weighted by the corresponding θ values, mirroring the Sage reference implementation.
pub fn evaluate_parallel_constraints_over_polynomials<P: Pacs>(
    pacs: &P,
    input_polys: &[Vec<BaseField>],
    theta_polys: &[Vec<Vec<BaseField>>],
    deg_q: usize,
) -> Result<Vec<Vec<BaseField>>> {
    let eval_points: Vec<BaseField> = (0..=deg_q).map(|i| BaseField::from(i as u64)).collect();
    let mut evals = Vec::with_capacity(eval_points.len());

    for eval_point in &eval_points {
        let wit_evals: Vec<BaseField> = input_polys
            .iter()
            .map(|poly| poly_eval(poly, *eval_point))
            .collect();
        let theta_evals = format_theta(theta_polys, |coeffs| poly_eval(coeffs, *eval_point));
        evals.push(pacs.evaluate_parallel_constraints(&wit_evals, &theta_evals));
    }

    let nb_constraints = pacs.nb_parallel_constraints();
    (0..nb_constraints)
        .map(|constraint_idx| {
            let relations: Vec<(BaseField, Vec<BaseField>)> = eval_points
                .iter()
                .zip(evals.iter())
                .map(|(point, row)| (row[constraint_idx], vec![*point]))
                .collect();
            restore_only_from_relation(&relations, deg_q)
        })
        .collect()
}

pub fn evaluate_aggregated_constraints_over_polynomials<P: Pacs>(
    pacs: &P,
    input_polys: &[Vec<BaseField>],
    theta_polys: &[Vec<Vec<BaseField>>],
    deg_q: usize,
) -> Result<Vec<Vec<BaseField>>> {
    let eval_points: Vec<BaseField> = (0..=deg_q).map(|i| BaseField::from(i as u64)).collect();
    let mut evals = Vec::with_capacity(eval_points.len());

    for eval_point in &eval_points {
        let wit_evals: Vec<BaseField> = input_polys
            .iter()
            .map(|poly| poly_eval(poly, *eval_point))
            .collect();
        let theta_evals = format_theta(theta_polys, |coeffs| poly_eval(coeffs, *eval_point));
        evals.push(pacs.evaluate_aggregated_constraints(&wit_evals, &theta_evals));
    }

    let nb_constraints = pacs.nb_aggregated_constraints();
    (0..nb_constraints)
        .map(|constraint_idx| {
            let relations: Vec<(BaseField, Vec<BaseField>)> = eval_points
                .iter()
                .zip(evals.iter())
                .map(|(point, row)| (row[constraint_idx], vec![*point]))
                .collect();
            restore_only_from_relation(&relations, deg_q)
        })
        .collect()
}

/// Derive two RLC challenges using Blake3. Matches the Fiat–Shamir style in the Python code,
/// but remains deterministic for now.
pub fn derive_rlc_challenges(fs_domain: &str, binding: &[u8]) -> (BaseField, BaseField) {
    let mut hasher = Hasher::new();
    hasher.update(fs_domain.as_bytes());
    hasher.update(binding);
    let mut xof = hasher.finalize_xof();
    let mut buf = [0u8; 32];
    xof.fill(&mut buf);
    let gamma = bytes_to_field(&buf);
    xof.fill(&mut buf);
    let gamma_prime = bytes_to_field(&buf);
    (gamma, gamma_prime)
}

/// Combine parallel and aggregated polynomials using the supplied RLC challenges.
pub fn batch_polynomials(
    parallel: &[Vec<BaseField>],
    aggregated: &[Vec<BaseField>],
    gamma: BaseField,
    gamma_prime: BaseField,
) -> Vec<Vec<BaseField>> {
    let mut batched = Vec::new();
    let max_len = parallel
        .iter()
        .chain(aggregated.iter())
        .map(|p| p.len())
        .max()
        .unwrap_or(1);

    for (idx, poly) in parallel.iter().enumerate() {
        let mut combined = vec![BaseField::zero(); max_len];
        for (i, coeff) in poly.iter().enumerate() {
            combined[i] += *coeff;
        }
        if let Some(agg) = aggregated.get(idx % aggregated.len().max(1)) {
            let weight = gamma + gamma_prime * BaseField::from((idx + 1) as u64);
            for (i, coeff) in agg.iter().enumerate() {
                combined[i] += *coeff * weight;
            }
        }
        batched.push(combined);
    }

    batched
}

pub fn serialize_polynomial(poly: &[BaseField]) -> Vec<u8> {
    let mut out = Vec::with_capacity(poly.len() * 32);
    for coeff in poly {
        out.extend_from_slice(&field_to_bytes(coeff));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bf(val: u64) -> BaseField {
        BaseField::from(val)
    }

    struct OneConstraintPacs;

    impl Pacs for OneConstraintPacs {
        fn nb_wit_rows(&self) -> usize {
            1
        }
        fn nb_wit_cols(&self) -> usize {
            1
        }
        fn constraint_degree(&self) -> usize {
            1
        }
        fn nb_parallel_constraints(&self) -> usize {
            1
        }
        fn nb_aggregated_constraints(&self) -> usize {
            1
        }
        fn theta(&self) -> Vec<Vec<Vec<BaseField>>> {
            vec![vec![vec![bf(1)]]]
        }
        fn theta_prime(&self) -> Vec<Vec<Vec<BaseField>>> {
            vec![vec![vec![bf(1)]]]
        }
        fn evaluate_parallel_constraints(
            &self,
            witness: &[BaseField],
            theta: &[Vec<BaseField>],
        ) -> Vec<BaseField> {
            vec![witness[0] * theta[0][0]]
        }
        fn evaluate_aggregated_constraints(
            &self,
            witness: &[BaseField],
            theta: &[Vec<BaseField>],
        ) -> Vec<BaseField> {
            vec![witness[0] + theta[0][0]]
        }
    }

    #[test]
    fn batch_polynomials_combines_inputs() {
        let parallel = vec![vec![bf(1), bf(2)], vec![bf(3)]];
        let aggregated = vec![vec![bf(4), bf(5)]];
        let gamma = bf(7);
        let gamma_prime = bf(11);
        let batched = batch_polynomials(&parallel, &aggregated, gamma, gamma_prime);
        assert_eq!(batched.len(), 2);
        assert_eq!(batched[0][0], bf(1) + bf(4) * (gamma + gamma_prime * bf(1)));
    }

    #[test]
    fn derive_rlc_challenges_distinct() {
        let (g1, g2) = derive_rlc_challenges("domain", b"binding");
        assert_ne!(g1, g2);
    }

    #[test]
    fn evaluate_parallel_constraints_matches_evaluations() -> Result<(), Box<dyn std::error::Error>>
    {
        let pacs = OneConstraintPacs;
        let input_polys = vec![vec![bf(1), bf(1)]]; // 1 + x
        let theta_polys = vec![vec![vec![bf(2)]]]; // constant 2
        let constraints =
            evaluate_parallel_constraints_over_polynomials(&pacs, &input_polys, &theta_polys, 2)?;
        assert_eq!(constraints.len(), 1);
        let coeffs = &constraints[0];
        // Witness eval times theta => (1 + x) * 2 => 2 + 2x
        assert_eq!(coeffs[0], bf(2));
        assert_eq!(coeffs[1], bf(2));
        Ok(())
    }

    #[test]
    fn evaluate_aggregated_constraints_reconstructs_polynomial()
    -> Result<(), Box<dyn std::error::Error>> {
        let pacs = OneConstraintPacs;
        let input_polys = vec![vec![bf(3), bf(0)]]; // constant 3
        let theta_polys = vec![vec![vec![bf(4)]]]; // constant 4
        let constraints =
            evaluate_aggregated_constraints_over_polynomials(&pacs, &input_polys, &theta_polys, 2)?;
        assert_eq!(constraints.len(), 1);
        // witness eval + theta constant -> 3 + 4 = 7 everywhere -> polynomial 7
        assert_eq!(constraints[0][0], bf(7));
        assert!(constraints[0].iter().skip(1).all(|c| c.is_zero()));
        Ok(())
    }
}
