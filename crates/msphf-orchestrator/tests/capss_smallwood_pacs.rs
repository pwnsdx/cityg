use capss::field::BaseField;
use capss::smallwood::pacs::{
    Pacs, batch_polynomials, derive_rlc_challenges,
    evaluate_aggregated_constraints_over_polynomials,
    evaluate_parallel_constraints_over_polynomials, format_theta,
};
use capss::smallwood::polynomial::eval as poly_eval;

fn bf(value: u64) -> BaseField {
    BaseField::from(value)
}

struct TestPacs;

impl Pacs for TestPacs {
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
        vec![vec![vec![bf(2)]]]
    }
    fn theta_prime(&self) -> Vec<Vec<Vec<BaseField>>> {
        vec![vec![vec![bf(3)]]]
    }
    fn evaluate_parallel_constraints(
        &self,
        witness: &[BaseField],
        theta: &[Vec<BaseField>],
    ) -> Vec<BaseField> {
        let sum = witness.iter().copied().fold(bf(0), |acc, x| acc + x);
        vec![sum + theta[0][0]]
    }
    fn evaluate_aggregated_constraints(
        &self,
        witness: &[BaseField],
        theta: &[Vec<BaseField>],
    ) -> Vec<BaseField> {
        vec![witness[0] * theta[0][0]]
    }
}

#[test]
fn format_theta_applies_callback() {
    let thetas = vec![vec![vec![bf(1), bf(2)], vec![bf(3)]]];
    let formatted = format_theta(&thetas, |slice| {
        slice.iter().copied().fold(bf(0), |acc, x| acc + x)
    });
    assert_eq!(formatted, vec![vec![bf(3), bf(3)]]);
}

#[test]
fn evaluate_parallel_constraints_over_polys_matches_pacs() {
    let pacs = TestPacs;
    let input_polys = vec![vec![bf(1), bf(1)]]; // 1 + x
    let theta_polys = pacs.theta();
    let constraints =
        evaluate_parallel_constraints_over_polynomials(&pacs, &input_polys, &theta_polys, 1);
    assert_eq!(constraints.len(), 1);
    let expected_constraints = vec![vec![bf(2)]];
    for x in 0..=1 {
        let point = bf(x as u64);
        let witness_evals: Vec<BaseField> = input_polys
            .iter()
            .map(|poly| poly_eval(poly, point))
            .collect();
        let expected = pacs.evaluate_parallel_constraints(&witness_evals, &expected_constraints);
        assert_eq!(poly_eval(&constraints[0], point), expected[0]);
    }
}

#[test]
fn evaluate_aggregated_constraints_over_polys_matches_pacs() {
    let pacs = TestPacs;
    let input_polys = vec![vec![bf(2), bf(0)]]; // constant 2
    let theta_polys = pacs.theta_prime();
    let constraints =
        evaluate_aggregated_constraints_over_polynomials(&pacs, &input_polys, &theta_polys, 1);
    assert_eq!(constraints.len(), 1);
    let expected_constraints = vec![vec![bf(3)]];
    for x in 0..=1 {
        let point = bf(x as u64);
        let witness_evals: Vec<BaseField> = input_polys
            .iter()
            .map(|poly| poly_eval(poly, point))
            .collect();
        let expected = pacs.evaluate_aggregated_constraints(&witness_evals, &expected_constraints);
        assert_eq!(poly_eval(&constraints[0], point), expected[0]);
    }
}

#[test]
fn derive_rlc_challenges_is_deterministic() {
    let (gamma, gamma_prime) = derive_rlc_challenges("domain", b"binding");
    let (gamma2, gamma_prime2) = derive_rlc_challenges("domain", b"binding");
    assert_eq!(gamma, gamma2);
    assert_eq!(gamma_prime, gamma_prime2);
    assert_ne!(gamma, bf(0));
}

#[test]
fn batch_polynomials_combines_entries() {
    let parallel = vec![vec![bf(1), bf(2)]];
    let aggregated = vec![vec![bf(3), bf(4)]];
    let combined = batch_polynomials(&parallel, &aggregated, bf(2), bf(3));
    assert_eq!(combined.len(), 1);
    let weight = bf(2) + bf(3) * bf(1);
    assert_eq!(combined[0][0], bf(1) + bf(3) * weight);
    assert_eq!(combined[0][1], bf(2) + bf(4) * weight);
}
