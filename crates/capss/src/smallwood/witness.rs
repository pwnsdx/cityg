use ark_ff::Zero;

use crate::{
    field::BaseField,
    smallwood::{polynomial, rng::SmallwoodSeeder},
};

pub fn create_witness_polynomials(
    rows: &[Vec<BaseField>],
    support: &[BaseField],
    nb_queries: usize,
    degree: usize,
    seeder: &SmallwoodSeeder,
) -> Vec<Vec<BaseField>> {
    rows.iter()
        .enumerate()
        .map(|(row_idx, row)| {
            let relations = row
                .iter()
                .zip(support.iter())
                .map(|(value, point)| (*value, vec![*point]))
                .collect::<Vec<_>>();
            let mut high_coeffs = vec![BaseField::zero(); nb_queries];
            for (query_idx, coeff) in high_coeffs.iter_mut().enumerate() {
                *coeff = seeder.witness_high(row_idx, query_idx);
            }
            polynomial::restore_from_relations(&relations, &high_coeffs, degree)
        })
        .collect()
}

pub fn create_mask_polynomials(
    count: usize,
    support: &[BaseField],
    degree: usize,
    seeder: &SmallwoodSeeder,
) -> Vec<Vec<BaseField>> {
    (0..count)
        .map(|mask_idx| {
            let relation = vec![(BaseField::zero(), support.to_vec())];
            let mut high_coeffs = vec![BaseField::zero(); degree];
            for (coeff_idx, coeff) in high_coeffs.iter_mut().enumerate() {
                *coeff = seeder.mask_high(mask_idx, coeff_idx);
            }
            polynomial::restore_from_relations(&relation, &high_coeffs, degree)
        })
        .collect()
}
