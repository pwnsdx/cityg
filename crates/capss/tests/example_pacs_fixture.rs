use ark_ff::{PrimeField, Zero};
use capss::{
    field::BaseField,
    smallwood::pacs::{ExamplePacs, Pacs, format_theta},
};
use num_bigint::BigUint;
use serde_json::Value;

fn base_from_dec(value: &str) -> BaseField {
    let big = BigUint::parse_bytes(value.as_bytes(), 10).expect("invalid decimal");
    let mut bytes = big.to_bytes_le();
    bytes.resize(32, 0);
    BaseField::from_le_bytes_mod_order(&bytes)
}

#[test]
fn example_pacs_matches_python_fixture() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/example_pacs_python.json");
    let fixture = std::fs::read_to_string(path).expect("read example pacs fixture");
    let data: Value = serde_json::from_str(&fixture).expect("parse example pacs fixture");

    let y_str = data["y"]
        .as_str()
        .expect("fixture y should be decimal string");
    let pacs = ExamplePacs::new(base_from_dec(y_str));

    let witness_vals = data["witness"].as_array().expect("fixture witness array");
    let witness: Vec<BaseField> = witness_vals
        .iter()
        .map(|v| base_from_dec(v.as_str().expect("witness entry string")))
        .collect();

    assert_eq!(
        witness,
        ExamplePacs::witness_from_root(witness[0]),
        "witness layout mismatch"
    );

    let rows = pacs.nb_wit_rows();
    let cols = pacs.nb_wit_cols();
    assert_eq!(witness.len(), rows * cols);

    let mut matrix = vec![vec![BaseField::zero(); cols]; rows];
    for r in 0..rows {
        for c in 0..cols {
            matrix[r][c] = witness[r * cols + c];
        }
    }

    // Build column views once so we can iterate without indexing matrices.
    let mut columns: Vec<Vec<BaseField>> = vec![Vec::with_capacity(rows); cols];
    for row in &matrix {
        for (col_idx, value) in row.iter().enumerate() {
            columns[col_idx].push(*value);
        }
    }

    // Parallel constraints: x_j^2 - x_{j+1} should vanish.
    let theta_parallel = pacs.theta();
    for (col, column) in columns.iter().enumerate() {
        let theta_col = format_theta(&theta_parallel, |entry| {
            entry.get(col).copied().unwrap_or_else(BaseField::zero)
        });
        let evals = pacs.evaluate_parallel_constraints(column, &theta_col);
        assert!(
            evals.into_iter().all(|v| v.is_zero()),
            "parallel constraint failed for column {col}"
        );
    }

    // Aggregated constraints summed across columns should also vanish.
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
    assert!(
        sums.into_iter().all(|v| v.is_zero()),
        "aggregated constraint failed"
    );
}
