use capss::field::FieldElement;
use capss::smallwood::{self, SmallwoodConfig};
use capss::types::{CapssPublicKey, CapssSignature, CapssStatement};
use serde_json::Value;

fn parse_statement(value: &Value) -> CapssStatement {
    let message = match value["message"].as_array() {
        Some(arr) => arr
            .iter()
            .map(|v| match v.as_u64() {
                Some(byte) => byte as u8,
                None => unreachable!("message byte should be u64"),
            })
            .collect(),
        None => unreachable!("message should be array"),
    };

    let iv = match value["public_key"]["iv"].as_array() {
        Some(arr) => arr,
        None => unreachable!("iv should be array"),
    };
    let iv = iv
        .iter()
        .map(|raw| {
            let bytes = match raw.as_array() {
                Some(arr) => arr
                    .iter()
                    .map(|b| match b.as_u64() {
                        Some(byte) => byte as u8,
                        None => unreachable!("iv byte should be u64"),
                    })
                    .collect::<Vec<_>>(),
                None => unreachable!("iv entry should be array"),
            };
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            FieldElement::from_bytes(arr)
        })
        .collect();

    let y = match value["public_key"]["y"].as_array() {
        Some(arr) => arr,
        None => unreachable!("y should be array"),
    };
    let bytes = y
        .iter()
        .map(|b| match b.as_u64() {
            Some(byte) => byte as u8,
            None => unreachable!("y byte should be u64"),
        })
        .collect::<Vec<_>>();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let public_key = CapssPublicKey {
        iv,
        y: FieldElement::from_bytes(arr),
    };

    CapssStatement {
        public_key,
        message,
    }
}

#[test]
fn compare_against_python_fixture_if_available() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/python_smallwood.json");
    if !path.exists() {
        eprintln!(
            "skipping python fixture comparison; {} not found",
            path.display()
        );
        return Ok(());
    }

    let fixture = std::fs::read_to_string(path)?;
    let data: Value = serde_json::from_str(&fixture)?;
    let config: SmallwoodConfig = serde_json::from_value(data["config"].clone())?;
    let statement = parse_statement(&data["statement"]);
    let proof_python = data["proof"].clone();

    let proof_rust = smallwood::prove(&config, &statement)?;
    let proof_json = serde_json::to_value(&proof_rust)?;
    assert_eq!(
        proof_json, proof_python,
        "python and rust transcripts diverge"
    );

    let signature: CapssSignature = proof_rust.clone().into();
    smallwood::verify(&config, &statement, &signature)?;
    Ok(())
}
