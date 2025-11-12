use capss::field::FieldElement;
use capss::smallwood::{self, SmallwoodConfig};
use capss::types::{CapssPublicKey, CapssSignature, CapssStatement};
use serde_json::Value;

fn parse_statement(value: &Value) -> CapssStatement {
    let message = value["message"]
        .as_array()
        .expect("message array")
        .iter()
        .map(|v| v.as_u64().expect("message byte") as u8)
        .collect();

    let iv = value["public_key"]["iv"].as_array().expect("iv array");
    let iv = iv
        .iter()
        .map(|raw| {
            let bytes = raw
                .as_array()
                .expect("iv entry")
                .iter()
                .map(|b| b.as_u64().expect("iv byte") as u8)
                .collect::<Vec<_>>();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            FieldElement::from_bytes(arr)
        })
        .collect();

    let y = value["public_key"]["y"].as_array().expect("y array");
    let bytes = y
        .iter()
        .map(|b| b.as_u64().expect("y byte") as u8)
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
fn compare_against_python_fixture_if_available() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/python_smallwood.json");
    if !path.exists() {
        eprintln!(
            "skipping python fixture comparison; {} not found",
            path.display()
        );
        return;
    }

    let fixture = std::fs::read_to_string(path).expect("read python fixture");
    let data: Value = serde_json::from_str(&fixture).expect("parse python fixture");
    let config: SmallwoodConfig =
        serde_json::from_value(data["config"].clone()).expect("config decode");
    let statement = parse_statement(&data["statement"]);
    let proof_python = data["proof"].clone();

    let proof_rust = smallwood::prove(&config, &statement).expect("rust prove");
    let proof_json = serde_json::to_value(&proof_rust).expect("proof to json");
    assert_eq!(
        proof_json, proof_python,
        "python and rust transcripts diverge"
    );

    let signature: CapssSignature = proof_rust.clone().into();
    smallwood::verify(&config, &statement, &signature).expect("rust verify");
}
