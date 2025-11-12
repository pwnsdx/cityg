use capss::field::FieldElement;
use capss::smallwood::{self, SmallwoodConfig};
use capss::types::{CapssPublicKey, CapssStatement};
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
fn smallwood_matches_fixture() {
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/smallwood_fixture.json");
    let fixture = std::fs::read_to_string(fixture_path).expect("read fixture");
    let data: Value = serde_json::from_str(&fixture).expect("parse fixture json");

    let config: SmallwoodConfig =
        serde_json::from_value(data["config"].clone()).expect("config parse");
    let statement = parse_statement(&data["statement"]);
    let proof_fixture: serde_json::Value = data["proof"].clone();

    let proof = smallwood::prove(&config, &statement).expect("prove");
    let proof_json = serde_json::to_value(&proof).expect("proof serialization");
    assert_eq!(proof_json, proof_fixture, "proof no longer matches fixture");

    let signature: capss::types::CapssSignature = proof.clone().into();
    smallwood::verify(&config, &statement, &signature).expect("verify");
}
