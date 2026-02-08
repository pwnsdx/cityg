use cityg_client::pivot::pivot_parity_from_cbor;

#[test]
fn test_pivot_parity_from_cbor_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    // Create a minimal CBOR structure that can be deserialized into PivotParity
    // This tests the deserialization path
    let mut cbor_map = std::collections::BTreeMap::new();
    cbor_map.insert("gid", ciborium::value::Value::Bytes(vec![0x01; 16]));
    cbor_map.insert("cat", ciborium::value::Value::Bytes(vec![0x02; 16]));
    cbor_map.insert("parent_root", ciborium::value::Value::Bytes(vec![0x03; 32]));
    cbor_map.insert("we_epoch_id", ciborium::value::Value::Bytes(vec![0x42; 32]));
    cbor_map.insert("rho_commit", ciborium::value::Value::Bytes(vec![0x43; 32]));
    cbor_map.insert(
        "seed_ctx_hash",
        ciborium::value::Value::Bytes(vec![0x04; 32]),
    );
    cbor_map.insert("seed_commit", ciborium::value::Value::Bytes(vec![0x05; 32]));
    cbor_map.insert("hp_commit", ciborium::value::Value::Bytes(vec![0x06; 32]));
    cbor_map.insert("xk_hash", ciborium::value::Value::Bytes(vec![0x07; 32]));
    cbor_map.insert(
        "join_delta_root",
        ciborium::value::Value::Bytes(vec![0x08; 32]),
    );
    cbor_map.insert(
        "revoked_since_root",
        ciborium::value::Value::Bytes(vec![0x09; 32]),
    );
    cbor_map.insert(
        "revoked_root",
        ciborium::value::Value::Bytes(vec![0x0A; 32]),
    );
    cbor_map.insert("accept_seq", ciborium::value::Value::Integer(1.into()));
    cbor_map.insert("crs_id", ciborium::value::Value::Bytes(vec![0x0B; 16]));
    cbor_map.insert("params_id", ciborium::value::Value::Bytes(vec![0x0C; 16]));
    cbor_map.insert(
        "policy_version",
        ciborium::value::Value::Text("v1".to_string()),
    );
    cbor_map.insert(
        "proof_mode",
        ciborium::value::Value::Text("standard".to_string()),
    );
    cbor_map.insert(
        "vrf_id",
        ciborium::value::Value::Text("lb-vrf-v1".to_string()),
    );
    cbor_map.insert("vrf_proof", ciborium::value::Value::Bytes(vec![0x0D; 80]));
    cbor_map.insert("vrf_public", ciborium::value::Value::Bytes(vec![0x0E; 32]));
    cbor_map.insert("mask_a", ciborium::value::Value::Bytes(vec![0x0F; 32]));
    cbor_map.insert("mask_b", ciborium::value::Value::Bytes(vec![0x10; 32]));
    cbor_map.insert("fs_capss", ciborium::value::Value::Bytes(vec![0x11; 64]));
    cbor_map.insert(
        "proofs_commit",
        ciborium::value::Value::Bytes(vec![0x12; 32]),
    );
    cbor_map.insert("is_join", ciborium::value::Value::Bool(true));
    cbor_map.insert(
        "hp_envelope",
        ciborium::value::Value::Bytes(vec![0x13; 128]),
    );

    let value = ciborium::value::Value::Map(
        cbor_map
            .into_iter()
            .map(|(k, v)| (ciborium::value::Value::Text(k.to_string()), v))
            .collect(),
    );

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes)?;

    // Deserialize using our function
    let result = pivot_parity_from_cbor(&bytes)?;

    assert_eq!(result.we_epoch_id, [0x42; 32]);
    assert_eq!(result.rho_commit, [0x43; 32]);
    Ok(())
}

#[test]
fn test_pivot_parity_from_cbor_invalid_data() {
    let invalid_bytes = vec![0xFF, 0xFF, 0xFF];
    let result = pivot_parity_from_cbor(&invalid_bytes);
    assert!(result.is_err(), "Should fail with invalid CBOR");
}

#[test]
fn test_pivot_parity_from_cbor_empty() {
    let empty_bytes = vec![];
    let result = pivot_parity_from_cbor(&empty_bytes);
    assert!(result.is_err(), "Should fail with empty input");
}

#[test]
fn test_pivot_parity_from_cbor_rejects_oversized_payload() {
    let oversized = vec![0u8; (2 * 1024 * 1024) + 1];
    let err =
        pivot_parity_from_cbor(&oversized).expect_err("oversized pivot parity payload must fail");
    assert!(err.to_string().contains("pivot parity payload too large"));
}

#[test]
fn test_pivot_parity_from_cbor_truncated() -> Result<(), Box<dyn std::error::Error>> {
    // Create valid CBOR and truncate it
    let mut cbor_map = std::collections::BTreeMap::new();
    cbor_map.insert("gid", ciborium::value::Value::Bytes(vec![0x01; 16]));
    cbor_map.insert("cat", ciborium::value::Value::Bytes(vec![0x02; 16]));

    let value = ciborium::value::Value::Map(
        cbor_map
            .into_iter()
            .map(|(k, v)| (ciborium::value::Value::Text(k.to_string()), v))
            .collect(),
    );

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes)?;

    // Truncate the bytes
    let truncated = &bytes[..bytes.len() / 2];
    let result = pivot_parity_from_cbor(truncated);
    assert!(result.is_err(), "Should fail with truncated data");
    Ok(())
}
