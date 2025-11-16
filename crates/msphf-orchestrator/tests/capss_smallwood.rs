use capss::field::BaseField;
use capss::smallwood::array::Array;
use capss::smallwood::merkle::{Blake3MerkleTree, verify_auth_paths};
use capss::smallwood::serializer::{
    deserialize_matrix, deserialize_matrix_exact, deserialize_vector, deserialize_vector_exact,
    deserialize_vector_fixed, serialize_matrix, serialize_vector, serialize_vector_fixed,
};

fn bf(val: u64) -> BaseField {
    BaseField::from(val)
}

#[test]
fn smallwood_array_indexing_and_zeros() {
    let mut zeros = Array::<BaseField>::zeros(&[2, 2]);
    assert_eq!(zeros.shape(), &[2, 2]);
    assert_eq!(*zeros.get(&[0, 0]), bf(0));
    *zeros.get_mut(&[1, 1]) = bf(99);
    assert_eq!(*zeros.get(&[1, 1]), bf(99));

    let arr = Array::from_vec(vec![bf(1), bf(2), bf(3), bf(4)], &[2, 2]);
    assert_eq!(arr.as_slice(), &[bf(1), bf(2), bf(3), bf(4)]);
    assert_eq!(*arr.get(&[0, 1]), bf(2));
}

#[test]
fn smallwood_merkle_verify_paths_and_errors() -> Result<(), Box<dyn std::error::Error>> {
    let leaves = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
    let tree = Blake3MerkleTree::from_leaves(&leaves);
    let root = tree.root();

    let path = tree.authentication_path(2);
    verify_auth_paths(
        root,
        &[(2, leaves[2].clone())],
        std::slice::from_ref(&path.clone()),
    )?;

    let err = match verify_auth_paths(
        root,
        &[(2, b"tampered".to_vec())],
        std::slice::from_ref(&path),
    ) {
        Err(e) => e,
        Ok(_) => return Err("expected error for tampered leaf".into()),
    };
    assert!(err.to_string().contains("mismatch"));
    Ok(())
}

#[test]
fn smallwood_serializer_roundtrip_and_errors() -> Result<(), Box<dyn std::error::Error>> {
    let matrix = vec![vec![bf(1), bf(2)], vec![bf(3), bf(4), bf(5)]];
    let bytes = serialize_matrix(&matrix);
    let (decoded, rest) = deserialize_matrix(&bytes)?;
    assert_eq!(matrix, decoded);
    assert!(rest.is_empty());

    let mut with_trailing = bytes.clone();
    with_trailing.push(0xFF);
    assert!(deserialize_matrix_exact(&with_trailing).is_err());

    let truncated = &bytes[..bytes.len() - 1];
    assert!(deserialize_matrix(truncated).is_err());

    let vector = vec![bf(7), bf(8), bf(9)];
    let v_bytes = serialize_vector(&vector);
    let (decoded_vec, rest_vec) = deserialize_vector(&v_bytes)?;
    assert_eq!(vector, decoded_vec);
    assert!(rest_vec.is_empty());

    let truncated_vec = &v_bytes[..v_bytes.len() - 1];
    assert!(deserialize_vector(truncated_vec).is_err());

    let fixed_bytes = serialize_vector_fixed(&vector);
    let (fixed_vec, remaining) = deserialize_vector_fixed(&fixed_bytes, 2)?;
    assert_eq!(fixed_vec, vec![bf(7), bf(8)]);
    assert_eq!(remaining, &fixed_bytes[64..]);

    let mut fixed_truncated = fixed_bytes.clone();
    fixed_truncated.pop();
    assert!(deserialize_vector_fixed(&fixed_truncated, 3).is_err());

    assert!(deserialize_vector_exact(&with_trailing).is_err());
    Ok(())
}
