use anyhow::{Result, anyhow, bail};

use crate::field::BaseField;

use super::commit::{bytes_to_field, field_to_bytes};

pub fn serialize_matrix(matrix: &[Vec<BaseField>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(matrix.len() as u64).to_le_bytes());
    for row in matrix {
        out.extend_from_slice(&(row.len() as u64).to_le_bytes());
        for value in row {
            out.extend_from_slice(&field_to_bytes(value));
        }
    }
    out
}

pub fn deserialize_matrix(bytes: &[u8]) -> Result<(Vec<Vec<BaseField>>, &[u8])> {
    const U64_LEN: usize = std::mem::size_of::<u64>();
    if bytes.len() < U64_LEN {
        bail!("matrix encoding truncated (row count)");
    }
    let rows = u64::from_le_bytes(
        bytes[..U64_LEN]
            .try_into()
            .map_err(|_| anyhow!("matrix rows slice malformed"))?,
    ) as usize;
    let mut cursor = &bytes[U64_LEN..];
    let mut matrix = Vec::with_capacity(rows);
    for _ in 0..rows {
        if cursor.len() < U64_LEN {
            bail!("matrix encoding truncated (row length)");
        }
        let cols = u64::from_le_bytes(
            cursor[..U64_LEN]
                .try_into()
                .map_err(|_| anyhow!("matrix columns slice malformed"))?,
        ) as usize;
        cursor = &cursor[U64_LEN..];
        let required = cols * 32;
        if cursor.len() < required {
            bail!("matrix encoding truncated (coefficients)");
        }
        let mut row = Vec::with_capacity(cols);
        for chunk in cursor[..required].chunks(32) {
            row.push(bytes_to_field(chunk));
        }
        matrix.push(row);
        cursor = &cursor[required..];
    }
    Ok((matrix, cursor))
}

pub fn deserialize_matrix_exact(bytes: &[u8]) -> Result<Vec<Vec<BaseField>>> {
    let (matrix, rest) = deserialize_matrix(bytes)?;
    if !rest.is_empty() {
        bail!("matrix encoding trailing data");
    }
    Ok(matrix)
}

pub fn serialize_vector(vector: &[BaseField]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(vector.len() as u64).to_le_bytes());
    for value in vector {
        out.extend_from_slice(&field_to_bytes(value));
    }
    out
}

pub fn serialize_vector_fixed(vector: &[BaseField]) -> Vec<u8> {
    let mut out = Vec::with_capacity(vector.len() * 32);
    for value in vector {
        out.extend_from_slice(&field_to_bytes(value));
    }
    out
}

pub fn deserialize_vector(bytes: &[u8]) -> Result<(Vec<BaseField>, &[u8])> {
    const U64_LEN: usize = std::mem::size_of::<u64>();
    if bytes.len() < U64_LEN {
        bail!("vector encoding truncated (length)");
    }
    let len = u64::from_le_bytes(
        bytes[..U64_LEN]
            .try_into()
            .map_err(|_| anyhow!("vector length slice malformed"))?,
    ) as usize;
    let mut cursor = &bytes[U64_LEN..];
    let required = len * 32;
    if cursor.len() < required {
        bail!("vector encoding truncated (coefficients)");
    }
    let mut vector = Vec::with_capacity(len);
    for chunk in cursor[..required].chunks(32) {
        vector.push(bytes_to_field(chunk));
    }
    cursor = &cursor[required..];
    Ok((vector, cursor))
}

pub fn deserialize_vector_fixed(bytes: &[u8], len: usize) -> Result<(Vec<BaseField>, &[u8])> {
    let required = len * 32;
    if bytes.len() < required {
        bail!("vector encoding truncated (fixed length)");
    }
    let mut vector = Vec::with_capacity(len);
    for chunk in bytes[..required].chunks(32) {
        vector.push(bytes_to_field(chunk));
    }
    Ok((vector, &bytes[required..]))
}

pub fn deserialize_vector_exact(bytes: &[u8]) -> Result<Vec<BaseField>> {
    let (vector, rest) = deserialize_vector(bytes)?;
    if !rest.is_empty() {
        bail!("vector encoding trailing data");
    }
    Ok(vector)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn bf(v: u64) -> BaseField {
        BaseField::from(v)
    }

    #[test]
    fn matrix_roundtrip_and_exact_validation() {
        let matrix = vec![vec![bf(1), bf(2)], vec![bf(3)]];
        let bytes = serialize_matrix(&matrix);
        let (decoded, rest) = deserialize_matrix(&bytes).expect("matrix decode");
        assert_eq!(decoded, matrix);
        assert!(rest.is_empty());
        let exact = deserialize_matrix_exact(&bytes).expect("matrix exact decode");
        assert_eq!(exact, matrix);

        let mut with_trailing = bytes.clone();
        with_trailing.push(0xFF);
        assert!(deserialize_matrix_exact(&with_trailing).is_err());
    }

    #[test]
    fn matrix_decode_rejects_truncated_forms() {
        assert!(deserialize_matrix(&[]).is_err());

        let mut bytes = serialize_matrix(&[vec![bf(1)]]);
        bytes.truncate(8);
        assert!(deserialize_matrix(&bytes).is_err());

        let mut bytes = serialize_matrix(&[vec![bf(1), bf(2)]]);
        bytes.truncate(bytes.len().saturating_sub(1));
        assert!(deserialize_matrix(&bytes).is_err());
    }

    #[test]
    fn vector_roundtrip_fixed_and_exact_validation() {
        let vector = vec![bf(9), bf(10), bf(11)];
        let bytes = serialize_vector(&vector);
        let (decoded, rest) = deserialize_vector(&bytes).expect("vector decode");
        assert_eq!(decoded, vector);
        assert!(rest.is_empty());
        let exact = deserialize_vector_exact(&bytes).expect("vector exact decode");
        assert_eq!(exact, vector);

        let fixed = serialize_vector_fixed(&vector);
        let (decoded_fixed, fixed_rest) =
            deserialize_vector_fixed(&fixed, vector.len()).expect("fixed decode");
        assert_eq!(decoded_fixed, vector);
        assert!(fixed_rest.is_empty());

        let mut with_trailing = bytes.clone();
        with_trailing.push(0xEE);
        assert!(deserialize_vector_exact(&with_trailing).is_err());
    }

    #[test]
    fn vector_decode_rejects_truncated_forms() {
        assert!(deserialize_vector(&[]).is_err());

        let bytes = serialize_vector(&[bf(1), bf(2)]);
        assert!(deserialize_vector(&bytes[..8]).is_err());
        assert!(deserialize_vector_fixed(&bytes[..31], 1).is_err());
    }
}
