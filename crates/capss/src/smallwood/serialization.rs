use anyhow::{Result, anyhow, bail};

use super::commit::{bytes_to_field, field_to_bytes};
use crate::field::BaseField;

/// Serialize a matrix of field elements into a compact byte representation
/// ([rows][cols] headers in little-endian, followed by row-major field bytes).
pub fn serialize_field_matrix(matrix: &[Vec<BaseField>]) -> Vec<u8> {
    let rows = matrix.len() as u64;
    let mut out = Vec::with_capacity(matrix.len() * 32);
    out.extend_from_slice(&rows.to_le_bytes());
    for row in matrix {
        let cols = row.len() as u64;
        out.extend_from_slice(&cols.to_le_bytes());
        for value in row {
            out.extend_from_slice(&field_to_bytes(value));
        }
    }
    out
}

/// Deserialize a matrix that was produced by `serialize_field_matrix`.
pub fn deserialize_field_matrix_prefix(bytes: &[u8]) -> Result<(Vec<Vec<BaseField>>, &[u8])> {
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

pub fn deserialize_field_matrix(bytes: &[u8]) -> Result<Vec<Vec<BaseField>>> {
    let (matrix, rest) = deserialize_field_matrix_prefix(bytes)?;
    if !rest.is_empty() {
        bail!("matrix encoding trailing data");
    }
    Ok(matrix)
}

/// Serialize a single vector of field elements (prefix with length).
pub fn serialize_field_vector(vector: &[BaseField]) -> Vec<u8> {
    let mut out = Vec::with_capacity((vector.len() + 1) * 32);
    out.extend_from_slice(&(vector.len() as u64).to_le_bytes());
    for value in vector {
        out.extend_from_slice(&field_to_bytes(value));
    }
    out
}

/// Deserialize a vector produced by `serialize_field_vector`.
pub fn deserialize_field_vector_prefix(bytes: &[u8]) -> Result<(Vec<BaseField>, &[u8])> {
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

pub fn deserialize_field_vector(bytes: &[u8]) -> Result<Vec<BaseField>> {
    let (vector, rest) = deserialize_field_vector_prefix(bytes)?;
    if !rest.is_empty() {
        bail!("vector encoding trailing data");
    }
    Ok(vector)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bf(val: u64) -> BaseField {
        BaseField::from(val)
    }

    #[test]
    fn roundtrip_matrix() -> Result<(), Box<dyn std::error::Error>> {
        let matrix = vec![vec![bf(1), bf(2)], vec![bf(3)]];
        let encoded = serialize_field_matrix(&matrix);
        let decoded = deserialize_field_matrix(&encoded)?;
        assert_eq!(decoded, matrix);

        let (prefixed, rest) = deserialize_field_matrix_prefix(&encoded)?;
        assert_eq!(prefixed, matrix);
        assert!(rest.is_empty());
        Ok(())
    }

    #[test]
    fn roundtrip_vector() -> Result<(), Box<dyn std::error::Error>> {
        let vector = vec![bf(7), bf(8), bf(9)];
        let encoded = serialize_field_vector(&vector);
        let decoded = deserialize_field_vector(&encoded)?;
        assert_eq!(decoded, vector);
        Ok(())
    }
}
