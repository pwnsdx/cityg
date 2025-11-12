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
