use anyhow::Result;

use crate::field::BaseField;

use super::serializer;

/// Serialize a matrix of field elements into a compact byte representation
/// ([rows][cols] headers in little-endian, followed by row-major field bytes).
pub fn serialize_field_matrix(matrix: &[Vec<BaseField>]) -> Vec<u8> {
    serializer::serialize_matrix(matrix)
}

/// Deserialize a matrix that was produced by `serialize_field_matrix`.
pub fn deserialize_field_matrix_prefix(bytes: &[u8]) -> Result<(Vec<Vec<BaseField>>, &[u8])> {
    serializer::deserialize_matrix(bytes)
}

pub fn deserialize_field_matrix(bytes: &[u8]) -> Result<Vec<Vec<BaseField>>> {
    serializer::deserialize_matrix_exact(bytes)
}

/// Serialize a single vector of field elements (prefix with length).
pub fn serialize_field_vector(vector: &[BaseField]) -> Vec<u8> {
    serializer::serialize_vector(vector)
}

/// Deserialize a vector produced by `serialize_field_vector`.
pub fn deserialize_field_vector_prefix(bytes: &[u8]) -> Result<(Vec<BaseField>, &[u8])> {
    serializer::deserialize_vector(bytes)
}

pub fn deserialize_field_vector(bytes: &[u8]) -> Result<Vec<BaseField>> {
    serializer::deserialize_vector_exact(bytes)
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
