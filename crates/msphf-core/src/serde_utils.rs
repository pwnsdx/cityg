//! Helper functions for deterministic CBOR serialisation.

use ciborium::ser::into_writer;
use serde::Serialize;

use crate::MsphfError;

/// Serialize the provided value to deterministic CBOR bytes.
pub fn to_cbor_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, MsphfError> {
    let mut buf = Vec::new();
    into_writer(value, &mut buf).map_err(MsphfError::serialization)?;
    Ok(buf)
}
