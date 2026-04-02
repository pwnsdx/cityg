use std::{collections::BTreeMap, convert::TryInto};

use anyhow::{Result, anyhow};
use ciborium::value::Value;
use hex::decode as hex_decode;

pub fn header_bytes32(header: &BTreeMap<u64, Value>, key: u64) -> Option<[u8; 32]> {
    match header.get(&key)? {
        Value::Bytes(bytes) => bytes.as_slice().try_into().ok(),
        _ => None,
    }
}

pub fn decode_hex_32(input: &str) -> Option<[u8; 32]> {
    let bytes = hex_decode(input).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Some(result)
}

pub fn bytes32(name: &str, data: &[u8]) -> Result<[u8; 32]> {
    data.try_into()
        .map_err(|_| anyhow!("{name} must be 32 bytes, received {} bytes", data.len()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_32_rejects_wrong_length() {
        assert!(decode_hex_32("aa").is_none());
    }

    #[test]
    fn bytes32_accepts_exact_length() {
        let data = [0xAB; 32];
        assert_eq!(bytes32("field", &data).unwrap(), data);
    }
}
