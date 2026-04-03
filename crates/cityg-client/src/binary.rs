use std::{collections::BTreeMap, convert::TryInto};

use anyhow::{Result, anyhow};
use ciborium::value::Value;
use hex::{decode as hex_decode, encode as hex_encode};
use rand::{Rng, rng};

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

pub fn fingerprint_full_hex(bytes: &[u8; 32]) -> String {
    hex_encode(bytes)
}

pub fn fingerprint_preview_hex(bytes: &[u8; 32]) -> String {
    let hex = fingerprint_full_hex(bytes);
    let first = &hex[..8];
    let second = &hex[8..16];
    format!(
        "{}-{} {}-{} …",
        &first[..4],
        &first[4..],
        &second[..4],
        &second[4..]
    )
}

pub fn random_hex_32() -> String {
    let mut bytes = [0u8; 32];
    rng().fill(&mut bytes);
    hex_encode(bytes)
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

    #[test]
    fn fingerprint_preview_uses_expected_shape() {
        let data = [0xAB; 32];
        assert_eq!(fingerprint_full_hex(&data), "ab".repeat(32));
        assert_eq!(fingerprint_preview_hex(&data), "abab-abab abab-abab …");
    }

    #[test]
    fn random_hex_32_returns_64_hex_chars() {
        let room_id = random_hex_32();
        assert_eq!(room_id.len(), 64);
        assert!(room_id.chars().all(|ch| ch.is_ascii_hexdigit()));
    }
}
