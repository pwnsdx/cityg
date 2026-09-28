//! Deterministic CBOR (`CBOR_det`, RFC 8949 §4.2.1 core deterministic
//! encoding) and small helpers to read profile objects.
//!
//! Encoding rules: shortest integer and length heads, definite lengths only,
//! map keys sorted by the bytewise order of their encodings, no duplicate
//! keys, no floats and no tags. Decoding re-encodes the parsed value and
//! requires byte equality, which rejects every non-deterministic input.

use ciborium::value::{Integer, Value};

use crate::error::{CoreError, CoreResult};

const MAJOR_UINT: u8 = 0;
const MAJOR_NINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;

fn push_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    if value < 24 {
        out.push(major | value as u8);
    } else if value <= u64::from(u8::MAX) {
        out.push(major | 24);
        out.push(value as u8);
    } else if value <= u64::from(u16::MAX) {
        out.push(major | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u64::from(u32::MAX) {
        out.push(major | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn push_len(out: &mut Vec<u8>, major: u8, len: usize) -> CoreResult<()> {
    let len = u64::try_from(len).map_err(|_| CoreError::TooLarge("CBOR item length"))?;
    push_head(out, major, len);
    Ok(())
}

fn encode_into(value: &Value, out: &mut Vec<u8>) -> CoreResult<()> {
    match value {
        Value::Integer(integer) => {
            let n = i128::from(*integer);
            if n >= 0 {
                let n = u64::try_from(n).map_err(|_| CoreError::Malformed("CBOR integer"))?;
                push_head(out, MAJOR_UINT, n);
            } else {
                let n = u64::try_from(-1 - n).map_err(|_| CoreError::Malformed("CBOR integer"))?;
                push_head(out, MAJOR_NINT, n);
            }
        }
        Value::Bytes(bytes) => {
            push_len(out, MAJOR_BYTES, bytes.len())?;
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            push_len(out, MAJOR_TEXT, text.len())?;
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            push_len(out, MAJOR_ARRAY, items.len())?;
            for item in items {
                encode_into(item, out)?;
            }
        }
        Value::Map(entries) => {
            let mut encoded = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let mut key_bytes = Vec::new();
                encode_into(key, &mut key_bytes)?;
                let mut value_bytes = Vec::new();
                encode_into(value, &mut value_bytes)?;
                encoded.push((key_bytes, value_bytes));
            }
            encoded.sort_by(|left, right| left.0.cmp(&right.0));
            if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(CoreError::Malformed("CBOR map with duplicate keys"));
            }
            push_len(out, MAJOR_MAP, encoded.len())?;
            for (key, value) in encoded {
                out.extend_from_slice(&key);
                out.extend_from_slice(&value);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
        Value::Float(_) => return Err(CoreError::Malformed("CBOR float")),
        Value::Tag(_, _) => return Err(CoreError::Malformed("CBOR tag")),
        _ => return Err(CoreError::Malformed("CBOR item")),
    }
    Ok(())
}

/// Encode `value` as `CBOR_det`.
pub fn encode(value: &Value) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

/// Decode `bytes` and require them to be the `CBOR_det` encoding of the
/// decoded value. `what` names the object in errors.
pub fn decode(bytes: &[u8], max_len: usize, what: &'static str) -> CoreResult<Value> {
    if bytes.len() > max_len {
        return Err(CoreError::TooLarge(what));
    }
    let value: Value = ciborium::de::from_reader(bytes).map_err(|_| CoreError::Malformed(what))?;
    let canonical = encode(&value).map_err(|_| CoreError::Malformed(what))?;
    if canonical != bytes {
        return Err(CoreError::NonDeterministic(what));
    }
    Ok(value)
}

/// Unsigned integer value.
#[must_use]
pub fn uint(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}

/// Byte-string value.
#[must_use]
pub fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

/// Text value.
#[must_use]
pub fn text(value: &str) -> Value {
    Value::Text(value.to_string())
}

/// Array value.
#[must_use]
pub fn array(items: Vec<Value>) -> Value {
    Value::Array(items)
}

/// Read an array of exactly `len` items.
pub fn expect_array(value: Value, len: usize, what: &'static str) -> CoreResult<Vec<Value>> {
    match value {
        Value::Array(items) if items.len() == len => Ok(items),
        _ => Err(CoreError::Malformed(what)),
    }
}

/// Read an array of any length.
pub fn expect_list(value: Value, what: &'static str) -> CoreResult<Vec<Value>> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(CoreError::Malformed(what)),
    }
}

/// Read an unsigned integer that fits in `u64`.
pub fn expect_uint(value: &Value, what: &'static str) -> CoreResult<u64> {
    match value {
        Value::Integer(integer) => {
            u64::try_from(i128::from(*integer)).map_err(|_| CoreError::Malformed(what))
        }
        _ => Err(CoreError::Malformed(what)),
    }
}

/// Read an unsigned integer that fits in `u32`.
pub fn expect_u32(value: &Value, what: &'static str) -> CoreResult<u32> {
    u32::try_from(expect_uint(value, what)?).map_err(|_| CoreError::Malformed(what))
}

/// Read a byte string.
pub fn expect_bytes(value: Value, what: &'static str) -> CoreResult<Vec<u8>> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(CoreError::Malformed(what)),
    }
}

/// Read a 32-byte string.
pub fn expect_bytes32(value: Value, what: &'static str) -> CoreResult<[u8; 32]> {
    expect_bytes(value, what)?
        .try_into()
        .map_err(|_| CoreError::Malformed(what))
}

/// Read a text string and require it to equal `expected`.
pub fn expect_label(value: &Value, expected: &str, what: &'static str) -> CoreResult<()> {
    match value {
        Value::Text(text) if text == expected => Ok(()),
        _ => Err(CoreError::Malformed(what)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn encodes_rfc8949_examples() {
        let cases: Vec<(Value, &str)> = vec![
            (uint(0), "00"),
            (uint(23), "17"),
            (uint(24), "1818"),
            (uint(1000), "1903e8"),
            (uint(1_000_000), "1a000f4240"),
            (uint(1_000_000_000_000), "1b000000e8d4a51000"),
            (Value::Integer(Integer::from(-1i64)), "20"),
            (Value::Integer(Integer::from(-1000i64)), "3903e7"),
            (bytes(&[1, 2, 3, 4]), "4401020304"),
            (text("IETF"), "6449455446"),
            (array(vec![uint(1), uint(2), uint(3)]), "83010203"),
            (Value::Bool(true), "f5"),
            (Value::Null, "f6"),
        ];
        for (value, expected) in cases {
            assert_eq!(hex::encode(encode(&value).unwrap()), expected);
        }
    }

    #[test]
    fn sorts_map_keys_by_encoded_bytes() {
        let map = Value::Map(vec![
            (text("aa"), uint(1)),
            (uint(100), uint(2)),
            (uint(10), uint(3)),
            (Value::Integer(Integer::from(-1i64)), uint(4)),
        ]);
        // 0a < 1864 < 20 < 626161
        assert_eq!(
            hex::encode(encode(&map).unwrap()),
            "a40a03186402200462616101"
        );
    }

    #[test]
    fn rejects_duplicate_keys_floats_and_tags() {
        let duplicate = Value::Map(vec![(uint(1), uint(1)), (uint(1), uint(2))]);
        assert!(encode(&duplicate).is_err());
        assert!(encode(&Value::Float(1.5)).is_err());
        assert!(encode(&Value::Tag(1, Box::new(uint(0)))).is_err());
    }

    #[test]
    fn decode_requires_deterministic_bytes() {
        let value = array(vec![uint(1), bytes(b"x")]);
        let canonical = encode(&value).unwrap();
        assert_eq!(decode(&canonical, 64, "test").unwrap(), value);
        // Non-shortest integer head for 1.
        assert_eq!(
            decode(
                &hex::decode("82180141 78".replace(' ', "")).unwrap(),
                64,
                "test"
            ),
            Err(CoreError::NonDeterministic("test"))
        );
        // Indefinite-length array.
        assert_eq!(
            decode(&hex::decode("9f01ff").unwrap(), 64, "test"),
            Err(CoreError::NonDeterministic("test"))
        );
        // Trailing bytes.
        let mut trailing = canonical.clone();
        trailing.push(0x00);
        assert!(decode(&trailing, 64, "test").is_err());
        // Unsorted map.
        assert_eq!(
            decode(
                &hex::decode("a2020101 01".replace(' ', "")).unwrap(),
                64,
                "test"
            ),
            Err(CoreError::NonDeterministic("test"))
        );
        assert_eq!(
            decode(&canonical, 2, "test"),
            Err(CoreError::TooLarge("test"))
        );
        assert!(decode(&[0xff], 64, "test").is_err());
    }

    #[test]
    fn readers_check_shapes() {
        let value = array(vec![uint(7), bytes(&[9; 32]), text("label")]);
        let items = expect_array(value.clone(), 3, "t").unwrap();
        assert_eq!(expect_uint(&items[0], "t").unwrap(), 7);
        assert_eq!(expect_u32(&items[0], "t").unwrap(), 7);
        assert_eq!(expect_bytes32(items[1].clone(), "t").unwrap(), [9; 32]);
        expect_label(&items[2], "label", "t").unwrap();
        assert!(expect_label(&items[2], "other", "t").is_err());
        assert!(expect_array(value.clone(), 2, "t").is_err());
        assert_eq!(expect_list(value, "t").unwrap().len(), 3);
        assert!(expect_list(uint(1), "t").is_err());
        assert!(expect_uint(&text("x"), "t").is_err());
        assert!(expect_uint(&Value::Integer(Integer::from(-1i64)), "t").is_err());
        assert!(expect_u32(&uint(u64::MAX), "t").is_err());
        assert!(expect_bytes(uint(1), "t").is_err());
        assert!(expect_bytes32(bytes(&[1; 31]), "t").is_err());
    }
}
