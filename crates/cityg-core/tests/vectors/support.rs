//! Shared helpers of the vector tests: a generator that replays the
//! randomness a vector lists, a sampler of inputs, hex and JSON helpers.

use std::collections::VecDeque;
use std::path::PathBuf;

use cityg_core::crypto::Digest;
use cityg_core::identity::DeviceIdentity;
use cityg_core::kem::KemSecret;
use cityg_core::tree::{NodeId, Occupancy};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde_json::{Value, json};

/// The directory of the vector files.
pub fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/vectors")
}

/// Read a vector file.
pub fn read(name: &str) -> Value {
    let path = dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("cannot parse {}: {error}", path.display()))
}

/// Write a vector file.
pub fn write(name: &str, value: &Value) {
    let path = dir().join(name);
    let mut text = serde_json::to_string_pretty(value).unwrap();
    text.push('\n');
    std::fs::write(&path, text)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
}

/// Fail unless `generated` is `file`, naming the first difference.
pub fn assert_same(file: &Value, generated: &Value) {
    if let Some(difference) = first_difference(file, generated, "$") {
        panic!(
            "the vectors differ from the file at {difference}; if the change is intended, \
             regenerate them with `cargo test -p cityg-core --test vectors write_vectors -- \
             --ignored`"
        );
    }
}

fn first_difference(file: &Value, generated: &Value, path: &str) -> Option<String> {
    match (file, generated) {
        (Value::Object(left), Value::Object(right)) => {
            for key in left
                .keys()
                .chain(right.keys().filter(|key| !left.contains_key(*key)))
            {
                let child = format!("{path}.{key}");
                match (left.get(key), right.get(key)) {
                    (Some(a), Some(b)) => {
                        if let Some(difference) = first_difference(a, b, &child) {
                            return Some(difference);
                        }
                    }
                    (Some(_), None) => return Some(format!("{child} (not generated)")),
                    (None, _) => return Some(format!("{child} (not in the file)")),
                }
            }
            None
        }
        (Value::Array(left), Value::Array(right)) => {
            if left.len() != right.len() {
                return Some(format!(
                    "{path} ({} items in the file, {} generated)",
                    left.len(),
                    right.len()
                ));
            }
            left.iter()
                .zip(right)
                .enumerate()
                .find_map(|(index, (a, b))| first_difference(a, b, &format!("{path}[{index}]")))
        }
        _ => {
            (file != generated).then(|| format!("{path}: {} vs {}", short(file), short(generated)))
        }
    }
}

fn short(value: &Value) -> String {
    let text = value.to_string();
    if text.len() > 72 {
        format!("{}...", &text[..72])
    } else {
        text
    }
}

/// A generator that hands out recorded bytes, in order, and nothing else:
/// an operation run on it draws exactly the randomness a vector lists.
pub struct Replay {
    bytes: VecDeque<u8>,
    short: bool,
}

impl Replay {
    fn new(parts: &[&[u8]]) -> Self {
        Self {
            bytes: parts.iter().flat_map(|part| part.iter().copied()).collect(),
            short: false,
        }
    }
}

impl RngCore for Replay {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            match self.bytes.pop_front() {
                Some(next) => *byte = next,
                None => {
                    self.short = true;
                    *byte = 0;
                }
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Replay {}

/// Run `operation` on the recorded randomness `parts`, which it must draw
/// in full and nothing beyond.
pub fn replay<T>(parts: &[&[u8]], operation: impl FnOnce(&mut Replay) -> T) -> T {
    let mut rng = Replay::new(parts);
    let out = operation(&mut rng);
    assert!(
        rng.bytes.is_empty() && !rng.short,
        "the operation drew other randomness than the vector lists"
    );
    out
}

/// A deterministic source of the inputs the vectors record.
pub struct Sampler {
    rng: ChaCha20Rng,
}

impl Sampler {
    pub fn new() -> Self {
        Self {
            rng: ChaCha20Rng::seed_from_u64(20_260_927),
        }
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.rng.fill_bytes(&mut out);
        out
    }

    pub fn seed(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.rng.fill_bytes(&mut out);
        out
    }

    pub fn device(&mut self) -> ([u8; 32], DeviceIdentity) {
        let seed = self.seed();
        (seed, DeviceIdentity::from_seed(&seed))
    }

    pub fn kem(&mut self) -> ([u8; 32], KemSecret) {
        let seed = self.seed();
        (seed, KemSecret::from_seed(seed))
    }
}

pub fn hex(bytes: &[u8]) -> Value {
    Value::String(hex::encode(bytes))
}

pub fn optional_hex(bytes: Option<&[u8]>) -> Value {
    bytes.map_or(Value::Null, hex)
}

pub fn unhex(value: &Value) -> Vec<u8> {
    hex::decode(
        value
            .as_str()
            .unwrap_or_else(|| panic!("not a string: {value}")),
    )
    .unwrap()
}

pub fn get<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
}

pub fn bytes(value: &Value, key: &str) -> Vec<u8> {
    unhex(get(value, key))
}

pub fn optional_bytes(value: &Value, key: &str) -> Option<Vec<u8>> {
    match get(value, key) {
        Value::Null => None,
        other => Some(unhex(other)),
    }
}

pub fn digest_of(value: &Value) -> Digest {
    unhex(value).try_into().unwrap()
}

pub fn digest(value: &Value, key: &str) -> Digest {
    digest_of(get(value, key))
}

pub fn uint(value: &Value, key: &str) -> u64 {
    get(value, key).as_u64().unwrap()
}

pub fn u32_of(value: &Value, key: &str) -> u32 {
    u32::try_from(uint(value, key)).unwrap()
}

pub fn u8_of(value: &Value, key: &str) -> u8 {
    u8::try_from(uint(value, key)).unwrap()
}

pub fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    get(value, key).as_str().unwrap()
}

pub fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    get(value, key).as_array().unwrap()
}

pub fn digest_list(value: &Value, key: &str) -> Vec<Digest> {
    list(value, key).iter().map(digest_of).collect()
}

pub fn occupancy(occupancy: Occupancy) -> Value {
    json!([occupancy.leaf, occupancy.since])
}

pub fn occupancy_of(value: &Value) -> Occupancy {
    let items = value.as_array().unwrap();
    Occupancy {
        leaf: u32::try_from(items[0].as_u64().unwrap()).unwrap(),
        since: items[1].as_u64().unwrap(),
    }
}

pub fn node(node: NodeId) -> Value {
    json!([node.level, node.index])
}

pub fn node_of(value: &Value) -> NodeId {
    let items = value.as_array().unwrap();
    NodeId {
        level: u8::try_from(items[0].as_u64().unwrap()).unwrap(),
        index: u32::try_from(items[1].as_u64().unwrap()).unwrap(),
    }
}
