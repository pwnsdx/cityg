//! Key-value storage of a Durable Object.

use std::{collections::BTreeMap, error::Error as StdError};

/// Durable Object storage as the room host uses it: byte values under
/// string keys, listed by prefix in key order.
///
/// The Cloudflare binding implements it over the object's SQLite storage;
/// tests use [`MemoryDurableObjectStorage`].
pub trait DurableObjectStorage {
    type Error: StdError + Send + Sync + 'static;

    fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, Self::Error>;

    fn put_bytes(&mut self, key: &str, value: Vec<u8>) -> Result<(), Self::Error>;

    fn delete_bytes(&mut self, key: &str) -> Result<(), Self::Error>;

    fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Self::Error>;
}

/// In-memory Durable Object storage useful for parity tests.
#[derive(Clone, Debug, Default)]
pub struct MemoryDurableObjectStorage {
    entries: BTreeMap<String, Vec<u8>>,
}

impl MemoryDurableObjectStorage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn entries(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.entries
    }
}

impl DurableObjectStorage for MemoryDurableObjectStorage {
    type Error = std::convert::Infallible;

    fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.entries.get(key).cloned())
    }

    fn put_bytes(&mut self, key: &str, value: Vec<u8>) -> Result<(), Self::Error> {
        self.entries.insert(key.to_owned(), value);
        Ok(())
    }

    fn delete_bytes(&mut self, key: &str) -> Result<(), Self::Error> {
        self.entries.remove(key);
        Ok(())
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Self::Error> {
        Ok(self
            .entries
            .range(prefix.to_owned()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_storage_lists_prefixes_in_key_order() {
        let mut storage = MemoryDurableObjectStorage::new();
        for key in ["a/2", "b/1", "a/1", "ab"] {
            storage
                .put_bytes(key, key.as_bytes().to_vec())
                .unwrap_or(());
        }
        let listed: Vec<String> = storage
            .list_prefix("a/")
            .unwrap_or_default()
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(listed, ["a/1", "a/2"]);
        assert_eq!(
            storage.get_bytes("b/1").unwrap_or_default(),
            Some(b"b/1".to_vec())
        );
        storage.delete_bytes("b/1").unwrap_or(());
        assert_eq!(storage.get_bytes("b/1").unwrap_or_default(), None);
        assert_eq!(storage.entries().len(), 3);
    }
}
