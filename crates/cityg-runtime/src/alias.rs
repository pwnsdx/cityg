use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// NFC-normalized alias binding tracked under TOFU semantics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasBinding {
    pub leaf_id: [u8; 32],
    pub pop_public_key: Vec<u8>,
}

/// Leaf-indexed alias materialization used by member listing endpoints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasLeafEntry {
    pub alias: String,
    pub pop_public_key: Vec<u8>,
}

pub type AliasLeafLookup = BTreeMap<[u8; 32], AliasLeafEntry>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliasRegistrationOutcome {
    Registered,
    MatchedExisting,
    UpdatedLeafBinding,
}

impl AliasRegistrationOutcome {
    #[must_use]
    pub const fn is_new(self) -> bool {
        matches!(self, Self::Registered)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AliasRegistrationError {
    #[error("alias already bound to a different identity")]
    Conflict,
}

/// Shared alias registry with native/Worker parity semantics.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasRegistry {
    bindings: BTreeMap<String, AliasBinding>,
}

impl AliasRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    #[must_use]
    pub fn contains_key(&self, alias: &str) -> bool {
        let normalized = normalize_alias(alias);
        self.bindings.contains_key(normalized.as_str())
    }

    #[must_use]
    pub fn get(&self, alias: &str) -> Option<&AliasBinding> {
        let normalized = normalize_alias(alias);
        self.bindings.get(normalized.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &AliasBinding)> {
        self.bindings
            .iter()
            .map(|(alias, binding)| (alias.as_str(), binding))
    }

    pub fn register_alias(
        &mut self,
        alias: &str,
        leaf_id: [u8; 32],
        pop_public_key: Vec<u8>,
    ) -> Result<AliasRegistrationOutcome, AliasRegistrationError> {
        let normalized = normalize_alias(alias);
        match self.bindings.get_mut(normalized.as_str()) {
            Some(existing) if existing.pop_public_key == pop_public_key => {
                if existing.leaf_id == leaf_id {
                    Ok(AliasRegistrationOutcome::MatchedExisting)
                } else {
                    existing.leaf_id = leaf_id;
                    Ok(AliasRegistrationOutcome::UpdatedLeafBinding)
                }
            }
            Some(_) => Err(AliasRegistrationError::Conflict),
            None => {
                self.bindings.insert(
                    normalized,
                    AliasBinding {
                        leaf_id,
                        pop_public_key,
                    },
                );
                Ok(AliasRegistrationOutcome::Registered)
            }
        }
    }

    pub fn remove_revoked_members(&mut self, revoked: &HashSet<[u8; 32]>) -> usize {
        if revoked.is_empty() {
            return 0;
        }
        let before = self.bindings.len();
        self.bindings
            .retain(|_, binding| !revoked.contains(&binding.leaf_id));
        before.saturating_sub(self.bindings.len())
    }

    pub fn remove_revoked_slice(&mut self, revoked: &[[u8; 32]]) -> usize {
        if revoked.is_empty() {
            return 0;
        }
        let revoked = revoked.iter().copied().collect::<HashSet<_>>();
        self.remove_revoked_members(&revoked)
    }

    #[must_use]
    pub fn leaf_lookup(&self) -> AliasLeafLookup {
        self.iter()
            .map(|(alias, binding)| {
                (
                    binding.leaf_id,
                    AliasLeafEntry {
                        alias: alias.to_string(),
                        pop_public_key: binding.pop_public_key.clone(),
                    },
                )
            })
            .collect()
    }

    #[must_use]
    pub fn leaf_lookup_for<I>(&self, leaves: I) -> AliasLeafLookup
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        let leaves = leaves.into_iter().collect::<HashSet<_>>();
        self.iter()
            .filter_map(|(alias, binding)| {
                leaves.get(&binding.leaf_id).map(|leaf_id| {
                    (
                        *leaf_id,
                        AliasLeafEntry {
                            alias: alias.to_string(),
                            pop_public_key: binding.pop_public_key.clone(),
                        },
                    )
                })
            })
            .collect()
    }
}

#[must_use]
pub fn normalize_alias(alias: &str) -> String {
    alias.nfc().collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn register_alias_covers_match_update_and_conflict() {
        let mut registry = AliasRegistry::default();
        let alias = "alice";
        let leaf_a = [0x11; 32];
        let leaf_b = [0x22; 32];
        let key_a = vec![0xAA; 8];
        let key_b = vec![0xBB; 8];

        assert_eq!(
            registry
                .register_alias(alias, leaf_a, key_a.clone())
                .expect("register new alias"),
            AliasRegistrationOutcome::Registered
        );
        assert_eq!(
            registry
                .register_alias(alias, leaf_a, key_a.clone())
                .expect("match existing alias"),
            AliasRegistrationOutcome::MatchedExisting
        );
        assert_eq!(
            registry
                .register_alias(alias, leaf_b, key_a.clone())
                .expect("update leaf binding"),
            AliasRegistrationOutcome::UpdatedLeafBinding
        );
        assert_eq!(
            registry
                .register_alias(alias, leaf_b, key_b)
                .expect_err("conflicting key must fail"),
            AliasRegistrationError::Conflict
        );
    }

    #[test]
    fn register_alias_normalizes_unicode_to_nfc() {
        let mut registry = AliasRegistry::default();
        let alias_nfc = "Café";
        let alias_nfd = "Cafe\u{301}";

        registry
            .register_alias(alias_nfd, [0x33; 32], vec![0x44; 8])
            .expect("register normalized alias");

        assert!(registry.contains_key(alias_nfc));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn revoked_leafs_are_unbound() {
        let mut registry = AliasRegistry::default();
        registry
            .register_alias("alice", [0xA1; 32], vec![0x11; 8])
            .expect("register alice");
        registry
            .register_alias("bob", [0xB2; 32], vec![0x22; 8])
            .expect("register bob");

        assert_eq!(registry.remove_revoked_slice(&[[0xA1; 32]]), 1);
        assert!(!registry.contains_key("alice"));
        assert!(registry.contains_key("bob"));
    }

    #[test]
    fn leaf_lookup_can_be_filtered() {
        let mut registry = AliasRegistry::default();
        registry
            .register_alias("alice", [0xA1; 32], vec![0x11; 8])
            .expect("register alice");
        registry
            .register_alias("bob", [0xB2; 32], vec![0x22; 8])
            .expect("register bob");

        let lookup = registry.leaf_lookup_for([[0xB2; 32]]);
        let entry = lookup.get(&[0xB2; 32]).expect("bob entry");
        assert_eq!(entry.alias, "bob");
        assert_eq!(entry.pop_public_key, vec![0x22; 8]);
        assert!(!lookup.contains_key(&[0xA1; 32]));
    }
}
