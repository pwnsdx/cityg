//! Registry (docs/specs.md section 8, with the map of keys of
//! docs/specs-v0.5-draft.md section 4.2).
//!
//! ```text
//! registry_hash := H_L("registry", [[[admin, admin_pk], ...], devices_root,
//!                                   admissions_root, keys_root, policy_hash or null,
//!                                   admission_mode, authorizer_pk_hash or null])
//! ```
//!
//! * the admins, as occupancies with their device keys, in occupancy order;
//! * `devices`: `device_id` of every member → its occupancy;
//! * `admissions`: hash of every admission ever used (of the join request,
//!   for a join without admission) → the occupancy it admitted: an admission
//!   is good for one join;
//! * `keys`: the hash of every leaf key and card of the tree → the occupancy
//!   that holds it: no key twice;
//! * the hash of the group policy in force, if any, its admission mode (0
//!   closed, 1 open, 2 authorized; a group without policy is closed), and
//!   the hash of the authorizer's key in an authorized group.
//!
//! Members keep the [`RegistryHeader`] (admins, roots, policy hash); the
//! delivery service and committers keep the maps.

use std::collections::{BTreeMap, BTreeSet};

use ciborium::value::Value;

use crate::cbor::{array, bytes, uint};
use crate::crypto::{Digest, h_l};
use crate::error::{CoreError, CoreResult};
use crate::objects::{AdmissionMode, Admitters};
use crate::smm::{Smm, SmmDelta, SmmProof};
use crate::tree::Occupancy;

/// What a member keeps of the registry: enough to recompute its hash, check
/// admin signatures and check map proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryHeader {
    pub admins: BTreeMap<Occupancy, Vec<u8>>,
    pub devices_root: Digest,
    pub admissions_root: Digest,
    pub keys_root: Digest,
    pub policy: Option<Digest>,
    pub admission: AdmissionMode,
    /// `H_L("authorizer", [authorizer_pk])` in an authorized group.
    pub authorizer: Option<Digest>,
}

impl RegistryHeader {
    /// `registry_hash`.
    pub fn hash(&self) -> CoreResult<Digest> {
        h_l(
            "registry",
            vec![
                array(
                    self.admins
                        .iter()
                        .map(|(occupancy, key)| array(vec![occupancy.value(), bytes(key)]))
                        .collect(),
                ),
                bytes(&self.devices_root),
                bytes(&self.admissions_root),
                bytes(&self.keys_root),
                self.policy.as_ref().map_or(Value::Null, |p| bytes(p)),
                uint(self.admission.code()),
                self.authorizer.as_ref().map_or(Value::Null, |a| bytes(a)),
            ],
        )
    }

    /// Whether the group is open: a join needs no admission.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.admission == AdmissionMode::Open
    }

    /// Who may admit and remove devices under this registry; in an
    /// authorized group, with the authorizer's key, which must match the
    /// registry's hash of it.
    pub fn admitters<'a>(&'a self, authorizer_pk: Option<&'a [u8]>) -> CoreResult<Admitters<'a>> {
        Admitters::new(
            &self.admins,
            self.admission,
            self.authorizer.as_ref(),
            authorizer_pk,
        )
    }

    /// Device key of admin `occupancy`.
    #[must_use]
    pub fn admin_key(&self, occupancy: Occupancy) -> Option<&[u8]> {
        self.admins.get(&occupancy).map(Vec::as_slice)
    }

    /// Check that `device_id` is not a member, with a proof against
    /// `devices_root`.
    pub fn check_new_device(&self, device_id: &Digest, proof: &SmmProof) -> CoreResult<()> {
        match proof.verify(&self.devices_root, device_id)? {
            None => Ok(()),
            Some(_) => Err(CoreError::Invalid("device already a member")),
        }
    }

    /// Check that `admission_hash` was never used, with a proof against
    /// `admissions_root`.
    pub fn check_unused_admission(
        &self,
        admission_hash: &Digest,
        proof: &SmmProof,
    ) -> CoreResult<()> {
        match proof.verify(&self.admissions_root, admission_hash)? {
            None => Ok(()),
            Some(_) => Err(CoreError::Invalid("admission already used")),
        }
    }
}

/// Changes a window makes to the registry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegistryDelta {
    pub admins_removed: BTreeSet<Occupancy>,
    pub admins_added: BTreeMap<Occupancy, Vec<u8>>,
    pub devices: SmmDelta,
    pub admissions: SmmDelta,
    pub keys: SmmDelta,
    /// The policy's hash, admission mode and authorizer's key hash, when
    /// the window sets the group policy.
    pub policy: Option<(Digest, AdmissionMode, Option<Digest>)>,
}

/// The full registry.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    admins: BTreeMap<Occupancy, Vec<u8>>,
    devices: Smm,
    admissions: Smm,
    keys: Smm,
    policy: Option<Digest>,
    admission: AdmissionMode,
    authorizer: Option<Digest>,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admins and their device keys.
    #[must_use]
    pub const fn admins(&self) -> &BTreeMap<Occupancy, Vec<u8>> {
        &self.admins
    }

    /// Whether `occupancy` is an admin.
    #[must_use]
    pub fn is_admin(&self, occupancy: Occupancy) -> bool {
        self.admins.contains_key(&occupancy)
    }

    /// Occupancy of the member with `device_id`.
    #[must_use]
    pub fn device(&self, device_id: &Digest) -> Option<Occupancy> {
        self.devices.get(device_id)
    }

    /// Occupancy admitted by `admission_hash`, if it was used.
    #[must_use]
    pub fn admission(&self, admission_hash: &Digest) -> Option<Occupancy> {
        self.admissions.get(admission_hash)
    }

    /// Occupancy that holds the leaf key or card whose hash is `key_hash`.
    #[must_use]
    pub fn key(&self, key_hash: &Digest) -> Option<Occupancy> {
        self.keys.get(key_hash)
    }

    /// Hash of the group policy in force.
    #[must_use]
    pub const fn policy(&self) -> Option<&Digest> {
        self.policy.as_ref()
    }

    /// Whether the group is open: a join needs no admission.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.admission == AdmissionMode::Open
    }

    /// The admission mode in force.
    #[must_use]
    pub const fn admission_mode(&self) -> AdmissionMode {
        self.admission
    }

    /// Who may admit and remove devices; in an authorized group, with the
    /// authorizer's key, which must match the registry's hash of it.
    pub fn admitters<'a>(&'a self, authorizer_pk: Option<&'a [u8]>) -> CoreResult<Admitters<'a>> {
        Admitters::new(
            &self.admins,
            self.admission,
            self.authorizer.as_ref(),
            authorizer_pk,
        )
    }

    /// Proof of the entry (or absence) of `device_id`.
    pub fn device_proof(&self, device_id: &Digest) -> CoreResult<SmmProof> {
        self.devices.prove(device_id)
    }

    /// Proof of the entry (or absence) of `admission_hash`.
    pub fn admission_proof(&self, admission_hash: &Digest) -> CoreResult<SmmProof> {
        self.admissions.prove(admission_hash)
    }

    /// Proof of the entry (or absence) of `key_hash`.
    pub fn key_proof(&self, key_hash: &Digest) -> CoreResult<SmmProof> {
        self.keys.prove(key_hash)
    }

    /// The header of the registry.
    pub fn header(&self) -> CoreResult<RegistryHeader> {
        Ok(RegistryHeader {
            admins: self.admins.clone(),
            devices_root: self.devices.root()?,
            admissions_root: self.admissions.root()?,
            keys_root: self.keys.root()?,
            policy: self.policy,
            admission: self.admission,
            authorizer: self.authorizer,
        })
    }

    /// Admins after `delta`.
    #[must_use]
    pub fn admins_with(&self, delta: &RegistryDelta) -> BTreeMap<Occupancy, Vec<u8>> {
        let mut admins = self.admins.clone();
        for removed in &delta.admins_removed {
            admins.remove(removed);
        }
        for (occupancy, key) in &delta.admins_added {
            admins.insert(*occupancy, key.clone());
        }
        admins
    }

    /// The header after `delta`, without applying it.
    pub fn header_with(&self, delta: &RegistryDelta) -> CoreResult<RegistryHeader> {
        Ok(RegistryHeader {
            admins: self.admins_with(delta),
            devices_root: self.devices.root_with(&delta.devices)?,
            admissions_root: self.admissions.root_with(&delta.admissions)?,
            keys_root: self.keys.root_with(&delta.keys)?,
            policy: delta.policy.map(|(hash, _, _)| hash).or(self.policy),
            admission: delta.policy.map_or(self.admission, |(_, mode, _)| mode),
            authorizer: delta
                .policy
                .map_or(self.authorizer, |(_, _, authorizer)| authorizer),
        })
    }

    /// Apply `delta`.
    pub fn apply(&mut self, delta: &RegistryDelta) {
        self.admins = self.admins_with(delta);
        self.devices.apply(&delta.devices);
        self.admissions.apply(&delta.admissions);
        self.keys.apply(&delta.keys);
        if let Some((hash, mode, authorizer)) = delta.policy {
            self.policy = Some(hash);
            self.admission = mode;
            self.authorizer = authorizer;
        }
    }

    /// Number of members in the device map.
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn deltas_predict_the_applied_header() {
        let mut registry = Registry::new();
        let admin = Occupancy { leaf: 0, since: 0 };
        let mut delta = RegistryDelta::default();
        delta.admins_added.insert(admin, vec![1; 4]);
        delta.devices.insert([1; 32], Some(admin));
        let header = registry.header_with(&delta).unwrap();
        registry.apply(&delta);
        assert_eq!(registry.header().unwrap(), header);
        assert!(registry.is_admin(admin));
        assert_eq!(registry.device(&[1; 32]), Some(admin));
        let member = Occupancy { leaf: 1, since: 1 };
        let mut next = RegistryDelta::default();
        next.admins_removed.insert(admin);
        next.devices.insert([2; 32], Some(member));
        next.admissions.insert([3; 32], Some(member));
        next.keys.insert([5; 32], Some(member));
        next.policy = Some(([4; 32], AdmissionMode::Open, None));
        let predicted = registry.header_with(&next).unwrap();
        assert_ne!(predicted.hash().unwrap(), header.hash().unwrap());
        registry.apply(&next);
        assert_eq!(registry.header().unwrap(), predicted);
        assert!(!registry.is_admin(admin));
        assert_eq!(registry.policy(), Some(&[4; 32]));
        assert!(registry.is_open());
        assert_eq!(registry.key(&[5; 32]), Some(member));
        let mut closed = registry.header().unwrap();
        closed.admission = AdmissionMode::Closed;
        assert_ne!(
            closed.hash().unwrap(),
            registry.header().unwrap().hash().unwrap()
        );
        let header = registry.header().unwrap();
        header
            .check_new_device(&[9; 32], &registry.device_proof(&[9; 32]).unwrap())
            .unwrap();
        assert!(
            header
                .check_new_device(&[2; 32], &registry.device_proof(&[2; 32]).unwrap())
                .is_err()
        );
        assert!(
            header
                .check_unused_admission(&[3; 32], &registry.admission_proof(&[3; 32]).unwrap())
                .is_err()
        );
    }
}
