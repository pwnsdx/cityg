//! Registry of profile v0.4-draft (docs/specs-v0.4-draft.md section 8).
//!
//! ```text
//! registry_hash := H_L("registry", [[[admin, admin_pk], ...], devices_root,
//!                                   admissions_root, policy_hash or null, open])
//! ```
//!
//! * the admins, as occupancies with their device keys, in occupancy order;
//! * `devices`: `device_id` of every member → its occupancy;
//! * `admissions`: hash of every admission ever used (of the join request,
//!   for a join without admission) → the occupancy it admitted: an admission
//!   is good for one join;
//! * the hash of the group policy in force, if any, and whether it opens the
//!   group (`open`, 0 or 1; a group without policy is closed).
//!
//! Members keep the [`RegistryHeader`] (admins, roots, policy hash); the
//! delivery service and committers keep the maps.

use std::collections::{BTreeMap, BTreeSet};

use ciborium::value::Value;
use cityg_core::cbor::{array, bytes, uint};
use cityg_core::error::{CoreError, CoreResult};
use cityg_core::hash::Digest;

use crate::crypto::h_l;
use crate::smm::{Smm, SmmDelta, SmmProof};
use crate::tree::Occupancy;

/// What a member keeps of the registry: enough to recompute its hash, check
/// admin signatures and check map proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryHeader {
    pub admins: BTreeMap<Occupancy, Vec<u8>>,
    pub devices_root: Digest,
    pub admissions_root: Digest,
    pub policy: Option<Digest>,
    /// Whether the group is open: a join needs no admission.
    pub open: bool,
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
                self.policy.as_ref().map_or(Value::Null, |p| bytes(p)),
                uint(u64::from(self.open)),
            ],
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
    /// `Some((hash, open))` when the window sets the group policy.
    pub policy: Option<(Digest, bool)>,
}

/// The full registry.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    admins: BTreeMap<Occupancy, Vec<u8>>,
    devices: Smm,
    admissions: Smm,
    policy: Option<Digest>,
    open: bool,
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

    /// Hash of the group policy in force.
    #[must_use]
    pub const fn policy(&self) -> Option<&Digest> {
        self.policy.as_ref()
    }

    /// Whether the group is open: a join needs no admission.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.open
    }

    /// Proof of the entry (or absence) of `device_id`.
    pub fn device_proof(&self, device_id: &Digest) -> CoreResult<SmmProof> {
        self.devices.prove(device_id)
    }

    /// Proof of the entry (or absence) of `admission_hash`.
    pub fn admission_proof(&self, admission_hash: &Digest) -> CoreResult<SmmProof> {
        self.admissions.prove(admission_hash)
    }

    /// The header of the registry.
    pub fn header(&self) -> CoreResult<RegistryHeader> {
        Ok(RegistryHeader {
            admins: self.admins.clone(),
            devices_root: self.devices.root()?,
            admissions_root: self.admissions.root()?,
            policy: self.policy,
            open: self.open,
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
            policy: delta.policy.map(|(hash, _)| hash).or(self.policy),
            open: delta.policy.map_or(self.open, |(_, open)| open),
        })
    }

    /// Apply `delta`.
    pub fn apply(&mut self, delta: &RegistryDelta) {
        self.admins = self.admins_with(delta);
        self.devices.apply(&delta.devices);
        self.admissions.apply(&delta.admissions);
        if let Some((hash, open)) = delta.policy {
            self.policy = Some(hash);
            self.open = open;
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
        next.policy = Some(([4; 32], true));
        let predicted = registry.header_with(&next).unwrap();
        assert_ne!(predicted.hash().unwrap(), header.hash().unwrap());
        registry.apply(&next);
        assert_eq!(registry.header().unwrap(), predicted);
        assert!(!registry.is_admin(admin));
        assert_eq!(registry.policy(), Some(&[4; 32]));
        assert!(registry.is_open());
        let mut closed = registry.header().unwrap();
        closed.open = false;
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
