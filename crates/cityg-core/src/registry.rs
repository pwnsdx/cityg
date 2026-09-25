//! Group registry: the group-wide state kept beside the tree.
//!
//! ```text
//! registry_hash := H_L("registry", [capacity,
//!                                   [admin leaf, ... increasing],
//!                                   [[admission_hash, expires_epoch], ... oldest first],
//!                                   retired_floor])
//! ```
//!
//! * `capacity`: the largest number of leaves, fixed at genesis.
//! * Admins are named by their leaf: admin rights belong to an occupancy and
//!   end with it (a removal), survive a resync of the same leaf and a
//!   rotation of the device key. At most [`MAX_ADMINS`].
//! * Retired admissions: the admission of an occupancy that ended by a
//!   removal cannot be used again while it is valid. An admission is valid
//!   for at most [`MAX_ADMISSION_EPOCHS`] epochs, so the entry of a member
//!   that joined at epoch `since` expires at `since + MAX_ADMISSION_EPOCHS`
//!   and is dropped once that epoch has passed. At most [`MAX_RETIRED`]
//!   entries are kept, the oldest going first; dropping an entry that has
//!   not expired raises `retired_floor` to its expiry, and an admission is
//!   only valid if its last epoch is above the floor. A removed member thus
//!   never comes back with its admission, however many members leave.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ciborium::value::Value;

use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes32, expect_list, expect_u32,
    expect_uint, uint,
};
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, ZERO32, h_l};
use crate::tree::{LeafNode, PublicTree, next, validate_capacity};

/// Maximum number of admins of a group.
pub const MAX_ADMINS: usize = 64;
/// Number of retired admissions a registry keeps (the oldest go first,
/// raising the retired floor).
pub const MAX_RETIRED: usize = 4096;
/// Longest validity of an admission, in epochs: an admission used at epoch
/// `n` must name a last epoch between `n` and `n + MAX_ADMISSION_EPOCHS`.
pub const MAX_ADMISSION_EPOCHS: u64 = 4096;

/// The membership of one epoch: the members and the registry (admins,
/// retired admissions). Signed objects are authorized against it.
///
/// A full member knows every member (the tree). A light member only knows
/// the members whose records it verified with a [`crate::tree::LeafProof`]:
/// lookups outside that set find nothing, so an authorization that needs an
/// unproven member fails, and the only check it cannot make is that a
/// joining device is not already a member elsewhere in the tree.
#[derive(Clone, Copy, Debug)]
pub struct Membership<'a> {
    members: Members<'a>,
    pub registry: &'a Registry,
}

#[derive(Clone, Copy, Debug)]
enum Members<'a> {
    Tree(&'a PublicTree),
    Proven(&'a BTreeMap<u32, LeafNode>),
}

impl<'a> Membership<'a> {
    /// Membership of a full tree.
    #[must_use]
    pub fn new(tree: &'a PublicTree, registry: &'a Registry) -> Self {
        Self {
            members: Members::Tree(tree),
            registry,
        }
    }

    /// Membership restricted to proven member records, by leaf.
    #[must_use]
    pub fn proven(members: &'a BTreeMap<u32, LeafNode>, registry: &'a Registry) -> Self {
        Self {
            members: Members::Proven(members),
            registry,
        }
    }

    /// Member in `leaf`.
    #[must_use]
    pub fn leaf(&self, leaf: u32) -> Option<&'a LeafNode> {
        match self.members {
            Members::Tree(tree) => tree.leaf(leaf),
            Members::Proven(members) => members.get(&leaf),
        }
    }

    /// Member occupying `leaf` since epoch `since`.
    #[must_use]
    pub fn member(&self, leaf: u32, since: u64) -> Option<&'a LeafNode> {
        self.leaf(leaf).filter(|member| member.since == since)
    }

    /// Leaf and record of the member whose device key is `device_pk`.
    #[must_use]
    pub fn member_by_device(&self, device_pk: &[u8]) -> Option<(u32, &'a LeafNode)> {
        match self.members {
            Members::Tree(tree) => {
                let leaf = tree.find_device(device_pk)?;
                tree.leaf(leaf).map(|member| (leaf, member))
            }
            Members::Proven(members) => members
                .iter()
                .find(|(_, member)| member.device_pk == device_pk)
                .map(|(leaf, member)| (*leaf, member)),
        }
    }

    /// Whether `device_pk` is the device key of an admin.
    #[must_use]
    pub fn is_admin_key(&self, device_pk: &[u8]) -> bool {
        self.member_by_device(device_pk)
            .is_some_and(|(leaf, _)| self.registry.is_admin(leaf))
    }
}

/// Admission of an ended occupancy, unusable until `expires_epoch` passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredAdmission {
    pub admission_hash: Digest,
    pub expires_epoch: u64,
}

/// Capacity, admins and retired admissions of a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registry {
    capacity: u32,
    admins: BTreeSet<u32>,
    retired: VecDeque<RetiredAdmission>,
    retired_floor: u64,
}

impl Registry {
    /// Registry of a new group: its creator, in leaf 0, is the only admin.
    pub fn genesis(capacity: u32) -> CoreResult<Self> {
        validate_capacity(capacity)?;
        Ok(Self {
            capacity,
            admins: BTreeSet::from([0]),
            retired: VecDeque::new(),
            retired_floor: 0,
        })
    }

    /// Largest number of leaves of the group.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Admin leaves, increasing.
    pub fn admins(&self) -> impl Iterator<Item = u32> + '_ {
        self.admins.iter().copied()
    }

    /// Whether the member in `leaf` is an admin.
    #[must_use]
    pub fn is_admin(&self, leaf: u32) -> bool {
        self.admins.contains(&leaf)
    }

    /// Make the member in `leaf` an admin.
    pub fn grant_admin(&mut self, leaf: u32) -> CoreResult<()> {
        if self.admins.insert(leaf) && self.admins.len() > MAX_ADMINS {
            self.admins.remove(&leaf);
            return Err(CoreError::TooLarge("admins"));
        }
        Ok(())
    }

    /// Withdraw the admin rights of the member in `leaf`.
    pub fn revoke_admin(&mut self, leaf: u32) -> CoreResult<()> {
        if !self.admins.remove(&leaf) {
            return Err(CoreError::Invalid("revoked member is not an admin"));
        }
        Ok(())
    }

    /// End the admin rights of a removed member (no-op for other members).
    pub fn forget_leaf(&mut self, leaf: u32) {
        self.admins.remove(&leaf);
    }

    /// Whether some admin remains.
    #[must_use]
    pub fn has_admin(&self) -> bool {
        !self.admins.is_empty()
    }

    /// Retired admissions, oldest first.
    pub fn retired(&self) -> impl Iterator<Item = &RetiredAdmission> {
        self.retired.iter()
    }

    /// Whether `admission_hash` belongs to an ended occupancy.
    #[must_use]
    pub fn is_retired(&self, admission_hash: &Digest) -> bool {
        self.retired
            .iter()
            .any(|entry| entry.admission_hash == *admission_hash)
    }

    /// Largest expiry of a retired admission dropped before it expired:
    /// admissions whose last epoch is not above it are refused.
    #[must_use]
    pub fn retired_floor(&self) -> u64 {
        self.retired_floor
    }

    /// Last epoch to give an admission made while `epoch` is current, so
    /// that it stays usable for about `validity` epochs: `epoch + validity`,
    /// raised above the retired floor, and at most `epoch +
    /// MAX_ADMISSION_EPOCHS`.
    #[must_use]
    pub fn admission_not_after(&self, epoch: u64, validity: u64) -> u64 {
        epoch
            .saturating_add(validity)
            .max(self.retired_floor.saturating_add(1))
            .min(epoch.saturating_add(MAX_ADMISSION_EPOCHS))
    }

    /// Drop the retired admissions that expired before `epoch`.
    pub fn prune(&mut self, epoch: u64) {
        self.retired.retain(|entry| entry.expires_epoch >= epoch);
    }

    /// Retire the admission of an occupancy that began at epoch `since` and
    /// ends with the commit of `epoch`, unless it can no longer be used.
    pub fn retire(&mut self, admission_hash: &Digest, since: u64, epoch: u64) {
        let expires_epoch = since.saturating_add(MAX_ADMISSION_EPOCHS);
        if *admission_hash == ZERO32 || expires_epoch < epoch || self.is_retired(admission_hash) {
            return;
        }
        self.retired.push_back(RetiredAdmission {
            admission_hash: *admission_hash,
            expires_epoch,
        });
        while self.retired.len() > MAX_RETIRED {
            if let Some(dropped) = self.retired.pop_front() {
                self.retired_floor = self.retired_floor.max(dropped.expires_epoch);
            }
        }
    }

    fn to_value(&self) -> Value {
        array(vec![
            uint(u64::from(self.capacity)),
            array(
                self.admins
                    .iter()
                    .map(|leaf| uint(u64::from(*leaf)))
                    .collect(),
            ),
            array(
                self.retired
                    .iter()
                    .map(|entry| {
                        array(vec![
                            bytes(&entry.admission_hash),
                            uint(entry.expires_epoch),
                        ])
                    })
                    .collect(),
            ),
            uint(self.retired_floor),
        ])
    }

    /// `registry_hash`, bound into every GroupContext.
    pub fn registry_hash(&self) -> CoreResult<Digest> {
        let Value::Array(args) = self.to_value() else {
            return Err(CoreError::Malformed("registry"));
        };
        h_l("registry", args)
    }

    /// Deterministic CBOR encoding.
    pub fn to_cbor(&self) -> CoreResult<Vec<u8>> {
        encode(&self.to_value())
    }

    /// Decode a registry and check its invariants.
    pub fn from_cbor(encoded: &[u8]) -> CoreResult<Self> {
        let mut items =
            expect_array(decode(encoded, 1 << 20, "registry")?, 4, "registry")?.into_iter();
        let capacity = expect_u32(&next(&mut items, "registry")?, "registry capacity")?;
        validate_capacity(capacity)?;
        let admin_list = expect_list(next(&mut items, "registry")?, "registry admins")?
            .iter()
            .map(|leaf| expect_u32(leaf, "registry admin"))
            .collect::<CoreResult<Vec<_>>>()?;
        if admin_list.len() > MAX_ADMINS
            || admin_list.windows(2).any(|pair| pair[0] >= pair[1])
            || admin_list.iter().any(|leaf| *leaf >= capacity)
        {
            return Err(CoreError::Malformed("registry admins"));
        }
        let mut registry = Self {
            capacity,
            admins: admin_list.into_iter().collect(),
            retired: VecDeque::new(),
            retired_floor: 0,
        };
        for entry in expect_list(next(&mut items, "registry")?, "registry retired")? {
            let mut fields = expect_array(entry, 2, "retired admission")?.into_iter();
            let admission_hash =
                expect_bytes32(next(&mut fields, "retired admission")?, "retired admission")?;
            let expires_epoch =
                expect_uint(&next(&mut fields, "retired admission")?, "retired expiry")?;
            if admission_hash == ZERO32 || registry.is_retired(&admission_hash) {
                return Err(CoreError::Malformed("registry retired"));
            }
            registry.retired.push_back(RetiredAdmission {
                admission_hash,
                expires_epoch,
            });
        }
        if registry.retired.len() > MAX_RETIRED {
            return Err(CoreError::Malformed("registry retired"));
        }
        registry.retired_floor = expect_uint(&next(&mut items, "registry")?, "retired floor")?;
        Ok(registry)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn genesis_admins_and_hash() {
        let mut registry = Registry::genesis(8).unwrap();
        assert!(Registry::genesis(3).is_err());
        assert_eq!(registry.capacity(), 8);
        assert!(registry.is_admin(0) && registry.has_admin());
        let genesis_hash = registry.registry_hash().unwrap();
        registry.grant_admin(3).unwrap();
        registry.grant_admin(3).unwrap();
        assert_eq!(registry.admins().collect::<Vec<_>>(), vec![0, 3]);
        assert_ne!(registry.registry_hash().unwrap(), genesis_hash);
        registry.revoke_admin(0).unwrap();
        assert_eq!(
            registry.revoke_admin(0),
            Err(CoreError::Invalid("revoked member is not an admin"))
        );
        registry.forget_leaf(3);
        registry.forget_leaf(5);
        assert!(!registry.has_admin());
        let mut registry = Registry::genesis(128).unwrap();
        for leaf in 1..64 {
            registry.grant_admin(leaf).unwrap();
        }
        assert_eq!(
            registry.grant_admin(100),
            Err(CoreError::TooLarge("admins"))
        );
        assert!(!registry.is_admin(100));
        let decoded = Registry::from_cbor(&registry.to_cbor().unwrap()).unwrap();
        assert_eq!(decoded, registry);
    }

    #[test]
    fn retired_admissions_expire_and_are_bounded() {
        let mut registry = Registry::genesis(8).unwrap();
        registry.retire(&ZERO32, 0, 1);
        assert_eq!(
            registry.retired().count(),
            0,
            "the creator has no admission"
        );
        registry.retire(&[1; 32], 10, 20);
        registry.retire(&[1; 32], 10, 20);
        assert_eq!(registry.retired().count(), 1, "no duplicate");
        assert!(registry.is_retired(&[1; 32]));
        // An admission that can no longer be used is not retired.
        registry.retire(&[2; 32], 0, MAX_ADMISSION_EPOCHS + 1);
        assert!(!registry.is_retired(&[2; 32]));
        registry.prune(10 + MAX_ADMISSION_EPOCHS);
        assert!(registry.is_retired(&[1; 32]));
        registry.prune(11 + MAX_ADMISSION_EPOCHS);
        assert!(!registry.is_retired(&[1; 32]));

        for index in 0..=MAX_RETIRED {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            registry.retire(&hash, 100, 100);
        }
        assert_eq!(registry.retired().count(), MAX_RETIRED);
        let mut first = [0u8; 32];
        first[..8].copy_from_slice(&1u64.to_be_bytes());
        assert!(!registry.is_retired(&first), "the oldest entry went first");
        // It had not expired: the floor now shuts out every admission that
        // could have been it.
        assert_eq!(registry.retired_floor(), 100 + MAX_ADMISSION_EPOCHS);
        let decoded = Registry::from_cbor(&registry.to_cbor().unwrap()).unwrap();
        assert_eq!(decoded, registry);
        assert_eq!(
            decoded.registry_hash().unwrap(),
            registry.registry_hash().unwrap()
        );
        registry.prune(200);
        assert_eq!(registry.retired_floor(), 100 + MAX_ADMISSION_EPOCHS);
    }

    #[test]
    fn admissions_are_given_a_last_epoch_above_the_floor() {
        let mut registry = Registry::genesis(8).unwrap();
        assert_eq!(registry.admission_not_after(10, 1024), 1034);
        assert_eq!(
            registry.admission_not_after(u64::MAX - 1, 1024),
            u64::MAX,
            "saturates"
        );
        registry.retired_floor = 3000;
        assert_eq!(registry.admission_not_after(10, 1024), 3001);
        registry.retired_floor = 10 + MAX_ADMISSION_EPOCHS;
        assert_eq!(
            registry.admission_not_after(10, 1024),
            10 + MAX_ADMISSION_EPOCHS,
            "never beyond the longest validity"
        );
    }

    #[test]
    fn malformed_registries_are_rejected() {
        let registry = Registry::genesis(4).unwrap();
        let encode_with = |admins: Vec<Value>, retired: Vec<Value>| {
            encode(&array(vec![
                uint(4),
                array(admins),
                array(retired),
                uint(0),
            ]))
            .unwrap()
        };
        assert!(Registry::from_cbor(&registry.to_cbor().unwrap()).is_ok());
        assert_eq!(
            Registry::from_cbor(&encode_with(vec![uint(2), uint(1)], vec![])),
            Err(CoreError::Malformed("registry admins"))
        );
        assert_eq!(
            Registry::from_cbor(&encode_with(vec![uint(4)], vec![])),
            Err(CoreError::Malformed("registry admins"))
        );
        let entry = |hash: [u8; 32]| array(vec![bytes(&hash), uint(9)]);
        assert_eq!(
            Registry::from_cbor(&encode_with(vec![], vec![entry([1; 32]), entry([1; 32])])),
            Err(CoreError::Malformed("registry retired"))
        );
        assert_eq!(
            Registry::from_cbor(&encode_with(vec![], vec![entry(ZERO32)])),
            Err(CoreError::Malformed("registry retired"))
        );
        assert!(
            Registry::from_cbor(
                &encode(&array(vec![uint(3), array(vec![]), array(vec![]), uint(0)])).unwrap()
            )
            .is_err()
        );
        assert!(
            Registry::from_cbor(
                &encode(&array(vec![uint(4), array(vec![]), array(vec![])])).unwrap()
            )
            .is_err(),
            "the floor is required"
        );
    }
}
