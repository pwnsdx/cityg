//! Group roster: members, admins and slot generations (audit P-4).
//!
//! ```text
//! MemberRecord := [leaf_id, device_pk, slot, generation, admission_hash]
//! roster_hash  := H_L("roster", [[MemberRecord sorted by slot],
//!                                [admin device keys, sorted],
//!                                [[slot, last_generation] sorted by slot]])
//! ```
//!
//! The roster hash enters every GroupContext, so every member and every
//! joiner agrees on who is in the group, who administers it and which slot
//! occupancy each member holds.

use std::collections::{BTreeMap, BTreeSet};

use ciborium::value::Value;

use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_list,
    expect_u32, expect_uint, uint,
};
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, h_l};
use crate::identity::leaf_id;
use crate::tree::next;

/// Maximum number of admins of a group.
pub const MAX_ADMINS: usize = 64;

/// One member of the group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRecord {
    pub leaf_id: Digest,
    pub device_pk: Vec<u8>,
    pub slot: u32,
    pub generation: u64,
    pub admission_hash: Digest,
}

impl MemberRecord {
    fn to_value(&self) -> Value {
        array(vec![
            bytes(&self.leaf_id),
            bytes(&self.device_pk),
            uint(u64::from(self.slot)),
            uint(self.generation),
            bytes(&self.admission_hash),
        ])
    }

    fn from_value(value: Value) -> CoreResult<Self> {
        let mut fields = expect_array(value, 5, "member record")?.into_iter();
        Ok(Self {
            leaf_id: expect_bytes32(next(&mut fields, "member record")?, "member leaf id")?,
            device_pk: expect_bytes(next(&mut fields, "member record")?, "member device key")?,
            slot: expect_u32(&next(&mut fields, "member record")?, "member slot")?,
            generation: expect_uint(&next(&mut fields, "member record")?, "member generation")?,
            admission_hash: expect_bytes32(
                next(&mut fields, "member record")?,
                "member admission hash",
            )?,
        })
    }
}

/// Members, admins and per-slot generation counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Roster {
    members: BTreeMap<u32, MemberRecord>,
    admins: BTreeSet<Vec<u8>>,
    last_generation: BTreeMap<u32, u64>,
}

impl Roster {
    /// Roster of a new group: its creator in slot 0, sole admin.
    pub fn genesis(gid: &Digest, creator_device_pk: &[u8]) -> CoreResult<Self> {
        let mut roster = Self::default();
        roster.admins.insert(creator_device_pk.to_vec());
        roster.add_member(MemberRecord {
            leaf_id: leaf_id(gid, creator_device_pk)?,
            device_pk: creator_device_pk.to_vec(),
            slot: 0,
            generation: 1,
            admission_hash: [0u8; 32],
        })?;
        Ok(roster)
    }

    /// Members, by slot.
    pub fn members(&self) -> impl Iterator<Item = &MemberRecord> {
        self.members.values()
    }

    /// Number of members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the group has no member.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Member in `slot`.
    #[must_use]
    pub fn member_in_slot(&self, slot: u32) -> Option<&MemberRecord> {
        self.members.get(&slot)
    }

    /// Member with `leaf_id`.
    #[must_use]
    pub fn member_by_leaf(&self, leaf: &Digest) -> Option<&MemberRecord> {
        self.members.values().find(|member| &member.leaf_id == leaf)
    }

    /// Member with device key `device_pk`.
    #[must_use]
    pub fn member_by_device(&self, device_pk: &[u8]) -> Option<&MemberRecord> {
        self.members
            .values()
            .find(|member| member.device_pk == device_pk)
    }

    /// Whether `device_pk` is an admin.
    #[must_use]
    pub fn is_admin(&self, device_pk: &[u8]) -> bool {
        self.admins.contains(device_pk)
    }

    /// Admin device keys.
    pub fn admins(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.admins.iter()
    }

    /// Generation the next occupant of `slot` must carry.
    #[must_use]
    pub fn next_generation(&self, slot: u32) -> u64 {
        self.last_generation.get(&slot).copied().unwrap_or(0) + 1
    }

    /// Add a member to an empty slot with the next generation of that slot.
    pub fn add_member(&mut self, record: MemberRecord) -> CoreResult<()> {
        if self.members.contains_key(&record.slot) {
            return Err(CoreError::Invalid("roster slot already occupied"));
        }
        if record.generation != self.next_generation(record.slot) {
            return Err(CoreError::Invalid("roster slot generation"));
        }
        if self.member_by_leaf(&record.leaf_id).is_some() {
            return Err(CoreError::Invalid("member already in roster"));
        }
        self.last_generation.insert(record.slot, record.generation);
        self.members.insert(record.slot, record);
        Ok(())
    }

    /// Remove the member occupying `slot` with `generation`; a removed
    /// member also loses its admin rights.
    pub fn remove_member(&mut self, slot: u32, generation: u64) -> CoreResult<MemberRecord> {
        match self.members.get(&slot) {
            Some(member) if member.generation == generation => {}
            Some(_) => return Err(CoreError::Invalid("removal generation")),
            None => return Err(CoreError::Invalid("removal of an empty slot")),
        }
        let removed = self
            .members
            .remove(&slot)
            .ok_or(CoreError::Invalid("removal of an empty slot"))?;
        self.admins.remove(&removed.device_pk);
        Ok(removed)
    }

    /// Re-admit the member of `slot` under the next generation of the slot
    /// (resynchronisation); identity, admission and admin rights are kept.
    pub fn renew_generation(&mut self, slot: u32) -> CoreResult<&MemberRecord> {
        let generation = self.next_generation(slot);
        let member = self
            .members
            .get_mut(&slot)
            .ok_or(CoreError::Invalid("renewal of an empty slot"))?;
        member.generation = generation;
        self.last_generation.insert(slot, generation);
        Ok(member)
    }

    /// If members remain but no admin does, the member in the lowest
    /// occupied slot becomes admin. Returns its device key when it applies.
    pub fn promote_if_adminless(&mut self) -> Option<Vec<u8>> {
        if !self.admins.is_empty() {
            return None;
        }
        let promoted = self.members.values().next()?.device_pk.clone();
        self.admins.insert(promoted.clone());
        Some(promoted)
    }

    /// Grant admin rights to the member with device key `device_pk`.
    pub fn grant_admin(&mut self, device_pk: &[u8]) -> CoreResult<()> {
        if self.member_by_device(device_pk).is_none() {
            return Err(CoreError::Invalid("admin grant to a non-member"));
        }
        if self.admins.len() >= MAX_ADMINS {
            return Err(CoreError::TooLarge("admin set"));
        }
        if !self.admins.insert(device_pk.to_vec()) {
            return Err(CoreError::Invalid("admin already granted"));
        }
        Ok(())
    }

    /// Revoke the admin rights of `device_pk`; the last admin stays.
    pub fn revoke_admin(&mut self, device_pk: &[u8]) -> CoreResult<()> {
        if !self.admins.contains(device_pk) {
            return Err(CoreError::Invalid("admin not present"));
        }
        if self.admins.len() == 1 {
            return Err(CoreError::Invalid("the last admin cannot be revoked"));
        }
        self.admins.remove(device_pk);
        Ok(())
    }

    fn to_value(&self) -> Value {
        array(vec![
            array(self.members.values().map(MemberRecord::to_value).collect()),
            array(self.admins.iter().map(|admin| bytes(admin)).collect()),
            array(
                self.last_generation
                    .iter()
                    .map(|(slot, generation)| {
                        array(vec![uint(u64::from(*slot)), uint(*generation)])
                    })
                    .collect(),
            ),
        ])
    }

    /// `roster_hash`.
    pub fn roster_hash(&self) -> CoreResult<Digest> {
        let Value::Array(parts) = self.to_value() else {
            return Err(CoreError::Malformed("roster"));
        };
        h_l("roster", parts)
    }

    /// Deterministic CBOR encoding.
    pub fn to_cbor(&self) -> CoreResult<Vec<u8>> {
        encode(&self.to_value())
    }

    /// Decode a roster encoding, checking its internal consistency.
    pub fn from_cbor(encoded: &[u8], gid: &Digest) -> CoreResult<Self> {
        let mut parts =
            expect_array(decode(encoded, 16 << 20, "roster")?, 3, "roster")?.into_iter();
        let members = expect_list(next(&mut parts, "roster")?, "roster members")?;
        let admins = expect_list(next(&mut parts, "roster")?, "roster admins")?;
        let generations = expect_list(next(&mut parts, "roster")?, "roster generations")?;
        let mut roster = Self::default();
        for pair in generations {
            let mut fields = expect_array(pair, 2, "roster generation")?.into_iter();
            let slot = expect_u32(&next(&mut fields, "roster generation")?, "roster slot")?;
            let generation = expect_uint(
                &next(&mut fields, "roster generation")?,
                "roster generation",
            )?;
            roster.last_generation.insert(slot, generation);
        }
        for admin in admins {
            let admin = expect_bytes(admin, "roster admin")?;
            if !roster.admins.insert(admin) {
                return Err(CoreError::Malformed("duplicate roster admin"));
            }
        }
        for member in members {
            let member = MemberRecord::from_value(member)?;
            if member.leaf_id != leaf_id(gid, &member.device_pk)?
                || roster.last_generation.get(&member.slot) != Some(&member.generation)
                || roster.members.insert(member.slot, member).is_some()
            {
                return Err(CoreError::Malformed("roster member"));
            }
        }
        if roster
            .admins
            .iter()
            .any(|admin| roster.member_by_device(admin).is_none())
            || roster.admins.len() > MAX_ADMINS
        {
            return Err(CoreError::Malformed("roster admin"));
        }
        if roster.to_cbor()? != encoded {
            return Err(CoreError::NonDeterministic("roster"));
        }
        Ok(roster)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn record(gid: &Digest, pk: &[u8], slot: u32, generation: u64) -> MemberRecord {
        MemberRecord {
            leaf_id: leaf_id(gid, pk).unwrap(),
            device_pk: pk.to_vec(),
            slot,
            generation,
            admission_hash: [7; 32],
        }
    }

    #[test]
    fn membership_changes_update_the_hash() {
        let gid = [1; 32];
        let mut roster = Roster::genesis(&gid, b"alice").unwrap();
        let genesis_hash = roster.roster_hash().unwrap();
        assert!(roster.is_admin(b"alice"));
        assert_eq!(roster.len(), 1);
        roster.add_member(record(&gid, b"bob", 1, 1)).unwrap();
        let with_bob = roster.roster_hash().unwrap();
        assert_ne!(with_bob, genesis_hash);
        assert_eq!(roster.member_by_device(b"bob").unwrap().slot, 1);
        assert!(
            roster
                .member_by_leaf(&leaf_id(&gid, b"bob").unwrap())
                .is_some()
        );

        assert!(roster.remove_member(1, 2).is_err(), "generation is checked");
        roster.remove_member(1, 1).unwrap();
        let after = roster.roster_hash().unwrap();
        assert_ne!(after, genesis_hash, "slot generations are committed");
        assert_eq!(roster.next_generation(1), 2);
        assert!(roster.add_member(record(&gid, b"carol", 1, 1)).is_err());
        roster.add_member(record(&gid, b"carol", 1, 2)).unwrap();
        assert!(roster.add_member(record(&gid, b"dave", 1, 3)).is_err());
        assert!(roster.add_member(record(&gid, b"carol", 2, 1)).is_err());
        assert!(roster.remove_member(5, 1).is_err());
    }

    #[test]
    fn admin_rules() {
        let gid = [2; 32];
        let mut roster = Roster::genesis(&gid, b"alice").unwrap();
        assert!(roster.revoke_admin(b"alice").is_err(), "last admin stays");
        assert!(roster.grant_admin(b"bob").is_err(), "bob is not a member");
        roster.add_member(record(&gid, b"bob", 1, 1)).unwrap();
        roster.grant_admin(b"bob").unwrap();
        assert!(roster.grant_admin(b"bob").is_err());
        let hash = roster.roster_hash().unwrap();
        roster.revoke_admin(b"alice").unwrap();
        assert_ne!(roster.roster_hash().unwrap(), hash);
        assert!(roster.revoke_admin(b"carol").is_err());
        assert_eq!(roster.admins().count(), 1);
        assert_eq!(roster.promote_if_adminless(), None);

        // Removing the last admin drops its rights; the lowest slot is promoted.
        roster.add_member(record(&gid, b"carol", 2, 1)).unwrap();
        roster.remove_member(1, 1).unwrap();
        assert!(!roster.is_admin(b"bob"));
        assert_eq!(roster.promote_if_adminless(), Some(b"alice".to_vec()));
        assert!(roster.is_admin(b"alice"));
    }

    #[test]
    fn renewal_keeps_identity_and_rights() {
        let gid = [5; 32];
        let mut roster = Roster::genesis(&gid, b"alice").unwrap();
        let before = roster.roster_hash().unwrap();
        let renewed = roster.renew_generation(0).unwrap().clone();
        assert_eq!(renewed.generation, 2);
        assert_eq!(renewed.device_pk, b"alice".to_vec());
        assert!(roster.is_admin(b"alice"));
        assert_ne!(roster.roster_hash().unwrap(), before);
        assert_eq!(roster.next_generation(0), 3);
        assert!(roster.renew_generation(4).is_err());
    }

    #[test]
    fn encoding_round_trips_and_is_checked() {
        let gid = [3; 32];
        let mut roster = Roster::genesis(&gid, b"alice").unwrap();
        roster.add_member(record(&gid, b"bob", 3, 1)).unwrap();
        let encoded = roster.to_cbor().unwrap();
        let decoded = Roster::from_cbor(&encoded, &gid).unwrap();
        assert_eq!(decoded, roster);
        assert_eq!(
            decoded.roster_hash().unwrap(),
            roster.roster_hash().unwrap()
        );
        assert!(
            Roster::from_cbor(&encoded, &[4; 32]).is_err(),
            "leaf ids bind the gid"
        );
        assert!(Roster::from_cbor(&[0x80], &gid).is_err());
        assert!(!roster.is_empty());
    }
}
