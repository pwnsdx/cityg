//! The membership log (docs/specs-v0.5-draft.md section 4.10): each seal
//! commits the changes of its window, one record per change, which members
//! check on demand against the log its header carries.
//!
//! ```text
//! membership_log := [count, root]                               in the seal header
//! root           := MTH("membership-log", [H(CBOR_det(record_1)), ..., H(CBOR_det(record_count))])
//! record         := [kind, leaf, device_id, card_prefix]        in change order (v0.4 §10.1)
//!   card_prefix  := the first 8 bytes of H_L("card", [card])
//! ```
//!
//! A removal or an eviction names the device and the card that leave the
//! leaf; a join, an update or a re-entry, those the leaf holds after the
//! window. The genesis seal logs the creator's join at leaf 0.

use ciborium::value::Value;

use crate::card::Card;
use crate::cbor::{array, bytes, encode, expect_array, uint};
use crate::codec::Fields;
use crate::crypto::{Digest, h};
use crate::error::{CoreError, CoreResult};
use crate::merkle;
use crate::objects::{ChangeKind, Request, device_id};
use crate::window::{PublicState, Requests, WindowShape};

/// Label of the membership log's Merkle tree.
const LOG_LABEL: &str = "membership-log";

/// Bytes of a card's hash that a record keeps.
pub const CARD_PREFIX_BYTES: usize = 8;

/// One change of a window, as the membership log records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipRecord {
    pub kind: ChangeKind,
    pub leaf: u32,
    pub device_id: Digest,
    pub card_prefix: [u8; CARD_PREFIX_BYTES],
}

impl MembershipRecord {
    /// The record of a change of kind `kind` at `leaf`, naming the device
    /// `device_id` and its card.
    pub fn new(kind: ChangeKind, leaf: u32, device_id: Digest, card: &Card) -> CoreResult<Self> {
        let mut card_prefix = [0u8; CARD_PREFIX_BYTES];
        card_prefix.copy_from_slice(&card.hash()?[..CARD_PREFIX_BYTES]);
        Ok(Self {
            kind,
            leaf,
            device_id,
            card_prefix,
        })
    }

    /// CBOR `[kind, leaf, device_id, card_prefix]`.
    #[must_use]
    pub fn value(&self) -> Value {
        array(vec![
            uint(self.kind.code()),
            uint(u64::from(self.leaf)),
            bytes(&self.device_id),
            bytes(&self.card_prefix),
        ])
    }

    /// Read a record.
    pub fn from_value(value: Value) -> CoreResult<Self> {
        const WHAT: &str = "membership record";
        let mut fields = Fields::new(expect_array(value, 4, WHAT)?, WHAT);
        Ok(Self {
            kind: ChangeKind::from_code(fields.uint()?)?,
            leaf: fields.u32()?,
            device_id: fields.digest()?,
            card_prefix: fields
                .bytes()?
                .try_into()
                .map_err(|_| CoreError::Malformed(WHAT))?,
        })
    }

    /// `H(CBOR_det(record))`, a leaf of the log.
    pub fn hash(&self) -> CoreResult<Digest> {
        Ok(h(&encode(&self.value())?))
    }

    /// Whether the record names `card`.
    pub fn names_card(&self, card: &Card) -> CoreResult<bool> {
        Ok(card.hash()?[..CARD_PREFIX_BYTES] == self.card_prefix)
    }
}

/// The log of a window's changes: their number and the root of the Merkle
/// tree of their records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipLog {
    pub count: u64,
    pub root: Digest,
}

fn hashes(records: &[MembershipRecord]) -> CoreResult<Vec<Digest>> {
    records.iter().map(MembershipRecord::hash).collect()
}

impl MembershipLog {
    /// The log of `records`, in order.
    pub fn of(records: &[MembershipRecord]) -> CoreResult<Self> {
        Ok(Self {
            count: u64::try_from(records.len())
                .map_err(|_| CoreError::TooLarge("membership log"))?,
            root: merkle::root(LOG_LABEL, &hashes(records)?)?,
        })
    }

    /// CBOR `[count, root]`.
    #[must_use]
    pub fn value(&self) -> Value {
        array(vec![uint(self.count), bytes(&self.root)])
    }

    /// Read `[count, root]`.
    pub fn from_value(value: Value, what: &'static str) -> CoreResult<Self> {
        let mut fields = Fields::new(expect_array(value, 2, what)?, what);
        Ok(Self {
            count: fields.uint()?,
            root: fields.digest()?,
        })
    }

    /// Check that `records` are the whole log, in order.
    pub fn check(&self, records: &[MembershipRecord]) -> CoreResult<()> {
        if Self::of(records)? == *self {
            Ok(())
        } else {
            Err(CoreError::Invalid("membership log"))
        }
    }

    /// Check that `record` is the `index`-th of the log, by an inclusion
    /// proof.
    pub fn verify_inclusion(
        &self,
        index: u64,
        record: &MembershipRecord,
        proof: &[Digest],
    ) -> CoreResult<()> {
        merkle::verify_inclusion(
            LOG_LABEL,
            &self.root,
            self.count,
            index,
            &record.hash()?,
            proof,
        )
        .map_err(|_| CoreError::Invalid("membership log proof"))
    }
}

/// The inclusion proof of the `index`-th of `records`.
pub fn inclusion_proof(records: &[MembershipRecord], index: usize) -> CoreResult<Vec<Digest>> {
    merkle::inclusion_proof(LOG_LABEL, &hashes(records)?, index)
}

/// The records of a window's changes over `state`, the state before it, in
/// change order.
pub fn records(
    state: &PublicState,
    window: &WindowShape,
    requests: &Requests,
) -> CoreResult<Vec<MembershipRecord>> {
    window
        .all_changes()
        .map(|change| {
            let request = requests
                .get(&change.request)
                .ok_or(CoreError::Invalid("missing request"))?;
            let current = || {
                state
                    .tree
                    .leaf(change.leaf)
                    .ok_or(CoreError::Invalid("change of a blank leaf"))
            };
            let (device, card) = match request {
                Request::Removal(_) | Request::Eviction(_) => {
                    let leaf = current()?;
                    (leaf.device_id, &leaf.card)
                }
                Request::Join(join) => (device_id(&state.gid, &join.device_pk)?, &join.card),
                Request::Update(update) => (current()?.device_id, &update.card),
                Request::ReEntry(re_entry) => (current()?.device_id, &re_entry.card),
            };
            MembershipRecord::new(change.kind, change.leaf, device, card)
        })
        .collect()
}

/// The genesis seal's record: the creator's join at leaf 0.
pub fn genesis(gid: &Digest, creator_pk: &[u8], card: &Card) -> CoreResult<Vec<MembershipRecord>> {
    Ok(vec![MembershipRecord::new(
        ChangeKind::Join,
        0,
        device_id(gid, creator_pk)?,
        card,
    )?])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::card::CardKey;
    use crate::cbor::decode;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn a_log_commits_its_records_in_order() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let cards: Vec<Card> = (0..3).map(|_| CardKey::generate(&mut rng).card()).collect();
        let records: Vec<MembershipRecord> = [
            (ChangeKind::Removal, 2),
            (ChangeKind::Join, 5),
            (ChangeKind::Update, 9),
        ]
        .iter()
        .zip(&cards)
        .map(|((kind, leaf), card)| {
            MembershipRecord::new(*kind, *leaf, [*leaf as u8; 32], card).unwrap()
        })
        .collect();
        let log = MembershipLog::of(&records).unwrap();
        log.check(&records).unwrap();
        let mut reordered = records.clone();
        reordered.swap(0, 1);
        assert!(log.check(&reordered).is_err());
        for (index, record) in records.iter().enumerate() {
            let proof = inclusion_proof(&records, index).unwrap();
            log.verify_inclusion(index as u64, record, &proof).unwrap();
            assert!(record.names_card(&cards[index]).unwrap());
            assert!(!record.names_card(&cards[(index + 1) % 3]).unwrap());
        }
        // About 50 bytes a record.
        let encoded = encode(&records[0].value()).unwrap();
        assert!(encoded.len() <= 52);
        let decoded =
            MembershipRecord::from_value(decode(&encoded, 64, "record").unwrap()).unwrap();
        assert_eq!(decoded, records[0]);
    }
}
