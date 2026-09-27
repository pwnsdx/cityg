//! District commits, city tasks and seals (docs/specs.md section 10, with
//! the seal header of docs/specs-v0.5-draft.md sections 2.1 and 3.1, and the
//! city tasks and seal body of its sections 3.2 and 3.5).
//!
//! ```text
//! DistrictCommit := ["city-g/district-commit/v5", gid, epoch, district, height,
//!                    prev_district_hash, committer, changes, nodes, wraps,
//!                    district_hash, signature]      ctx DISTRICT_COMMIT, by the committer
//!   change := [kind, leaf, request_ref]             sorted by (leaf, kind)
//!   node   := [level, index, public_key or null]    in plan order
//!   wrap   := [level, index, target_level, target_index, kem_ciphertext, sealed]
//!
//! CityTask := ["city-g/city-task/v5", gid, epoch, part, height, prev_part_hash,
//!              performer, nodes, wraps, part_hash, signature]
//!                                                 ctx CITY_TASK, by the performer
//!   part := k (sub-city k) or null (the top)
//!
//! SealHeader := ["city-g/seal/v5", gid, epoch, prev_interim, kind, sealer, height,
//!                district_bits, island_bits, subcity_bits, tree_hash, registry_hash,
//!                body_hash, time_ms, message_log, [kem_output, request_ref] or null]
//!   kind 0 genesis, 1 member, 2 entrant (the last field is set for kind 2)
//!   message_log := [count, root], the log of the previous epoch's messages
//!                  (docs/specs-v0.5-draft.md section 4.8)
//! SealBody   := ["city-g/seal-body/v5", [[district, H(district commit)], ...],
//!                [[part, H(city task)], ...], eviction_policy or null,
//!                [nonce, creator_pk, encryption_key, card, root_pk] or null]
//! Seal       := [SealHeader, SealBody, tag, external_pk, signature]
//!   seal_hash := H(SealHeader), body_hash := H(SealBody)
//!   signature := Sign(sealer, CBOR_det([seal_hash, tag, external_pk]), ctx SEAL)
//! SealProof  := [SealHeader, tag, external_pk, signature]
//! ```
//!
//! A change names its request by hash; requests travel beside the commit.
//! Members and joiners download seal proofs, not bodies.

use ciborium::value::Value;
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::card::Card;
use crate::cbor::{array, bytes, decode, encode, expect_array, expect_label, text, uint};
use crate::codec::{Fields, Signed, nullable, open_signed, sign_fields};
use crate::crypto::{Digest, Wrap, h};
use crate::error::{CoreError, CoreResult};
use crate::identity::{DeviceIdentity, verify_signature};
use crate::message::MessageLog;
use crate::objects::ChangeKind;
use crate::rekey::NodeUpdate;
use crate::tree::{CityPart, NodeId, Occupancy};

pub const DISTRICT_COMMIT_LABEL: &str = "city-g/district-commit/v5";
pub const CITY_TASK_LABEL: &str = "city-g/city-task/v5";
pub const SEAL_LABEL: &str = "city-g/seal/v5";
pub const SEAL_BODY_LABEL: &str = "city-g/seal-body/v5";
/// Upper bound on an encoded district commit or city task.
pub const MAX_DISTRICT_COMMIT_BYTES: usize = 64 * 1024 * 1024;
/// Upper bound on an encoded seal.
pub const MAX_SEAL_BYTES: usize = 64 * 1024 * 1024;

/// One change of a district commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Change {
    pub leaf: u32,
    pub kind: ChangeKind,
    pub request: Digest,
}

impl Change {
    fn value(&self) -> Value {
        array(vec![
            uint(self.kind.code()),
            uint(u64::from(self.leaf)),
            bytes(&self.request),
        ])
    }

    fn from_value(value: Value) -> CoreResult<Self> {
        let mut fields = Fields::new(expect_array(value, 3, "change")?, "change");
        Ok(Self {
            kind: ChangeKind::from_code(fields.uint()?)?,
            leaf: fields.u32()?,
            request: fields.digest()?,
        })
    }
}

fn updates_value(updates: &[NodeUpdate]) -> Value {
    array(
        updates
            .iter()
            .map(|update| {
                array(vec![
                    uint(u64::from(update.node.level)),
                    uint(u64::from(update.node.index)),
                    nullable(update.public_key.as_deref(), bytes),
                ])
            })
            .collect(),
    )
}

fn updates_from(values: Vec<Value>) -> CoreResult<Vec<NodeUpdate>> {
    values
        .into_iter()
        .map(|value| {
            let items = expect_array(value, 3, "node update")?;
            let mut fields = Fields::new(items, "node update");
            let level = fields.u8()?;
            let index = fields.u32()?;
            Ok(NodeUpdate {
                node: NodeId { level, index },
                public_key: fields.optional_bytes()?,
            })
        })
        .collect()
}

/// A wrap as `[level, index, target_level, target_index, kem_ciphertext,
/// sealed]`.
pub(crate) fn wrap_value(wrapped: &Wrap) -> Value {
    array(vec![
        uint(u64::from(wrapped.node.level)),
        uint(u64::from(wrapped.node.index)),
        uint(u64::from(wrapped.target.level)),
        uint(u64::from(wrapped.target.index)),
        bytes(&wrapped.kem_ciphertext),
        bytes(&wrapped.sealed),
    ])
}

/// Parse a wrap.
pub(crate) fn wrap_from(value: Value) -> CoreResult<Wrap> {
    let items = expect_array(value, 6, "wrap")?;
    let mut fields = Fields::new(items, "wrap");
    let level = fields.u8()?;
    let index = fields.u32()?;
    let target_level = fields.u8()?;
    let target_index = fields.u32()?;
    Ok(Wrap {
        node: NodeId { level, index },
        target: NodeId {
            level: target_level,
            index: target_index,
        },
        kem_ciphertext: fields.bytes()?,
        sealed: fields.bytes()?,
    })
}

fn wraps_value(wraps: &[Wrap]) -> Value {
    array(wraps.iter().map(wrap_value).collect())
}

fn wraps_from(values: Vec<Value>) -> CoreResult<Vec<Wrap>> {
    values.into_iter().map(wrap_from).collect()
}

/// The re-key of one district in a window, signed by its committer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistrictCommit {
    pub gid: Digest,
    pub epoch: u64,
    pub district: u32,
    pub height: u8,
    pub prev_district_hash: Digest,
    pub committer: Occupancy,
    pub changes: Vec<Change>,
    pub updates: Vec<NodeUpdate>,
    pub wraps: Vec<Wrap>,
    pub district_hash: Digest,
    signed: Signed,
}

/// The content of a district commit before it is signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistrictCommitContent {
    pub gid: Digest,
    pub epoch: u64,
    pub district: u32,
    pub height: u8,
    pub prev_district_hash: Digest,
    pub committer: Occupancy,
    pub changes: Vec<Change>,
    pub updates: Vec<NodeUpdate>,
    pub wraps: Vec<Wrap>,
    pub district_hash: Digest,
}

impl DistrictCommit {
    /// Sign `content` with the committer's device key.
    pub fn sign(
        content: DistrictCommitContent,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let signed = sign_fields(
            vec![
                text(DISTRICT_COMMIT_LABEL),
                bytes(&content.gid),
                uint(content.epoch),
                uint(u64::from(content.district)),
                uint(u64::from(content.height)),
                bytes(&content.prev_district_hash),
                content.committer.value(),
                array(content.changes.iter().map(Change::value).collect()),
                updates_value(&content.updates),
                wraps_value(&content.wraps),
                bytes(&content.district_hash),
            ],
            identity,
            SignatureContext::DISTRICT_COMMIT,
            rng,
        )?;
        Ok(Self {
            gid: content.gid,
            epoch: content.epoch,
            district: content.district,
            height: content.height,
            prev_district_hash: content.prev_district_hash,
            committer: content.committer,
            changes: content.changes,
            updates: content.updates,
            wraps: content.wraps,
            district_hash: content.district_hash,
            signed,
        })
    }

    /// Parse a district commit.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) = open_signed(
            encoded,
            DISTRICT_COMMIT_LABEL,
            11,
            MAX_DISTRICT_COMMIT_BYTES,
            "district commit",
        )?;
        Ok(Self {
            gid: fields.digest()?,
            epoch: fields.uint()?,
            district: fields.u32()?,
            height: fields.u8()?,
            prev_district_hash: fields.digest()?,
            committer: fields.occupancy()?,
            changes: fields
                .list()?
                .into_iter()
                .map(Change::from_value)
                .collect::<CoreResult<_>>()?,
            updates: updates_from(fields.list()?)?,
            wraps: wraps_from(fields.list()?)?,
            district_hash: fields.digest()?,
            signed,
        })
    }

    /// Encoded signed commit.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// `H(encoded)`, which the seal lists.
    #[must_use]
    pub fn hash(&self) -> Digest {
        h(&self.signed.encoded)
    }

    /// Check the committer's signature under `committer_pk`.
    pub fn verify_signature(&self, committer_pk: &[u8]) -> CoreResult<()> {
        self.signed.verify(
            committer_pk,
            SignatureContext::DISTRICT_COMMIT,
            "district commit",
        )
    }
}

fn part_value(part: CityPart) -> Value {
    match part {
        CityPart::SubCity(subcity) => uint(u64::from(subcity)),
        CityPart::Top => Value::Null,
    }
}

fn part_from(value: Option<Value>, what: &'static str) -> CoreResult<CityPart> {
    match value {
        None => Ok(CityPart::Top),
        Some(value) => Ok(CityPart::SubCity(crate::cbor::expect_u32(&value, what)?)),
    }
}

/// The re-key of a sub-city or of the top in a window, signed by its
/// performer (docs/specs-v0.5-draft.md section 3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CityTask {
    pub gid: Digest,
    pub epoch: u64,
    pub part: CityPart,
    pub height: u8,
    pub prev_part_hash: Digest,
    pub performer: Occupancy,
    pub updates: Vec<NodeUpdate>,
    pub wraps: Vec<Wrap>,
    pub part_hash: Digest,
    signed: Signed,
}

/// The content of a city task before it is signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CityTaskContent {
    pub gid: Digest,
    pub epoch: u64,
    pub part: CityPart,
    pub height: u8,
    pub prev_part_hash: Digest,
    pub performer: Occupancy,
    pub updates: Vec<NodeUpdate>,
    pub wraps: Vec<Wrap>,
    pub part_hash: Digest,
}

impl CityTask {
    /// Sign `content` with the performer's device key.
    pub fn sign(
        content: CityTaskContent,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let signed = sign_fields(
            vec![
                text(CITY_TASK_LABEL),
                bytes(&content.gid),
                uint(content.epoch),
                part_value(content.part),
                uint(u64::from(content.height)),
                bytes(&content.prev_part_hash),
                content.performer.value(),
                updates_value(&content.updates),
                wraps_value(&content.wraps),
                bytes(&content.part_hash),
            ],
            identity,
            SignatureContext::CITY_TASK,
            rng,
        )?;
        Ok(Self {
            gid: content.gid,
            epoch: content.epoch,
            part: content.part,
            height: content.height,
            prev_part_hash: content.prev_part_hash,
            performer: content.performer,
            updates: content.updates,
            wraps: content.wraps,
            part_hash: content.part_hash,
            signed,
        })
    }

    /// Parse a city task.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        const WHAT: &str = "city task";
        let (mut fields, signed) = open_signed(
            encoded,
            CITY_TASK_LABEL,
            10,
            MAX_DISTRICT_COMMIT_BYTES,
            WHAT,
        )?;
        Ok(Self {
            gid: fields.digest()?,
            epoch: fields.uint()?,
            part: part_from(fields.optional()?, WHAT)?,
            height: fields.u8()?,
            prev_part_hash: fields.digest()?,
            performer: fields.occupancy()?,
            updates: updates_from(fields.list()?)?,
            wraps: wraps_from(fields.list()?)?,
            part_hash: fields.digest()?,
            signed,
        })
    }

    /// Encoded signed task.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// `H(encoded)`, which the seal lists.
    #[must_use]
    pub fn hash(&self) -> Digest {
        h(&self.signed.encoded)
    }

    /// Check the performer's signature under `performer_pk`.
    pub fn verify_signature(&self, performer_pk: &[u8]) -> CoreResult<()> {
        self.signed
            .verify(performer_pk, SignatureContext::CITY_TASK, "city task")
    }
}

/// Who sealed a window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealKind {
    Genesis = 0,
    Member = 1,
    Entrant = 2,
}

/// The external init of a window sealed by an entrant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntrantInit {
    /// X-Wing ciphertext to the external key of the previous epoch.
    pub kem_output: Vec<u8>,
    /// The entrant's join or re-entry request.
    pub request: Digest,
}

/// The signed header of a seal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealHeader {
    pub gid: Digest,
    pub epoch: u64,
    pub prev_interim: Digest,
    pub kind: SealKind,
    pub sealer: Occupancy,
    pub height: u8,
    pub district_bits: u8,
    pub island_bits: u8,
    pub subcity_bits: u8,
    pub tree_hash: Digest,
    pub registry_hash: Digest,
    pub body_hash: Digest,
    pub time_ms: u64,
    /// The log of the previous epoch's messages, which the DS closed when it
    /// gave the sealer its work (empty at genesis).
    pub message_log: MessageLog,
    pub entrant: Option<EntrantInit>,
}

impl SealHeader {
    fn value(&self) -> Value {
        array(vec![
            text(SEAL_LABEL),
            bytes(&self.gid),
            uint(self.epoch),
            bytes(&self.prev_interim),
            uint(self.kind as u64),
            self.sealer.value(),
            uint(u64::from(self.height)),
            uint(u64::from(self.district_bits)),
            uint(u64::from(self.island_bits)),
            uint(u64::from(self.subcity_bits)),
            bytes(&self.tree_hash),
            bytes(&self.registry_hash),
            bytes(&self.body_hash),
            uint(self.time_ms),
            self.message_log.value(),
            nullable(self.entrant.as_ref(), |entrant| {
                array(vec![bytes(&entrant.kem_output), bytes(&entrant.request)])
            }),
        ])
    }

    fn from_value(value: Value) -> CoreResult<Self> {
        const WHAT: &str = "seal header";
        let items = expect_array(value, 16, WHAT)?;
        expect_label(&items[0], SEAL_LABEL, WHAT)?;
        let mut fields = Fields::new(items, WHAT);
        fields.next()?;
        let gid = fields.digest()?;
        let epoch = fields.uint()?;
        let prev_interim = fields.digest()?;
        let kind = match fields.uint()? {
            0 => SealKind::Genesis,
            1 => SealKind::Member,
            2 => SealKind::Entrant,
            _ => return Err(CoreError::Malformed(WHAT)),
        };
        let sealer = fields.occupancy()?;
        let height = fields.u8()?;
        let district_bits = fields.u8()?;
        let island_bits = fields.u8()?;
        let subcity_bits = fields.u8()?;
        let tree_hash = fields.digest()?;
        let registry_hash = fields.digest()?;
        let body_hash = fields.digest()?;
        let time_ms = fields.uint()?;
        let message_log = MessageLog::from_value(fields.next()?, WHAT)?;
        let entrant = match fields.optional()? {
            None => None,
            Some(value) => {
                let mut entrant = Fields::new(expect_array(value, 2, WHAT)?, WHAT);
                Some(EntrantInit {
                    kem_output: entrant.bytes()?,
                    request: entrant.digest()?,
                })
            }
        };
        if entrant.is_some() != (kind == SealKind::Entrant) {
            return Err(CoreError::Malformed(WHAT));
        }
        Ok(Self {
            gid,
            epoch,
            prev_interim,
            kind,
            sealer,
            height,
            district_bits,
            island_bits,
            subcity_bits,
            tree_hash,
            registry_hash,
            body_hash,
            time_ms,
            message_log,
            entrant,
        })
    }

    /// Encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&self.value())
    }

    /// `seal_hash := H(SealHeader)`.
    pub fn hash(&self) -> CoreResult<Digest> {
        Ok(h(&self.encode()?))
    }
}

/// The creator's leaf and root key, in the genesis seal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    pub nonce: [u8; 32],
    pub creator_pk: Vec<u8>,
    pub encryption_key: Vec<u8>,
    /// The creator's card (docs/specs-v0.5-draft.md section 4.1).
    pub card: Card,
    pub root_pk: Vec<u8>,
}

/// What the seal lists and adds: the window's district commits and city
/// tasks, and the registry changes that are not in the tree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SealBody {
    pub districts: Vec<(u32, Digest)>,
    pub city: Vec<(CityPart, Digest)>,
    pub policy: Option<Vec<u8>>,
    pub genesis: Option<Genesis>,
}

impl SealBody {
    fn value(&self) -> Value {
        array(vec![
            text(SEAL_BODY_LABEL),
            array(
                self.districts
                    .iter()
                    .map(|(district, hash)| array(vec![uint(u64::from(*district)), bytes(hash)]))
                    .collect(),
            ),
            array(
                self.city
                    .iter()
                    .map(|(part, hash)| array(vec![part_value(*part), bytes(hash)]))
                    .collect(),
            ),
            nullable(self.policy.as_deref(), bytes),
            nullable(self.genesis.as_ref(), |genesis| {
                array(vec![
                    bytes(&genesis.nonce),
                    bytes(&genesis.creator_pk),
                    bytes(&genesis.encryption_key),
                    genesis.card.value(),
                    bytes(&genesis.root_pk),
                ])
            }),
        ])
    }

    fn from_value(value: Value) -> CoreResult<Self> {
        const WHAT: &str = "seal body";
        let items = expect_array(value, 5, WHAT)?;
        expect_label(&items[0], SEAL_BODY_LABEL, WHAT)?;
        let mut fields = Fields::new(items, WHAT);
        fields.next()?;
        let districts = fields
            .list()?
            .into_iter()
            .map(|value| {
                let mut entry = Fields::new(expect_array(value, 2, WHAT)?, WHAT);
                Ok((entry.u32()?, entry.digest()?))
            })
            .collect::<CoreResult<_>>()?;
        let city = fields
            .list()?
            .into_iter()
            .map(|value| {
                let mut entry = Fields::new(expect_array(value, 2, WHAT)?, WHAT);
                Ok((part_from(entry.optional()?, WHAT)?, entry.digest()?))
            })
            .collect::<CoreResult<_>>()?;
        let policy = fields.optional_bytes()?;
        let genesis = match fields.optional()? {
            None => None,
            Some(value) => {
                let mut genesis = Fields::new(expect_array(value, 5, WHAT)?, WHAT);
                Some(Genesis {
                    nonce: genesis.digest()?,
                    creator_pk: genesis.bytes()?,
                    encryption_key: genesis.bytes()?,
                    card: Card::from_value(genesis.next()?, WHAT)?,
                    root_pk: genesis.bytes()?,
                })
            }
        };
        Ok(Self {
            districts,
            city,
            policy,
            genesis,
        })
    }

    /// `body_hash := H(SealBody)`.
    pub fn hash(&self) -> CoreResult<Digest> {
        Ok(h(&encode(&self.value())?))
    }
}

fn signed_payload(seal_hash: &Digest, tag: &Digest, external_pk: &[u8]) -> CoreResult<Vec<u8>> {
    encode(&array(vec![
        bytes(seal_hash),
        bytes(tag),
        bytes(external_pk),
    ]))
}

/// A seal: the epoch a window creates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seal {
    pub header: SealHeader,
    pub body: SealBody,
    pub tag: Digest,
    pub external_pk: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Seal {
    /// Sign a seal. `header.body_hash` must be `H(body)`.
    pub fn sign(
        header: SealHeader,
        body: SealBody,
        tag: Digest,
        external_pk: Vec<u8>,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        if header.body_hash != body.hash()? {
            return Err(CoreError::Invalid("seal body hash"));
        }
        let payload = signed_payload(&header.hash()?, &tag, &external_pk)?;
        let signature = identity.sign(SignatureContext::SEAL, &payload, rng)?;
        Ok(Self {
            header,
            body,
            tag,
            external_pk,
            signature,
        })
    }

    /// Encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            self.header.value(),
            self.body.value(),
            bytes(&self.tag),
            bytes(&self.external_pk),
            bytes(&self.signature),
        ]))
    }

    /// Parse a seal.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let items = expect_array(decode(encoded, MAX_SEAL_BYTES, "seal")?, 5, "seal")?;
        let mut items = items.into_iter();
        let mut next = || items.next().ok_or(CoreError::Malformed("seal"));
        let header = SealHeader::from_value(next()?)?;
        let body = SealBody::from_value(next()?)?;
        let mut rest = Fields::new(vec![next()?, next()?, next()?], "seal");
        Ok(Self {
            header,
            body,
            tag: rest.digest()?,
            external_pk: rest.bytes()?,
            signature: rest.bytes()?,
        })
    }

    /// The part of the seal members and joiners download.
    #[must_use]
    pub fn proof(&self) -> SealProof {
        SealProof {
            header: self.header.clone(),
            tag: self.tag,
            external_pk: self.external_pk.clone(),
            signature: self.signature.clone(),
        }
    }
}

/// A seal without its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealProof {
    pub header: SealHeader,
    pub tag: Digest,
    pub external_pk: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SealProof {
    /// Check the sealer's signature under `sealer_pk`.
    pub fn verify_signature(&self, sealer_pk: &[u8]) -> CoreResult<()> {
        let payload = signed_payload(&self.header.hash()?, &self.tag, &self.external_pk)?;
        verify_signature(
            sealer_pk,
            SignatureContext::SEAL,
            &payload,
            &self.signature,
            "seal",
        )
    }

    /// Encoding (`[SealHeader, tag, external_pk, signature]`).
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            self.header.value(),
            bytes(&self.tag),
            bytes(&self.external_pk),
            bytes(&self.signature),
        ]))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn district_commits_round_trip_and_verify() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let identity = DeviceIdentity::from_seed(&[1; 32]);
        let content = DistrictCommitContent {
            gid: [1; 32],
            epoch: 3,
            district: 2,
            height: 5,
            prev_district_hash: [2; 32],
            committer: Occupancy { leaf: 1, since: 0 },
            changes: vec![Change {
                leaf: 9,
                kind: ChangeKind::Join,
                request: [3; 32],
            }],
            updates: vec![
                NodeUpdate {
                    node: NodeId { level: 1, index: 4 },
                    public_key: Some(vec![7; 3]),
                },
                NodeUpdate {
                    node: NodeId { level: 2, index: 2 },
                    public_key: None,
                },
            ],
            wraps: vec![Wrap {
                node: NodeId { level: 1, index: 4 },
                target: NodeId::leaf(9),
                kem_ciphertext: vec![1; 5],
                sealed: vec![2; 6],
            }],
            district_hash: [4; 32],
        };
        let commit = DistrictCommit::sign(content, &identity, &mut rng).unwrap();
        let decoded = DistrictCommit::decode(commit.encoded()).unwrap();
        assert_eq!(decoded, commit);
        decoded.verify_signature(identity.public_key()).unwrap();
        let other = DeviceIdentity::from_seed(&[2; 32]);
        assert!(decoded.verify_signature(other.public_key()).is_err());
    }

    #[test]
    fn city_tasks_round_trip_and_verify() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let identity = DeviceIdentity::from_seed(&[1; 32]);
        for part in [CityPart::SubCity(3), CityPart::Top] {
            let content = CityTaskContent {
                gid: [1; 32],
                epoch: 3,
                part,
                height: 6,
                prev_part_hash: [2; 32],
                performer: Occupancy { leaf: 12, since: 3 },
                updates: vec![NodeUpdate {
                    node: NodeId { level: 4, index: 3 },
                    public_key: Some(vec![7; 3]),
                }],
                wraps: vec![Wrap {
                    node: NodeId { level: 4, index: 3 },
                    target: NodeId { level: 3, index: 6 },
                    kem_ciphertext: vec![1; 5],
                    sealed: vec![2; 6],
                }],
                part_hash: [4; 32],
            };
            let task = CityTask::sign(content, &identity, &mut rng).unwrap();
            let decoded = CityTask::decode(task.encoded()).unwrap();
            assert_eq!(decoded, task);
            decoded.verify_signature(identity.public_key()).unwrap();
            let other = DeviceIdentity::from_seed(&[2; 32]);
            assert!(decoded.verify_signature(other.public_key()).is_err());
            // Not a district commit, whatever the bytes say.
            assert!(DistrictCommit::decode(task.encoded()).is_err());
        }
    }

    #[test]
    fn seals_round_trip_and_sign_header_tag_and_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let identity = DeviceIdentity::from_seed(&[1; 32]);
        let body = SealBody {
            districts: vec![(0, [1; 32]), (3, [2; 32])],
            city: vec![(CityPart::SubCity(1), [3; 32]), (CityPart::Top, [4; 32])],
            policy: Some(vec![5; 4]),
            ..SealBody::default()
        };
        let header = SealHeader {
            gid: [1; 32],
            epoch: 4,
            prev_interim: [2; 32],
            kind: SealKind::Entrant,
            sealer: Occupancy { leaf: 7, since: 4 },
            height: 5,
            district_bits: 2,
            island_bits: 1,
            subcity_bits: 1,
            tree_hash: [3; 32],
            registry_hash: [4; 32],
            body_hash: body.hash().unwrap(),
            time_ms: 99,
            message_log: MessageLog {
                count: 3,
                root: [5; 32],
            },
            entrant: Some(EntrantInit {
                kem_output: vec![6; 3],
                request: [8; 32],
            }),
        };
        let seal = Seal::sign(header, body, [9; 32], vec![1, 2], &identity, &mut rng).unwrap();
        let decoded = Seal::decode(&seal.encode().unwrap()).unwrap();
        assert_eq!(decoded, seal);
        let proof = decoded.proof();
        proof.verify_signature(identity.public_key()).unwrap();
        let mut other_tag = proof.clone();
        other_tag.tag = [0; 32];
        assert!(other_tag.verify_signature(identity.public_key()).is_err());
        let mut other_key = proof.clone();
        other_key.external_pk = vec![3];
        assert!(other_key.verify_signature(identity.public_key()).is_err());
        let mut bad = seal.clone();
        bad.header.body_hash = [0; 32];
        assert!(Seal::sign(bad.header, bad.body, [9; 32], vec![], &identity, &mut rng).is_err());
    }
}
