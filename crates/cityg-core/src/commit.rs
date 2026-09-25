//! Commits: the v0.2 anchors (audit P-2, P-5, H-04).
//!
//! A commit moves a group from epoch `n - 1` to epoch `n`. It is a CBOR map
//! with a closed key registry; an unknown key, a key absent where it is
//! required or present where it is forbidden makes the commit malformed.
//!
//! | Key | Name | Type | Genesis | Member | Join | Resync |
//! | --- | --- | --- | --- | --- | --- | --- |
//! | 1 | profile | tstr `"city-g/v0.2"` | R | R | R | R |
//! | 2 | gid | bstr .size 32 | R | R | R | R |
//! | 3 | epoch | uint (`n`) | R (0) | R | R | R |
//! | 4 | kind | uint (0..3) | R | R | R | R |
//! | 5 | prev_interim_transcript_hash | bstr .size 32 | R (zero) | R | R | R |
//! | 6 | author_leaf_id | bstr .size 32 | R | R | R | R |
//! | 7 | roster_hash (epoch `n`) | bstr .size 32 | R | R | R | R |
//! | 8 | tree_hash (epoch `n`) | bstr .size 32 | R | R | R | R |
//! | 9 | update_path | array | R | R | R | R |
//! | 10 | removals | array of bstr (SignedRemoveProposal) | - | R | R | R |
//! | 11 | admin_changes | array of [op, device_pk] | - | R | - | - |
//! | 12 | join | [slot, generation, bstr / null] | - | - | R | R |
//! | 13 | external_init (ML-KEM ciphertext) | bstr | - | - | R | R |
//! | 14 | group_nonce | bstr .size 32 | R | - | - | - |
//! | 15 | n_max | uint | R | - | - | - |
//! | 108 | author_device_pk | bstr (ML-DSA-87) | R | R | R | R |
//! | 109 | signature | bstr | R | R | R | R |
//! | 110 | confirmation_tag | bstr .size 32 | R | R | R | R |
//!
//! ```text
//! anchor_tbs := CBOR_det(commit map without keys 109 and 110)
//! signature  := ML-DSA-87.Sign(author_sk, anchor_tbs, ctx = "city-g/anchor/v2")
//! confirmation_tag := MAC(confirm_key_n, confirmed_transcript_hash_n)
//! ```
//!
//! The confirmation tag cannot be signed: it authenticates the confirmed
//! transcript hash, which covers the signature. Every commit, whatever its
//! kind, carries exactly one signature (P-5); no proof material from other
//! commits is ever copied in.

use ciborium::value::Value;
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::admission::SignedAdmission;
use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_label,
    expect_list, expect_u32, expect_uint, text, uint,
};
use crate::error::{CoreError, CoreResult};
use crate::hash::Digest;
use crate::identity::{DeviceIdentity, check_device_key, verify_signature};
use crate::key_schedule::PROFILE_ID;
use crate::proposal::SignedRemoveProposal;
use crate::roster::MAX_ADMINS;
use crate::tree::{
    MAX_N_MAX, UpdatePath, max_update_path_bytes, next, update_path_from_value,
    update_path_to_value,
};

/// Registry keys of a commit.
pub mod key {
    pub const PROFILE: u64 = 1;
    pub const GID: u64 = 2;
    pub const EPOCH: u64 = 3;
    pub const KIND: u64 = 4;
    pub const PREV_INTERIM_TRANSCRIPT_HASH: u64 = 5;
    pub const AUTHOR_LEAF_ID: u64 = 6;
    pub const ROSTER_HASH: u64 = 7;
    pub const TREE_HASH: u64 = 8;
    pub const UPDATE_PATH: u64 = 9;
    pub const REMOVALS: u64 = 10;
    pub const ADMIN_CHANGES: u64 = 11;
    pub const JOIN: u64 = 12;
    pub const EXTERNAL_INIT: u64 = 13;
    pub const GROUP_NONCE: u64 = 14;
    pub const N_MAX: u64 = 15;
    pub const AUTHOR_DEVICE_PK: u64 = 108;
    pub const SIGNATURE: u64 = 109;
    pub const CONFIRMATION_TAG: u64 = 110;
}

/// Largest encoded commit for a tree of `n_max` leaves: the update path, one
/// removal proposal per slot, an admission and fixed-size fields.
#[must_use]
pub fn max_commit_bytes(n_max: u32) -> usize {
    max_update_path_bytes(n_max) + n_max as usize * 12 * 1024 + 64 * 1024
}

/// What a commit does besides re-keying its author's path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitKind {
    /// First commit of a group (epoch 0), authored by its creator.
    Genesis,
    /// Commit by a current member: removals and admin changes.
    Member,
    /// External commit by an admitted joiner (MLS-style external join).
    ExternalJoin,
    /// External commit by a current member that lost its state or could not
    /// process a commit: it re-enters its own slot under a new generation.
    Resync,
}

impl CommitKind {
    fn code(self) -> u64 {
        match self {
            Self::Genesis => 0,
            Self::Member => 1,
            Self::ExternalJoin => 2,
            Self::Resync => 3,
        }
    }

    fn from_code(code: u64) -> CoreResult<Self> {
        match code {
            0 => Ok(Self::Genesis),
            1 => Ok(Self::Member),
            2 => Ok(Self::ExternalJoin),
            3 => Ok(Self::Resync),
            _ => Err(CoreError::Malformed("commit kind")),
        }
    }

    /// Whether the commit is external (its author does not know the previous
    /// epoch's init secret and uses an external init instead).
    #[must_use]
    pub fn is_external(self) -> bool {
        matches!(self, Self::ExternalJoin | Self::Resync)
    }
}

/// Change of the admin set, signed as part of a member commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminChange {
    Grant(Vec<u8>),
    Revoke(Vec<u8>),
}

impl AdminChange {
    fn to_value(&self) -> Value {
        match self {
            Self::Grant(device_pk) => array(vec![uint(0), bytes(device_pk)]),
            Self::Revoke(device_pk) => array(vec![uint(1), bytes(device_pk)]),
        }
    }

    fn from_value(value: Value) -> CoreResult<Self> {
        let mut items = expect_array(value, 2, "admin change")?.into_iter();
        let op = expect_uint(&next(&mut items, "admin change")?, "admin change op")?;
        let device_pk = expect_bytes(next(&mut items, "admin change")?, "admin change key")?;
        check_device_key(&device_pk, "admin change key")?;
        match op {
            0 => Ok(Self::Grant(device_pk)),
            1 => Ok(Self::Revoke(device_pk)),
            _ => Err(CoreError::Malformed("admin change op")),
        }
    }

    /// Device key the change applies to.
    #[must_use]
    pub fn device_pk(&self) -> &[u8] {
        match self {
            Self::Grant(device_pk) | Self::Revoke(device_pk) => device_pk,
        }
    }
}

/// Slot entered by the author of an external commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRecord {
    pub slot: u32,
    pub generation: u64,
    /// Admission of a joiner; `None` for a resynchronisation.
    pub admission: Option<SignedAdmission>,
}

/// Everything a commit carries except its signature and confirmation tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitContent {
    pub gid: Digest,
    pub epoch: u64,
    pub kind: CommitKind,
    pub prev_interim_transcript_hash: Digest,
    pub author_leaf_id: Digest,
    pub author_device_pk: Vec<u8>,
    pub roster_hash: Digest,
    pub tree_hash: Digest,
    pub update_path: UpdatePath,
    pub removals: Vec<SignedRemoveProposal>,
    pub admin_changes: Vec<AdminChange>,
    pub join: Option<JoinRecord>,
    pub external_init: Option<Vec<u8>>,
    pub group_nonce: Option<Digest>,
    pub n_max: Option<u32>,
}

fn entry(key: u64, value: Value) -> (Value, Value) {
    (uint(key), value)
}

impl CommitContent {
    fn entries(&self) -> Vec<(Value, Value)> {
        let mut entries = vec![
            entry(key::PROFILE, text(PROFILE_ID)),
            entry(key::GID, bytes(&self.gid)),
            entry(key::EPOCH, uint(self.epoch)),
            entry(key::KIND, uint(self.kind.code())),
            entry(
                key::PREV_INTERIM_TRANSCRIPT_HASH,
                bytes(&self.prev_interim_transcript_hash),
            ),
            entry(key::AUTHOR_LEAF_ID, bytes(&self.author_leaf_id)),
            entry(key::ROSTER_HASH, bytes(&self.roster_hash)),
            entry(key::TREE_HASH, bytes(&self.tree_hash)),
            entry(key::UPDATE_PATH, update_path_to_value(&self.update_path)),
            entry(key::AUTHOR_DEVICE_PK, bytes(&self.author_device_pk)),
        ];
        if self.kind != CommitKind::Genesis {
            entries.push(entry(
                key::REMOVALS,
                array(
                    self.removals
                        .iter()
                        .map(|proposal| bytes(proposal.encoded()))
                        .collect(),
                ),
            ));
        }
        if self.kind == CommitKind::Member {
            entries.push(entry(
                key::ADMIN_CHANGES,
                array(
                    self.admin_changes
                        .iter()
                        .map(AdminChange::to_value)
                        .collect(),
                ),
            ));
        }
        if let Some(join) = &self.join {
            entries.push(entry(
                key::JOIN,
                array(vec![
                    uint(u64::from(join.slot)),
                    uint(join.generation),
                    join.admission
                        .as_ref()
                        .map_or(Value::Null, |admission| bytes(admission.encoded())),
                ]),
            ));
        }
        if let Some(external_init) = &self.external_init {
            entries.push(entry(key::EXTERNAL_INIT, bytes(external_init)));
        }
        if let Some(nonce) = &self.group_nonce {
            entries.push(entry(key::GROUP_NONCE, bytes(nonce)));
        }
        if let Some(n_max) = self.n_max {
            entries.push(entry(key::N_MAX, uint(u64::from(n_max))));
        }
        entries
    }

    /// `anchor_tbs := CBOR_det(commit map without keys 109 and 110)`.
    pub fn tbs(&self) -> CoreResult<Vec<u8>> {
        self.check_shape()?;
        encode(&Value::Map(self.entries()))
    }

    /// Sign the content with the author identity.
    pub fn sign(
        &self,
        author: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Vec<u8>> {
        if author.public_key() != self.author_device_pk {
            return Err(CoreError::Invalid("author key does not match the identity"));
        }
        author.sign(SignatureContext::ANCHOR, &self.tbs()?, rng)
    }

    /// Check the per-kind presence rules and list invariants.
    fn check_shape(&self) -> CoreResult<()> {
        let kind = self.kind;
        let genesis = kind == CommitKind::Genesis;
        let external = kind.is_external();
        let shape_ok = (self.group_nonce.is_some() == genesis)
            && (self.n_max.is_some() == genesis)
            && (self.join.is_some() == external)
            && (self.external_init.is_some() == external)
            && (kind == CommitKind::Member || self.admin_changes.is_empty())
            && (!genesis || self.removals.is_empty())
            && match (&self.join, kind) {
                (Some(join), CommitKind::ExternalJoin) => join.admission.is_some(),
                (Some(join), CommitKind::Resync) => join.admission.is_none(),
                _ => true,
            };
        if !shape_ok {
            return Err(CoreError::Malformed("commit fields for its kind"));
        }
        if self
            .removals
            .windows(2)
            .any(|pair| pair[0].proposal().target_slot >= pair[1].proposal().target_slot)
        {
            return Err(CoreError::Malformed("commit removals order"));
        }
        if self.admin_changes.len() > MAX_ADMINS {
            return Err(CoreError::TooLarge("commit admin changes"));
        }
        let mut keys: Vec<&[u8]> = self
            .admin_changes
            .iter()
            .map(AdminChange::device_pk)
            .collect();
        keys.sort_unstable();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CoreError::Malformed("duplicate admin change"));
        }
        if self.n_max.is_some_and(|n_max| n_max > MAX_N_MAX) {
            return Err(CoreError::Invalid("n_max"));
        }
        Ok(())
    }
}

/// A signed commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub content: CommitContent,
    pub signature: Vec<u8>,
    pub confirmation_tag: Digest,
}

impl Commit {
    /// Deterministic encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        self.content.check_shape()?;
        let mut entries = self.content.entries();
        entries.push(entry(key::SIGNATURE, bytes(&self.signature)));
        entries.push(entry(key::CONFIRMATION_TAG, bytes(&self.confirmation_tag)));
        encode(&Value::Map(entries))
    }

    /// Decode a commit of at most `max_len` bytes, enforce the registry and
    /// verify the author signature. Returns the commit and `anchor_tbs`.
    pub fn decode(encoded: &[u8], max_len: usize) -> CoreResult<(Self, Vec<u8>)> {
        let Value::Map(entries) = decode(encoded, max_len, "commit")? else {
            return Err(CoreError::Malformed("commit"));
        };
        let mut fields = std::collections::BTreeMap::new();
        for (key, value) in entries {
            let key = expect_uint(&key, "commit key")?;
            if !matches!(key, 1..=15 | 108..=110) {
                return Err(CoreError::Malformed("unknown commit key"));
            }
            fields.insert(key, value);
        }
        let mut take = |key: u64| fields.remove(&key);
        let required =
            |value: Option<Value>| value.ok_or(CoreError::Malformed("missing commit key"));

        expect_label(&required(take(key::PROFILE))?, PROFILE_ID, "commit profile")?;
        let gid = expect_bytes32(required(take(key::GID))?, "commit gid")?;
        let epoch = expect_uint(&required(take(key::EPOCH))?, "commit epoch")?;
        let kind = CommitKind::from_code(expect_uint(&required(take(key::KIND))?, "commit kind")?)?;
        let prev_interim_transcript_hash = expect_bytes32(
            required(take(key::PREV_INTERIM_TRANSCRIPT_HASH))?,
            "commit transcript",
        )?;
        let author_leaf_id = expect_bytes32(required(take(key::AUTHOR_LEAF_ID))?, "commit author")?;
        let roster_hash = expect_bytes32(required(take(key::ROSTER_HASH))?, "commit roster hash")?;
        let tree_hash = expect_bytes32(required(take(key::TREE_HASH))?, "commit tree hash")?;
        let update_path = update_path_from_value(required(take(key::UPDATE_PATH))?)?;
        let author_device_pk =
            expect_bytes(required(take(key::AUTHOR_DEVICE_PK))?, "commit author key")?;
        check_device_key(&author_device_pk, "commit author key")?;
        let signature = expect_bytes(required(take(key::SIGNATURE))?, "commit signature")?;
        let confirmation_tag = expect_bytes32(
            required(take(key::CONFIRMATION_TAG))?,
            "commit confirmation tag",
        )?;

        let removals = match take(key::REMOVALS) {
            Some(value) => expect_list(value, "commit removals")?
                .into_iter()
                .map(|item| SignedRemoveProposal::decode(&expect_bytes(item, "commit removal")?))
                .collect::<CoreResult<Vec<_>>>()?,
            None if kind == CommitKind::Genesis => Vec::new(),
            None => return Err(CoreError::Malformed("missing commit key")),
        };
        let admin_changes = match take(key::ADMIN_CHANGES) {
            Some(value) if kind == CommitKind::Member => {
                expect_list(value, "commit admin changes")?
                    .into_iter()
                    .map(AdminChange::from_value)
                    .collect::<CoreResult<Vec<_>>>()?
            }
            Some(_) => return Err(CoreError::Malformed("commit fields for its kind")),
            None if kind == CommitKind::Member => {
                return Err(CoreError::Malformed("missing commit key"));
            }
            None => Vec::new(),
        };
        let join = take(key::JOIN)
            .map(|value| {
                let mut items = expect_array(value, 3, "commit join")?.into_iter();
                let slot = expect_u32(&next(&mut items, "commit join")?, "commit join slot")?;
                let generation =
                    expect_uint(&next(&mut items, "commit join")?, "commit join generation")?;
                let admission = match next(&mut items, "commit join")? {
                    Value::Null => None,
                    Value::Bytes(encoded) => Some(SignedAdmission::decode(&encoded)?),
                    _ => return Err(CoreError::Malformed("commit join admission")),
                };
                Ok(JoinRecord {
                    slot,
                    generation,
                    admission,
                })
            })
            .transpose()?;
        let external_init = take(key::EXTERNAL_INIT)
            .map(|value| expect_bytes(value, "commit external init"))
            .transpose()?;
        let group_nonce = take(key::GROUP_NONCE)
            .map(|value| expect_bytes32(value, "commit group nonce"))
            .transpose()?;
        let n_max = take(key::N_MAX)
            .map(|value| expect_u32(&value, "commit n_max"))
            .transpose()?;

        let content = CommitContent {
            gid,
            epoch,
            kind,
            prev_interim_transcript_hash,
            author_leaf_id,
            author_device_pk,
            roster_hash,
            tree_hash,
            update_path,
            removals,
            admin_changes,
            join,
            external_init,
            group_nonce,
            n_max,
        };
        let anchor_tbs = content.tbs()?;
        verify_signature(
            &content.author_device_pk,
            SignatureContext::ANCHOR,
            &anchor_tbs,
            &signature,
            "commit",
        )?;
        let commit = Self {
            content,
            signature,
            confirmation_tag,
        };
        if commit.encode()? != encoded {
            return Err(CoreError::NonDeterministic("commit"));
        }
        Ok((commit, anchor_tbs))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::identity::leaf_id;
    use crate::kem::KemSecret;
    use crate::tree::UpdatePath;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn content(author: &DeviceIdentity, kind: CommitKind, rng: &mut ChaCha20Rng) -> CommitContent {
        let gid = [3; 32];
        CommitContent {
            gid,
            epoch: 4,
            kind,
            prev_interim_transcript_hash: [5; 32],
            author_leaf_id: leaf_id(&gid, author.public_key()).unwrap(),
            author_device_pk: author.public_key().to_vec(),
            roster_hash: [6; 32],
            tree_hash: [7; 32],
            update_path: UpdatePath {
                leaf_public_key: KemSecret::generate(rng).public_key(),
                nodes: Vec::new(),
            },
            removals: Vec::new(),
            admin_changes: Vec::new(),
            join: None,
            external_init: None,
            group_nonce: None,
            n_max: None,
        }
    }

    fn signed(content: CommitContent, author: &DeviceIdentity, rng: &mut ChaCha20Rng) -> Vec<u8> {
        let signature = content.sign(author, rng).unwrap();
        Commit {
            content,
            signature,
            confirmation_tag: [8; 32],
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn commits_round_trip_and_verify() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let mut member = content(&alice, CommitKind::Member, &mut rng);
        member.admin_changes = vec![AdminChange::Grant(
            DeviceIdentity::from_seed(&[2; 32]).public_key().to_vec(),
        )];
        let encoded = signed(member.clone(), &alice, &mut rng);
        let (decoded, tbs) = Commit::decode(&encoded, 1 << 20).unwrap();
        assert_eq!(decoded.content, member);
        assert_eq!(tbs, member.tbs().unwrap());
        assert_eq!(decoded.encode().unwrap(), encoded);

        let mut genesis = content(&alice, CommitKind::Genesis, &mut rng);
        genesis.group_nonce = Some([1; 32]);
        genesis.n_max = Some(8);
        let encoded = signed(genesis.clone(), &alice, &mut rng);
        assert_eq!(
            Commit::decode(&encoded, 1 << 20).unwrap().0.content,
            genesis
        );

        let mut resync = content(&alice, CommitKind::Resync, &mut rng);
        resync.join = Some(JoinRecord {
            slot: 1,
            generation: 2,
            admission: None,
        });
        resync.external_init = Some(vec![1, 2, 3]);
        let encoded = signed(resync.clone(), &alice, &mut rng);
        assert_eq!(Commit::decode(&encoded, 1 << 20).unwrap().0.content, resync);
        assert!(CommitKind::Resync.is_external() && !CommitKind::Member.is_external());
    }

    #[test]
    fn registry_and_signature_are_enforced() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let member = content(&alice, CommitKind::Member, &mut rng);
        assert!(member.sign(&bob, &mut rng).is_err());

        // Genesis fields on a member commit are rejected.
        let mut wrong = member.clone();
        wrong.n_max = Some(8);
        assert!(wrong.tbs().is_err());
        // External join without admission is rejected.
        let mut join = content(&alice, CommitKind::ExternalJoin, &mut rng);
        join.join = Some(JoinRecord {
            slot: 1,
            generation: 1,
            admission: None,
        });
        join.external_init = Some(vec![0]);
        assert!(join.tbs().is_err());

        // A signature over other content does not verify.
        let encoded = signed(member.clone(), &alice, &mut rng);
        let Value::Map(mut entries) = decode(&encoded, 1 << 20, "t").unwrap() else {
            panic!("map")
        };
        for (key, value) in &mut entries {
            if *key == uint(key::EPOCH) {
                *value = uint(5);
            }
        }
        let forged = encode(&Value::Map(entries.clone())).unwrap();
        assert_eq!(
            Commit::decode(&forged, 1 << 20).err(),
            Some(CoreError::BadSignature("commit"))
        );
        // Unknown keys are rejected.
        entries.push((uint(99), uint(1)));
        let unknown = encode(&Value::Map(entries)).unwrap();
        assert_eq!(
            Commit::decode(&unknown, 1 << 20).err(),
            Some(CoreError::Malformed("unknown commit key"))
        );
        assert!(Commit::decode(&encoded, 100).is_err(), "size bound");
        assert!(Commit::decode(&[0x80], 100).is_err());
        assert!(max_commit_bytes(1024) > max_update_path_bytes(1024));
    }

    #[test]
    fn admin_change_encoding() {
        let key = DeviceIdentity::from_seed(&[1; 32]).public_key().to_vec();
        for change in [
            AdminChange::Grant(key.clone()),
            AdminChange::Revoke(key.clone()),
        ] {
            assert_eq!(AdminChange::from_value(change.to_value()).unwrap(), change);
            assert_eq!(change.device_pk(), key.as_slice());
        }
        assert!(AdminChange::from_value(array(vec![uint(2), bytes(&key)])).is_err());
        assert!(AdminChange::from_value(array(vec![uint(0), bytes(&[1])])).is_err());
    }
}
