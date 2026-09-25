//! Commits (audit P-2, P-5, H-04), with batched joins and key rotation.
//!
//! A commit moves a group from epoch `n - 1` to epoch `n`. It is a CBOR map
//! with a closed key registry; an unknown key, a key absent where it is
//! required or present where it is forbidden makes the commit malformed
//! (R required, O optional, - forbidden).
//!
//! | Key | Name | Type | Genesis | Member | ExternalJoin | Resync |
//! | --- | --- | --- | --- | --- | --- | --- |
//! | 1 | profile | tstr `"city-g/v0.3"` | R | R | R | R |
//! | 2 | gid | bstr .size 32 | R | R | R | R |
//! | 3 | epoch | uint (`n`) | R (0) | R | R | R |
//! | 4 | kind | uint (0..3) | R | R | R | R |
//! | 5 | prev_interim_transcript_hash | bstr .size 32 | R (zero) | R | R | R |
//! | 6 | author_leaf | uint (in epoch `n`) | R (0) | R | R | R |
//! | 7 | tree_hash (epoch `n`) | bstr .size 32 | R | R | R | R |
//! | 8 | registry_hash (epoch `n`) | bstr .size 32 | R | R | R | R |
//! | 9 | update_path | array | R | R | R | R |
//! | 10 | removals | array of bstr (SignedRemoveProposal) | - | R | R | R |
//! | 11 | joins | array of bstr (SignedJoinRequest) | - | R | R | R |
//! | 12 | admin_changes | array of `[op, leaf, since]` | - | R | - | - |
//! | 13 | admission | bstr (SignedAdmission of the author) | - | - | R | - |
//! | 14 | external_init | bstr (X-Wing ciphertext) | - | - | R | R |
//! | 15 | group_nonce | bstr .size 32 | R | - | - | - |
//! | 16 | capacity | uint | R | - | - | - |
//! | 17 | new_device_pk | bstr (ML-DSA-65) | - | O | - | - |
//! | 108 | author_device_pk | bstr (ML-DSA-65) | R | R | R | R |
//! | 109 | signature | bstr | R | R | R | R |
//! | 110 | confirmation_tag | bstr .size 32 | R | R | R | R |
//! | 111 | rotation_signature | bstr | - | R iff 17 | - | - |
//!
//! ```text
//! anchor_tbs := CBOR_det(commit map without keys 109, 110 and 111)
//! signature  := ML-DSA-65.Sign(author_sk, anchor_tbs, ctx = "city-g/anchor/v3")
//! rotation_signature := ML-DSA-65.Sign(new_sk, anchor_tbs, ctx = "city-g/key-rotation/v1")
//! confirmation_tag := MAC(confirm_key_n, confirmed_transcript_hash_n)
//! ```
//!
//! The confirmation tag cannot be signed: it authenticates the confirmed
//! transcript hash, which covers the signatures. A commit carries exactly
//! one signature by its author, and a second one by the author's new device
//! key when it rotates it.

use ciborium::value::Value;
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::admission::{MAX_ADMISSION_BYTES, SignedAdmission};
use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_label,
    expect_list, expect_u32, expect_uint, text, uint,
};
use crate::error::{CoreError, CoreResult};
use crate::hash::Digest;
use crate::identity::{DeviceIdentity, check_device_key, verify_signature};
use crate::join::{MAX_JOIN_REQUEST_BYTES, SignedJoinRequest};
use crate::key_schedule::PROFILE_ID;
use crate::proposal::{MAX_REMOVE_PROPOSAL_BYTES, SignedRemoveProposal};
use crate::registry::MAX_ADMINS;
use crate::tree::{
    MAX_CAPACITY, UpdatePath, max_update_path_bytes, next, update_path_from_value,
    update_path_to_value, validate_capacity,
};

/// Registry keys of a commit.
pub mod key {
    pub const PROFILE: u64 = 1;
    pub const GID: u64 = 2;
    pub const EPOCH: u64 = 3;
    pub const KIND: u64 = 4;
    pub const PREV_INTERIM_TRANSCRIPT_HASH: u64 = 5;
    pub const AUTHOR_LEAF: u64 = 6;
    pub const TREE_HASH: u64 = 7;
    pub const REGISTRY_HASH: u64 = 8;
    pub const UPDATE_PATH: u64 = 9;
    pub const REMOVALS: u64 = 10;
    pub const JOINS: u64 = 11;
    pub const ADMIN_CHANGES: u64 = 12;
    pub const ADMISSION: u64 = 13;
    pub const EXTERNAL_INIT: u64 = 14;
    pub const GROUP_NONCE: u64 = 15;
    pub const CAPACITY: u64 = 16;
    pub const NEW_DEVICE_PK: u64 = 17;
    pub const AUTHOR_DEVICE_PK: u64 = 108;
    pub const SIGNATURE: u64 = 109;
    pub const CONFIRMATION_TAG: u64 = 110;
    pub const ROTATION_SIGNATURE: u64 = 111;
}

/// Most removals one commit carries.
pub const MAX_REMOVALS_PER_COMMIT: usize = 256;
/// Most join requests one commit carries.
pub const MAX_JOINS_PER_COMMIT: usize = 64;

/// Largest encoded commit for a group of `capacity` leaves: the update path,
/// the largest batches of removals and joins, an admission and fixed-size
/// fields.
#[must_use]
pub fn max_commit_bytes(capacity: u32) -> usize {
    max_update_path_bytes(capacity)
        + MAX_REMOVALS_PER_COMMIT * MAX_REMOVE_PROPOSAL_BYTES
        + MAX_JOINS_PER_COMMIT * MAX_JOIN_REQUEST_BYTES
        + MAX_ADMISSION_BYTES
        + 64 * 1024
}

/// What a commit does besides re-keying its author's path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitKind {
    /// First commit of a group (epoch 0), authored by its creator.
    Genesis,
    /// Commit by a current member: removals, joins, admin changes and a
    /// rotation of its own device key.
    Member,
    /// External commit by an admitted joiner, which may bring other joiners.
    ExternalJoin,
    /// External commit by a current member that lost its state or could not
    /// process a commit: it re-enters its own leaf as a new occupancy.
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

/// Change of the admin set, signed as part of a member commit by an admin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminChange {
    Grant { leaf: u32, since: u64 },
    Revoke { leaf: u32, since: u64 },
}

impl AdminChange {
    fn to_value(&self) -> Value {
        let (op, leaf, since) = match self {
            Self::Grant { leaf, since } => (0, leaf, since),
            Self::Revoke { leaf, since } => (1, leaf, since),
        };
        array(vec![uint(op), uint(u64::from(*leaf)), uint(*since)])
    }

    fn from_value(value: Value) -> CoreResult<Self> {
        let mut items = expect_array(value, 3, "admin change")?.into_iter();
        let op = expect_uint(&next(&mut items, "admin change")?, "admin change op")?;
        let leaf = expect_u32(&next(&mut items, "admin change")?, "admin change leaf")?;
        let since = expect_uint(&next(&mut items, "admin change")?, "admin change since")?;
        match op {
            0 => Ok(Self::Grant { leaf, since }),
            1 => Ok(Self::Revoke { leaf, since }),
            _ => Err(CoreError::Malformed("admin change op")),
        }
    }

    /// Occupancy `[leaf, since]` the change applies to.
    #[must_use]
    pub fn target(&self) -> (u32, u64) {
        match self {
            Self::Grant { leaf, since } | Self::Revoke { leaf, since } => (*leaf, *since),
        }
    }
}

/// Everything a commit carries except its signatures and confirmation tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitContent {
    pub gid: Digest,
    pub epoch: u64,
    pub kind: CommitKind,
    pub prev_interim_transcript_hash: Digest,
    pub author_leaf: u32,
    pub author_device_pk: Vec<u8>,
    pub tree_hash: Digest,
    pub registry_hash: Digest,
    pub update_path: UpdatePath,
    pub removals: Vec<SignedRemoveProposal>,
    pub joins: Vec<SignedJoinRequest>,
    pub admin_changes: Vec<AdminChange>,
    pub admission: Option<SignedAdmission>,
    pub external_init: Option<Vec<u8>>,
    pub group_nonce: Option<Digest>,
    pub capacity: Option<u32>,
    pub new_device_pk: Option<Vec<u8>>,
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
            entry(key::AUTHOR_LEAF, uint(u64::from(self.author_leaf))),
            entry(key::TREE_HASH, bytes(&self.tree_hash)),
            entry(key::REGISTRY_HASH, bytes(&self.registry_hash)),
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
            entries.push(entry(
                key::JOINS,
                array(
                    self.joins
                        .iter()
                        .map(|request| bytes(request.encoded()))
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
        if let Some(admission) = &self.admission {
            entries.push(entry(key::ADMISSION, bytes(admission.encoded())));
        }
        if let Some(external_init) = &self.external_init {
            entries.push(entry(key::EXTERNAL_INIT, bytes(external_init)));
        }
        if let Some(nonce) = &self.group_nonce {
            entries.push(entry(key::GROUP_NONCE, bytes(nonce)));
        }
        if let Some(capacity) = self.capacity {
            entries.push(entry(key::CAPACITY, uint(u64::from(capacity))));
        }
        if let Some(new_device_pk) = &self.new_device_pk {
            entries.push(entry(key::NEW_DEVICE_PK, bytes(new_device_pk)));
        }
        entries
    }

    /// `anchor_tbs := CBOR_det(commit map without keys 109, 110 and 111)`.
    pub fn tbs(&self) -> CoreResult<Vec<u8>> {
        self.check_shape()?;
        encode(&Value::Map(self.entries()))
    }

    /// Sign the content with the author identity (key 109).
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

    /// Sign the content with the author's new device key (key 111).
    pub fn sign_rotation(
        &self,
        new_identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Vec<u8>> {
        if self.new_device_pk.as_deref() != Some(new_identity.public_key()) {
            return Err(CoreError::Invalid("new key does not match the identity"));
        }
        new_identity.sign(SignatureContext::KEY_ROTATION, &self.tbs()?, rng)
    }

    /// Check the per-kind presence rules and list invariants.
    fn check_shape(&self) -> CoreResult<()> {
        let kind = self.kind;
        let genesis = kind == CommitKind::Genesis;
        let shape_ok = (self.group_nonce.is_some() == genesis)
            && (self.capacity.is_some() == genesis)
            && (self.admission.is_some() == (kind == CommitKind::ExternalJoin))
            && (self.external_init.is_some() == kind.is_external())
            && (kind == CommitKind::Member || self.admin_changes.is_empty())
            && (kind == CommitKind::Member || self.new_device_pk.is_none())
            && (!genesis || (self.removals.is_empty() && self.joins.is_empty()))
            && (!genesis || self.author_leaf == 0);
        if !shape_ok {
            return Err(CoreError::Malformed("commit fields for its kind"));
        }
        if self.removals.len() > MAX_REMOVALS_PER_COMMIT {
            return Err(CoreError::TooLarge("commit removals"));
        }
        if self.joins.len() > MAX_JOINS_PER_COMMIT {
            return Err(CoreError::TooLarge("commit joins"));
        }
        if self
            .removals
            .windows(2)
            .any(|pair| pair[0].proposal().target_leaf >= pair[1].proposal().target_leaf)
        {
            return Err(CoreError::Malformed("commit removals order"));
        }
        if self.admin_changes.len() > MAX_ADMINS {
            return Err(CoreError::TooLarge("commit admin changes"));
        }
        let mut leaves: Vec<u32> = self
            .admin_changes
            .iter()
            .map(|change| change.target().0)
            .collect();
        leaves.sort_unstable();
        if leaves.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CoreError::Malformed("duplicate admin change"));
        }
        if let Some(capacity) = self.capacity {
            validate_capacity(capacity)?;
        }
        Ok(())
    }
}

/// A signed commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub content: CommitContent,
    pub signature: Vec<u8>,
    /// Signature by the new device key when the commit rotates it.
    pub rotation_signature: Option<Vec<u8>>,
    pub confirmation_tag: Digest,
}

impl Commit {
    /// Deterministic encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        self.content.check_shape()?;
        if self.rotation_signature.is_some() != self.content.new_device_pk.is_some() {
            return Err(CoreError::Malformed("commit fields for its kind"));
        }
        let mut entries = self.content.entries();
        entries.push(entry(key::SIGNATURE, bytes(&self.signature)));
        entries.push(entry(key::CONFIRMATION_TAG, bytes(&self.confirmation_tag)));
        if let Some(rotation_signature) = &self.rotation_signature {
            entries.push(entry(key::ROTATION_SIGNATURE, bytes(rotation_signature)));
        }
        encode(&Value::Map(entries))
    }

    /// Decode a commit of at most `max_len` bytes, enforce the registry and
    /// verify its signatures. Returns the commit and `anchor_tbs`.
    pub fn decode(encoded: &[u8], max_len: usize) -> CoreResult<(Self, Vec<u8>)> {
        let Value::Map(entries) = decode(encoded, max_len, "commit")? else {
            return Err(CoreError::Malformed("commit"));
        };
        let mut fields = std::collections::BTreeMap::new();
        for (key, value) in entries {
            let key = expect_uint(&key, "commit key")?;
            if !matches!(key, 1..=17 | 108..=111) {
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
        let author_leaf = expect_u32(&required(take(key::AUTHOR_LEAF))?, "commit author leaf")?;
        let tree_hash = expect_bytes32(required(take(key::TREE_HASH))?, "commit tree hash")?;
        let registry_hash =
            expect_bytes32(required(take(key::REGISTRY_HASH))?, "commit registry hash")?;
        let update_path = update_path_from_value(required(take(key::UPDATE_PATH))?)?;
        let author_device_pk =
            expect_bytes(required(take(key::AUTHOR_DEVICE_PK))?, "commit author key")?;
        check_device_key(&author_device_pk, "commit author key")?;
        let signature = expect_bytes(required(take(key::SIGNATURE))?, "commit signature")?;
        let confirmation_tag = expect_bytes32(
            required(take(key::CONFIRMATION_TAG))?,
            "commit confirmation tag",
        )?;
        let (removals, joins) = match (take(key::REMOVALS), take(key::JOINS)) {
            (Some(removals), Some(joins)) if kind != CommitKind::Genesis => {
                let removals = expect_list(removals, "commit removals")?;
                let joins = expect_list(joins, "commit joins")?;
                if removals.len() > MAX_REMOVALS_PER_COMMIT || joins.len() > MAX_JOINS_PER_COMMIT {
                    return Err(CoreError::TooLarge("commit proposals"));
                }
                (
                    removals
                        .into_iter()
                        .map(|item| {
                            SignedRemoveProposal::decode(&expect_bytes(item, "commit removal")?)
                        })
                        .collect::<CoreResult<Vec<_>>>()?,
                    joins
                        .into_iter()
                        .map(|item| SignedJoinRequest::decode(&expect_bytes(item, "commit join")?))
                        .collect::<CoreResult<Vec<_>>>()?,
                )
            }
            (None, None) if kind == CommitKind::Genesis => (Vec::new(), Vec::new()),
            _ => return Err(CoreError::Malformed("commit fields for its kind")),
        };
        let admin_changes = match take(key::ADMIN_CHANGES) {
            Some(value) if kind == CommitKind::Member => {
                expect_list(value, "commit admin changes")?
                    .into_iter()
                    .map(AdminChange::from_value)
                    .collect::<CoreResult<Vec<_>>>()?
            }
            None if kind != CommitKind::Member => Vec::new(),
            _ => return Err(CoreError::Malformed("commit fields for its kind")),
        };
        let admission = take(key::ADMISSION)
            .map(|value| SignedAdmission::decode(&expect_bytes(value, "commit admission")?))
            .transpose()?;
        let external_init = take(key::EXTERNAL_INIT)
            .map(|value| expect_bytes(value, "commit external init"))
            .transpose()?;
        let group_nonce = take(key::GROUP_NONCE)
            .map(|value| expect_bytes32(value, "commit group nonce"))
            .transpose()?;
        let capacity = take(key::CAPACITY)
            .map(|value| expect_u32(&value, "commit capacity"))
            .transpose()?;
        let new_device_pk = take(key::NEW_DEVICE_PK)
            .map(|value| {
                let key = expect_bytes(value, "commit new device key")?;
                check_device_key(&key, "commit new device key")?;
                Ok(key)
            })
            .transpose()?;
        let rotation_signature = take(key::ROTATION_SIGNATURE)
            .map(|value| expect_bytes(value, "commit rotation signature"))
            .transpose()?;

        let content = CommitContent {
            gid,
            epoch,
            kind,
            prev_interim_transcript_hash,
            author_leaf,
            author_device_pk,
            tree_hash,
            registry_hash,
            update_path,
            removals,
            joins,
            admin_changes,
            admission,
            external_init,
            group_nonce,
            capacity,
            new_device_pk,
        };
        let anchor_tbs = content.tbs()?;
        verify_signature(
            &content.author_device_pk,
            SignatureContext::ANCHOR,
            &anchor_tbs,
            &signature,
            "commit",
        )?;
        match (&content.new_device_pk, &rotation_signature) {
            (Some(new_device_pk), Some(rotation_signature)) => verify_signature(
                new_device_pk,
                SignatureContext::KEY_ROTATION,
                &anchor_tbs,
                rotation_signature,
                "commit key rotation",
            )?,
            (None, None) => {}
            _ => return Err(CoreError::Malformed("commit fields for its kind")),
        }
        let commit = Self {
            content,
            signature,
            rotation_signature,
            confirmation_tag,
        };
        if commit.encode()? != encoded {
            return Err(CoreError::NonDeterministic("commit"));
        }
        Ok((commit, anchor_tbs))
    }
}

/// Upper bound of [`Commit::decode`] for a group of `capacity` leaves, capped
/// by the profile maximum.
#[must_use]
pub fn commit_bound(capacity: Option<u32>) -> usize {
    max_commit_bytes(capacity.unwrap_or(MAX_CAPACITY).min(MAX_CAPACITY))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;
