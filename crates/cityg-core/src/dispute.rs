//! Disputes (docs/specs-v0.5-draft.md section 3.8).
//!
//! ```text
//! Dispute          := ["city-g/dispute/v5", gid, epoch, seal_hash, member, task,
//!                      wrap_index, statement, proof]              ctx DISPUTE
//! DisputeStatement := ["city-g/dispute-statement/v5", statement, context, pk_t,
//!                      kem_ciphertext, sealed, pk_v or null]
//! ```
//!
//! A member that a wrap addressed to it cuts off proves the wrap faulty in
//! zero knowledge, and the delivery service convicts the performer that
//! made it. The proof system is not part of this crate: a
//! [`DisputeVerifier`] runs the public checks of a [`DisputeStatement`] and
//! checks a proof of it. [`classify`] tells a member which statement holds.

use ciborium::value::Value;
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::cbor::{array, bytes, encode, text, uint};
use crate::codec::{Signed, open_signed, sign_fields};
use crate::crypto::{Digest, Wrap, kem_pk_hash, node_key, unwrap, wrap_context};
use crate::error::{CoreError, CoreResult};
use crate::identity::DeviceIdentity;
use crate::kem::KemSecret;
use crate::tree::Occupancy;

pub const DISPUTE_LABEL: &str = "city-g/dispute/v5";
pub const DISPUTE_STATEMENT_LABEL: &str = "city-g/dispute-statement/v5";
/// Upper bound on a dispute's proof. The longest proof the research notes
/// measure, the second branch in full, is 805,484 bytes.
pub const MAX_DISPUTE_PROOF_BYTES: usize = 1 << 20;
const MAX_DISPUTE_BYTES: usize = MAX_DISPUTE_PROOF_BYTES + 8 * 1024;
/// An X-Wing public key is ML-KEM-768's `t̂` (1,152 bytes) and matrix seed
/// `ρ` (32 bytes), then the X25519 key: its matrix seed and X25519 key
/// start here.
const SEED_AND_X25519_OFFSET: usize = 1152;

/// What a dispute proves about a wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DisputeKind {
    /// The wrap does not open (branch 1).
    DoesNotOpen,
    /// Its ciphertext's re-encryption differs: no X-Wing encapsulation gives
    /// that ciphertext.
    ReEncryptionDiffers,
    /// It opens to a secret whose node key differs from the published one in
    /// its matrix seed or its X25519 key (branch 2, short).
    KeyDiffersShort,
    /// It opens to a secret whose node key is not the published one
    /// (branch 2).
    KeyDiffers,
}

impl DisputeKind {
    /// The code of the statement in a dispute.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::DoesNotOpen => 1,
            Self::ReEncryptionDiffers => 2,
            Self::KeyDiffersShort => 3,
            Self::KeyDiffers => 4,
        }
    }

    /// The statement of code `code`.
    pub const fn from_code(code: u64) -> CoreResult<Self> {
        match code {
            1 => Ok(Self::DoesNotOpen),
            2 => Ok(Self::ReEncryptionDiffers),
            3 => Ok(Self::KeyDiffersShort),
            4 => Ok(Self::KeyDiffers),
            _ => Err(CoreError::Malformed("dispute statement")),
        }
    }

    /// Whether the statement compares the wrapped secret's node key with the
    /// published key of the wrapped node.
    #[must_use]
    pub const fn names_node_key(self) -> bool {
        matches!(self, Self::KeyDiffersShort | Self::KeyDiffers)
    }
}

/// The public inputs of a dispute: all public data of its epoch. A proof
/// binds them, as the proof system's transcript absorbs [`Self::encode`]
/// before it draws any challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeStatement {
    pub kind: DisputeKind,
    /// The wrap's context (docs/specs.md section 7.2).
    pub context: Vec<u8>,
    /// `pk_t`: the key the wrap is addressed to.
    pub target_key: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub sealed: Vec<u8>,
    /// `pk_v`: the published key of the wrapped node, for the statements
    /// that name it.
    pub node_key: Option<Vec<u8>>,
}

impl DisputeStatement {
    /// The statement `kind` about `wrapped`, a wrap of the window that
    /// created `epoch`, addressed to `target_key`; `node_key` is the
    /// published key of the wrapped node.
    pub fn new(
        gid: &Digest,
        epoch: u64,
        wrapped: &Wrap,
        target_key: &[u8],
        node_key: &[u8],
        kind: DisputeKind,
    ) -> CoreResult<Self> {
        Ok(Self {
            kind,
            context: wrap_context(
                gid,
                epoch,
                wrapped.node,
                wrapped.target,
                &kem_pk_hash(target_key)?,
            )?,
            target_key: target_key.to_vec(),
            kem_ciphertext: wrapped.kem_ciphertext.clone(),
            sealed: wrapped.sealed.clone(),
            node_key: kind.names_node_key().then(|| node_key.to_vec()),
        })
    }

    /// The encoded public inputs.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            text(DISPUTE_STATEMENT_LABEL),
            uint(self.kind.code()),
            bytes(&self.context),
            bytes(&self.target_key),
            bytes(&self.kem_ciphertext),
            bytes(&self.sealed),
            self.node_key.as_deref().map_or(Value::Null, bytes),
        ]))
    }
}

/// A proof system for disputes.
pub trait DisputeVerifier {
    /// Whether `statement` holds: one of its public checks fails (the
    /// ciphertext's X25519 part is not the canonical u-coordinate of a point
    /// of prime order, or a node key the statement names is not canonical),
    /// or `proof` proves it.
    fn verify(&self, statement: &DisputeStatement, proof: &[u8]) -> bool;
}

/// Which statement holds about `wrapped`, a wrap of the window that created
/// `epoch`, for a member that opens it with `key`, its key for `target_key`;
/// `node_key` is the published key of the wrapped node. `None` if the wrap
/// opens to a secret whose node key is `node_key`. A wrap that does not open
/// may also be one whose re-encryption differs, which only ML-KEM's
/// decapsulation shows: the prover, which computes it, proves that statement
/// first when it holds (docs/specs-v0.5-draft.md section 3.8).
pub fn classify(
    gid: &Digest,
    epoch: u64,
    wrapped: &Wrap,
    key: &KemSecret,
    target_key: &[u8],
    node_key_published: &[u8],
) -> CoreResult<Option<DisputeKind>> {
    let Ok(secret) = unwrap(gid, epoch, wrapped, key, target_key) else {
        return Ok(Some(DisputeKind::DoesNotOpen));
    };
    let derived = node_key(&secret)?.public_key();
    if derived == node_key_published {
        return Ok(None);
    }
    let short =
        derived.get(SEED_AND_X25519_OFFSET..) != node_key_published.get(SEED_AND_X25519_OFFSET..);
    Ok(Some(if short {
        DisputeKind::KeyDiffersShort
    } else {
        DisputeKind::KeyDiffers
    }))
}

/// What a member disputes, before it signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeContent {
    pub gid: Digest,
    pub epoch: u64,
    /// The hash of the seal header of the window that created `epoch`.
    pub seal_hash: Digest,
    pub member: Occupancy,
    /// The hash of the district commit or city task that holds the wrap.
    pub task: Digest,
    /// The wrap's index in the task's wraps.
    pub wrap_index: u32,
    pub kind: DisputeKind,
    pub proof: Vec<u8>,
}

/// A member's dispute of a wrap, signed with its device key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dispute {
    pub content: DisputeContent,
    signed: Signed,
}

impl Dispute {
    /// Sign a dispute.
    pub fn sign(
        content: DisputeContent,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        if content.proof.len() > MAX_DISPUTE_PROOF_BYTES {
            return Err(CoreError::Invalid("dispute proof too long"));
        }
        let signed = sign_fields(
            vec![
                text(DISPUTE_LABEL),
                bytes(&content.gid),
                uint(content.epoch),
                bytes(&content.seal_hash),
                content.member.value(),
                bytes(&content.task),
                uint(u64::from(content.wrap_index)),
                uint(content.kind.code()),
                bytes(&content.proof),
            ],
            identity,
            SignatureContext::DISPUTE,
            rng,
        )?;
        Self::decode(&signed.encoded)
    }

    /// Parse a dispute.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) =
            open_signed(encoded, DISPUTE_LABEL, 9, MAX_DISPUTE_BYTES, "dispute")?;
        let content = DisputeContent {
            gid: fields.digest()?,
            epoch: fields.uint()?,
            seal_hash: fields.digest()?,
            member: fields.occupancy()?,
            task: fields.digest()?,
            wrap_index: fields.u32()?,
            kind: DisputeKind::from_code(fields.uint()?)?,
            proof: fields.bytes()?,
        };
        if content.proof.len() > MAX_DISPUTE_PROOF_BYTES {
            return Err(CoreError::Malformed("dispute proof"));
        }
        Ok(Self { content, signed })
    }

    /// Encoded signed dispute.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// Check the member's signature with its device key `device_pk`.
    pub fn verify(&self, gid: &Digest, device_pk: &[u8]) -> CoreResult<()> {
        if &self.content.gid != gid {
            return Err(CoreError::Invalid("dispute of another group"));
        }
        self.signed
            .verify(device_pk, SignatureContext::DISPUTE, "dispute")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::wrap;
    use crate::tree::NodeId;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const GID: Digest = [3u8; 32];

    struct Case {
        target: KemSecret,
        secret: [u8; 32],
        wrapped: Wrap,
    }

    fn case(rng: &mut ChaCha20Rng, secret: [u8; 32]) -> Case {
        let target = KemSecret::generate(rng);
        let node = NodeId { level: 1, index: 0 };
        let wrapped = wrap(
            &GID,
            7,
            node,
            NodeId::leaf(0),
            &target.public_key(),
            &secret,
            &[9; 32],
            rng,
        )
        .unwrap();
        Case {
            target,
            secret,
            wrapped,
        }
    }

    fn published(secret: &[u8; 32]) -> Vec<u8> {
        node_key(secret).unwrap().public_key()
    }

    #[test]
    fn a_member_finds_the_statement_that_holds() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let good = case(&mut rng, [1; 32]);
        let pk_t = good.target.public_key();
        let pk_v = published(&good.secret);
        let classify_with = |wrapped: &Wrap, pk_v: &[u8]| {
            classify(&GID, 7, wrapped, &good.target, &pk_t, pk_v).unwrap()
        };
        // A good wrap: nothing to dispute.
        assert_eq!(classify_with(&good.wrapped, &pk_v), None);
        // A wrong tag: it does not open.
        let mut tampered = good.wrapped.clone();
        tampered.sealed[40] ^= 1;
        assert_eq!(
            classify_with(&tampered, &pk_v),
            Some(DisputeKind::DoesNotOpen)
        );
        // Another secret than the published key's: its matrix seed differs.
        assert_eq!(
            classify_with(&good.wrapped, &published(&[2; 32])),
            Some(DisputeKind::KeyDiffersShort)
        );
        // A published key false in `t` alone takes the full statement.
        let mut forged = pk_v.clone();
        forged[5] ^= 1;
        assert_eq!(
            classify_with(&good.wrapped, &forged),
            Some(DisputeKind::KeyDiffers)
        );
        // In its X25519 key, the short one.
        let mut forged = pk_v;
        forged[SEED_AND_X25519_OFFSET + 40] ^= 1;
        assert_eq!(
            classify_with(&good.wrapped, &forged),
            Some(DisputeKind::KeyDiffersShort)
        );
    }

    #[test]
    fn a_statement_names_the_node_key_only_where_it_compares_it() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let good = case(&mut rng, [1; 32]);
        let pk_t = good.target.public_key();
        let pk_v = published(&good.secret);
        let statement =
            |kind| DisputeStatement::new(&GID, 7, &good.wrapped, &pk_t, &pk_v, kind).unwrap();
        assert_eq!(statement(DisputeKind::DoesNotOpen).node_key, None);
        assert_eq!(statement(DisputeKind::ReEncryptionDiffers).node_key, None);
        assert_eq!(
            statement(DisputeKind::KeyDiffers).node_key.as_deref(),
            Some(pk_v.as_slice())
        );
        // The encoding binds the statement and its inputs.
        let short = statement(DisputeKind::KeyDiffersShort).encode().unwrap();
        assert_eq!(
            short,
            statement(DisputeKind::KeyDiffersShort).encode().unwrap()
        );
        assert_ne!(short, statement(DisputeKind::KeyDiffers).encode().unwrap());
        let other = DisputeStatement::new(
            &GID,
            8,
            &good.wrapped,
            &pk_t,
            &pk_v,
            DisputeKind::KeyDiffersShort,
        )
        .unwrap();
        assert_ne!(short, other.encode().unwrap());
    }

    #[test]
    fn a_dispute_round_trips_and_binds_its_signer() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let member = DeviceIdentity::generate(&mut rng);
        let content = DisputeContent {
            gid: GID,
            epoch: 7,
            seal_hash: [4; 32],
            member: Occupancy { leaf: 5, since: 2 },
            task: [6; 32],
            wrap_index: 3,
            kind: DisputeKind::KeyDiffersShort,
            proof: vec![8; 1000],
        };
        let dispute = Dispute::sign(content.clone(), &member, &mut rng).unwrap();
        assert_eq!(dispute.content, content);
        assert_eq!(Dispute::decode(dispute.encoded()).unwrap(), dispute);
        dispute.verify(&GID, member.public_key()).unwrap();
        let other = DeviceIdentity::generate(&mut rng);
        assert!(dispute.verify(&GID, other.public_key()).is_err());
        assert!(dispute.verify(&[0; 32], member.public_key()).is_err());
        // Proofs are bounded.
        let long = DisputeContent {
            proof: vec![0; MAX_DISPUTE_PROOF_BYTES + 1],
            ..content
        };
        assert!(Dispute::sign(long, &member, &mut rng).is_err());
        assert!(DisputeKind::from_code(5).is_err());
    }
}
