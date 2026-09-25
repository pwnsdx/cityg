//! Epoch-chained key schedule (audit P-2, replaces ME-OR, `E_k` and `K_fs`).
//!
//! ```text
//! GroupContext_n := CBOR_det(["city-g/group-context/v2", gid, n, tree_hash_n,
//!                             roster_hash_n, profile_id, confirmed_transcript_hash_n])
//! commit_secret_n := DeriveSecret(root path secret of commit n, "commit")
//! epoch_secret_n  := ExpandLabel(Extract(init_secret_{n-1}, commit_secret_n),
//!                                "epoch", H(GroupContext_n), 32)
//! init_secret_n     := DeriveSecret(epoch_secret_n, "init")
//! msg_secret_n      := DeriveSecret(epoch_secret_n, "msg")
//! confirm_key_n     := DeriveSecret(epoch_secret_n, "confirm")
//! external_secret_n := DeriveSecret(epoch_secret_n, "external")
//! confirmation_tag_n := MAC(confirm_key_n, confirmed_transcript_hash_n)
//! confirmed_transcript_hash_n := H_L("confirmed-transcript",
//!                                    [interim_transcript_hash_{n-1}, anchor_tbs_n, signature_n])
//! interim_transcript_hash_n := H_L("interim-transcript",
//!                                  [confirmed_transcript_hash_n, confirmation_tag_n])
//! ```
//!
//! `init_secret_{-1}` and `interim_transcript_hash_{-1}` are `ZERO32`.
//! Members erase `epoch_secret_{n-1}` and `init_secret_{n-1}` once epoch `n`
//! is active (forward secrecy per epoch). The GroupContext binds the tree,
//! the roster and the full transcript into every epoch secret, so members
//! with diverging views derive different keys and fail the confirmation tag.
//!
//! **External join.** From `external_secret_n` everyone in epoch `n` derives
//! the ML-KEM-768 key pair `external_n`. A joiner encapsulates to its public
//! key (published in the signed GroupInfo) and uses the resulting
//! `external_init_secret` in place of `init_secret_n`; members recover it by
//! decapsulation. No member has to be online for the join.

use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cbor::{array, bytes, encode, text, uint};
use crate::error::CoreResult;
use crate::hash::{Digest, ZERO32, derive_secret, expand_label32, extract, h, h_l, mac};
use crate::kem::{KemSecret, encapsulate};

/// Profile identifier bound into every GroupContext.
pub const PROFILE_ID: &str = "city-g/v0.2";

/// Public context of epoch `n`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupContext {
    pub gid: Digest,
    pub epoch: u64,
    pub tree_hash: Digest,
    pub roster_hash: Digest,
    pub confirmed_transcript_hash: Digest,
}

impl GroupContext {
    /// `CBOR_det` encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            text("city-g/group-context/v2"),
            bytes(&self.gid),
            uint(self.epoch),
            bytes(&self.tree_hash),
            bytes(&self.roster_hash),
            text(PROFILE_ID),
            bytes(&self.confirmed_transcript_hash),
        ]))
    }

    /// Decode a GroupContext encoding.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        use crate::cbor::{decode, expect_array, expect_bytes32, expect_label, expect_uint};
        use crate::tree::next;
        let mut items =
            expect_array(decode(encoded, 512, "group context")?, 7, "group context")?.into_iter();
        expect_label(
            &next(&mut items, "group context")?,
            "city-g/group-context/v2",
            "group context",
        )?;
        let gid = expect_bytes32(next(&mut items, "group context")?, "group context gid")?;
        let epoch = expect_uint(&next(&mut items, "group context")?, "group context epoch")?;
        let tree_hash = expect_bytes32(next(&mut items, "group context")?, "group context tree")?;
        let roster_hash =
            expect_bytes32(next(&mut items, "group context")?, "group context roster")?;
        expect_label(
            &next(&mut items, "group context")?,
            PROFILE_ID,
            "group context profile",
        )?;
        let confirmed_transcript_hash = expect_bytes32(
            next(&mut items, "group context")?,
            "group context transcript",
        )?;
        Ok(Self {
            gid,
            epoch,
            tree_hash,
            roster_hash,
            confirmed_transcript_hash,
        })
    }

    /// `H(GroupContext_n)`.
    pub fn hash(&self) -> CoreResult<Digest> {
        Ok(h(&self.encode()?))
    }
}

/// `commit_secret := DeriveSecret(root_path_secret, "commit")`.
pub fn commit_secret(root_path_secret: &[u8; 32]) -> CoreResult<Zeroizing<[u8; 32]>> {
    derive_secret(root_path_secret, "commit")
}

/// `confirmed_transcript_hash_n`.
pub fn confirmed_transcript_hash(
    prev_interim_transcript_hash: &Digest,
    anchor_tbs: &[u8],
    signature: &[u8],
) -> CoreResult<Digest> {
    h_l(
        "confirmed-transcript",
        vec![
            bytes(prev_interim_transcript_hash),
            bytes(anchor_tbs),
            bytes(signature),
        ],
    )
}

/// `interim_transcript_hash_n`.
pub fn interim_transcript_hash(
    confirmed_transcript_hash: &Digest,
    confirmation_tag: &Digest,
) -> CoreResult<Digest> {
    h_l(
        "interim-transcript",
        vec![bytes(confirmed_transcript_hash), bytes(confirmation_tag)],
    )
}

/// Secrets of one epoch. Dropping the value zeroizes them.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EpochSecrets {
    epoch_secret: [u8; 32],
    init_secret: [u8; 32],
    msg_secret: [u8; 32],
    confirm_key: [u8; 32],
    external_secret: [u8; 32],
}

impl core::fmt::Debug for EpochSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EpochSecrets(..)")
    }
}

impl EpochSecrets {
    /// Derive the secrets of epoch `n` from `init_secret_{n-1}` (or an
    /// external init secret), `commit_secret_n` and `GroupContext_n`.
    pub fn derive(
        prev_init_secret: &[u8; 32],
        commit_secret: &[u8; 32],
        context: &GroupContext,
    ) -> CoreResult<Self> {
        let prk = extract(prev_init_secret, commit_secret);
        let epoch_secret = expand_label32(&prk, "epoch", &context.hash()?)?;
        Ok(Self {
            epoch_secret: *epoch_secret,
            init_secret: *derive_secret(&epoch_secret, "init")?,
            msg_secret: *derive_secret(&epoch_secret, "msg")?,
            confirm_key: *derive_secret(&epoch_secret, "confirm")?,
            external_secret: *derive_secret(&epoch_secret, "external")?,
        })
    }

    /// `init_secret_n`, the salt of the next epoch.
    #[must_use]
    pub fn init_secret(&self) -> &[u8; 32] {
        &self.init_secret
    }

    /// `msg_secret_n`, root of the message plane of the epoch.
    #[must_use]
    pub fn msg_secret(&self) -> &[u8; 32] {
        &self.msg_secret
    }

    /// `confirmation_tag_n := MAC(confirm_key_n, confirmed_transcript_hash_n)`.
    pub fn confirmation_tag(&self, confirmed_transcript_hash: &Digest) -> CoreResult<Digest> {
        mac(&self.confirm_key, confirmed_transcript_hash)
    }

    /// The external ML-KEM-768 key pair of the epoch.
    pub fn external_key(&self) -> CoreResult<KemSecret> {
        external_key(&self.external_secret)
    }

    /// Recover the init secret an external joiner encapsulated to this epoch.
    pub fn external_init_secret(&self, kem_output: &[u8]) -> CoreResult<Zeroizing<[u8; 32]>> {
        let shared = self.external_key()?.decapsulate(kem_output)?;
        external_init_from_shared(&shared, kem_output)
    }

    /// The secrets a member keeps once the epoch is active.
    #[must_use]
    pub fn retained(&self) -> RetainedEpochSecrets {
        RetainedEpochSecrets {
            init_secret: self.init_secret,
            external_secret: self.external_secret,
        }
    }
}

fn external_key(external_secret: &[u8; 32]) -> CoreResult<KemSecret> {
    KemSecret::derive(external_secret, "external kem")
}

/// Secrets a member keeps for the whole epoch: `init_secret_n` (salt of the
/// next epoch) and `external_secret_n` (external commits). `epoch_secret_n`,
/// `confirm_key_n` and `msg_secret_n` are erased once the epoch is active
/// (the message plane keeps only per-sender ratchets derived from the last).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RetainedEpochSecrets {
    init_secret: [u8; 32],
    external_secret: [u8; 32],
}

impl core::fmt::Debug for RetainedEpochSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RetainedEpochSecrets(..)")
    }
}

impl RetainedEpochSecrets {
    /// Rebuild from persisted parts.
    #[must_use]
    pub fn from_parts(init_secret: [u8; 32], external_secret: [u8; 32]) -> Self {
        Self {
            init_secret,
            external_secret,
        }
    }

    /// `init_secret_n`.
    #[must_use]
    pub fn init_secret(&self) -> &[u8; 32] {
        &self.init_secret
    }

    /// `external_secret_n`.
    #[must_use]
    pub fn external_secret(&self) -> &[u8; 32] {
        &self.external_secret
    }

    /// The external ML-KEM-768 key pair of the epoch.
    pub fn external_key(&self) -> CoreResult<KemSecret> {
        external_key(&self.external_secret)
    }

    /// Recover the init secret an external committer encapsulated to this
    /// epoch.
    pub fn external_init_secret(&self, kem_output: &[u8]) -> CoreResult<Zeroizing<[u8; 32]>> {
        let shared = self.external_key()?.decapsulate(kem_output)?;
        external_init_from_shared(&shared, kem_output)
    }
}

fn external_init_from_shared(
    shared: &[u8; 32],
    kem_output: &[u8],
) -> CoreResult<Zeroizing<[u8; 32]>> {
    let prk = extract(&ZERO32, shared);
    expand_label32(&prk, "external init", &h(kem_output))
}

/// Joiner side of the external init: encapsulate to `external_public_key`.
/// Returns `(kem_output, external_init_secret)`.
pub fn external_init(
    external_public_key: &[u8],
    rng: &mut impl CryptoRngCore,
) -> CoreResult<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let (kem_output, shared) = encapsulate(external_public_key, rng)?;
    let init = external_init_from_shared(&shared, &kem_output)?;
    Ok((kem_output, init))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn context(epoch: u64) -> GroupContext {
        GroupContext {
            gid: [1; 32],
            epoch,
            tree_hash: [2; 32],
            roster_hash: [3; 32],
            confirmed_transcript_hash: [4; 32],
        }
    }

    #[test]
    fn group_context_round_trips_and_binds_every_field() {
        let base = context(5);
        assert_eq!(GroupContext::decode(&base.encode().unwrap()).unwrap(), base);
        let hash = base.hash().unwrap();
        for changed in [
            GroupContext {
                gid: [9; 32],
                ..base.clone()
            },
            GroupContext {
                epoch: 6,
                ..base.clone()
            },
            GroupContext {
                tree_hash: [9; 32],
                ..base.clone()
            },
            GroupContext {
                roster_hash: [9; 32],
                ..base.clone()
            },
            GroupContext {
                confirmed_transcript_hash: [9; 32],
                ..base.clone()
            },
        ] {
            assert_ne!(changed.hash().unwrap(), hash);
        }
        assert!(GroupContext::decode(&[0x80]).is_err());
    }

    #[test]
    fn epoch_secrets_depend_on_every_input() {
        let a = EpochSecrets::derive(&[1; 32], &[2; 32], &context(1)).unwrap();
        let b = EpochSecrets::derive(&[1; 32], &[2; 32], &context(1)).unwrap();
        assert_eq!(a.msg_secret(), b.msg_secret());
        assert_ne!(a.msg_secret(), a.init_secret());
        let c = EpochSecrets::derive(&[9; 32], &[2; 32], &context(1)).unwrap();
        let d = EpochSecrets::derive(&[1; 32], &[9; 32], &context(1)).unwrap();
        let e = EpochSecrets::derive(&[1; 32], &[2; 32], &context(2)).unwrap();
        for other in [&c, &d, &e] {
            assert_ne!(other.msg_secret(), a.msg_secret());
        }
        let tag = a.confirmation_tag(&[5; 32]).unwrap();
        assert_eq!(tag, b.confirmation_tag(&[5; 32]).unwrap());
        assert_ne!(tag, c.confirmation_tag(&[5; 32]).unwrap());
        assert_eq!(format!("{a:?}"), "EpochSecrets(..)");
    }

    #[test]
    fn external_join_agrees_on_init_secret() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let epoch = EpochSecrets::derive(&[1; 32], &[2; 32], &context(4)).unwrap();
        let public_key = epoch.external_key().unwrap().public_key();
        let (kem_output, joiner_init) = external_init(&public_key, &mut rng).unwrap();
        assert_eq!(
            *epoch.external_init_secret(&kem_output).unwrap(),
            *joiner_init
        );
        let other = EpochSecrets::derive(&[1; 32], &[2; 32], &context(5)).unwrap();
        assert_ne!(
            *other.external_init_secret(&kem_output).unwrap(),
            *joiner_init
        );

        let retained = epoch.retained();
        assert_eq!(retained.init_secret(), epoch.init_secret());
        assert_eq!(
            *retained.external_init_secret(&kem_output).unwrap(),
            *joiner_init
        );
        let restored =
            RetainedEpochSecrets::from_parts(*retained.init_secret(), *retained.external_secret());
        assert_eq!(
            restored.external_key().unwrap().public_key(),
            public_key,
            "the external key derives from the persisted secret"
        );
        assert_eq!(format!("{restored:?}"), "RetainedEpochSecrets(..)");
    }

    #[test]
    fn transcript_hashes_chain() {
        let confirmed = confirmed_transcript_hash(&[0; 32], b"tbs", b"sig").unwrap();
        assert_ne!(
            confirmed,
            confirmed_transcript_hash(&[1; 32], b"tbs", b"sig").unwrap()
        );
        assert_ne!(
            confirmed,
            confirmed_transcript_hash(&[0; 32], b"tbs", b"sig2").unwrap()
        );
        let interim = interim_transcript_hash(&confirmed, &[7; 32]).unwrap();
        assert_ne!(
            interim,
            interim_transcript_hash(&confirmed, &[8; 32]).unwrap()
        );
        assert_ne!(*commit_secret(&[1; 32]).unwrap(), [1; 32]);
    }
}
