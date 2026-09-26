//! Key schedule (docs/specs.md section 9): one epoch per window, keyed by
//! the window's root secret and chained through the init secrets:
//!
//! ```text
//! GroupContext_n := CBOR_det(["city-g/group-context/v4", gid, n, tree_hash_n,
//!                             registry_hash_n, height_n, district_bits,
//!                             "city-g/v0.4", confirmed_transcript_hash_n])
//! commit_secret_n := DeriveSecret(root_secret_n, "commit")
//! joiner_secret_n := ExpandLabel(Extract(init_n-1, commit_secret_n),
//!                                "joiner", H(GroupContext_n), 32)
//! epoch_secret_n := DeriveSecret(joiner_secret_n, "epoch")
//! init_secret_n, msg_secret_n, confirm_key_n, external_secret_n
//!                := DeriveSecret(epoch_secret_n, "init" | "msg" | "confirm" | "external")
//! confirmed_transcript_hash_n := H_L("confirmed-transcript",
//!                                    [interim_transcript_hash_n-1, seal_hash_n])
//! confirmation_tag_n := MAC(confirm_key_n, confirmed_transcript_hash_n)
//! interim_transcript_hash_n := H_L("interim-transcript",
//!                                  [confirmed_transcript_hash_n, confirmation_tag_n])
//! ```
//!
//! `init_-1` and `interim_transcript_hash_-1` are `ZERO32`. In a window
//! sealed by an entrant, `init_n-1` is replaced by the external init secret
//! the entrant encapsulated to the external key of epoch `n - 1`, which
//! every member of that epoch recovers.

use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cbor::{array, bytes, encode, text, uint};
use crate::crypto::{
    Digest, PROFILE, Secret, ZERO32, derive_secret, digest_eq, expand_label32, extract, h, h_l, mac,
};
use crate::error::{CoreError, CoreResult};
use crate::kem::{KemSecret, encapsulate};

/// Public context of an epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupContext {
    pub gid: Digest,
    pub epoch: u64,
    pub tree_hash: Digest,
    pub registry_hash: Digest,
    pub height: u8,
    pub district_bits: u8,
    pub confirmed_transcript_hash: Digest,
}

impl GroupContext {
    /// `CBOR_det` encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            text("city-g/group-context/v4"),
            bytes(&self.gid),
            uint(self.epoch),
            bytes(&self.tree_hash),
            bytes(&self.registry_hash),
            uint(u64::from(self.height)),
            uint(u64::from(self.district_bits)),
            text(PROFILE),
            bytes(&self.confirmed_transcript_hash),
        ]))
    }

    /// `H(GroupContext_n)`.
    pub fn hash(&self) -> CoreResult<Digest> {
        Ok(h(&self.encode()?))
    }
}

/// `confirmed_transcript_hash_n`.
pub fn confirmed_transcript_hash(prev_interim: &Digest, seal_hash: &Digest) -> CoreResult<Digest> {
    h_l(
        "confirmed-transcript",
        vec![bytes(prev_interim), bytes(seal_hash)],
    )
}

/// `interim_transcript_hash_n`.
pub fn interim_transcript_hash(confirmed: &Digest, tag: &Digest) -> CoreResult<Digest> {
    h_l("interim-transcript", vec![bytes(confirmed), bytes(tag)])
}

/// `joiner_secret_n`.
pub fn joiner_secret(
    prev_init: &[u8; 32],
    commit_secret: &[u8; 32],
    context: &GroupContext,
) -> CoreResult<Secret> {
    let prk = extract(prev_init, commit_secret);
    expand_label32(&prk, "joiner", &context.hash()?)
}

/// Secrets of one epoch. Dropping the value zeroizes them.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EpochSecrets {
    joiner_secret: [u8; 32],
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
    /// Secrets of epoch `n` from `init_n-1` (or an external init secret),
    /// `commit_secret_n` and `GroupContext_n`.
    pub fn derive(
        prev_init: &[u8; 32],
        commit_secret: &[u8; 32],
        context: &GroupContext,
    ) -> CoreResult<Self> {
        let joiner = joiner_secret(prev_init, commit_secret, context)?;
        Self::from_joiner_secret(&joiner)
    }

    /// Secrets of an epoch from its joiner secret.
    pub fn from_joiner_secret(joiner: &[u8; 32]) -> CoreResult<Self> {
        let epoch_secret = derive_secret(joiner, "epoch")?;
        Ok(Self {
            joiner_secret: *joiner,
            init_secret: *derive_secret(&epoch_secret, "init")?,
            msg_secret: *derive_secret(&epoch_secret, "msg")?,
            confirm_key: *derive_secret(&epoch_secret, "confirm")?,
            external_secret: *derive_secret(&epoch_secret, "external")?,
        })
    }

    /// `joiner_secret_n`, kept for the epoch so that the window's committers
    /// can welcome its joiners.
    #[must_use]
    pub const fn joiner_secret(&self) -> &[u8; 32] {
        &self.joiner_secret
    }

    /// `init_secret_n`, the salt of the next epoch.
    #[must_use]
    pub const fn init_secret(&self) -> &[u8; 32] {
        &self.init_secret
    }

    /// `msg_secret_n`, root of the message plane of the epoch.
    #[must_use]
    pub const fn msg_secret(&self) -> &[u8; 32] {
        &self.msg_secret
    }

    /// `confirmation_tag_n`.
    pub fn confirmation_tag(&self, confirmed: &Digest) -> CoreResult<Digest> {
        mac(&self.confirm_key, confirmed)
    }

    /// Check a received confirmation tag, in constant time.
    pub fn check_confirmation_tag(&self, confirmed: &Digest, tag: &Digest) -> CoreResult<()> {
        if digest_eq(&self.confirmation_tag(confirmed)?, tag) {
            Ok(())
        } else {
            Err(CoreError::Invalid("confirmation tag"))
        }
    }

    /// The external X-Wing key pair of the epoch.
    pub fn external_key(&self) -> CoreResult<KemSecret> {
        let seed = expand_label32(&self.external_secret, "external kem", &[])?;
        Ok(KemSecret::from_seed(*seed))
    }

    /// Recover the init secret an entrant encapsulated to this epoch.
    pub fn external_init_secret(&self, kem_output: &[u8]) -> CoreResult<Secret> {
        let shared = self.external_key()?.decapsulate(kem_output)?;
        external_init_from_shared(&shared, kem_output)
    }
}

fn external_init_from_shared(shared: &[u8; 32], kem_output: &[u8]) -> CoreResult<Secret> {
    let prk = extract(&ZERO32, shared);
    expand_label32(&prk, "external init", &h(kem_output))
}

/// Entrant side of the external init: encapsulate to the external key of
/// the current epoch. Returns `(kem_output, external_init_secret)`.
pub fn external_init(
    external_pk: &[u8],
    rng: &mut impl CryptoRngCore,
) -> CoreResult<(Vec<u8>, Secret)> {
    let (kem_output, shared) = encapsulate(external_pk, rng)?;
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
            registry_hash: [3; 32],
            height: 4,
            district_bits: 2,
            confirmed_transcript_hash: [5; 32],
        }
    }

    #[test]
    fn the_context_binds_every_field() {
        let base = context(3);
        let hash = base.hash().unwrap();
        for changed in [
            GroupContext {
                gid: [9; 32],
                ..base.clone()
            },
            GroupContext {
                epoch: 4,
                ..base.clone()
            },
            GroupContext {
                tree_hash: [9; 32],
                ..base.clone()
            },
            GroupContext {
                registry_hash: [9; 32],
                ..base.clone()
            },
            GroupContext {
                height: 5,
                ..base.clone()
            },
            GroupContext {
                district_bits: 3,
                ..base.clone()
            },
            GroupContext {
                confirmed_transcript_hash: [9; 32],
                ..base.clone()
            },
        ] {
            assert_ne!(changed.hash().unwrap(), hash);
        }
    }

    #[test]
    fn epoch_secrets_follow_the_init_chain() {
        let a = EpochSecrets::derive(&[1; 32], &[2; 32], &context(1)).unwrap();
        let b = EpochSecrets::derive(&[7; 32], &[2; 32], &context(1)).unwrap();
        assert_ne!(a.msg_secret(), b.msg_secret());
        let joiner = joiner_secret(&[1; 32], &[2; 32], &context(1)).unwrap();
        let welcomed = EpochSecrets::from_joiner_secret(&joiner).unwrap();
        assert_eq!(welcomed.msg_secret(), a.msg_secret());
        assert_eq!(welcomed.joiner_secret(), &*joiner);
        assert_eq!(
            a.confirmation_tag(&[3; 32]).unwrap(),
            welcomed.confirmation_tag(&[3; 32]).unwrap()
        );
        let tag = a.confirmation_tag(&[3; 32]).unwrap();
        welcomed.check_confirmation_tag(&[3; 32], &tag).unwrap();
        assert!(b.check_confirmation_tag(&[3; 32], &tag).is_err());
        assert_eq!(format!("{a:?}"), "EpochSecrets(..)");
    }

    #[test]
    fn an_entrant_and_the_members_agree_on_the_external_init() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let epoch = EpochSecrets::derive(&[1; 32], &[2; 32], &context(1)).unwrap();
        let external_pk = epoch.external_key().unwrap().public_key();
        let (kem_output, init) = external_init(&external_pk, &mut rng).unwrap();
        assert_eq!(*epoch.external_init_secret(&kem_output).unwrap(), *init);
        let other = EpochSecrets::derive(&[1; 32], &[2; 32], &context(2)).unwrap();
        assert_ne!(*other.external_init_secret(&kem_output).unwrap(), *init);
    }

    #[test]
    fn transcripts_chain() {
        let first = confirmed_transcript_hash(&ZERO32, &[1; 32]).unwrap();
        let interim = interim_transcript_hash(&first, &[2; 32]).unwrap();
        let second = confirmed_transcript_hash(&interim, &[1; 32]).unwrap();
        assert_ne!(first, second);
        assert_ne!(interim, interim_transcript_hash(&first, &[3; 32]).unwrap());
    }
}
