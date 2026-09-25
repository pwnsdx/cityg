//! Signed group information for external commits (audit P-2, "adhésion
//! asynchrone").
//!
//! ```text
//! GroupInfo       := ["city-g/group-info/v2", GroupContext_n (bstr),
//!                     confirmation_tag_n, external_pub_n, signer_leaf_id]
//! SignedGroupInfo := [GroupInfo..., signature]   ctx "city-g/group-info/v2"
//! ```
//!
//! The author of epoch `n` signs the GroupInfo of that epoch and publishes
//! it with its commit; the delivery service checks that it matches the
//! epoch it computed and that its signer authored the commit, and never
//! signs it itself. A joiner verifies the signature under the device key the
//! roster of epoch `n` lists for `signer_leaf_id`, after checking the tree
//! and roster it received against the hashes in `GroupContext_n`.

use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::cbor::{bytes, expect_bytes, expect_bytes32, text};
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, digest_eq};
use crate::identity::DeviceIdentity;
use crate::kem::validate_public_key;
use crate::key_schedule::{GroupContext, interim_transcript_hash};
use crate::roster::Roster;
use crate::signed::{open_signed, sign_fields};
use crate::tree::PublicTree;

/// Label of a GroupInfo.
pub const GROUP_INFO_LABEL: &str = "city-g/group-info/v2";
/// Upper bound on an encoded signed GroupInfo.
pub const MAX_GROUP_INFO_BYTES: usize = 16 * 1024;

/// Public information about epoch `n` signed by its author.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInfo {
    pub group_context: GroupContext,
    pub confirmation_tag: Digest,
    pub external_public_key: Vec<u8>,
    pub signer_leaf_id: Digest,
}

impl GroupInfo {
    /// Sign the GroupInfo.
    pub fn sign(
        &self,
        signer: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedGroupInfo> {
        if signer.leaf_id(&self.group_context.gid)? != self.signer_leaf_id {
            return Err(CoreError::Invalid(
                "group info signer does not match the identity",
            ));
        }
        let encoded = sign_fields(
            vec![
                text(GROUP_INFO_LABEL),
                bytes(&self.group_context.encode()?),
                bytes(&self.confirmation_tag),
                bytes(&self.external_public_key),
                bytes(&self.signer_leaf_id),
            ],
            signer,
            SignatureContext::GROUP_INFO,
            rng,
        )?;
        SignedGroupInfo::decode_unverified(&encoded)
    }

    /// `interim_transcript_hash_n` of the epoch.
    pub fn interim_transcript_hash(&self) -> CoreResult<Digest> {
        interim_transcript_hash(
            &self.group_context.confirmed_transcript_hash,
            &self.confirmation_tag,
        )
    }
}

/// A decoded GroupInfo and its signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedGroupInfo {
    info: GroupInfo,
    tbs: Vec<u8>,
    signature: Vec<u8>,
    encoded: Vec<u8>,
}

impl SignedGroupInfo {
    /// Decode without verifying the signature (the signer key comes from
    /// the roster; see [`SignedGroupInfo::verify`]).
    pub fn decode_unverified(encoded: &[u8]) -> CoreResult<Self> {
        let opened = open_signed(
            encoded,
            GROUP_INFO_LABEL,
            5,
            MAX_GROUP_INFO_BYTES,
            "group info",
        )?;
        let mut fields = opened.fields.iter().skip(1).cloned();
        let mut next = || fields.next().ok_or(CoreError::Malformed("group info"));
        let group_context = GroupContext::decode(&expect_bytes(next()?, "group info context")?)?;
        let confirmation_tag = expect_bytes32(next()?, "group info confirmation tag")?;
        let external_public_key = expect_bytes(next()?, "group info external key")?;
        validate_public_key(&external_public_key)?;
        let signer_leaf_id = expect_bytes32(next()?, "group info signer")?;
        Ok(Self {
            info: GroupInfo {
                group_context,
                confirmation_tag,
                external_public_key,
                signer_leaf_id,
            },
            tbs: opened.tbs,
            signature: opened.signature,
            encoded: encoded.to_vec(),
        })
    }

    /// The GroupInfo content (not yet authenticated unless
    /// [`SignedGroupInfo::verify`] succeeded).
    #[must_use]
    pub fn info(&self) -> &GroupInfo {
        &self.info
    }

    /// Deterministic encoding (signature included).
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Verify the GroupInfo against the tree and roster of its epoch: both
    /// match the hashes of the GroupContext and the signer is a member.
    pub fn verify(&self, tree: &PublicTree, roster: &Roster) -> CoreResult<()> {
        let context = &self.info.group_context;
        if !digest_eq(&tree.tree_hash()?, &context.tree_hash) {
            return Err(CoreError::Invalid("tree does not match the group info"));
        }
        if !digest_eq(&roster.roster_hash()?, &context.roster_hash) {
            return Err(CoreError::Invalid("roster does not match the group info"));
        }
        let signer = roster
            .member_by_leaf(&self.info.signer_leaf_id)
            .ok_or(CoreError::Unauthorized("group info signer is not a member"))?;
        crate::identity::verify_signature(
            &signer.device_pk,
            SignatureContext::GROUP_INFO,
            &self.tbs,
            &self.signature,
            "group info",
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::identity::leaf_id;
    use crate::kem::KemSecret;
    use crate::tree::LeafNode;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn group_info_verifies_against_its_epoch() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let gid = [4; 32];
        let roster = Roster::genesis(&gid, alice.public_key()).unwrap();
        let mut tree = PublicTree::new(4).unwrap();
        tree.add_leaf(
            0,
            LeafNode {
                leaf_id: leaf_id(&gid, alice.public_key()).unwrap(),
                generation: 1,
                public_key: KemSecret::generate(&mut rng).public_key(),
            },
        )
        .unwrap();
        let info = GroupInfo {
            group_context: GroupContext {
                gid,
                epoch: 0,
                tree_hash: tree.tree_hash().unwrap(),
                roster_hash: roster.roster_hash().unwrap(),
                confirmed_transcript_hash: [9; 32],
            },
            confirmation_tag: [8; 32],
            external_public_key: KemSecret::generate(&mut rng).public_key(),
            signer_leaf_id: alice.leaf_id(&gid).unwrap(),
        };
        let signed = info.sign(&alice, &mut rng).unwrap();
        signed.verify(&tree, &roster).unwrap();
        let decoded = SignedGroupInfo::decode_unverified(signed.encoded()).unwrap();
        assert_eq!(decoded.info(), &info);
        assert_ne!(info.interim_transcript_hash().unwrap(), [0; 32]);
        assert!(info.sign(&bob, &mut rng).is_err());

        // A different tree or roster, or a non-member signer, is rejected.
        let empty = PublicTree::new(4).unwrap();
        assert!(signed.verify(&empty, &roster).is_err());
        let other = Roster::genesis(&gid, bob.public_key()).unwrap();
        assert!(signed.verify(&tree, &other).is_err());
        let forged = GroupInfo {
            signer_leaf_id: bob.leaf_id(&gid).unwrap(),
            ..info
        }
        .sign(&bob, &mut rng)
        .unwrap();
        assert!(matches!(
            forged.verify(&tree, &roster),
            Err(CoreError::Unauthorized(_))
        ));
        assert!(SignedGroupInfo::decode_unverified(&[0x80]).is_err());
    }
}
