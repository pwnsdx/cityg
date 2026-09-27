//! The top of a member's path, for island followers
//! (docs/specs-v0.5-draft.md sections 2.2 to 2.5).
//!
//! An *island* is the subtree of `2^c` leaves under node `(c, j)`
//! (`c = island_bits`). An island follower takes the steps of its path up
//! to its island root, and the window's root secret `r_n` from one of:
//!
//! ```text
//! RelayElement := ["city-g/relay/v5", gid, epoch, island, sealed]
//!   context := CBOR_det([gid, epoch, island_bits, island, interim_transcript_hash_n])
//!   sealed  := ChaCha20-Poly1305(key   = ExpandLabel(s_j, "relay key", context, 32),
//!                                nonce = ExpandLabel(s_j, "relay nonce", context, 12),
//!                                aad = context, plaintext = r_n)            (48 bytes)
//! flat element := the Wrap of r_n from the root (height, 0) to the island
//!                 root (c, j), under the island root's key
//! refresh      := the last step of every level above c on the member's path,
//!                 each with the epoch of the window that made it
//! ```
//!
//! `s_j` is the secret of the island root after the window, and
//! `interim_transcript_hash_n` that of the window's epoch, which covers its
//! seal and its confirmation tag. A relay element is made by a member of the
//! island, which knows `s_j` and `r_n`; a flat element by any member that
//! knows `r_n`, once it checked the island root's key against its header.
//! Neither is signed: the member checks the confirmation tag, so a wrong
//! element only makes it fall back to another.
//!
//! The interim hash keeps the branches of a fork apart. They share the epoch
//! and the islands the window left alone; they differ by their seal, or, when
//! an insider led a member into a root of its choice under the real seal, by
//! their tag. Without it, two honest relays would seal two root secrets under
//! the same key and nonce, and the XOR of the elements would give one root to
//! whoever knows the other. Members that accepted the same interim hash hold
//! the same root, so each key seals one plaintext.

use std::collections::BTreeMap;

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::cbor::{array, bytes, decode, encode, expect_array, text, uint};
use crate::codec::Fields;
use crate::crypto::{
    Digest, KEM_WRAP_BYTES, SEALED_SECRET_BYTES, Secret, Wrap, expand_label_into, expand_label32,
    node_key, unwrap, wrap,
};
use crate::error::{CoreError, CoreResult};
use crate::packet::EntrySteps;
use crate::rekey::Step;
use crate::tree::{Occupancy, Shape};

/// Label of a relay element.
pub const RELAY_LABEL: &str = "city-g/relay/v5";

/// Size of a relay element in a packet: the island index and the sealed
/// root secret.
pub const RELAY_ELEMENT_BYTES: usize = SEALED_SECRET_BYTES + 4;

/// What a relay element is bound to: its group, window, island, and the
/// interim transcript hash of the window's epoch, which differs between the
/// branches of a fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayContext {
    pub gid: Digest,
    pub epoch: u64,
    pub island_bits: u8,
    pub island: u32,
    /// `interim_transcript_hash_n`: the window's seal and confirmation tag.
    pub interim: Digest,
}

impl RelayContext {
    fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            bytes(&self.gid),
            uint(self.epoch),
            uint(u64::from(self.island_bits)),
            uint(u64::from(self.island)),
            bytes(&self.interim),
        ]))
    }

    fn cipher(
        &self,
        island_secret: &[u8; 32],
    ) -> CoreResult<(ChaCha20Poly1305, [u8; 12], Vec<u8>)> {
        let context = self.encode()?;
        let key = expand_label32(island_secret, "relay key", &context)?;
        let mut nonce = [0u8; 12];
        expand_label_into(island_secret, "relay nonce", &context, &mut nonce)?;
        Ok((ChaCha20Poly1305::new(key.as_ref().into()), nonce, context))
    }
}

/// The window's root secret, sealed under the secret of an island root by a
/// member of the island.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayElement {
    pub gid: Digest,
    pub epoch: u64,
    pub island: u32,
    /// `r_n` under ChaCha20-Poly1305 (48 bytes).
    pub sealed: Vec<u8>,
}

impl RelayElement {
    /// Seal `root_secret` for the island and window of `context` under the
    /// secret of the island root.
    pub fn seal(
        context: &RelayContext,
        island_secret: &[u8; 32],
        root_secret: &[u8; 32],
    ) -> CoreResult<Self> {
        let (cipher, nonce, aad) = context.cipher(island_secret)?;
        let sealed = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: root_secret,
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::Crypto("relay element"))?;
        Ok(Self {
            gid: context.gid,
            epoch: context.epoch,
            island: context.island,
            sealed,
        })
    }

    /// Open the element of the island and window of `context` with the
    /// secret of the island root. The element's own fields must name them,
    /// and an element sealed for another seal does not open.
    pub fn open(&self, context: &RelayContext, island_secret: &[u8; 32]) -> CoreResult<Secret> {
        if self.gid != context.gid || self.epoch != context.epoch || self.island != context.island {
            return Err(CoreError::Invalid(
                "relay element of another window or island",
            ));
        }
        if self.sealed.len() != SEALED_SECRET_BYTES {
            return Err(CoreError::Malformed("relay element"));
        }
        let (cipher, nonce, aad) = context.cipher(island_secret)?;
        let opened = Zeroizing::new(
            cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &self.sealed,
                        aad: &aad,
                    },
                )
                .map_err(|_| CoreError::Decrypt("relay element"))?,
        );
        let mut secret = Zeroizing::new([0u8; 32]);
        if opened.len() != 32 {
            return Err(CoreError::Malformed("relay element"));
        }
        secret.copy_from_slice(&opened);
        Ok(secret)
    }

    /// `CBOR_det` encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            text(RELAY_LABEL),
            bytes(&self.gid),
            uint(self.epoch),
            uint(u64::from(self.island)),
            bytes(&self.sealed),
        ]))
    }

    /// Parse a relay element.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        const WHAT: &str = "relay element";
        let items = expect_array(decode(encoded, 256, WHAT)?, 5, WHAT)?;
        let mut fields = Fields::new(items, WHAT);
        let label = fields.next()?;
        crate::cbor::expect_label(&label, RELAY_LABEL, WHAT)?;
        let element = Self {
            gid: fields.digest()?,
            epoch: fields.uint()?,
            island: fields.u32()?,
            sealed: fields.bytes()?,
        };
        if element.sealed.len() != SEALED_SECRET_BYTES {
            return Err(CoreError::Malformed(WHAT));
        }
        Ok(element)
    }
}

/// The flat element of island `island`: `root_secret` wrapped from the root
/// to the island root, whose key is `island_pk`, with coins hedged by
/// `hedge` (the maker's, docs/specs-v0.5-draft.md section 3.3).
#[allow(clippy::too_many_arguments)]
pub fn flat_element(
    gid: &Digest,
    epoch: u64,
    shape: Shape,
    island: u32,
    island_pk: &[u8],
    root_secret: &[u8; 32],
    hedge: &[u8; 32],
    rng: &mut impl CryptoRngCore,
) -> CoreResult<Wrap> {
    if !shape.has_islands() || island >= shape.island_count() {
        return Err(CoreError::Invalid("flat element for no island"));
    }
    wrap(
        gid,
        epoch,
        shape.root(),
        shape.island_root(island),
        island_pk,
        root_secret,
        hedge,
        rng,
    )
}

/// Open the flat element of island `island` with the secret of its root.
pub fn open_flat(
    gid: &Digest,
    epoch: u64,
    shape: Shape,
    island: u32,
    wrapped: &Wrap,
    island_secret: &[u8; 32],
) -> CoreResult<Secret> {
    if !shape.has_islands()
        || wrapped.node != shape.root()
        || wrapped.target != shape.island_root(island)
    {
        return Err(CoreError::Invalid("flat element of another island"));
    }
    let key = node_key(island_secret)?;
    let pk = key.public_key();
    unwrap(gid, epoch, wrapped, &key, &pk)
}

/// How an island follower gets the root secret of a window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Top {
    /// A relay element of its island.
    Relay(RelayElement),
    /// A flat element of its island.
    Flat(Wrap),
    /// The last step of every level above its island, as of the window.
    Refresh(EntrySteps),
}

impl Top {
    /// Size in bytes as a deployment would send it.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Relay(_) => RELAY_ELEMENT_BYTES,
            Self::Flat(_) => KEM_WRAP_BYTES,
            Self::Refresh(steps) => steps
                .values()
                .map(|(_, step)| match step {
                    Step::Chain => 12,
                    Step::Wrap(_) => 12 + KEM_WRAP_BYTES,
                })
                .sum(),
        }
    }
}

/// Who gives the islands of a window their top: a relay per island that
/// has an online member of the previous epoch, and flat elements for the
/// other islands, spread over the relays.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TopTask {
    pub epoch: u64,
    /// The relay of each island.
    pub relays: BTreeMap<u32, Occupancy>,
    /// The islands whose flat elements each member makes.
    pub flats: BTreeMap<Occupancy, Vec<u32>>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::fresh_secret;
    use crate::tree::{Divisions, NodeId};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const GID: Digest = [6u8; 32];

    fn context(epoch: u64, island_bits: u8, island: u32, interim: Digest) -> RelayContext {
        RelayContext {
            gid: GID,
            epoch,
            island_bits,
            island,
            interim,
        }
    }

    #[test]
    fn a_relay_element_opens_only_for_its_window_island_transcript_and_secret() {
        let island_secret = [4u8; 32];
        let root = [9u8; 32];
        let here = context(7, 2, 3, [1; 32]);
        let relay = RelayElement::seal(&here, &island_secret, &root).unwrap();
        assert_eq!(relay.sealed.len(), SEALED_SECRET_BYTES);
        assert_eq!(*relay.open(&here, &island_secret).unwrap(), root);
        let decoded = RelayElement::decode(&relay.encode().unwrap()).unwrap();
        assert_eq!(decoded, relay);
        // Another window, island, island size, transcript or secret: refused.
        assert!(
            relay
                .open(&context(8, 2, 3, [1; 32]), &island_secret)
                .is_err()
        );
        assert!(
            relay
                .open(&context(7, 2, 4, [1; 32]), &island_secret)
                .is_err()
        );
        assert!(
            relay
                .open(&context(7, 3, 3, [1; 32]), &island_secret)
                .is_err()
        );
        assert!(
            relay
                .open(&context(7, 2, 3, [2; 32]), &island_secret)
                .is_err()
        );
        assert!(relay.open(&here, &[5u8; 32]).is_err());
        let mut moved = relay.clone();
        moved.epoch = 8;
        assert!(
            moved
                .open(&context(8, 2, 3, [1; 32]), &island_secret)
                .is_err()
        );
        let mut flipped = relay;
        flipped.sealed[0] ^= 1;
        assert!(flipped.open(&here, &island_secret).is_err());
    }

    #[test]
    fn two_branches_of_a_fork_seal_under_different_keys() {
        // Two branches of one epoch, as a fork shows them to two relays of an
        // island that neither re-keyed: two seals, or one seal with the tag of
        // an insider that chose the root. The same island secret, two roots,
        // two interim transcript hashes.
        let island_secret = [4u8; 32];
        let (root_a, root_b) = ([9u8; 32], [7u8; 32]);
        let a = RelayElement::seal(&context(7, 2, 3, [1; 32]), &island_secret, &root_a).unwrap();
        let b = RelayElement::seal(&context(7, 2, 3, [2; 32]), &island_secret, &root_b).unwrap();
        // Under one key and nonce, the ciphertexts would differ by the XOR of
        // the roots, and a member of one branch would read the other's root.
        let xor = |x: &[u8], y: &[u8]| x.iter().zip(y).map(|(p, q)| p ^ q).collect::<Vec<u8>>();
        assert_ne!(xor(&a.sealed[..32], &b.sealed[..32]), xor(&root_a, &root_b));
        assert!(a.open(&context(7, 2, 3, [2; 32]), &island_secret).is_err());
    }

    #[test]
    fn a_flat_element_opens_with_the_island_root_secret() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let shape = Shape::new(5, Divisions::new(3, 2, 8).unwrap()).unwrap();
        let island_secret = fresh_secret(&[0; 32], &mut rng).unwrap();
        let island_pk = node_key(&island_secret).unwrap().public_key();
        let root = [8u8; 32];
        let flat = flat_element(&GID, 4, shape, 5, &island_pk, &root, &[6; 32], &mut rng).unwrap();
        assert_eq!(flat.node, shape.root());
        assert_eq!(flat.target, NodeId { level: 2, index: 5 });
        assert_eq!(
            *open_flat(&GID, 4, shape, 5, &flat, &island_secret).unwrap(),
            root
        );
        assert!(open_flat(&GID, 4, shape, 4, &flat, &island_secret).is_err());
        assert!(open_flat(&GID, 5, shape, 5, &flat, &island_secret).is_err());
        assert!(open_flat(&GID, 4, shape, 5, &flat, &[1u8; 32]).is_err());
        let small = Shape::new(2, Divisions::new(3, 2, 8).unwrap()).unwrap();
        assert!(flat_element(&GID, 4, small, 0, &island_pk, &root, &[6; 32], &mut rng).is_err());
    }
}
