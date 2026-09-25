//! Message plane v4 (audit P-6; fixes M-01, M-02, M-03 and H-10).
//!
//! ```text
//! FramedContent   := ["city-g/msg/v4", gid, epoch, sender_leaf, sender_since,
//!                     generation, content_type, authenticated_data,
//!                     signed_timestamp_ms, plaintext]
//! signature       := ML-DSA-65.Sign(sender_sk, CBOR_det(FramedContent),
//!                                   ctx = "city-g/msg/v4")
//! epoch_ref       := H_L("msg/epoch-ref", [gid, epoch])
//! EnvelopeHeader  := ["city-g-msg-v4", epoch_ref, sender_leaf, sender_since,
//!                     generation, key_commitment]
//! Envelope        := [EnvelopeHeader..., ciphertext]
//! ciphertext      := ChaCha20-Poly1305(key_g, nonce_g,
//!                        aad = CBOR_det(EnvelopeHeader),
//!                        pt  = CBOR_det([CBOR_det(FramedContent), signature]))
//! ```
//!
//! **Per-sender ratchet.** When an epoch becomes active, every member derives
//! one chain per member of the epoch and erases `msg_secret`:
//!
//! ```text
//! sender_secret_0 := ExpandLabel(msg_secret_n, "msg sender",
//!                                CBOR_det([sender_leaf, sender_since]), 32)
//! sender_secret_{g+1} := DeriveSecret(sender_secret_g, "msg next")
//! key_g   := ExpandLabel(sender_secret_g, "msg key", h'', 32)
//! nonce_g := ExpandLabel(sender_secret_g, "msg nonce", h'', 12)
//! key_commitment_g := H_L("msg/key-commitment", [key_g, nonce_g])
//! ```
//!
//! Each device only ever sends on its own chain, with a strictly increasing
//! `generation`, so no two messages share a key and nonce (M-02). A secret
//! is erased as soon as the chain moves past it, which gives forward secrecy
//! inside an epoch. Receivers keep at most [`MAX_SKIPPED_KEYS`] keys of
//! skipped generations and accept at most [`MAX_FORWARD_GENERATIONS`] ahead;
//! a key is deleted once used, so a replayed or too-old generation has no key
//! and is rejected (M-01). The key commitment makes the ciphertext commit to
//! the key. Receivers check that the sender is a member of the epoch (it has
//! a chain) and verify its signature under the device key it held in that
//! epoch before releasing the plaintext, and applications display
//! `signed_timestamp_ms` (H-10).

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ciborium::value::Value;
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_label,
    expect_list, expect_u32, expect_uint, text, uint,
};
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, derive_secret, digest_eq, expand_label_into, h_l};
use crate::identity::{DeviceIdentity, verify_signature};
use crate::tree::{MemberRef, next};

/// Label of framed message content.
pub const MESSAGE_LABEL: &str = "city-g/msg/v4";
/// Label of a message envelope.
pub const ENVELOPE_LABEL: &str = "city-g-msg-v4";
/// Largest plaintext of one message.
pub const MAX_PLAINTEXT_BYTES: usize = 256 * 1024;
/// Largest authenticated data of one message.
pub const MAX_AUTHENTICATED_DATA_BYTES: usize = 4 * 1024;
/// Largest encoded envelope.
pub const MAX_ENVELOPE_BYTES: usize =
    MAX_PLAINTEXT_BYTES + MAX_AUTHENTICATED_DATA_BYTES + 16 * 1024;
/// How far ahead of a sender chain a received generation may be.
pub const MAX_FORWARD_GENERATIONS: u32 = 1024;
/// Keys of skipped generations kept per sender.
pub const MAX_SKIPPED_KEYS: usize = 256;
/// How long the keys of an epoch are kept, after the next epoch became
/// active, to decrypt late messages.
pub const GRACE_WINDOW_MS: u64 = 10 * 60 * 1000;
/// Number of previous epochs whose messages are still accepted during the
/// grace window.
pub const MAX_GRACE_EPOCHS: usize = 4;

/// `epoch_ref := H_L("msg/epoch-ref", [gid, epoch])`.
pub fn epoch_ref(gid: &Digest, epoch: u64) -> CoreResult<Digest> {
    h_l("msg/epoch-ref", vec![bytes(gid), uint(epoch)])
}

/// Clear header of an envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub epoch_ref: Digest,
    pub sender: MemberRef,
    pub generation: u32,
    pub key_commitment: Digest,
}

impl EnvelopeHeader {
    fn fields(&self) -> Vec<Value> {
        vec![
            text(ENVELOPE_LABEL),
            bytes(&self.epoch_ref),
            uint(u64::from(self.sender.leaf)),
            uint(self.sender.since),
            uint(u64::from(self.generation)),
            bytes(&self.key_commitment),
        ]
    }

    /// `CBOR_det(EnvelopeHeader)`, the AEAD associated data.
    pub fn aad(&self) -> CoreResult<Vec<u8>> {
        encode(&array(self.fields()))
    }
}

/// An encrypted message as stored and relayed by the delivery service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub header: EnvelopeHeader,
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    /// Deterministic encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        let mut fields = self.header.fields();
        fields.push(bytes(&self.ciphertext));
        encode(&array(fields))
    }

    /// Decode an envelope (structure only).
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let mut items = expect_array(
            decode(encoded, MAX_ENVELOPE_BYTES, "envelope")?,
            7,
            "envelope",
        )?
        .into_iter();
        expect_label(&next(&mut items, "envelope")?, ENVELOPE_LABEL, "envelope")?;
        let header = EnvelopeHeader {
            epoch_ref: expect_bytes32(next(&mut items, "envelope")?, "envelope epoch")?,
            sender: MemberRef {
                leaf: expect_u32(&next(&mut items, "envelope")?, "envelope sender")?,
                since: expect_uint(&next(&mut items, "envelope")?, "envelope sender")?,
            },
            generation: expect_u32(&next(&mut items, "envelope")?, "envelope generation")?,
            key_commitment: expect_bytes32(next(&mut items, "envelope")?, "envelope commitment")?,
        };
        let ciphertext = expect_bytes(next(&mut items, "envelope")?, "envelope ciphertext")?;
        Ok(Self { header, ciphertext })
    }
}

/// Content signed by the sender.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramedContent {
    pub gid: Digest,
    pub epoch: u64,
    pub sender: MemberRef,
    pub generation: u32,
    pub content_type: u64,
    pub authenticated_data: Vec<u8>,
    pub signed_timestamp_ms: u64,
    pub plaintext: Vec<u8>,
}

impl FramedContent {
    fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            text(MESSAGE_LABEL),
            bytes(&self.gid),
            uint(self.epoch),
            uint(u64::from(self.sender.leaf)),
            uint(self.sender.since),
            uint(u64::from(self.generation)),
            uint(self.content_type),
            bytes(&self.authenticated_data),
            uint(self.signed_timestamp_ms),
            bytes(&self.plaintext),
        ]))
    }

    fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let mut items = expect_array(
            decode(encoded, MAX_ENVELOPE_BYTES, "framed content")?,
            10,
            "framed content",
        )?
        .into_iter();
        expect_label(
            &next(&mut items, "framed content")?,
            MESSAGE_LABEL,
            "framed content",
        )?;
        Ok(Self {
            gid: expect_bytes32(next(&mut items, "framed content")?, "framed content gid")?,
            epoch: expect_uint(&next(&mut items, "framed content")?, "framed content epoch")?,
            sender: MemberRef {
                leaf: expect_u32(&next(&mut items, "framed content")?, "framed sender")?,
                since: expect_uint(&next(&mut items, "framed content")?, "framed sender")?,
            },
            generation: expect_u32(&next(&mut items, "framed content")?, "framed generation")?,
            content_type: expect_uint(&next(&mut items, "framed content")?, "content type")?,
            authenticated_data: expect_bytes(next(&mut items, "framed content")?, "framed aad")?,
            signed_timestamp_ms: expect_uint(&next(&mut items, "framed content")?, "timestamp")?,
            plaintext: expect_bytes(next(&mut items, "framed content")?, "framed plaintext")?,
        })
    }
}

/// A decrypted and authenticated message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedMessage {
    pub epoch: u64,
    pub sender: MemberRef,
    /// Device key the sender signed with (its key in the message's epoch).
    pub sender_device_pk: Vec<u8>,
    pub generation: u32,
    pub content_type: u64,
    pub authenticated_data: Vec<u8>,
    /// Sender-signed timestamp, to display next to the message.
    pub signed_timestamp_ms: u64,
    pub plaintext: Vec<u8>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct MessageKey {
    key: [u8; 32],
    nonce: [u8; 12],
}

impl MessageKey {
    fn derive(sender_secret: &[u8; 32]) -> CoreResult<Self> {
        let mut key = Self {
            key: [0; 32],
            nonce: [0; 12],
        };
        expand_label_into(sender_secret, "msg key", &[], &mut key.key)?;
        expand_label_into(sender_secret, "msg nonce", &[], &mut key.nonce)?;
        Ok(key)
    }

    fn commitment(&self) -> CoreResult<Digest> {
        h_l(
            "msg/key-commitment",
            vec![bytes(&self.key), bytes(&self.nonce)],
        )
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.key))
    }
}

/// One sender's ratchet.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SenderChain {
    next_generation: u32,
    secret: [u8; 32],
    #[zeroize(skip)]
    skipped: BTreeMap<u32, MessageKey>,
}

/// New chain position: next generation, its secret and the keys of the
/// generations skipped to reach it.
struct ChainAdvance {
    next_generation: u32,
    secret: Zeroizing<[u8; 32]>,
    skipped: Vec<(u32, MessageKey)>,
}

/// Result of a tentative key lookup, applied once the message verifies.
struct ChainStep {
    generation: u32,
    key: MessageKey,
    advance: Option<ChainAdvance>,
}

impl SenderChain {
    fn new(msg_secret: &[u8; 32], sender: MemberRef) -> CoreResult<Self> {
        let mut secret = [0u8; 32];
        expand_label_into(
            msg_secret,
            "msg sender",
            &encode(&sender.to_value())?,
            &mut secret,
        )?;
        Ok(Self {
            next_generation: 0,
            secret,
            skipped: BTreeMap::new(),
        })
    }

    fn lookup(&self, generation: u32) -> CoreResult<ChainStep> {
        if generation < self.next_generation {
            let key = self
                .skipped
                .get(&generation)
                .cloned()
                .ok_or(CoreError::Replay)?;
            return Ok(ChainStep {
                generation,
                key,
                advance: None,
            });
        }
        if generation - self.next_generation > MAX_FORWARD_GENERATIONS {
            return Err(CoreError::TooLarge("message generation gap"));
        }
        if generation == u32::MAX {
            return Err(CoreError::TooLarge("message generation"));
        }
        let mut secret = Zeroizing::new(self.secret);
        let mut skipped = Vec::new();
        for skipped_generation in self.next_generation..generation {
            skipped.push((skipped_generation, MessageKey::derive(&secret)?));
            secret = derive_secret(&secret, "msg next")?;
        }
        let key = MessageKey::derive(&secret)?;
        let next_secret = derive_secret(&secret, "msg next")?;
        Ok(ChainStep {
            generation,
            key,
            advance: Some(ChainAdvance {
                next_generation: generation + 1,
                secret: next_secret,
                skipped,
            }),
        })
    }

    fn apply(&mut self, step: ChainStep) {
        match step.advance {
            None => {
                self.skipped.remove(&step.generation);
            }
            Some(advance) => {
                self.next_generation = advance.next_generation;
                self.secret = *advance.secret;
                self.skipped.extend(advance.skipped);
                while self.skipped.len() > MAX_SKIPPED_KEYS {
                    self.skipped.pop_first();
                }
            }
        }
    }

    fn to_value(&self) -> Value {
        array(vec![
            uint(u64::from(self.next_generation)),
            bytes(&self.secret),
            array(
                self.skipped
                    .iter()
                    .map(|(generation, key)| {
                        array(vec![
                            uint(u64::from(*generation)),
                            bytes(&key.key),
                            bytes(&key.nonce),
                        ])
                    })
                    .collect(),
            ),
        ])
    }

    fn from_value(value: Value) -> CoreResult<Self> {
        let mut items = expect_array(value, 3, "sender chain")?.into_iter();
        let next_generation = expect_u32(&next(&mut items, "sender chain")?, "chain generation")?;
        let secret = expect_bytes32(next(&mut items, "sender chain")?, "chain secret")?;
        let mut skipped = BTreeMap::new();
        for entry in expect_list(next(&mut items, "sender chain")?, "skipped keys")? {
            let mut fields = expect_array(entry, 3, "skipped key")?.into_iter();
            let generation = expect_u32(&next(&mut fields, "skipped key")?, "skipped generation")?;
            let key = expect_bytes32(next(&mut fields, "skipped key")?, "skipped key")?;
            let nonce: [u8; 12] = expect_bytes(next(&mut fields, "skipped key")?, "skipped nonce")?
                .try_into()
                .map_err(|_| CoreError::Malformed("skipped nonce"))?;
            if generation >= next_generation {
                return Err(CoreError::Malformed("skipped key generation"));
            }
            skipped.insert(generation, MessageKey { key, nonce });
        }
        if skipped.len() > MAX_SKIPPED_KEYS {
            return Err(CoreError::Malformed("skipped keys"));
        }
        Ok(Self {
            next_generation,
            secret,
            skipped,
        })
    }
}

/// Message keys of one epoch: one ratchet per member.
#[derive(Clone)]
pub struct EpochMessages {
    gid: Digest,
    epoch: u64,
    epoch_ref: Digest,
    own: MemberRef,
    chains: BTreeMap<MemberRef, SenderChain>,
}

impl core::fmt::Debug for EpochMessages {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpochMessages")
            .field("epoch", &self.epoch)
            .field("senders", &self.chains.len())
            .finish_non_exhaustive()
    }
}

impl EpochMessages {
    /// Derive one chain per member of the epoch from `msg_secret`. The
    /// caller erases `msg_secret` afterwards.
    pub fn new(
        gid: &Digest,
        epoch: u64,
        msg_secret: &[u8; 32],
        members: impl IntoIterator<Item = MemberRef>,
        own: MemberRef,
    ) -> CoreResult<Self> {
        let chains = members
            .into_iter()
            .map(|member| Ok((member, SenderChain::new(msg_secret, member)?)))
            .collect::<CoreResult<BTreeMap<_, _>>>()?;
        if !chains.contains_key(&own) {
            return Err(CoreError::Invalid("own leaf is not a member of the epoch"));
        }
        Ok(Self {
            gid: *gid,
            epoch,
            epoch_ref: epoch_ref(gid, epoch)?,
            own,
            chains,
        })
    }

    /// Epoch of these keys.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// `epoch_ref` of these keys.
    #[must_use]
    pub fn epoch_ref(&self) -> &Digest {
        &self.epoch_ref
    }

    /// Next generation this member will send.
    #[must_use]
    pub fn next_own_generation(&self) -> u32 {
        self.chains
            .get(&self.own)
            .map_or(0, |chain| chain.next_generation)
    }

    /// Whether `member` was a member of the epoch (it has a chain).
    #[must_use]
    pub fn has_sender(&self, member: MemberRef) -> bool {
        self.chains.contains_key(&member)
    }

    /// Occupancies of the members of the epoch.
    pub fn senders(&self) -> impl Iterator<Item = MemberRef> + '_ {
        self.chains.keys().copied()
    }

    /// Encrypt and sign a message from this member. `identity` holds the
    /// member's device key; the session checks it owns the leaf.
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt(
        &mut self,
        identity: &DeviceIdentity,
        content_type: u64,
        authenticated_data: &[u8],
        plaintext: &[u8],
        signed_timestamp_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(CoreError::TooLarge("message plaintext"));
        }
        if authenticated_data.len() > MAX_AUTHENTICATED_DATA_BYTES {
            return Err(CoreError::TooLarge("message authenticated data"));
        }
        let sender = self.own;
        self.seal(
            sender,
            identity,
            content_type,
            authenticated_data,
            plaintext,
            signed_timestamp_ms,
            rng,
        )
    }

    /// Encrypt on the chain of `sender`, signing with `identity`.
    #[allow(clippy::too_many_arguments)]
    fn seal(
        &mut self,
        sender: MemberRef,
        identity: &DeviceIdentity,
        content_type: u64,
        authenticated_data: &[u8],
        plaintext: &[u8],
        signed_timestamp_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Vec<u8>> {
        let chain = self
            .chains
            .get(&sender)
            .ok_or(CoreError::Invalid("own leaf is not a member of the epoch"))?;
        let step = chain.lookup(chain.next_generation)?;
        let generation = step.generation;
        let framed = FramedContent {
            gid: self.gid,
            epoch: self.epoch,
            sender,
            generation,
            content_type,
            authenticated_data: authenticated_data.to_vec(),
            signed_timestamp_ms,
            plaintext: plaintext.to_vec(),
        }
        .encode()?;
        let signature = identity.sign(SignatureContext::MESSAGE, &framed, rng)?;
        let inner = Zeroizing::new(encode(&array(vec![bytes(&framed), bytes(&signature)]))?);
        let header = EnvelopeHeader {
            epoch_ref: self.epoch_ref,
            sender,
            generation,
            key_commitment: step.key.commitment()?,
        };
        let aad = header.aad()?;
        let ciphertext = step
            .key
            .cipher()
            .encrypt(
                Nonce::from_slice(&step.key.nonce),
                Payload {
                    msg: &inner,
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::Crypto("message encryption"))?;
        let envelope = Envelope { header, ciphertext }.encode()?;
        if let Some(chain) = self.chains.get_mut(&sender) {
            chain.apply(step);
            // A sender never keeps keys of its own past generations.
            chain.skipped.clear();
        }
        Ok(envelope)
    }

    /// Decrypt and authenticate an envelope of this epoch. The caller checks
    /// that the sender may still send (a member of the current epoch without
    /// a recorded removal) and passes `sender_device_pk`, the device key the
    /// sender held in this epoch.
    pub fn decrypt(
        &mut self,
        envelope: &Envelope,
        sender_device_pk: &[u8],
    ) -> CoreResult<ReceivedMessage> {
        let header = &envelope.header;
        if !digest_eq(&header.epoch_ref, &self.epoch_ref) {
            return Err(CoreError::Invalid("message for another epoch"));
        }
        if header.sender == self.own {
            return Err(CoreError::Invalid("message sent by this member"));
        }
        let chain = self
            .chains
            .get(&header.sender)
            .ok_or(CoreError::Unauthorized(
                "sender is not a member of the epoch",
            ))?;
        let step = chain.lookup(header.generation)?;
        if !digest_eq(&step.key.commitment()?, &header.key_commitment) {
            return Err(CoreError::Decrypt("key commitment"));
        }
        let aad = header.aad()?;
        let inner = Zeroizing::new(
            step.key
                .cipher()
                .decrypt(
                    Nonce::from_slice(&step.key.nonce),
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CoreError::Decrypt("message"))?,
        );
        let mut parts = expect_array(
            decode(&inner, MAX_ENVELOPE_BYTES, "message content")?,
            2,
            "message content",
        )?
        .into_iter();
        let framed_bytes = expect_bytes(next(&mut parts, "message content")?, "framed content")?;
        let signature = expect_bytes(next(&mut parts, "message content")?, "message signature")?;
        let framed = FramedContent::decode(&framed_bytes)?;
        if framed.gid != self.gid
            || framed.epoch != self.epoch
            || framed.sender != header.sender
            || framed.generation != header.generation
        {
            return Err(CoreError::Invalid(
                "framed content does not match its envelope",
            ));
        }
        verify_signature(
            sender_device_pk,
            SignatureContext::MESSAGE,
            &framed_bytes,
            &signature,
            "message",
        )?;
        let received = ReceivedMessage {
            epoch: self.epoch,
            sender: framed.sender,
            sender_device_pk: sender_device_pk.to_vec(),
            generation: framed.generation,
            content_type: framed.content_type,
            authenticated_data: framed.authenticated_data,
            signed_timestamp_ms: framed.signed_timestamp_ms,
            plaintext: framed.plaintext,
        };
        if let Some(chain) = self.chains.get_mut(&header.sender) {
            chain.apply(step);
        }
        Ok(received)
    }

    /// Deterministic encoding, secrets included (persistence by the owner).
    pub fn to_value(&self) -> Value {
        array(vec![
            bytes(&self.gid),
            uint(self.epoch),
            self.own.to_value(),
            array(
                self.chains
                    .iter()
                    .map(|(member, chain)| array(vec![member.to_value(), chain.to_value()]))
                    .collect(),
            ),
        ])
    }

    /// Decode [`EpochMessages::to_value`].
    pub fn from_value(value: Value) -> CoreResult<Self> {
        let mut items = expect_array(value, 4, "epoch messages")?.into_iter();
        let gid = expect_bytes32(next(&mut items, "epoch messages")?, "messages gid")?;
        let epoch = expect_uint(&next(&mut items, "epoch messages")?, "messages epoch")?;
        let own = MemberRef::from_value(next(&mut items, "epoch messages")?)?;
        let mut chains = BTreeMap::new();
        for entry in expect_list(next(&mut items, "epoch messages")?, "sender chains")? {
            let mut fields = expect_array(entry, 2, "sender chain entry")?.into_iter();
            let member = MemberRef::from_value(next(&mut fields, "sender chain entry")?)?;
            let chain = SenderChain::from_value(next(&mut fields, "sender chain entry")?)?;
            if chains.insert(member, chain).is_some() {
                return Err(CoreError::Malformed("duplicate sender chain"));
            }
        }
        if !chains.contains_key(&own) {
            return Err(CoreError::Malformed("own sender chain"));
        }
        Ok(Self {
            gid,
            epoch,
            epoch_ref: epoch_ref(&gid, epoch)?,
            own,
            chains,
        })
    }
}

/// Delivery-service replay window: per `(epoch, sender)` high-water mark
/// plus a 64-generation bitmap below it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayWindow {
    highest: Option<u32>,
    bitmap: u64,
}

impl ReplayWindow {
    /// Width of the window below the high-water mark.
    pub const WIDTH: u32 = 64;

    /// Record `generation`; fails if it was seen or is below the window.
    pub fn accept(&mut self, generation: u32) -> CoreResult<()> {
        let Some(highest) = self.highest else {
            self.highest = Some(generation);
            self.bitmap = 0;
            return Ok(());
        };
        if generation > highest {
            let shift = generation - highest;
            // Bit i records generation (highest - 1 - i).
            self.bitmap = match shift {
                s if s > Self::WIDTH => 0,
                s if s == Self::WIDTH => 1u64 << (Self::WIDTH - 1),
                s => (self.bitmap << s) | (1u64 << (s - 1)),
            };
            self.highest = Some(generation);
            return Ok(());
        }
        if generation == highest {
            return Err(CoreError::Replay);
        }
        let offset = highest - generation - 1;
        if offset >= Self::WIDTH {
            return Err(CoreError::Replay);
        }
        let bit = 1u64 << offset;
        if self.bitmap & bit != 0 {
            return Err(CoreError::Replay);
        }
        self.bitmap |= bit;
        Ok(())
    }

    /// `[highest, bitmap]`, or `null` when nothing was accepted.
    pub fn to_value(&self) -> Value {
        match self.highest {
            None => Value::Null,
            Some(highest) => array(vec![uint(u64::from(highest)), uint(self.bitmap)]),
        }
    }

    /// Decode [`ReplayWindow::to_value`].
    pub fn from_value(value: Value) -> CoreResult<Self> {
        if value == Value::Null {
            return Ok(Self::default());
        }
        let mut items = expect_array(value, 2, "replay window")?.into_iter();
        Ok(Self {
            highest: Some(expect_u32(
                &next(&mut items, "replay window")?,
                "replay window",
            )?),
            bitmap: expect_uint(&next(&mut items, "replay window")?, "replay window")?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const ALICE: MemberRef = MemberRef { leaf: 0, since: 0 };
    const BOB: MemberRef = MemberRef { leaf: 1, since: 2 };
    const CAROL: MemberRef = MemberRef { leaf: 2, since: 3 };

    struct Fixture {
        gid: Digest,
        alice: DeviceIdentity,
        bob: DeviceIdentity,
    }

    fn fixture() -> Fixture {
        Fixture {
            gid: [5; 32],
            alice: DeviceIdentity::from_seed(&[1; 32]),
            bob: DeviceIdentity::from_seed(&[2; 32]),
        }
    }

    fn view(f: &Fixture, epoch: u64, own: MemberRef) -> EpochMessages {
        EpochMessages::new(&f.gid, epoch, &[9u8; 32], [ALICE, BOB, CAROL], own).unwrap()
    }

    #[test]
    fn messages_round_trip_with_sender_authentication() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let f = fixture();
        let (mut alice, mut bob) = (view(&f, 3, ALICE), view(&f, 3, BOB));
        let sealed = alice
            .encrypt(&f.alice, 1, b"ad", b"hello", 1234, &mut rng)
            .unwrap();
        assert_eq!(alice.next_own_generation(), 1);
        let envelope = Envelope::decode(&sealed).unwrap();
        assert_eq!(envelope.encode().unwrap(), sealed);
        assert_eq!(envelope.header.sender, ALICE);
        let received = bob.decrypt(&envelope, f.alice.public_key()).unwrap();
        assert_eq!(received.plaintext, b"hello");
        assert_eq!(received.authenticated_data, b"ad");
        assert_eq!(received.signed_timestamp_ms, 1234);
        assert_eq!(received.sender_device_pk, f.alice.public_key());
        assert_eq!(received.sender, ALICE);
        assert_eq!(received.epoch, 3);
        // Replays have no key any more.
        assert_eq!(
            bob.decrypt(&envelope, f.alice.public_key()),
            Err(CoreError::Replay)
        );
        // Own messages are not decrypted.
        assert!(alice.decrypt(&envelope, f.alice.public_key()).is_err());
        assert!(bob.has_sender(CAROL) && !bob.has_sender(MemberRef { leaf: 2, since: 4 }));
        assert_eq!(bob.senders().count(), 3);
    }

    #[test]
    fn out_of_order_delivery_and_window_bounds() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let f = fixture();
        let (mut alice, mut bob) = (view(&f, 1, ALICE), view(&f, 1, BOB));
        let key = f.alice.public_key();
        let sealed: Vec<Envelope> = (0..4)
            .map(|i| {
                Envelope::decode(&alice.encrypt(&f.alice, 1, b"", &[i], 0, &mut rng).unwrap())
                    .unwrap()
            })
            .collect();
        assert_eq!(bob.decrypt(&sealed[3], key).unwrap().plaintext, [3]);
        assert_eq!(bob.decrypt(&sealed[1], key).unwrap().plaintext, [1]);
        assert_eq!(bob.decrypt(&sealed[1], key), Err(CoreError::Replay));
        assert_eq!(bob.decrypt(&sealed[0], key).unwrap().plaintext, [0]);
        assert_eq!(bob.decrypt(&sealed[2], key).unwrap().plaintext, [2]);

        // A generation too far ahead is refused without advancing the chain.
        let mut far = sealed[0].clone();
        far.header.generation = 4 + MAX_FORWARD_GENERATIONS + 1;
        assert_eq!(
            bob.decrypt(&far, key),
            Err(CoreError::TooLarge("message generation gap"))
        );
        // A forged commitment or ciphertext does not burn the key.
        let next =
            Envelope::decode(&alice.encrypt(&f.alice, 1, b"", b"x", 0, &mut rng).unwrap()).unwrap();
        let mut forged = next.clone();
        forged.header.key_commitment = [0; 32];
        assert_eq!(
            bob.decrypt(&forged, key),
            Err(CoreError::Decrypt("key commitment"))
        );
        let mut flipped = next.clone();
        flipped.ciphertext[0] ^= 1;
        assert_eq!(
            bob.decrypt(&flipped, key),
            Err(CoreError::Decrypt("message"))
        );
        assert_eq!(bob.decrypt(&next, key).unwrap().plaintext, b"x");
    }

    #[test]
    fn membership_epochs_and_sizes_are_enforced() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let f = fixture();
        let mut alice = view(&f, 1, ALICE);
        let sealed =
            Envelope::decode(&alice.encrypt(&f.alice, 1, b"", b"hi", 0, &mut rng).unwrap())
                .unwrap();
        // An epoch in which alice was not a member has no chain for her.
        let mut without_alice =
            EpochMessages::new(&f.gid, 1, &[9u8; 32], [BOB, CAROL], BOB).unwrap();
        assert!(matches!(
            without_alice.decrypt(&sealed, f.alice.public_key()),
            Err(CoreError::Unauthorized(_))
        ));
        // Another epoch's keys do not apply.
        let mut other_epoch = view(&f, 2, BOB);
        assert!(other_epoch.decrypt(&sealed, f.alice.public_key()).is_err());
        // A key other than the sender's does not verify.
        let mut bob = view(&f, 1, BOB);
        assert_eq!(
            bob.decrypt(&sealed, f.bob.public_key()),
            Err(CoreError::BadSignature("message"))
        );
        assert!(
            alice
                .encrypt(
                    &f.alice,
                    1,
                    b"",
                    &vec![0; MAX_PLAINTEXT_BYTES + 1],
                    0,
                    &mut rng
                )
                .is_err()
        );
        assert!(
            alice
                .encrypt(
                    &f.alice,
                    1,
                    &vec![0; MAX_AUTHENTICATED_DATA_BYTES + 1],
                    b"",
                    0,
                    &mut rng
                )
                .is_err()
        );
        assert!(EpochMessages::new(&f.gid, 1, &[0; 32], [BOB], ALICE).is_err());
    }

    #[test]
    fn a_member_cannot_speak_for_another() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let f = fixture();
        let mut alice = view(&f, 1, ALICE);
        let mut carol_view = view(&f, 1, CAROL);
        // Every member can derive bob's chain keys, but not bob's signature.
        let forged = alice
            .seal(BOB, &f.alice, 1, b"", b"spoof", 0, &mut rng)
            .unwrap();
        assert_eq!(
            carol_view.decrypt(&Envelope::decode(&forged).unwrap(), f.bob.public_key()),
            Err(CoreError::BadSignature("message"))
        );
        // The rejected forgery did not consume bob's key: his real message
        // at the same generation still decrypts.
        let mut bob = view(&f, 1, BOB);
        let genuine = bob.encrypt(&f.bob, 1, b"", b"real", 0, &mut rng).unwrap();
        let received = carol_view
            .decrypt(&Envelope::decode(&genuine).unwrap(), f.bob.public_key())
            .unwrap();
        assert_eq!(received.plaintext, b"real");
        // The framed sender must match the envelope.
        let mut moved = Envelope::decode(&genuine).unwrap();
        moved.header.sender = CAROL;
        assert!(carol_view.decrypt(&moved, f.bob.public_key()).is_err());
    }

    #[test]
    fn state_persists_across_encoding() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let f = fixture();
        let (mut alice, mut bob) = (view(&f, 1, ALICE), view(&f, 1, BOB));
        let key = f.alice.public_key();
        let first =
            Envelope::decode(&alice.encrypt(&f.alice, 1, b"", b"1", 0, &mut rng).unwrap()).unwrap();
        let second =
            Envelope::decode(&alice.encrypt(&f.alice, 1, b"", b"2", 0, &mut rng).unwrap()).unwrap();
        bob.decrypt(&second, key).unwrap();
        let mut restored = EpochMessages::from_value(bob.to_value()).unwrap();
        assert_eq!(restored.epoch(), 1);
        assert_eq!(restored.epoch_ref(), bob.epoch_ref());
        assert!(format!("{restored:?}").contains("EpochMessages"));
        assert_eq!(restored.decrypt(&first, key).unwrap().plaintext, b"1");
        assert_eq!(restored.decrypt(&second, key), Err(CoreError::Replay));
        let alice_restored = EpochMessages::from_value(alice.to_value()).unwrap();
        assert_eq!(alice_restored.next_own_generation(), 2);
        assert!(EpochMessages::from_value(uint(1)).is_err());
    }

    #[test]
    fn replay_window_accepts_each_generation_once() {
        let mut window = ReplayWindow::default();
        assert_eq!(ReplayWindow::from_value(window.to_value()).unwrap(), window);
        window.accept(5).unwrap();
        assert_eq!(window.accept(5), Err(CoreError::Replay));
        window.accept(3).unwrap();
        assert_eq!(window.accept(3), Err(CoreError::Replay));
        window.accept(7).unwrap();
        window.accept(4).unwrap();
        window.accept(6).unwrap();
        assert_eq!(window.accept(6), Err(CoreError::Replay));
        window.accept(7 + 64).unwrap();
        assert_eq!(window.accept(7), Err(CoreError::Replay), "below the window");
        window.accept(8).unwrap();
        window.accept(1000).unwrap();
        assert_eq!(window.accept(8), Err(CoreError::Replay));
        let restored = ReplayWindow::from_value(window.to_value()).unwrap();
        assert_eq!(restored, window);
        assert!(ReplayWindow::from_value(uint(3)).is_err());
    }

    #[test]
    fn epoch_refs_differ() {
        let f = fixture();
        assert_ne!(epoch_ref(&f.gid, 1).unwrap(), epoch_ref(&f.gid, 2).unwrap());
        assert_eq!(MemberRef::from_value(BOB.to_value()).unwrap(), BOB);
        assert!(MemberRef::from_value(uint(1)).is_err());
    }
}
