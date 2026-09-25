//! Message plane v3 (audit P-6; fixes M-01, M-02, M-03 and H-10).
//!
//! ```text
//! FramedContent   := ["city-g/msg/v3", gid, epoch, sender_leaf_id, generation,
//!                     content_type, authenticated_data, signed_timestamp_ms,
//!                     plaintext]
//! signature       := ML-DSA-87.Sign(sender_sk, CBOR_det(FramedContent),
//!                                   ctx = "city-g/msg/v3")
//! epoch_ref       := H_L("msg/epoch-ref", [gid, epoch])
//! EnvelopeHeader  := ["city-g-msg-v3", epoch_ref, sender_leaf_id, generation,
//!                     key_commitment]
//! Envelope        := [EnvelopeHeader..., ciphertext]
//! ciphertext      := ChaCha20-Poly1305(key_g, nonce_g,
//!                        aad = CBOR_det(EnvelopeHeader),
//!                        pt  = CBOR_det([CBOR_det(FramedContent), signature]))
//! ```
//!
//! **Per-sender ratchet.** When an epoch becomes active, every member derives
//! one chain per roster member and erases `msg_secret`:
//!
//! ```text
//! sender_secret_0 := ExpandLabel(msg_secret_n, "msg sender", sender_leaf_id, 32)
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
//! the key. Receivers check that the sender is in the roster of the epoch
//! and verify its signature before releasing the plaintext, and applications
//! display `signed_timestamp_ms` (H-10).

use std::collections::{BTreeMap, BTreeSet};

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
use crate::roster::Roster;
use crate::tree::next;

/// Label of framed message content.
pub const MESSAGE_LABEL: &str = "city-g/msg/v3";
/// Label of a message envelope.
pub const ENVELOPE_LABEL: &str = "city-g-msg-v3";
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
/// How long the previous epoch's keys are kept to decrypt late messages.
pub const GRACE_WINDOW_MS: u64 = 10 * 60 * 1000;

/// `epoch_ref := H_L("msg/epoch-ref", [gid, epoch])`.
pub fn epoch_ref(gid: &Digest, epoch: u64) -> CoreResult<Digest> {
    h_l("msg/epoch-ref", vec![bytes(gid), uint(epoch)])
}

/// Clear header of an envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub epoch_ref: Digest,
    pub sender_leaf_id: Digest,
    pub generation: u32,
    pub key_commitment: Digest,
}

impl EnvelopeHeader {
    fn fields(&self) -> Vec<Value> {
        vec![
            text(ENVELOPE_LABEL),
            bytes(&self.epoch_ref),
            bytes(&self.sender_leaf_id),
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
            6,
            "envelope",
        )?
        .into_iter();
        expect_label(&next(&mut items, "envelope")?, ENVELOPE_LABEL, "envelope")?;
        let header = EnvelopeHeader {
            epoch_ref: expect_bytes32(next(&mut items, "envelope")?, "envelope epoch")?,
            sender_leaf_id: expect_bytes32(next(&mut items, "envelope")?, "envelope sender")?,
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
    pub sender_leaf_id: Digest,
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
            bytes(&self.sender_leaf_id),
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
            9,
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
            sender_leaf_id: expect_bytes32(next(&mut items, "framed content")?, "framed sender")?,
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
    pub sender_leaf_id: Digest,
    pub sender_device_pk: Vec<u8>,
    pub sender_slot: u32,
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
    fn new(msg_secret: &[u8; 32], sender_leaf_id: &Digest) -> CoreResult<Self> {
        let mut secret = [0u8; 32];
        expand_label_into(msg_secret, "msg sender", sender_leaf_id, &mut secret)?;
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
    own_leaf_id: Digest,
    chains: BTreeMap<Digest, SenderChain>,
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
    /// Derive one chain per member of `roster` from `msg_secret`. The caller
    /// erases `msg_secret` afterwards.
    pub fn new(
        gid: &Digest,
        epoch: u64,
        msg_secret: &[u8; 32],
        roster: &Roster,
        own_leaf_id: &Digest,
    ) -> CoreResult<Self> {
        let chains = roster
            .members()
            .map(|member| {
                Ok((
                    member.leaf_id,
                    SenderChain::new(msg_secret, &member.leaf_id)?,
                ))
            })
            .collect::<CoreResult<BTreeMap<_, _>>>()?;
        if !chains.contains_key(own_leaf_id) {
            return Err(CoreError::Invalid("own leaf is not in the roster"));
        }
        Ok(Self {
            gid: *gid,
            epoch,
            epoch_ref: epoch_ref(gid, epoch)?,
            own_leaf_id: *own_leaf_id,
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
            .get(&self.own_leaf_id)
            .map_or(0, |chain| chain.next_generation)
    }

    /// Encrypt and sign a message from this member.
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
        if identity.leaf_id(&self.gid)? != self.own_leaf_id {
            return Err(CoreError::Invalid("identity does not own this session"));
        }
        let sender = self.own_leaf_id;
        self.seal(
            &sender,
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
        sender: &Digest,
        identity: &DeviceIdentity,
        content_type: u64,
        authenticated_data: &[u8],
        plaintext: &[u8],
        signed_timestamp_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Vec<u8>> {
        let chain = self
            .chains
            .get(sender)
            .ok_or(CoreError::Invalid("own leaf is not in the roster"))?;
        let step = chain.lookup(chain.next_generation)?;
        let generation = step.generation;
        let framed = FramedContent {
            gid: self.gid,
            epoch: self.epoch,
            sender_leaf_id: *sender,
            generation,
            content_type,
            authenticated_data: authenticated_data.to_vec(),
            signed_timestamp_ms,
            plaintext: plaintext.to_vec(),
        }
        .encode()?;
        let signature = identity.sign(SignatureContext::MESSAGE_V3, &framed, rng)?;
        let inner = Zeroizing::new(encode(&array(vec![bytes(&framed), bytes(&signature)]))?);
        let header = EnvelopeHeader {
            epoch_ref: self.epoch_ref,
            sender_leaf_id: *sender,
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
        if let Some(chain) = self.chains.get_mut(sender) {
            chain.apply(step);
            // A sender never keeps keys of its own past generations.
            chain.skipped.clear();
        }
        Ok(envelope)
    }

    /// Decrypt and authenticate an envelope of this epoch. `roster` is the
    /// roster of the epoch; `blocked` lists leaves with a recorded removal
    /// proposal, whose messages are rejected.
    pub fn decrypt(
        &mut self,
        envelope: &Envelope,
        roster: &Roster,
        blocked: &BTreeSet<Digest>,
    ) -> CoreResult<ReceivedMessage> {
        let header = &envelope.header;
        if !digest_eq(&header.epoch_ref, &self.epoch_ref) {
            return Err(CoreError::Invalid("message for another epoch"));
        }
        if header.sender_leaf_id == self.own_leaf_id {
            return Err(CoreError::Invalid("message sent by this member"));
        }
        let sender =
            roster
                .member_by_leaf(&header.sender_leaf_id)
                .ok_or(CoreError::Unauthorized(
                    "sender is not a member of the epoch",
                ))?;
        if blocked.contains(&header.sender_leaf_id) {
            return Err(CoreError::Unauthorized("sender has a pending removal"));
        }
        let chain = self
            .chains
            .get(&header.sender_leaf_id)
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
            || framed.sender_leaf_id != header.sender_leaf_id
            || framed.generation != header.generation
        {
            return Err(CoreError::Invalid(
                "framed content does not match its envelope",
            ));
        }
        verify_signature(
            &sender.device_pk,
            SignatureContext::MESSAGE_V3,
            &framed_bytes,
            &signature,
            "message",
        )?;
        let received = ReceivedMessage {
            epoch: self.epoch,
            sender_leaf_id: framed.sender_leaf_id,
            sender_device_pk: sender.device_pk.clone(),
            sender_slot: sender.slot,
            generation: framed.generation,
            content_type: framed.content_type,
            authenticated_data: framed.authenticated_data,
            signed_timestamp_ms: framed.signed_timestamp_ms,
            plaintext: framed.plaintext,
        };
        if let Some(chain) = self.chains.get_mut(&header.sender_leaf_id) {
            chain.apply(step);
        }
        Ok(received)
    }

    /// Deterministic encoding, secrets included (persistence by the owner).
    pub fn to_value(&self) -> Value {
        array(vec![
            bytes(&self.gid),
            uint(self.epoch),
            bytes(&self.own_leaf_id),
            array(
                self.chains
                    .iter()
                    .map(|(leaf, chain)| array(vec![bytes(leaf), chain.to_value()]))
                    .collect(),
            ),
        ])
    }

    /// Decode [`EpochMessages::to_value`].
    pub fn from_value(value: Value) -> CoreResult<Self> {
        let mut items = expect_array(value, 4, "epoch messages")?.into_iter();
        let gid = expect_bytes32(next(&mut items, "epoch messages")?, "messages gid")?;
        let epoch = expect_uint(&next(&mut items, "epoch messages")?, "messages epoch")?;
        let own_leaf_id = expect_bytes32(next(&mut items, "epoch messages")?, "messages leaf")?;
        let mut chains = BTreeMap::new();
        for entry in expect_list(next(&mut items, "epoch messages")?, "sender chains")? {
            let mut fields = expect_array(entry, 2, "sender chain entry")?.into_iter();
            let leaf = expect_bytes32(next(&mut fields, "sender chain entry")?, "chain leaf")?;
            let chain = SenderChain::from_value(next(&mut fields, "sender chain entry")?)?;
            if chains.insert(leaf, chain).is_some() {
                return Err(CoreError::Malformed("duplicate sender chain"));
            }
        }
        if !chains.contains_key(&own_leaf_id) {
            return Err(CoreError::Malformed("own sender chain"));
        }
        Ok(Self {
            gid,
            epoch,
            epoch_ref: epoch_ref(&gid, epoch)?,
            own_leaf_id,
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

/// Sender set helper: leaf ids of `roster` members.
#[must_use]
pub fn roster_leaves(roster: &Roster) -> BTreeSet<Digest> {
    roster.members().map(|member| member.leaf_id).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::identity::leaf_id;
    use crate::roster::MemberRecord;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    struct Fixture {
        gid: Digest,
        alice: DeviceIdentity,
        bob: DeviceIdentity,
        roster: Roster,
    }

    fn fixture() -> Fixture {
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let gid = [5; 32];
        let mut roster = Roster::genesis(&gid, alice.public_key()).unwrap();
        roster
            .add_member(MemberRecord {
                leaf_id: leaf_id(&gid, bob.public_key()).unwrap(),
                device_pk: bob.public_key().to_vec(),
                slot: 1,
                generation: 1,
                admission_hash: [0; 32],
            })
            .unwrap();
        Fixture {
            gid,
            alice,
            bob,
            roster,
        }
    }

    fn pair(f: &Fixture, epoch: u64) -> (EpochMessages, EpochMessages) {
        let secret = [9u8; 32];
        let a = EpochMessages::new(
            &f.gid,
            epoch,
            &secret,
            &f.roster,
            &f.alice.leaf_id(&f.gid).unwrap(),
        )
        .unwrap();
        let b = EpochMessages::new(
            &f.gid,
            epoch,
            &secret,
            &f.roster,
            &f.bob.leaf_id(&f.gid).unwrap(),
        )
        .unwrap();
        (a, b)
    }

    #[test]
    fn messages_round_trip_with_sender_authentication() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let f = fixture();
        let (mut alice, mut bob) = pair(&f, 3);
        let blocked = BTreeSet::new();
        let sealed = alice
            .encrypt(&f.alice, 1, b"ad", b"hello", 1234, &mut rng)
            .unwrap();
        assert_eq!(alice.next_own_generation(), 1);
        let envelope = Envelope::decode(&sealed).unwrap();
        assert_eq!(envelope.encode().unwrap(), sealed);
        let received = bob.decrypt(&envelope, &f.roster, &blocked).unwrap();
        assert_eq!(received.plaintext, b"hello");
        assert_eq!(received.authenticated_data, b"ad");
        assert_eq!(received.signed_timestamp_ms, 1234);
        assert_eq!(received.sender_device_pk, f.alice.public_key());
        assert_eq!(received.sender_slot, 0);
        assert_eq!(received.epoch, 3);
        // Replays have no key any more.
        assert_eq!(
            bob.decrypt(&envelope, &f.roster, &blocked),
            Err(CoreError::Replay)
        );
        // Own messages are not decrypted.
        assert!(alice.decrypt(&envelope, &f.roster, &blocked).is_err());
    }

    #[test]
    fn out_of_order_delivery_and_window_bounds() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let f = fixture();
        let (mut alice, mut bob) = pair(&f, 1);
        let blocked = BTreeSet::new();
        let sealed: Vec<Envelope> = (0..4)
            .map(|i| {
                Envelope::decode(&alice.encrypt(&f.alice, 1, b"", &[i], 0, &mut rng).unwrap())
                    .unwrap()
            })
            .collect();
        assert_eq!(
            bob.decrypt(&sealed[3], &f.roster, &blocked)
                .unwrap()
                .plaintext,
            [3]
        );
        assert_eq!(
            bob.decrypt(&sealed[1], &f.roster, &blocked)
                .unwrap()
                .plaintext,
            [1]
        );
        assert_eq!(
            bob.decrypt(&sealed[1], &f.roster, &blocked),
            Err(CoreError::Replay)
        );
        assert_eq!(
            bob.decrypt(&sealed[0], &f.roster, &blocked)
                .unwrap()
                .plaintext,
            [0]
        );
        assert_eq!(
            bob.decrypt(&sealed[2], &f.roster, &blocked)
                .unwrap()
                .plaintext,
            [2]
        );

        // A generation too far ahead is refused without advancing the chain.
        let mut far = sealed[0].clone();
        far.header.generation = 4 + MAX_FORWARD_GENERATIONS + 1;
        assert_eq!(
            bob.decrypt(&far, &f.roster, &blocked),
            Err(CoreError::TooLarge("message generation gap"))
        );
        // A forged commitment or ciphertext does not burn the key.
        let next =
            Envelope::decode(&alice.encrypt(&f.alice, 1, b"", b"x", 0, &mut rng).unwrap()).unwrap();
        let mut forged = next.clone();
        forged.header.key_commitment = [0; 32];
        assert_eq!(
            bob.decrypt(&forged, &f.roster, &blocked),
            Err(CoreError::Decrypt("key commitment"))
        );
        let mut flipped = next.clone();
        flipped.ciphertext[0] ^= 1;
        assert_eq!(
            bob.decrypt(&flipped, &f.roster, &blocked),
            Err(CoreError::Decrypt("message"))
        );
        assert_eq!(
            bob.decrypt(&next, &f.roster, &blocked).unwrap().plaintext,
            b"x"
        );
    }

    #[test]
    fn membership_and_blocking_are_enforced() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let f = fixture();
        let (mut alice, mut bob) = pair(&f, 1);
        let sealed =
            Envelope::decode(&alice.encrypt(&f.alice, 1, b"", b"hi", 0, &mut rng).unwrap())
                .unwrap();
        let mut blocked = BTreeSet::new();
        blocked.insert(f.alice.leaf_id(&f.gid).unwrap());
        assert!(matches!(
            bob.decrypt(&sealed, &f.roster, &blocked),
            Err(CoreError::Unauthorized(_))
        ));
        let mut without_alice = f.roster.clone();
        without_alice.grant_admin(f.bob.public_key()).unwrap();
        without_alice.remove_member(0, 1).unwrap();
        assert!(matches!(
            bob.decrypt(&sealed, &without_alice, &BTreeSet::new()),
            Err(CoreError::Unauthorized(_))
        ));
        // Another epoch's keys do not apply.
        let (_, mut other_epoch) = pair(&f, 2);
        assert!(
            other_epoch
                .decrypt(&sealed, &f.roster, &BTreeSet::new())
                .is_err()
        );
        // The wrong identity cannot send on alice's chain.
        assert!(alice.encrypt(&f.bob, 1, b"", b"x", 0, &mut rng).is_err());
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
    }

    #[test]
    fn a_member_cannot_speak_for_another() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let f = fixture();
        let carol = DeviceIdentity::from_seed(&[3; 32]);
        let mut roster = f.roster.clone();
        roster
            .add_member(MemberRecord {
                leaf_id: leaf_id(&f.gid, carol.public_key()).unwrap(),
                device_pk: carol.public_key().to_vec(),
                slot: 2,
                generation: 1,
                admission_hash: [0; 32],
            })
            .unwrap();
        let secret = [9u8; 32];
        let alice_leaf = f.alice.leaf_id(&f.gid).unwrap();
        let bob_leaf = f.bob.leaf_id(&f.gid).unwrap();
        let mut alice = EpochMessages::new(&f.gid, 1, &secret, &roster, &alice_leaf).unwrap();
        let mut carol_view =
            EpochMessages::new(&f.gid, 1, &secret, &roster, &carol.leaf_id(&f.gid).unwrap())
                .unwrap();
        // Every member can derive bob's chain keys, but not bob's signature.
        let forged = alice
            .seal(&bob_leaf, &f.alice, 1, b"", b"spoof", 0, &mut rng)
            .unwrap();
        assert_eq!(
            carol_view.decrypt(
                &Envelope::decode(&forged).unwrap(),
                &roster,
                &BTreeSet::new()
            ),
            Err(CoreError::BadSignature("message"))
        );
        // The rejected forgery did not consume bob's key: his real message
        // at the same generation still decrypts.
        let mut bob = EpochMessages::new(&f.gid, 1, &secret, &roster, &bob_leaf).unwrap();
        let genuine = bob.encrypt(&f.bob, 1, b"", b"real", 0, &mut rng).unwrap();
        let received = carol_view
            .decrypt(
                &Envelope::decode(&genuine).unwrap(),
                &roster,
                &BTreeSet::new(),
            )
            .unwrap();
        assert_eq!(received.plaintext, b"real");
        assert!(alice.encrypt(&f.bob, 1, b"", b"x", 0, &mut rng).is_err());
    }

    #[test]
    fn state_persists_across_encoding() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let f = fixture();
        let (mut alice, mut bob) = pair(&f, 1);
        let first =
            Envelope::decode(&alice.encrypt(&f.alice, 1, b"", b"1", 0, &mut rng).unwrap()).unwrap();
        let second =
            Envelope::decode(&alice.encrypt(&f.alice, 1, b"", b"2", 0, &mut rng).unwrap()).unwrap();
        bob.decrypt(&second, &f.roster, &BTreeSet::new()).unwrap();
        let mut restored = EpochMessages::from_value(bob.to_value()).unwrap();
        assert_eq!(restored.epoch(), 1);
        assert_eq!(restored.epoch_ref(), bob.epoch_ref());
        assert!(format!("{restored:?}").contains("EpochMessages"));
        assert_eq!(
            restored
                .decrypt(&first, &f.roster, &BTreeSet::new())
                .unwrap()
                .plaintext,
            b"1"
        );
        assert_eq!(
            restored.decrypt(&second, &f.roster, &BTreeSet::new()),
            Err(CoreError::Replay)
        );
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
    fn epoch_refs_and_leaves() {
        let f = fixture();
        assert_ne!(epoch_ref(&f.gid, 1).unwrap(), epoch_ref(&f.gid, 2).unwrap());
        assert_eq!(roster_leaves(&f.roster).len(), 2);
        let missing = EpochMessages::new(&f.gid, 1, &[0; 32], &f.roster, &[7; 32]);
        assert!(missing.is_err());
    }
}
