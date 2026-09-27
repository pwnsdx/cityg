//! The message plane (docs/specs-v0.5-draft.md sections 4.3 to 4.8).
//!
//! ```text
//! sender_data_secret_n, encryption_secret_n, exporter_secret_n, epoch_authenticator_n
//!     := DeriveSecret(msg_secret_n, "sender data" | "encryption" | "exporter" | "authenticator")
//! Export_n(label, context, L) := ExpandLabel(DeriveSecret(exporter_secret_n, label),
//!                                            "exported", H(context), L)
//!
//! tree_secret(height_n, 0)   := encryption_secret_n
//! tree_secret(k - 1, 2i)     := DeriveSecret(tree_secret(k, i), "tree left")
//! tree_secret(k - 1, 2i + 1) := DeriveSecret(tree_secret(k, i), "tree right")
//! ratchet_0(i)               := DeriveSecret(tree_secret(0, i), "application")
//! key_g(i)                   := ExpandLabel(ratchet_g(i), "message key",    CBOR_det(g), 32)
//! nonce_g(i)                 := ExpandLabel(ratchet_g(i), "message nonce",  CBOR_det(g), 12)
//! ratchet_g+1(i)             := ExpandLabel(ratchet_g(i), "message secret", CBOR_det(g), 32)
//!
//! Message    := ["city-g/message/v5", gid, epoch, encrypted_sender_data, ciphertext, commitment]
//! SenderData := leaf || generation || reuse_guard      4-byte big-endian integers and 4 random
//!                                                      bytes: 12 bytes, whatever the sender
//! Content    := [application_data, first_generation, signature or null, padding]
//! aad        := CBOR_det(["city-g/message/v5", gid, epoch])
//! commitment := H_L("msg-commit", [key_g(i), nonce, H(ciphertext)])
//! chain_g    := H_L("msg-chain", [chain_g-1, H(CBOR_det([application_data_g, first_generation_g]))])
//! signature  := Card.Sign(CBOR_det([gid, epoch, leaf, first_generation, g, chain_g]))
//! message_log := [count, MTH("msg-log", [H(Message_1), ..., H(Message_count)])]
//! ```
//!
//! A member holds an [`EpochMessages`] per epoch it reads: it sends from the
//! chain of its leaf, and opens the messages of the others, which it
//! delivers once a signature of their sender's card covers them (a *burst
//! chain*). The delivery service sees neither the sender nor the content,
//! and seals the log of each epoch's messages in the next seal.

use std::collections::BTreeMap;

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use ciborium::value::Value;
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::card::{Card, CardKey};
use crate::cbor::{array, bytes, decode, encode, expect_array, expect_label, text, uint};
use crate::codec::{Fields, nullable};
use crate::crypto::{
    Digest, Secret, ZERO32, derive_secret, digest_eq, expand_label_into, expand_label32, h, h_l,
};
use crate::error::{CoreError, CoreResult};
use crate::tree::{LeafProof, MAX_HEIGHT};

/// Label and signature context of messages.
pub const MESSAGE_LABEL: &str = "city-g/message/v5";

/// A sender signs at once if its last signature is older.
pub const T_BURST_MS: u64 = 2_000;

/// The longest a burst waits for its signature.
pub const T_AUTH_MS: u64 = 5_000;

/// Generations whose keys a reader keeps ahead of the last it decrypted.
pub const MAX_SKIP: u32 = 1_024;

/// Largest encoded message, padding included.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Longest exported secret, as with MLS's exporter (a 16-bit length).
pub const MAX_EXPORT_BYTES: usize = u16::MAX as usize;

/// Smallest ciphertext: its first 32 bytes are the sample that keys the
/// sender data.
const MIN_CIPHERTEXT_BYTES: usize = 32;

/// ChaCha20-Poly1305's tag.
const TAG_BYTES: usize = 16;

const REUSE_GUARD_BYTES: usize = 4;

/// The sender data, of fixed length so that its ciphertext says nothing of
/// the sender's leaf or generation.
const SENDER_DATA_BYTES: usize = 12;

fn sender_data(
    leaf: u32,
    generation: u32,
    reuse_guard: &[u8; REUSE_GUARD_BYTES],
) -> Zeroizing<[u8; SENDER_DATA_BYTES]> {
    let mut data = Zeroizing::new([0u8; SENDER_DATA_BYTES]);
    data[..4].copy_from_slice(&leaf.to_be_bytes());
    data[4..8].copy_from_slice(&generation.to_be_bytes());
    data[8..].copy_from_slice(reuse_guard);
    data
}

fn read_sender_data(data: &[u8]) -> CoreResult<(u32, u32, [u8; REUSE_GUARD_BYTES])> {
    let field = |range: core::ops::Range<usize>| -> CoreResult<[u8; 4]> {
        data.get(range)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(CoreError::Malformed("sender data"))
    };
    if data.len() != SENDER_DATA_BYTES {
        return Err(CoreError::Malformed("sender data"));
    }
    Ok((
        u32::from_be_bytes(field(0..4)?),
        u32::from_be_bytes(field(4..8)?),
        field(8..12)?,
    ))
}

/// The secrets of one epoch's message plane, but the secret tree.
struct PlaneSecrets {
    sender_data: Secret,
    exporter: Secret,
    authenticator: Digest,
}

/// A message on the wire. Neither its sender nor its content is visible
/// without the epoch's secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub gid: Digest,
    pub epoch: u64,
    pub encrypted_sender_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub commitment: Digest,
}

impl Message {
    fn value(&self) -> Value {
        array(vec![
            text(MESSAGE_LABEL),
            bytes(&self.gid),
            uint(self.epoch),
            bytes(&self.encrypted_sender_data),
            bytes(&self.ciphertext),
            bytes(&self.commitment),
        ])
    }

    /// `CBOR_det` encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&self.value())
    }

    /// Parse a message and check the sizes of its parts.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        const WHAT: &str = "message";
        let items = expect_array(decode(encoded, MAX_MESSAGE_BYTES, WHAT)?, 6, WHAT)?;
        expect_label(&items[0], MESSAGE_LABEL, WHAT)?;
        let mut fields = Fields::new(items, WHAT);
        fields.next()?;
        let message = Self {
            gid: fields.digest()?,
            epoch: fields.uint()?,
            encrypted_sender_data: fields.bytes()?,
            ciphertext: fields.bytes()?,
            commitment: fields.digest()?,
        };
        message.check_sizes()?;
        Ok(message)
    }

    /// `H(Message)`, a leaf of the message log.
    pub fn hash(&self) -> CoreResult<Digest> {
        Ok(h(&self.encode()?))
    }

    /// Check what the DS can check without the epoch's secrets: the sizes.
    pub fn check_sizes(&self) -> CoreResult<()> {
        if self.ciphertext.len() < MIN_CIPHERTEXT_BYTES
            || self.encrypted_sender_data.len() != SENDER_DATA_BYTES + TAG_BYTES
        {
            return Err(CoreError::Malformed("message"));
        }
        if self.encode()?.len() > MAX_MESSAGE_BYTES {
            return Err(CoreError::TooLarge("message"));
        }
        Ok(())
    }

    fn aad(&self) -> CoreResult<Vec<u8>> {
        aad(&self.gid, self.epoch)
    }
}

fn aad(gid: &Digest, epoch: u64) -> CoreResult<Vec<u8>> {
    encode(&array(vec![text(MESSAGE_LABEL), bytes(gid), uint(epoch)]))
}

/// The key and nonce of one generation of a chain.
struct MessageKeys {
    key: Secret,
    nonce: Zeroizing<[u8; 12]>,
}

/// One chain of the secret tree: the secret of its next generation.
#[derive(Clone)]
struct Ratchet {
    generation: u32,
    secret: Secret,
}

impl Ratchet {
    fn new(secret: Secret) -> Self {
        Self {
            generation: 0,
            secret,
        }
    }

    /// The keys of the next generation; the chain moves past it and forgets
    /// its secret.
    fn next(&mut self) -> CoreResult<(u32, MessageKeys)> {
        let generation = self.generation;
        let context = encode(&uint(u64::from(generation)))?;
        let key = expand_label32(&self.secret, "message key", &context)?;
        let mut nonce = Zeroizing::new([0u8; 12]);
        expand_label_into(&self.secret, "message nonce", &context, nonce.as_mut())?;
        self.secret = expand_label32(&self.secret, "message secret", &context)?;
        self.generation = generation
            .checked_add(1)
            .ok_or(CoreError::TooLarge("generation"))?;
        Ok((generation, MessageKeys { key, nonce }))
    }
}

/// The secret tree of an epoch over `2^height` leaves, of which a member
/// keeps the frontier it has not derived: a node's secret goes once both
/// children are derived, a leaf's once its chain starts.
struct SecretTree {
    height: u8,
    nodes: BTreeMap<(u8, u32), Secret>,
}

impl SecretTree {
    fn new(height: u8, encryption_secret: Secret) -> CoreResult<Self> {
        if height > MAX_HEIGHT {
            return Err(CoreError::TooLarge("tree height"));
        }
        Ok(Self {
            height,
            nodes: BTreeMap::from([((height, 0), encryption_secret)]),
        })
    }

    fn contains(&self, leaf: u32) -> bool {
        u64::from(leaf) < 1u64 << self.height
    }

    /// `ratchet_0(leaf)`, or `None` when the leaf's chain was already
    /// started.
    fn start(&mut self, leaf: u32) -> CoreResult<Option<Ratchet>> {
        if !self.contains(leaf) {
            return Err(CoreError::Invalid("leaf outside the tree"));
        }
        let Some(mut level) =
            (0..=self.height).find(|level| self.nodes.contains_key(&(*level, leaf >> level)))
        else {
            return Ok(None);
        };
        while level > 0 {
            let index = leaf >> level;
            let secret = self
                .nodes
                .remove(&(level, index))
                .ok_or(CoreError::Invalid("secret tree"))?;
            level -= 1;
            self.nodes
                .insert((level, 2 * index), derive_secret(&secret, "tree left")?);
            self.nodes.insert(
                (level, 2 * index + 1),
                derive_secret(&secret, "tree right")?,
            );
        }
        let secret = self
            .nodes
            .remove(&(0, leaf))
            .ok_or(CoreError::Invalid("secret tree"))?;
        Ok(Some(Ratchet::new(derive_secret(&secret, "application")?)))
    }
}

/// What a message carries under its key.
struct Content {
    application_data: Vec<u8>,
    first_generation: u32,
    signature: Option<Vec<u8>>,
    padding: usize,
}

impl Content {
    fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            bytes(&self.application_data),
            uint(u64::from(self.first_generation)),
            nullable(self.signature.as_deref(), bytes),
            bytes(&vec![0; self.padding]),
        ]))
    }

    fn decode(encoded: &[u8]) -> CoreResult<Self> {
        const WHAT: &str = "message content";
        let items = expect_array(decode(encoded, MAX_MESSAGE_BYTES, WHAT)?, 4, WHAT)?;
        let mut fields = Fields::new(items, WHAT);
        let content = Self {
            application_data: fields.bytes()?,
            first_generation: fields.u32()?,
            signature: fields.optional_bytes()?,
            padding: {
                let padding = fields.bytes()?;
                if padding.iter().any(|byte| *byte != 0) {
                    return Err(CoreError::Malformed(WHAT));
                }
                padding.len()
            },
        };
        Ok(content)
    }
}

/// `H_L("msg-chain", [chain_g-1, H(CBOR_det([application_data_g, first_generation_g]))])`.
fn chain_step(
    previous: &Digest,
    application_data: &[u8],
    first_generation: u32,
) -> CoreResult<Digest> {
    let entry = encode(&array(vec![
        bytes(application_data),
        uint(u64::from(first_generation)),
    ]))?;
    h_l("msg-chain", vec![bytes(previous), bytes(&h(&entry))])
}

/// What a card signs for a burst: `CBOR_det([gid, epoch, leaf,
/// first_generation, g, chain_g])`.
fn signed_burst(
    gid: &Digest,
    epoch: u64,
    leaf: u32,
    first_generation: u32,
    generation: u32,
    chain: &Digest,
) -> CoreResult<Vec<u8>> {
    encode(&array(vec![
        bytes(gid),
        uint(epoch),
        uint(u64::from(leaf)),
        uint(u64::from(first_generation)),
        uint(u64::from(generation)),
        bytes(chain),
    ]))
}

/// `H_L("msg-commit", [key, nonce, H(ciphertext)])`.
fn commitment(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> CoreResult<Digest> {
    h_l(
        "msg-commit",
        vec![bytes(key), bytes(nonce), bytes(&h(ciphertext))],
    )
}

/// The nonce of a message: the generation's, its first four bytes XORed
/// with the reuse guard.
fn guarded(nonce: &[u8; 12], reuse_guard: &[u8; REUSE_GUARD_BYTES]) -> Zeroizing<[u8; 12]> {
    let mut guarded = Zeroizing::new(*nonce);
    for (byte, guard) in guarded.iter_mut().zip(reuse_guard) {
        *byte ^= guard;
    }
    guarded
}

fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

/// The key and nonce of the sender data, from the ciphertext's sample.
fn sender_data_cipher(
    sender_data_secret: &[u8; 32],
    ciphertext: &[u8],
) -> CoreResult<(ChaCha20Poly1305, [u8; 12])> {
    let sample = ciphertext
        .get(..MIN_CIPHERTEXT_BYTES)
        .ok_or(CoreError::Malformed("message"))?;
    let key = expand_label32(sender_data_secret, "sender data key", sample)?;
    let mut nonce = [0u8; 12];
    expand_label_into(sender_data_secret, "sender data nonce", sample, &mut nonce)?;
    Ok((cipher(&key), nonce))
}

/// The sender's chain and the burst it has not signed yet.
struct Sending {
    ratchet: Ratchet,
    /// `chain_g-1` of the next generation.
    chain: Digest,
    /// The first generation after the last signature.
    burst_start: u32,
    /// When the first unsigned message of the burst left.
    unsigned_since: Option<u64>,
    last_signed: Option<u64>,
}

/// A message opened and not yet delivered.
struct Held {
    application_data: Vec<u8>,
    first_generation: u32,
    signature: Option<Vec<u8>>,
    received_ms: u64,
}

/// What a member holds of another member's chain in one epoch.
struct Reading {
    ratchet: Ratchet,
    /// The keys of skipped generations, not yet used.
    skipped: BTreeMap<u32, MessageKeys>,
    held: BTreeMap<u32, Held>,
    /// Generations below are delivered.
    delivered: u32,
    /// `chain_(delivered - 1)`.
    chain: Digest,
    /// A burst failed or expired: the chain cannot be followed any more in
    /// this epoch.
    broken: bool,
}

impl Reading {
    fn new(ratchet: Ratchet) -> Self {
        Self {
            ratchet,
            skipped: BTreeMap::new(),
            held: BTreeMap::new(),
            delivered: 0,
            chain: ZERO32,
            broken: false,
        }
    }

    /// The end of the first burst ready to check: a signed message after an
    /// unbroken run of held messages from the first undelivered one.
    fn ready(&self) -> Option<u32> {
        let mut expected = self.delivered;
        for (generation, held) in self.held.range(self.delivered..) {
            if *generation != expected {
                return None;
            }
            if held.signature.is_some() {
                return Some(*generation);
            }
            expected = expected.checked_add(1)?;
        }
        None
    }
}

/// A message opened: its sender's leaf and generation, and whether a
/// signature waits to be checked (then [`EpochMessages::authenticate`]
/// delivers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Received {
    pub leaf: u32,
    pub generation: u32,
    /// A burst of the sender is ready to be checked against its card.
    pub ready: bool,
}

/// A message delivered to the application: its sender's card signed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    pub epoch: u64,
    pub leaf: u32,
    pub generation: u32,
    pub application_data: Vec<u8>,
}

/// A burst dropped unsigned: from `first` to `last`, of the sender at
/// `leaf`, whose chain the reader no longer follows in the epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dropped {
    pub leaf: u32,
    pub first: u32,
    pub last: u32,
}

/// The card of a sender for the messages of `epoch`: checked against a leaf
/// proof of `epoch` or of a later epoch whose leaf shows `since <= epoch`
/// and `updated <= epoch`, under `tree_hash`, the tree hash of the proof's
/// epoch `proof_epoch` (docs/specs-v0.5-draft.md section 4.1).
pub fn sender_card(
    proof: &LeafProof,
    tree_hash: &Digest,
    proof_epoch: u64,
    epoch: u64,
) -> CoreResult<Card> {
    proof.verify(tree_hash)?;
    let leaf = proof
        .leaf
        .as_ref()
        .ok_or(CoreError::Invalid("sender's leaf is blank"))?;
    if proof_epoch < epoch || leaf.since > epoch || leaf.updated > epoch {
        return Err(CoreError::Invalid("sender's leaf of another epoch"));
    }
    Ok(leaf.card.clone())
}

/// The message plane of one epoch, as a member holds it.
pub struct EpochMessages {
    gid: Digest,
    epoch: u64,
    leaf: u32,
    secrets: PlaneSecrets,
    tree: SecretTree,
    sending: Sending,
    reading: BTreeMap<u32, Reading>,
    /// The log of the epoch's messages, once a seal closed it.
    sealed_log: Option<MessageLog>,
}

impl core::fmt::Debug for EpochMessages {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpochMessages")
            .field("epoch", &self.epoch)
            .field("leaf", &self.leaf)
            .finish_non_exhaustive()
    }
}

impl EpochMessages {
    /// The message plane of `epoch`, whose tree has `2^height` leaves, for
    /// the member at `leaf`, from `msg_secret_n`, which the caller then
    /// erases.
    pub fn new(
        gid: &Digest,
        epoch: u64,
        height: u8,
        leaf: u32,
        msg_secret: &[u8; 32],
    ) -> CoreResult<Self> {
        let secrets = PlaneSecrets {
            sender_data: derive_secret(msg_secret, "sender data")?,
            exporter: derive_secret(msg_secret, "exporter")?,
            authenticator: *derive_secret(msg_secret, "authenticator")?,
        };
        let mut tree = SecretTree::new(height, derive_secret(msg_secret, "encryption")?)?;
        let ratchet = tree.start(leaf)?.ok_or(CoreError::Invalid("secret tree"))?;
        Ok(Self {
            gid: *gid,
            epoch,
            leaf,
            secrets,
            tree,
            sending: Sending {
                ratchet,
                chain: ZERO32,
                burst_start: 0,
                unsigned_since: None,
                last_signed: None,
            },
            reading: BTreeMap::new(),
            sealed_log: None,
        })
    }

    /// The epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// `epoch_authenticator_n`, the same for every member of the epoch: two
    /// members that compare it detect a fork.
    #[must_use]
    pub const fn authenticator(&self) -> &Digest {
        &self.secrets.authenticator
    }

    /// `Export_n(label, context, length)`: a secret of the epoch for the
    /// application, of at most `MAX_EXPORT_BYTES`.
    pub fn export(
        &self,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> CoreResult<Zeroizing<Vec<u8>>> {
        if length > MAX_EXPORT_BYTES {
            return Err(CoreError::TooLarge("exported secret"));
        }
        let secret = derive_secret(&self.secrets.exporter, label)?;
        let mut out = Zeroizing::new(vec![0u8; length]);
        expand_label_into(&secret, "exported", &h(context), &mut out)?;
        Ok(out)
    }

    /// Whether the sender should sign its burst now, alone if it has nothing
    /// to send: a message waits unsigned for `T_BURST` at most, well within
    /// `T_AUTH`.
    #[must_use]
    pub fn sign_due(&self, now_ms: u64) -> bool {
        self.sending
            .unsigned_since
            .is_some_and(|since| now_ms >= since.saturating_add(T_BURST_MS))
    }

    /// Send `application_data`, signed if the sender's last signature is
    /// older than `T_BURST` or its burst is due.
    pub fn send(
        &mut self,
        application_data: &[u8],
        card: &CardKey,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Message> {
        let sign = self
            .sending
            .last_signed
            .is_none_or(|at| now_ms >= at.saturating_add(T_BURST_MS))
            || self.sign_due(now_ms);
        self.seal_message(application_data, sign, card, now_ms, rng)
    }

    /// Sign the burst alone, in a message without application data, if it
    /// has unsigned messages.
    pub fn sign_burst(
        &mut self,
        card: &CardKey,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Option<Message>> {
        if self.sending.unsigned_since.is_none() {
            return Ok(None);
        }
        self.seal_message(&[], true, card, now_ms, rng).map(Some)
    }

    fn seal_message(
        &mut self,
        application_data: &[u8],
        sign: bool,
        card: &CardKey,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Message> {
        let first_generation = self.sending.burst_start;
        let mut ratchet = self.sending.ratchet.clone();
        let (generation, keys) = ratchet.next()?;
        let chain = chain_step(&self.sending.chain, application_data, first_generation)?;
        let signature = if sign {
            let signed = signed_burst(
                &self.gid,
                self.epoch,
                self.leaf,
                first_generation,
                generation,
                &chain,
            )?;
            Some(card.sign(&signed, rng)?)
        } else {
            None
        };
        let mut content = Content {
            application_data: application_data.to_vec(),
            first_generation,
            signature,
            padding: 0,
        };
        let short = (MIN_CIPHERTEXT_BYTES - TAG_BYTES).saturating_sub(content.encode()?.len());
        content.padding = short;
        let mut reuse_guard = [0u8; REUSE_GUARD_BYTES];
        rng.fill_bytes(&mut reuse_guard);
        let nonce = guarded(&keys.nonce, &reuse_guard);
        let aad = aad(&self.gid, self.epoch)?;
        let plaintext = Zeroizing::new(content.encode()?);
        let ciphertext = cipher(&keys.key)
            .encrypt(
                nonce.as_ref().into(),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::Crypto("message"))?;
        let commitment = commitment(&keys.key, &nonce, &ciphertext)?;
        let sender_data = sender_data(self.leaf, generation, &reuse_guard);
        let (sender_cipher, sender_nonce) =
            sender_data_cipher(&self.secrets.sender_data, &ciphertext)?;
        let encrypted_sender_data = sender_cipher
            .encrypt(
                (&sender_nonce).into(),
                Payload {
                    msg: sender_data.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::Crypto("message"))?;
        let message = Message {
            gid: self.gid,
            epoch: self.epoch,
            encrypted_sender_data,
            ciphertext,
            commitment,
        };
        message.check_sizes()?;
        // The generation is used: nothing is sent twice under its key.
        self.sending.ratchet = ratchet;
        self.sending.chain = chain;
        if sign {
            self.sending.burst_start = generation
                .checked_add(1)
                .ok_or(CoreError::TooLarge("generation"))?;
            self.sending.unsigned_since = None;
            self.sending.last_signed = Some(now_ms);
        } else if self.sending.unsigned_since.is_none() {
            self.sending.unsigned_since = Some(now_ms);
        }
        Ok(message)
    }

    /// Open a message of the epoch: decrypt its sender data, derive the key
    /// of its generation, check its commitment, decrypt it and hold it until
    /// a signature of its sender covers it. A generation is opened once.
    pub fn open(&mut self, message: &Message, now_ms: u64) -> CoreResult<Received> {
        if message.gid != self.gid || message.epoch != self.epoch {
            return Err(CoreError::Invalid("message of another epoch"));
        }
        message.check_sizes()?;
        let aad = message.aad()?;
        let (sender_cipher, sender_nonce) =
            sender_data_cipher(&self.secrets.sender_data, &message.ciphertext)?;
        let sender_data = Zeroizing::new(
            sender_cipher
                .decrypt(
                    (&sender_nonce).into(),
                    Payload {
                        msg: &message.encrypted_sender_data,
                        aad: &aad,
                    },
                )
                .map_err(|_| CoreError::Decrypt("sender data"))?,
        );
        let (leaf, generation, reuse_guard) = read_sender_data(&sender_data)?;
        if leaf == self.leaf {
            return Err(CoreError::Invalid("a message of the member's own leaf"));
        }
        if !self.tree.contains(leaf) {
            return Err(CoreError::Invalid("sender outside the tree"));
        }
        if !self.reading.contains_key(&leaf) {
            let ratchet = self
                .tree
                .start(leaf)?
                .ok_or(CoreError::Invalid("secret tree"))?;
            self.reading.insert(leaf, Reading::new(ratchet));
        }
        let reading = self
            .reading
            .get_mut(&leaf)
            .ok_or(CoreError::Invalid("secret tree"))?;
        if reading.broken {
            return Err(CoreError::Invalid("sender's chain broken in this epoch"));
        }
        // The keys of the generation, derived aside: nothing changes until
        // the message opens.
        let mut advanced = None;
        let mut skipped = Vec::new();
        let keys = if generation < reading.ratchet.generation {
            reading
                .skipped
                .get(&generation)
                .ok_or(CoreError::Invalid("generation already opened"))?
        } else {
            if generation - reading.ratchet.generation > MAX_SKIP {
                return Err(CoreError::Invalid("generation too far ahead"));
            }
            let mut ratchet = reading.ratchet.clone();
            loop {
                let (at, keys) = ratchet.next()?;
                if at == generation {
                    advanced = Some((ratchet, keys));
                    break;
                }
                skipped.push((at, keys));
            }
            advanced
                .as_ref()
                .map(|(_, keys)| keys)
                .ok_or(CoreError::Invalid("secret tree"))?
        };
        let nonce = guarded(&keys.nonce, &reuse_guard);
        if !digest_eq(
            &commitment(&keys.key, &nonce, &message.ciphertext)?,
            &message.commitment,
        ) {
            return Err(CoreError::Invalid("message commitment"));
        }
        let plaintext = Zeroizing::new(
            cipher(&keys.key)
                .decrypt(
                    nonce.as_ref().into(),
                    Payload {
                        msg: &message.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CoreError::Decrypt("message"))?,
        );
        let content = Content::decode(&plaintext)?;
        if content.first_generation > generation || content.first_generation < reading.delivered {
            return Err(CoreError::Invalid("message burst"));
        }
        // The message opened: its generation is used.
        match advanced {
            Some((ratchet, _)) => {
                reading.ratchet = ratchet;
                reading.skipped.extend(skipped);
                while reading.skipped.len() > MAX_SKIP as usize {
                    reading.skipped.pop_first();
                }
            }
            None => {
                reading.skipped.remove(&generation);
            }
        }
        reading.held.insert(
            generation,
            Held {
                application_data: content.application_data,
                first_generation: content.first_generation,
                signature: content.signature,
                received_ms: now_ms,
            },
        );
        Ok(Received {
            leaf,
            generation,
            ready: reading.ready().is_some(),
        })
    }

    /// Check the ready bursts of the sender at `leaf` against its card of
    /// the epoch (see [`sender_card`]) and deliver them, in order. A burst
    /// whose signature fails is dropped, and the sender's chain with it for
    /// the rest of the epoch.
    pub fn authenticate(&mut self, leaf: u32, card: &Card) -> CoreResult<Vec<Delivered>> {
        let (gid, epoch) = (self.gid, self.epoch);
        let reading = self
            .reading
            .get_mut(&leaf)
            .ok_or(CoreError::Invalid("no message of this sender"))?;
        if reading.broken {
            return Err(CoreError::Invalid("sender's chain broken in this epoch"));
        }
        let mut delivered = Vec::new();
        while let Some(last) = reading.ready() {
            let first = reading.delivered;
            let mut chain = reading.chain;
            let mut consistent = true;
            for generation in first..=last {
                let held = reading
                    .held
                    .get(&generation)
                    .ok_or(CoreError::Invalid("message burst"))?;
                consistent &= held.first_generation == first;
                chain = chain_step(&chain, &held.application_data, held.first_generation)?;
            }
            let signature = reading
                .held
                .get(&last)
                .and_then(|held| held.signature.as_deref())
                .ok_or(CoreError::Invalid("message burst"))?;
            let signed = signed_burst(&gid, epoch, leaf, first, last, &chain)?;
            if !consistent || card.verify(&signed, signature).is_err() {
                reading.broken = true;
                reading.held.clear();
                return Err(CoreError::BadSignature("message burst"));
            }
            for generation in first..=last {
                if let Some(held) = reading.held.remove(&generation) {
                    delivered.push(Delivered {
                        epoch,
                        leaf,
                        generation,
                        application_data: held.application_data,
                    });
                }
            }
            reading.delivered = last
                .checked_add(1)
                .ok_or(CoreError::TooLarge("generation"))?;
            reading.chain = chain;
        }
        Ok(delivered)
    }

    /// Drop the bursts that have waited for their signature longer than
    /// `T_AUTH` and `delay_ms`, for the application to report: the chains
    /// of their senders cannot be followed in this epoch any more.
    pub fn drop_unsigned(&mut self, now_ms: u64, delay_ms: u64) -> Vec<Dropped> {
        let limit = T_AUTH_MS.saturating_add(delay_ms);
        let mut dropped = Vec::new();
        for (leaf, reading) in &mut self.reading {
            let overdue = reading
                .held
                .values()
                .any(|held| now_ms.saturating_sub(held.received_ms) > limit);
            if !overdue {
                continue;
            }
            if let (Some(first), Some(last)) = (
                reading.held.keys().next().copied(),
                reading.held.keys().next_back().copied(),
            ) {
                dropped.push(Dropped {
                    leaf: *leaf,
                    first,
                    last,
                });
            }
            reading.held.clear();
            reading.broken = true;
        }
        dropped
    }

    /// Record the log of the epoch's messages that the next seal carries.
    pub fn set_sealed_log(&mut self, log: MessageLog) {
        self.sealed_log = Some(log);
    }

    /// The log of the epoch's messages, once sealed.
    #[must_use]
    pub const fn sealed_log(&self) -> Option<MessageLog> {
        self.sealed_log
    }
}

/// The log of an epoch's messages: their number and the root of their
/// Merkle tree, `MTH("msg-log", [H(Message_1), ...])` (RFC 6962 §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageLog {
    pub count: u64,
    pub root: Digest,
}

impl MessageLog {
    /// The log of the given message hashes, in order.
    pub fn of(hashes: &[Digest]) -> CoreResult<Self> {
        Ok(Self {
            count: u64::try_from(hashes.len()).map_err(|_| CoreError::TooLarge("message log"))?,
            root: mth(hashes)?,
        })
    }

    /// The log of an epoch without messages.
    pub fn empty() -> CoreResult<Self> {
        Self::of(&[])
    }

    /// CBOR `[count, root]`.
    #[must_use]
    pub fn value(&self) -> Value {
        array(vec![uint(self.count), bytes(&self.root)])
    }

    /// Read `[count, root]`.
    pub fn from_value(value: Value, what: &'static str) -> CoreResult<Self> {
        let mut fields = Fields::new(expect_array(value, 2, what)?, what);
        Ok(Self {
            count: fields.uint()?,
            root: fields.digest()?,
        })
    }

    /// Check that `messages` are the whole log, in order.
    pub fn check(&self, messages: &[Message]) -> CoreResult<()> {
        let hashes = messages
            .iter()
            .map(Message::hash)
            .collect::<CoreResult<Vec<_>>>()?;
        if Self::of(&hashes)? == *self {
            Ok(())
        } else {
            Err(CoreError::Invalid("message log"))
        }
    }

    /// Check that `message` is the `index`-th of the log, by an inclusion
    /// proof (RFC 9162 §2.1.3.2).
    pub fn verify_inclusion(
        &self,
        index: u64,
        message: &Message,
        proof: &[Digest],
    ) -> CoreResult<()> {
        if index >= self.count {
            return Err(CoreError::Invalid("message log proof"));
        }
        let mut fn_ = index;
        let mut sn = self.count - 1;
        let mut hash = h_l("msg-log", vec![bytes(&message.hash()?)])?;
        for sibling in proof {
            if sn == 0 {
                return Err(CoreError::Invalid("message log proof"));
            }
            if fn_ & 1 == 1 || fn_ == sn {
                hash = node(sibling, &hash)?;
                if fn_ & 1 == 0 {
                    while fn_ & 1 == 0 && fn_ != 0 {
                        fn_ >>= 1;
                        sn >>= 1;
                    }
                }
            } else {
                hash = node(&hash, sibling)?;
            }
            fn_ >>= 1;
            sn >>= 1;
        }
        if sn == 0 && hash == self.root {
            Ok(())
        } else {
            Err(CoreError::Invalid("message log proof"))
        }
    }
}

fn node(left: &Digest, right: &Digest) -> CoreResult<Digest> {
    h_l("msg-log", vec![bytes(left), bytes(right)])
}

/// `MTH("msg-log", hashes)`.
fn mth(hashes: &[Digest]) -> CoreResult<Digest> {
    match hashes.len() {
        0 => h_l("msg-log", vec![]),
        1 => h_l("msg-log", vec![bytes(&hashes[0])]),
        n => {
            let k = split(n);
            node(&mth(&hashes[..k])?, &mth(&hashes[k..])?)
        }
    }
}

/// The largest power of 2 below `n` (for `n >= 2`).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// The inclusion proof of the `index`-th of `hashes` (RFC 6962 §2.1.1).
pub fn inclusion_proof(hashes: &[Digest], index: usize) -> CoreResult<Vec<Digest>> {
    if index >= hashes.len() {
        return Err(CoreError::Invalid("message log index"));
    }
    if hashes.len() == 1 {
        return Ok(Vec::new());
    }
    let k = split(hashes.len());
    let (mut proof, sibling) = if index < k {
        (inclusion_proof(&hashes[..k], index)?, mth(&hashes[k..])?)
    } else {
        (
            inclusion_proof(&hashes[k..], index - k)?,
            mth(&hashes[..k])?,
        )
    };
    proof.push(sibling);
    Ok(proof)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn plane(leaf: u32) -> EpochMessages {
        EpochMessages::new(&[7; 32], 3, 4, leaf, &[1; 32]).unwrap()
    }

    #[test]
    fn a_secret_tree_derives_each_chain_once_and_forgets_its_frontier() {
        let mut tree = SecretTree::new(3, derive_secret(&[2; 32], "encryption").unwrap()).unwrap();
        let first = tree.start(5).unwrap().unwrap();
        // Leaf 5's path is gone; the siblings along it remain.
        assert!(tree.start(5).unwrap().is_none());
        let keys: Vec<(u8, u32)> = tree.nodes.keys().copied().collect();
        assert_eq!(keys, vec![(0, 4), (1, 3), (2, 0)]);
        // Another member derives the same chain.
        let mut other = SecretTree::new(3, derive_secret(&[2; 32], "encryption").unwrap()).unwrap();
        other.start(0).unwrap().unwrap();
        assert_eq!(*other.start(5).unwrap().unwrap().secret, *first.secret);
        assert!(tree.start(8).is_err());
    }

    #[test]
    fn a_log_proves_each_message_in_it() {
        let messages: Vec<Message> = (0..7u8)
            .map(|i| Message {
                gid: [1; 32],
                epoch: 2,
                encrypted_sender_data: vec![i; 28],
                ciphertext: vec![i; 40],
                commitment: [i; 32],
            })
            .collect();
        let hashes: Vec<Digest> = messages.iter().map(|m| m.hash().unwrap()).collect();
        for count in 1..=hashes.len() {
            let log = MessageLog::of(&hashes[..count]).unwrap();
            log.check(&messages[..count]).unwrap();
            for index in 0..count {
                let proof = inclusion_proof(&hashes[..count], index).unwrap();
                log.verify_inclusion(index as u64, &messages[index], &proof)
                    .unwrap();
                let other = &messages[(index + 1) % 7];
                assert!(log.verify_inclusion(index as u64, other, &proof).is_err());
            }
        }
        let log = MessageLog::of(&hashes).unwrap();
        assert!(log.check(&messages[..6]).is_err());
        assert_ne!(log.root, MessageLog::empty().unwrap().root);
    }

    #[test]
    fn a_burst_is_delivered_once_its_signature_checks() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let card = CardKey::generate(&mut rng);
        let mut sender = plane(2);
        let mut reader = plane(9);
        let first = sender.send(b"one", &card, 0, &mut rng).unwrap();
        let second = sender.send(b"two", &card, 500, &mut rng).unwrap();
        let third = sender.send(b"three", &card, 900, &mut rng).unwrap();
        assert!(sender.sign_due(2_500));
        let closing = sender.sign_burst(&card, 2_500, &mut rng).unwrap().unwrap();
        assert!(sender.sign_burst(&card, 2_600, &mut rng).unwrap().is_none());
        // The first is signed alone; the next two wait for the closing one.
        let opened = reader.open(&first, 10).unwrap();
        assert_eq!((opened.leaf, opened.generation, opened.ready), (2, 0, true));
        let delivered = reader.authenticate(2, &card.card()).unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].application_data, b"one");
        assert!(!reader.open(&third, 20).unwrap().ready);
        assert!(!reader.open(&closing, 30).unwrap().ready, "a gap");
        assert!(reader.open(&second, 40).unwrap().ready);
        let delivered = reader.authenticate(2, &card.card()).unwrap();
        let data: Vec<&[u8]> = delivered
            .iter()
            .map(|d| d.application_data.as_slice())
            .collect();
        assert_eq!(data, vec![&b"two"[..], b"three", b""]);
        // A generation opens once.
        assert!(reader.open(&second, 50).is_err());
        // Another card does not sign for the sender.
        let other = CardKey::generate(&mut rng);
        let next = sender.send(b"four", &card, 9_000, &mut rng).unwrap();
        reader.open(&next, 60).unwrap();
        assert!(reader.authenticate(2, &other.card()).is_err());
        assert!(
            reader
                .open(&sender.send(b"five", &card, 20_000, &mut rng).unwrap(), 70)
                .is_err()
        );
    }

    #[test]
    fn a_message_opens_to_one_content_under_its_commitment() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let card = CardKey::generate(&mut rng);
        let mut sender = plane(1);
        let mut reader = plane(3);
        let message = sender.send(b"hello", &card, 0, &mut rng).unwrap();
        assert!(message.ciphertext.len() >= MIN_CIPHERTEXT_BYTES);
        let decoded = Message::decode(&message.encode().unwrap()).unwrap();
        assert_eq!(decoded, message);
        let mut altered = message.clone();
        altered.commitment[0] ^= 1;
        assert_eq!(
            reader.open(&altered, 0).unwrap_err(),
            CoreError::Invalid("message commitment")
        );
        let mut altered = message.clone();
        altered.ciphertext[40] ^= 1;
        assert!(reader.open(&altered, 0).is_err());
        let mut elsewhere = message.clone();
        elsewhere.epoch = 4;
        assert!(reader.open(&elsewhere, 0).is_err());
        // The failures changed nothing: the message still opens, once.
        reader.open(&message, 0).unwrap();
        assert!(reader.open(&message, 0).is_err());
        // The sender does not read its own chain.
        assert!(sender.open(&message, 0).is_err());
    }

    #[test]
    fn skipped_generations_open_later_within_max_skip() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let card = CardKey::generate(&mut rng);
        let mut sender = plane(0);
        let mut reader = plane(1);
        let messages: Vec<Message> = (0..4u64)
            .map(|i| sender.send(&[i as u8], &card, i * 3_000, &mut rng).unwrap())
            .collect();
        for message in messages.iter().rev() {
            reader.open(message, 0).unwrap();
        }
        let delivered = reader.authenticate(0, &card.card()).unwrap();
        assert_eq!(delivered.len(), 4);
        // Too far ahead: refused, and nothing changes.
        let mut far = plane(0);
        let mut last = None;
        for _ in 0..=MAX_SKIP + 5 {
            last = Some(far.send(&[1], &card, 0, &mut rng).unwrap());
        }
        let mut reader = plane(1);
        assert_eq!(
            reader.open(&last.unwrap(), 0).unwrap_err(),
            CoreError::Invalid("generation too far ahead")
        );
    }

    #[test]
    fn an_unsigned_burst_is_dropped_after_t_auth() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let card = CardKey::generate(&mut rng);
        let mut sender = plane(4);
        let mut reader = plane(5);
        let signed = sender.send(b"a", &card, 0, &mut rng).unwrap();
        let unsigned = sender.send(b"b", &card, 100, &mut rng).unwrap();
        reader.open(&signed, 0).unwrap();
        reader.open(&unsigned, 100).unwrap();
        assert_eq!(reader.authenticate(4, &card.card()).unwrap().len(), 1);
        assert!(reader.drop_unsigned(4_000, 0).is_empty());
        assert_eq!(
            reader.drop_unsigned(5_200, 0),
            vec![Dropped {
                leaf: 4,
                first: 1,
                last: 1
            }]
        );
        let late = sender.sign_burst(&card, 5_300, &mut rng).unwrap().unwrap();
        assert!(reader.open(&late, 5_400).is_err());
    }

    #[test]
    fn an_insiders_forgery_is_never_delivered() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let card = CardKey::generate(&mut rng);
        let forger_card = CardKey::generate(&mut rng);
        let mut victim = plane(2);
        // An insider holds the epoch's secrets: it derives the victim's chain
        // and sends on it, but holds no card of the victim's.
        let mut insider = plane(2);
        let mut reader = plane(8);
        let genuine = victim.send(b"genuine", &card, 0, &mut rng).unwrap();
        reader.open(&genuine, 0).unwrap();
        assert_eq!(reader.authenticate(2, &card.card()).unwrap().len(), 1);
        // The insider forges generation 1, unsigned, ahead of the victim.
        insider.send(b"skipped", &forger_card, 0, &mut rng).unwrap();
        let forged = insider
            .send(b"forged", &forger_card, 100, &mut rng)
            .unwrap();
        assert!(!reader.open(&forged, 100).unwrap().ready);
        // The victim's generation 1 is refused, and its next signature, over
        // the genuine chain, does not cover the forgery.
        let second = victim.send(b"second", &card, 200, &mut rng).unwrap();
        let closing = victim.sign_burst(&card, 2_300, &mut rng).unwrap().unwrap();
        assert_eq!(
            reader.open(&second, 200).unwrap_err(),
            CoreError::Invalid("generation already opened")
        );
        assert!(reader.open(&closing, 2_300).unwrap().ready);
        assert_eq!(
            reader.authenticate(2, &card.card()).unwrap_err(),
            CoreError::BadSignature("message burst")
        );
        // A forgery the insider signs with its own card is refused too.
        let mut reader = plane(8);
        let mut insider = plane(2);
        let signed = insider.send(b"forged", &forger_card, 0, &mut rng).unwrap();
        assert!(reader.open(&signed, 0).unwrap().ready);
        assert!(reader.authenticate(2, &card.card()).is_err());
    }

    #[test]
    fn sender_data_hides_the_senders_leaf_and_generation() {
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let card = CardKey::generate(&mut rng);
        let mut low = EpochMessages::new(&[7; 32], 3, 20, 1, &[1; 32]).unwrap();
        let mut high = EpochMessages::new(&[7; 32], 3, 20, 1 << 19, &[1; 32]).unwrap();
        let first = low.send(b"same", &card, 0, &mut rng).unwrap();
        for _ in 0..300 {
            high.send(b"same", &card, 0, &mut rng).unwrap();
        }
        let later = high.send(b"same", &card, 0, &mut rng).unwrap();
        assert_eq!(
            first.encrypted_sender_data.len(),
            later.encrypted_sender_data.len()
        );
        assert_eq!(
            read_sender_data(&sender_data(7, 9, &[1, 2, 3, 4])[..]).unwrap(),
            (7, 9, [1, 2, 3, 4])
        );
        assert!(read_sender_data(&[0; 11]).is_err());
    }

    #[test]
    fn members_of_an_epoch_share_its_exports_and_authenticator() {
        let a = plane(0);
        let b = plane(6);
        assert_eq!(a.authenticator(), b.authenticator());
        assert_eq!(
            *a.export("app", b"ctx", 40).unwrap(),
            *b.export("app", b"ctx", 40).unwrap()
        );
        assert_ne!(
            *a.export("app", b"ctx", 40).unwrap(),
            *a.export("app", b"other", 40).unwrap()
        );
        let other = EpochMessages::new(&[7; 32], 3, 4, 0, &[2; 32]).unwrap();
        assert_ne!(a.authenticator(), other.authenticator());
        assert!(a.export("app", b"ctx", MAX_EXPORT_BYTES + 1).is_err());
    }
}
