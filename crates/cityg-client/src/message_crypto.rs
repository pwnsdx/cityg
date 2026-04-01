use anyhow::{Context as AnyhowContext, Result, anyhow};
use hex::{decode as hex_decode, encode as hex_encode};
use msphf_core::{hash::h_l, hkdf::hkdf_blake3, serde_utils::to_cbor_vec};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};

// Receiver-side anti-replay tracks a bounded recent window per sender-scoped tuple tag.
// Callers are expected to persist this bounded window alongside session state so accepted
// `(tuple_tag, msg_index)` pairs survive restarts.
pub const MAX_MSGS_PER_REPLAY_TUPLE: usize = 4_096;

const PAYLOAD_ENVELOPE_V2_MODE: &str = "fs-hybrid-msg-v2";
const PAYLOAD_AEAD_TAG_LEN: usize = 16;
const MAX_CT_PAYLOAD_BYTES: usize = 1_048_576;
const MAX_PAYLOAD_ENVELOPE_BYTES: usize = 1_048_640;
const PAYLOAD_MSG_EPOCH_INFO: &[u8] = b"city-g|fs/msg/epoch|v2";
const PAYLOAD_MSG_KEY_INFO: &[u8] = b"city-g|fs/msg/key|v2";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MsgReplayTupleState {
    context_id: [u8; 32],
    seen_msg_indices: VecDeque<u64>,
    seen_msg_index_set: HashSet<u64>,
    last_seen_order: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MsgReplayState {
    tuples: BTreeMap<[u8; 32], MsgReplayTupleState>,
    next_seen_order: u64,
}

impl MsgReplayState {
    pub fn ensure_tuple(&mut self, tuple_tag: [u8; 32], context_id: [u8; 32]) {
        let state = self.tuples.entry(tuple_tag).or_default();
        if state.context_id == [0u8; 32] {
            state.context_id = context_id;
        } else if state.context_id != context_id {
            *state = MsgReplayTupleState {
                context_id,
                ..MsgReplayTupleState::default()
            };
        }
    }

    pub fn prune_to_context(&mut self, context_id: [u8; 32], max_tuples: usize) {
        self.tuples
            .retain(|_, state| state.context_id == [0u8; 32] || state.context_id == context_id);

        let max_tuples = max_tuples.max(1);
        while self.tuples.len() > max_tuples {
            let Some((oldest_tag, _)) = self
                .tuples
                .iter()
                .min_by_key(|(_, state)| state.last_seen_order)
                .map(|(tag, state)| (*tag, state.last_seen_order))
            else {
                break;
            };
            self.tuples.remove(&oldest_tag);
        }
    }

    pub fn contains(&self, tuple_tag: [u8; 32], msg_index: u64) -> bool {
        self.tuples
            .get(&tuple_tag)
            .is_some_and(|state| state.seen_msg_index_set.contains(&msg_index))
    }

    pub fn record(&mut self, tuple_tag: [u8; 32], context_id: [u8; 32], msg_index: u64) {
        let state = self.tuples.entry(tuple_tag).or_default();
        if state.context_id == [0u8; 32] {
            state.context_id = context_id;
        } else if state.context_id != context_id {
            *state = MsgReplayTupleState {
                context_id,
                ..MsgReplayTupleState::default()
            };
        }
        if !state.seen_msg_index_set.insert(msg_index) {
            return;
        }
        self.next_seen_order = self.next_seen_order.saturating_add(1);
        state.last_seen_order = self.next_seen_order;
        state.seen_msg_indices.push_back(msg_index);
        if state.seen_msg_indices.len() > MAX_MSGS_PER_REPLAY_TUPLE
            && let Some(oldest) = state.seen_msg_indices.pop_front()
        {
            state.seen_msg_index_set.remove(&oldest);
        }
    }

    pub fn len(&self, tuple_tag: [u8; 32]) -> usize {
        self.tuples
            .get(&tuple_tag)
            .map(|state| state.seen_msg_indices.len())
            .unwrap_or(0)
    }

    pub fn tuple_count(&self) -> usize {
        self.tuples.len()
    }
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
pub struct PersistedMsgReplayState {
    #[serde(default)]
    tuple_tag_hex: String,
    #[serde(default)]
    seen_msg_indices: Vec<u64>,
    #[serde(default)]
    tuples: Vec<PersistedMsgReplayTupleState>,
    #[serde(default)]
    next_seen_order: u64,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
struct PersistedMsgReplayTupleState {
    #[serde(default)]
    tuple_tag_hex: String,
    #[serde(default)]
    context_id_hex: String,
    #[serde(default)]
    seen_msg_indices: Vec<u64>,
    #[serde(default)]
    last_seen_order: u64,
}

impl PersistedMsgReplayTupleState {
    fn semantic_key(&self) -> (&str, &str, &Vec<u64>) {
        (
            self.tuple_tag_hex.as_str(),
            self.context_id_hex.as_str(),
            &self.seen_msg_indices,
        )
    }
}

impl PersistedMsgReplayState {
    pub fn from_runtime(state: &MsgReplayState) -> Self {
        let tuples = state
            .tuples
            .iter()
            .map(|(tuple_tag, tuple_state)| PersistedMsgReplayTupleState {
                tuple_tag_hex: hex_encode(tuple_tag),
                context_id_hex: hex_encode(tuple_state.context_id),
                seen_msg_indices: tuple_state.seen_msg_indices.iter().copied().collect(),
                last_seen_order: tuple_state.last_seen_order,
            })
            .collect();
        Self {
            tuple_tag_hex: String::new(),
            seen_msg_indices: Vec::new(),
            tuples,
            next_seen_order: state.next_seen_order,
        }
    }

    pub fn into_runtime(self) -> Result<MsgReplayState> {
        let mut runtime = MsgReplayState {
            next_seen_order: self.next_seen_order,
            ..MsgReplayState::default()
        };
        if self.tuples.is_empty()
            && (!self.tuple_tag_hex.is_empty() || !self.seen_msg_indices.is_empty())
        {
            let tuple_tag =
                decode_hex32_or_zero("msg_replay_state.tuple_tag_hex", &self.tuple_tag_hex)?;
            runtime.ensure_tuple(tuple_tag, [0u8; 32]);
            for msg_index in self.seen_msg_indices {
                runtime.record(tuple_tag, [0u8; 32], msg_index);
            }
            return Ok(runtime);
        }

        for (index, tuple) in self.tuples.into_iter().enumerate() {
            let tuple_tag = decode_hex32_or_zero(
                &format!("msg_replay_state.tuples[{index}].tuple_tag_hex"),
                &tuple.tuple_tag_hex,
            )?;
            let context_id = decode_hex32_or_zero(
                &format!("msg_replay_state.tuples[{index}].context_id_hex"),
                &tuple.context_id_hex,
            )?;
            runtime.ensure_tuple(tuple_tag, context_id);
            for msg_index in tuple.seen_msg_indices {
                runtime.record(tuple_tag, context_id, msg_index);
            }
            if let Some(state) = runtime.tuples.get_mut(&tuple_tag) {
                state.last_seen_order = tuple.last_seen_order.max(state.last_seen_order);
            }
        }
        runtime.next_seen_order = runtime.next_seen_order.max(
            runtime
                .tuples
                .values()
                .map(|state| state.last_seen_order)
                .max()
                .unwrap_or(0),
        );
        Ok(runtime)
    }

    pub fn semantically_equivalent(&self, other: &Self) -> bool {
        self.tuple_tag_hex == other.tuple_tag_hex
            && self.seen_msg_indices == other.seen_msg_indices
            && self
                .tuples
                .iter()
                .map(PersistedMsgReplayTupleState::semantic_key)
                .collect::<Vec<_>>()
                == other
                    .tuples
                    .iter()
                    .map(PersistedMsgReplayTupleState::semantic_key)
                    .collect::<Vec<_>>()
    }
}

#[derive(Clone, Copy)]
pub struct MessageCryptoContext<'a> {
    pub gid: &'a [u8; 32],
    pub we_epoch_id: &'a [u8; 32],
    pub xk_hash: &'a [u8; 32],
    pub fs_ec: u64,
    pub barrier_version: u64,
    pub sender_leaf: &'a [u8; 32],
    pub epoch_key: &'a [u8; 32],
    pub k_barrier: &'a [u8; 32],
}

#[derive(Serialize)]
struct MsgEpochSaltArgs<'a> {
    #[serde(with = "serde_bytes")]
    we_epoch_id: &'a [u8; 32],
    fs_ec: u64,
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    e_k: &'a [u8; 32],
    barrier_version: u64,
    #[serde(with = "serde_bytes")]
    sender_leaf: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    k_barrier: &'a [u8; 32],
}

#[derive(Serialize)]
struct MsgKeySaltArgs<'a> {
    #[serde(with = "serde_bytes")]
    we_epoch_id: &'a [u8; 32],
    fs_ec: u64,
    #[serde(with = "serde_bytes")]
    sender_leaf: &'a [u8; 32],
    msg_index: u64,
}

#[derive(Serialize)]
struct MsgNonceArgs<'a> {
    #[serde(with = "serde_bytes")]
    gid: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    we_epoch_id: &'a [u8; 32],
    fs_ec: u64,
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    e_k: &'a [u8; 32],
    barrier_version: u64,
    #[serde(with = "serde_bytes")]
    sender_leaf: &'a [u8; 32],
    msg_index: u64,
}

#[derive(Serialize)]
struct MsgAad<'a>(
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u64,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u64,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u64,
);

#[derive(Serialize)]
struct MsgReplayTupleArgs<'a> {
    #[serde(with = "serde_bytes")]
    gid: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    we_epoch_id: &'a [u8; 32],
    fs_ec: u64,
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    e_k: &'a [u8; 32],
    barrier_version: u64,
    #[serde(with = "serde_bytes")]
    sender_leaf: &'a [u8; 32],
}

#[derive(Serialize)]
struct MsgReplayContextArgs<'a> {
    #[serde(with = "serde_bytes")]
    gid: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    we_epoch_id: &'a [u8; 32],
    fs_ec: u64,
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    e_k: &'a [u8; 32],
    barrier_version: u64,
}

#[derive(Serialize)]
struct PayloadEnvelopeV2Ref<'a>(&'a str, u64, #[serde(with = "serde_bytes")] &'a [u8]);

#[derive(Serialize, Deserialize)]
struct PayloadEnvelopeV2(String, u64, #[serde(with = "serde_bytes")] Vec<u8>);

fn derive_msg_key_material(context: &MessageCryptoContext<'_>, msg_index: u64) -> Result<[u8; 32]> {
    let epoch_salt = h_l(
        "fs/msg/epoch_salt",
        &MsgEpochSaltArgs {
            we_epoch_id: context.we_epoch_id,
            fs_ec: context.fs_ec,
            xk_hash: context.xk_hash,
            e_k: context.epoch_key,
            barrier_version: context.barrier_version,
            sender_leaf: context.sender_leaf,
            k_barrier: context.k_barrier,
        },
    )
    .context("derive fs/msg/epoch_salt")?;
    let k_msg_epoch = hkdf_blake3(&epoch_salt, context.epoch_key, PAYLOAD_MSG_EPOCH_INFO);

    let key_salt = h_l(
        "fs/msg/key_salt",
        &MsgKeySaltArgs {
            we_epoch_id: context.we_epoch_id,
            fs_ec: context.fs_ec,
            sender_leaf: context.sender_leaf,
            msg_index,
        },
    )
    .context("derive fs/msg/key_salt")?;
    Ok(hkdf_blake3(&key_salt, &k_msg_epoch, PAYLOAD_MSG_KEY_INFO))
}

fn derive_msg_nonce(context: &MessageCryptoContext<'_>, msg_index: u64) -> Result<[u8; 12]> {
    let nonce_bytes = h_l(
        "fs/msg/nonce",
        &MsgNonceArgs {
            gid: context.gid,
            we_epoch_id: context.we_epoch_id,
            fs_ec: context.fs_ec,
            xk_hash: context.xk_hash,
            e_k: context.epoch_key,
            barrier_version: context.barrier_version,
            sender_leaf: context.sender_leaf,
            msg_index,
        },
    )
    .context("derive fs/msg/nonce")?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes[..12]);
    Ok(nonce)
}

fn message_aad(context: &MessageCryptoContext<'_>, msg_index: u64) -> Result<Vec<u8>> {
    to_cbor_vec(&MsgAad(
        context.gid,
        context.we_epoch_id,
        context.fs_ec,
        context.xk_hash,
        context.epoch_key,
        context.barrier_version,
        context.sender_leaf,
        msg_index,
    ))
    .context("encode message aad")
}

pub fn derive_msg_replay_tuple_tag(context: &MessageCryptoContext<'_>) -> Result<[u8; 32]> {
    h_l(
        "fs/msg/replay/tuple",
        &MsgReplayTupleArgs {
            gid: context.gid,
            we_epoch_id: context.we_epoch_id,
            fs_ec: context.fs_ec,
            xk_hash: context.xk_hash,
            e_k: context.epoch_key,
            barrier_version: context.barrier_version,
            sender_leaf: context.sender_leaf,
        },
    )
    .context("derive fs/msg/replay/tuple")
}

pub fn derive_msg_replay_context_id(context: &MessageCryptoContext<'_>) -> Result<[u8; 32]> {
    h_l(
        "fs/msg/replay/context",
        &MsgReplayContextArgs {
            gid: context.gid,
            we_epoch_id: context.we_epoch_id,
            fs_ec: context.fs_ec,
            xk_hash: context.xk_hash,
            e_k: context.epoch_key,
            barrier_version: context.barrier_version,
        },
    )
    .context("derive fs/msg/replay/context")
}

pub fn encrypt_message_v2(
    plaintext: &[u8],
    context: &MessageCryptoContext<'_>,
    msg_index: u64,
) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };

    if plaintext.len().saturating_add(PAYLOAD_AEAD_TAG_LEN) > MAX_CT_PAYLOAD_BYTES {
        return Err(anyhow!(
            "payload plaintext would exceed MAX_CT_PAYLOAD_BYTES: {} > {}",
            plaintext.len().saturating_add(PAYLOAD_AEAD_TAG_LEN),
            MAX_CT_PAYLOAD_BYTES
        ));
    }

    let key = derive_msg_key_material(context, msg_index)?;
    let nonce = derive_msg_nonce(context, msg_index)?;
    let aad = message_aad(context, msg_index)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let ct_payload = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow!("encryption failed: {}", e))?;
    if ct_payload.is_empty() || ct_payload.len() > MAX_CT_PAYLOAD_BYTES {
        return Err(anyhow!(
            "payload ciphertext length is out of bounds: {}",
            ct_payload.len()
        ));
    }

    let encoded = to_cbor_vec(&PayloadEnvelopeV2Ref(
        PAYLOAD_ENVELOPE_V2_MODE,
        msg_index,
        &ct_payload,
    ))
    .context("encode payload envelope v2")?;
    if encoded.len() > MAX_PAYLOAD_ENVELOPE_BYTES {
        return Err(anyhow!(
            "payload envelope exceeds MAX_PAYLOAD_ENVELOPE_BYTES: {} > {}",
            encoded.len(),
            MAX_PAYLOAD_ENVELOPE_BYTES
        ));
    }
    Ok(encoded)
}

pub fn decrypt_message_v2_with_index(
    data: &[u8],
    context: &MessageCryptoContext<'_>,
) -> Result<(u64, Vec<u8>)> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };

    if data.is_empty() || data.len() > MAX_PAYLOAD_ENVELOPE_BYTES {
        return Err(anyhow!(
            "payload envelope length is out of bounds: {}",
            data.len()
        ));
    }

    let envelope: PayloadEnvelopeV2 =
        ciborium::de::from_reader(data).context("decode payload envelope v2")?;
    let canonical_bytes = to_cbor_vec(&envelope).context("re-encode payload envelope v2")?;
    if canonical_bytes.as_slice() != data {
        return Err(anyhow!("payload envelope v2 is not deterministic CBOR"));
    }
    if envelope.0 != PAYLOAD_ENVELOPE_V2_MODE {
        return Err(anyhow!("unexpected payload envelope mode"));
    }
    let msg_index = envelope.1;
    let ct_payload = envelope.2;
    if ct_payload.is_empty() || ct_payload.len() > MAX_CT_PAYLOAD_BYTES {
        return Err(anyhow!(
            "payload ciphertext length is out of bounds: {}",
            ct_payload.len()
        ));
    }
    let key = derive_msg_key_material(context, msg_index)?;
    let nonce = derive_msg_nonce(context, msg_index)?;
    let aad = message_aad(context, msg_index)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let plaintext = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &ct_payload,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow!("decryption failed: {}", e))?;
    Ok((msg_index, plaintext))
}

pub fn decrypt_message_v2(data: &[u8], context: &MessageCryptoContext<'_>) -> Result<Vec<u8>> {
    decrypt_message_v2_with_index(data, context).map(|(_, plaintext)| plaintext)
}

fn decode_hex32(name: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = hex_decode(value).with_context(|| format!("{name} is not valid hex"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{name} must decode to 32 bytes, got {}", bytes.len()))
}

fn decode_hex32_or_zero(name: &str, value: &str) -> Result<[u8; 32]> {
    if value.is_empty() {
        Ok([0u8; 32])
    } else {
        decode_hex32(name, value)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn payload_envelope_v2_roundtrip() -> Result<()> {
        let gid = [0x11u8; 32];
        let we_epoch_id = [0x22u8; 32];
        let xk_hash = [0x23u8; 32];
        let epoch_key = [0x33u8; 32];
        let k_barrier = [0x44u8; 32];
        let sender_leaf = [0x45u8; 32];
        let context = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 9,
            barrier_version: 5,
            sender_leaf: &sender_leaf,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let envelope = encrypt_message_v2(b"payload-v2-roundtrip", &context, 7)?;
        let decrypted = decrypt_message_v2(&envelope, &context)?;
        assert_eq!(decrypted, b"payload-v2-roundtrip");
        Ok(())
    }

    #[test]
    fn payload_envelope_v2_sender_scope_changes_ciphertext() -> Result<()> {
        let gid = [0x81u8; 32];
        let we_epoch_id = [0x82u8; 32];
        let xk_hash = [0x83u8; 32];
        let epoch_key = [0x84u8; 32];
        let k_barrier = [0x85u8; 32];
        let sender_leaf_a = [0x86u8; 32];
        let sender_leaf_b = [0x87u8; 32];
        let context_a = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 7,
            barrier_version: 3,
            sender_leaf: &sender_leaf_a,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let context_b = MessageCryptoContext {
            sender_leaf: &sender_leaf_b,
            ..context_a
        };
        let payload_a = encrypt_message_v2(b"same-plaintext", &context_a, 11)?;
        let payload_b = encrypt_message_v2(b"same-plaintext", &context_b, 11)?;
        assert_ne!(payload_a, payload_b);
        assert!(decrypt_message_v2(&payload_a, &context_b).is_err());
        Ok(())
    }

    #[test]
    fn same_msg_index_from_different_senders_is_not_replayed() -> Result<()> {
        let gid = [0x91u8; 32];
        let we_epoch_id = [0x92u8; 32];
        let xk_hash = [0x93u8; 32];
        let epoch_key = [0x94u8; 32];
        let k_barrier = [0x95u8; 32];
        let sender_leaf_a = [0x96u8; 32];
        let sender_leaf_b = [0x97u8; 32];
        let context_a = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 12,
            barrier_version: 4,
            sender_leaf: &sender_leaf_a,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let context_b = MessageCryptoContext {
            sender_leaf: &sender_leaf_b,
            ..context_a
        };
        let shared_msg_index = 41;
        let payload_a = encrypt_message_v2(b"from-sender-a", &context_a, shared_msg_index)?;
        let payload_b = encrypt_message_v2(b"from-sender-b", &context_b, shared_msg_index)?;

        let tag_a = derive_msg_replay_tuple_tag(&context_a)?;
        let tag_b = derive_msg_replay_tuple_tag(&context_b)?;
        assert_ne!(tag_a, tag_b);

        let mut replay = MsgReplayState::default();
        let context_id = derive_msg_replay_context_id(&context_a)?;
        replay.ensure_tuple(tag_a, context_id);
        replay.ensure_tuple(tag_b, context_id);

        let (msg_index_a, plaintext_a) = decrypt_message_v2_with_index(&payload_a, &context_a)?;
        assert_eq!(msg_index_a, shared_msg_index);
        assert_eq!(plaintext_a, b"from-sender-a");
        assert!(!replay.contains(tag_a, msg_index_a));
        replay.record(tag_a, context_id, msg_index_a);
        assert!(replay.contains(tag_a, shared_msg_index));
        assert!(
            !replay.contains(tag_b, shared_msg_index),
            "same msg_index from another sender must stay independently admissible"
        );

        let (msg_index_b, plaintext_b) = decrypt_message_v2_with_index(&payload_b, &context_b)?;
        assert_eq!(msg_index_b, shared_msg_index);
        assert_eq!(plaintext_b, b"from-sender-b");
        assert!(!replay.contains(tag_b, msg_index_b));
        replay.record(tag_b, context_id, msg_index_b);
        assert!(replay.contains(tag_b, shared_msg_index));

        Ok(())
    }

    #[test]
    fn msg_replay_state_tracks_multiple_tuples_and_caps_window() {
        let mut replay = MsgReplayState::default();
        let tuple_a = [0xA1; 32];
        let context_id = [0xC1; 32];
        replay.ensure_tuple(tuple_a, context_id);
        for msg_index in 0..(MAX_MSGS_PER_REPLAY_TUPLE as u64 + 8) {
            replay.record(tuple_a, context_id, msg_index);
        }
        assert_eq!(replay.len(tuple_a), MAX_MSGS_PER_REPLAY_TUPLE);
        assert!(!replay.contains(tuple_a, 0));
        assert!(replay.contains(tuple_a, MAX_MSGS_PER_REPLAY_TUPLE as u64 + 7));

        let tuple_b = [0xB2; 32];
        replay.ensure_tuple(tuple_b, context_id);
        assert!(replay.contains(tuple_a, MAX_MSGS_PER_REPLAY_TUPLE as u64 + 7));
        assert_eq!(replay.len(tuple_b), 0);
        replay.record(tuple_b, context_id, 99);
        assert!(replay.contains(tuple_b, 99));
    }

    #[test]
    fn derive_msg_replay_tuple_tag_changes_with_sender_scope() -> Result<()> {
        let gid = [0x31u8; 32];
        let we_epoch_id = [0x32u8; 32];
        let xk_hash = [0x33u8; 32];
        let epoch_key = [0x34u8; 32];
        let k_barrier = [0x35u8; 32];
        let sender_leaf_a = [0x36u8; 32];
        let sender_leaf_b = [0x37u8; 32];
        let context_a = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 8,
            barrier_version: 1,
            sender_leaf: &sender_leaf_a,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let context_b = MessageCryptoContext {
            sender_leaf: &sender_leaf_b,
            ..context_a
        };
        let tag_a = derive_msg_replay_tuple_tag(&context_a)?;
        let tag_b = derive_msg_replay_tuple_tag(&context_b)?;
        assert_ne!(tag_a, tag_b);
        Ok(())
    }

    #[test]
    fn derive_msg_replay_tuple_tag_changes_with_epoch_key() -> Result<()> {
        let gid = [0x41u8; 32];
        let we_epoch_id = [0x42u8; 32];
        let xk_hash = [0x43u8; 32];
        let epoch_key_a = [0x44u8; 32];
        let epoch_key_b = [0x45u8; 32];
        let k_barrier = [0x46u8; 32];
        let sender_leaf = [0x47u8; 32];
        let context_a = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 9,
            barrier_version: 2,
            sender_leaf: &sender_leaf,
            epoch_key: &epoch_key_a,
            k_barrier: &k_barrier,
        };
        let context_b = MessageCryptoContext {
            epoch_key: &epoch_key_b,
            ..context_a
        };
        let tag_a = derive_msg_replay_tuple_tag(&context_a)?;
        let tag_b = derive_msg_replay_tuple_tag(&context_b)?;
        assert_ne!(tag_a, tag_b);
        Ok(())
    }

    #[test]
    fn persisted_msg_replay_state_roundtrip_preserves_multi_tuple_state() -> Result<()> {
        let tuple_a = [0x11; 32];
        let tuple_b = [0x22; 32];
        let context_id = [0x33; 32];
        let mut state = MsgReplayState::default();
        state.record(tuple_a, context_id, 1);
        state.record(tuple_a, context_id, 2);
        state.record(tuple_b, context_id, 9);

        let persisted = PersistedMsgReplayState::from_runtime(&state);
        let restored = persisted.into_runtime()?;
        assert!(restored.contains(tuple_a, 1));
        assert!(restored.contains(tuple_a, 2));
        assert!(restored.contains(tuple_b, 9));
        assert_eq!(restored.len(tuple_a), 2);
        assert_eq!(restored.len(tuple_b), 1);
        Ok(())
    }

    #[test]
    fn msg_replay_state_ignores_duplicate_recordings() {
        let tuple = [0x51; 32];
        let context_id = [0x52; 32];
        let mut state = MsgReplayState::default();
        state.record(tuple, context_id, 7);
        state.record(tuple, context_id, 7);
        assert_eq!(state.len(tuple), 1);
        assert!(state.contains(tuple, 7));
    }

    #[test]
    fn persisted_msg_replay_state_supports_legacy_single_tuple_format() -> Result<()> {
        let tuple_tag = [0x61; 32];
        let persisted = PersistedMsgReplayState {
            tuple_tag_hex: hex_encode(tuple_tag),
            seen_msg_indices: vec![3, 5, 8],
            tuples: Vec::new(),
            next_seen_order: 0,
        };
        let restored = persisted.into_runtime()?;
        assert!(restored.contains(tuple_tag, 3));
        assert!(restored.contains(tuple_tag, 5));
        assert!(restored.contains(tuple_tag, 8));
        assert_eq!(restored.len(tuple_tag), 3);
        Ok(())
    }

    #[test]
    fn derive_msg_replay_context_id_ignores_sender_scope() -> Result<()> {
        let gid = [0x71u8; 32];
        let we_epoch_id = [0x72u8; 32];
        let xk_hash = [0x73u8; 32];
        let epoch_key = [0x74u8; 32];
        let k_barrier = [0x75u8; 32];
        let sender_leaf_a = [0x76u8; 32];
        let sender_leaf_b = [0x77u8; 32];
        let context_a = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 10,
            barrier_version: 3,
            sender_leaf: &sender_leaf_a,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let context_b = MessageCryptoContext {
            sender_leaf: &sender_leaf_b,
            ..context_a
        };
        let id_a = derive_msg_replay_context_id(&context_a)?;
        let id_b = derive_msg_replay_context_id(&context_b)?;
        assert_eq!(id_a, id_b);
        Ok(())
    }

    #[test]
    fn msg_replay_state_prunes_obsolete_contexts_and_caps_tuple_count() {
        let mut state = MsgReplayState::default();
        let stale_context = [0x81; 32];
        let current_context = [0x82; 32];
        state.record([0x11; 32], stale_context, 1);
        state.record([0x12; 32], stale_context, 2);
        state.record([0x21; 32], current_context, 3);
        state.record([0x22; 32], current_context, 4);
        state.record([0x23; 32], current_context, 5);

        state.prune_to_context(current_context, 2);

        assert_eq!(state.tuple_count(), 2);
        assert!(!state.contains([0x11; 32], 1));
        assert!(!state.contains([0x12; 32], 2));
        assert!(state.contains([0x22; 32], 4));
        assert!(state.contains([0x23; 32], 5));
    }

    #[test]
    fn persisted_msg_replay_state_allows_empty_tuple_tag_as_zero_in_legacy_formats() -> Result<()> {
        let persisted = PersistedMsgReplayState {
            tuple_tag_hex: String::new(),
            seen_msg_indices: vec![13],
            tuples: Vec::new(),
            next_seen_order: 0,
        };
        let restored = persisted.into_runtime()?;
        assert!(restored.contains([0u8; 32], 13));
        Ok(())
    }

    #[test]
    fn persisted_msg_replay_state_rejects_invalid_hex_tuple_tag() {
        let persisted = PersistedMsgReplayState {
            tuple_tag_hex: "zz".to_string(),
            seen_msg_indices: vec![1],
            tuples: Vec::new(),
            next_seen_order: 0,
        };
        let err = match persisted.into_runtime() {
            Ok(_) => unreachable!("invalid legacy tuple tag hex must fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("msg_replay_state.tuple_tag_hex"));
    }

    #[test]
    fn persisted_msg_replay_state_rejects_wrong_tuple_tag_length() {
        let persisted = PersistedMsgReplayState {
            tuple_tag_hex: "aa".repeat(31),
            seen_msg_indices: Vec::new(),
            tuples: vec![PersistedMsgReplayTupleState {
                tuple_tag_hex: "aa".repeat(31),
                context_id_hex: String::new(),
                seen_msg_indices: vec![9],
                last_seen_order: 0,
            }],
            next_seen_order: 0,
        };
        let err = match persisted.into_runtime() {
            Ok(_) => unreachable!("wrong tuple tag length must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("msg_replay_state.tuples[0].tuple_tag_hex")
        );
    }

    #[test]
    fn decrypt_message_v2_rejects_noncanonical_cbor() -> Result<()> {
        fn encode_definite_bytes(bytes: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            match bytes.len() {
                len @ 0..=23 => out.push(0x40 | (len as u8)),
                len @ 24..=0xFF => {
                    out.push(0x58);
                    out.push(len as u8);
                }
                len => {
                    out.push(0x59);
                    out.extend_from_slice(&(len as u16).to_be_bytes());
                }
            }
            out.extend_from_slice(bytes);
            out
        }

        let gid = [0x71u8; 32];
        let we_epoch_id = [0x72u8; 32];
        let xk_hash = [0x73u8; 32];
        let epoch_key = [0x74u8; 32];
        let k_barrier = [0x75u8; 32];
        let sender_leaf = [0x76u8; 32];
        let context = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 17,
            barrier_version: 6,
            sender_leaf: &sender_leaf,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let canonical = encrypt_message_v2(b"noncanonical", &context, 19)?;
        let envelope: PayloadEnvelopeV2 = ciborium::de::from_reader(canonical.as_slice())?;
        let mut noncanonical = Vec::new();
        noncanonical.push(0x83);
        noncanonical.push(0x70);
        noncanonical.extend_from_slice(PAYLOAD_ENVELOPE_V2_MODE.as_bytes());
        noncanonical.extend_from_slice(&[0x18, envelope.1 as u8]);
        noncanonical.extend_from_slice(&encode_definite_bytes(&envelope.2));
        assert_ne!(noncanonical, canonical);
        let err = match decrypt_message_v2(&noncanonical, &context) {
            Ok(_) => unreachable!("non-canonical CBOR must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("payload envelope v2 is not deterministic CBOR")
        );
        Ok(())
    }

    #[test]
    fn decrypt_message_v2_rejects_wrong_mode() -> Result<()> {
        let gid = [0x81u8; 32];
        let we_epoch_id = [0x82u8; 32];
        let xk_hash = [0x83u8; 32];
        let epoch_key = [0x84u8; 32];
        let k_barrier = [0x85u8; 32];
        let sender_leaf = [0x86u8; 32];
        let context = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 18,
            barrier_version: 7,
            sender_leaf: &sender_leaf,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let bad_mode = to_cbor_vec(&PayloadEnvelopeV2(
            "wrong-mode".to_string(),
            23,
            vec![0xAA; 16],
        ))?;
        let err = match decrypt_message_v2(&bad_mode, &context) {
            Ok(_) => unreachable!("wrong mode must be rejected before decryption"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("unexpected payload envelope mode"));
        Ok(())
    }

    #[test]
    fn encrypt_message_v2_rejects_oversized_plaintext() {
        let gid = [0x91u8; 32];
        let we_epoch_id = [0x92u8; 32];
        let xk_hash = [0x93u8; 32];
        let epoch_key = [0x94u8; 32];
        let k_barrier = [0x95u8; 32];
        let sender_leaf = [0x96u8; 32];
        let context = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 19,
            barrier_version: 8,
            sender_leaf: &sender_leaf,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let err = encrypt_message_v2(&vec![0xAA; MAX_CT_PAYLOAD_BYTES], &context, 1)
            .expect_err("oversized plaintext must fail");
        assert!(err.to_string().contains("MAX_CT_PAYLOAD_BYTES"));
    }

    #[test]
    fn decrypt_message_v2_rejects_oversized_ciphertext() -> Result<()> {
        let gid = [0xA1u8; 32];
        let we_epoch_id = [0xA2u8; 32];
        let xk_hash = [0xA3u8; 32];
        let epoch_key = [0xA4u8; 32];
        let k_barrier = [0xA5u8; 32];
        let sender_leaf = [0xA6u8; 32];
        let context = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 20,
            barrier_version: 9,
            sender_leaf: &sender_leaf,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let oversized = to_cbor_vec(&PayloadEnvelopeV2(
            PAYLOAD_ENVELOPE_V2_MODE.to_string(),
            7,
            vec![0xBB; MAX_CT_PAYLOAD_BYTES + 1],
        ))?;
        let err = decrypt_message_v2(&oversized, &context)
            .expect_err("oversized ciphertext must fail before decryption");
        assert!(
            err.to_string()
                .contains("payload ciphertext length is out of bounds")
        );
        Ok(())
    }
}
