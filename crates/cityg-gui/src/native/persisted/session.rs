use super::*;

/// Encrypted-at-rest state of one room session.
///
/// It holds the device identity and the exported member state, which
/// includes the group secrets of the current epoch: it is only ever written
/// through the encrypted envelope of `storage_crypto`.
#[derive(Serialize, Deserialize)]
pub(in crate::native) struct PersistedSession {
    pub(in crate::native) version: u32,
    pub(in crate::native) server_url: String,
    pub(in crate::native) room_id: String,
    pub(in crate::native) alias: String,
    pub(in crate::native) identity_secret_key_hex: String,
    pub(in crate::native) member_state_hex: String,
    #[serde(default)]
    pub(in crate::native) last_self_update_ms: u64,
}

impl PersistedSession {
    pub(in crate::native) fn check_version(&self) -> Result<()> {
        if self.version != SESSION_FORMAT_VERSION {
            return Err(anyhow!(
                "unsupported session file version {} (expected {}); join the room again",
                self.version,
                SESSION_FORMAT_VERSION
            ));
        }
        Ok(())
    }
}

/// Chat history kept for display (messages cannot be decrypted twice).
#[derive(Serialize, Deserialize, Default)]
pub(in crate::native) struct PersistedHistory {
    pub(in crate::native) version: u32,
    pub(in crate::native) messages: Vec<PersistedChatMessage>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(in crate::native) struct PersistedChatMessage {
    #[serde(default)]
    pub(in crate::native) sender_leaf_hex: String,
    pub(in crate::native) label: String,
    pub(in crate::native) text: String,
    pub(in crate::native) timestamp_ms: u64,
    pub(in crate::native) key: String,
}

impl PersistedChatMessage {
    pub(in crate::native) fn from_entry(entry: &ChatMessageEntry) -> Self {
        Self {
            sender_leaf_hex: entry.sender_leaf.map(hex_encode).unwrap_or_default(),
            label: entry.fallback_label.clone(),
            text: entry.plaintext.clone(),
            timestamp_ms: entry.timestamp_ms,
            key: entry.ciphertext_hex.clone(),
        }
    }

    pub(in crate::native) fn into_entry(self) -> ChatMessageEntry {
        ChatMessageEntry {
            sender_leaf: decode_hex32("sender_leaf", &self.sender_leaf_hex).ok(),
            fallback_label: self.label,
            plaintext: self.text,
            ciphertext_hex: self.key,
            timestamp_ms: self.timestamp_ms,
            delivery: MessageDelivery::Sent,
            pending_id: None,
        }
    }
}
