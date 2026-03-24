use super::*;

#[derive(Serialize, Deserialize)]
pub(in crate::native) struct PersistedRoomIdentity {
    version: u32,
    pop_public_hex: String,
    pop_secret_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
pub(in crate::native) struct PersistedAliasStore {
    pub(in crate::native) version: u32,
    pub(in crate::native) bindings: AHashMap<String, PersistedAliasBinding>,
}

#[derive(Serialize, Deserialize, Default)]
pub(in crate::native) struct PersistedAliasBinding {
    pub(in crate::native) pop_public_key_hex: String,
    #[serde(default)]
    pub(in crate::native) leaf_id_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
pub(in crate::native) struct PersistedSecurityLog {
    pub(in crate::native) version: u32,
    pub(in crate::native) events: Vec<PersistedSecurityEvent>,
}

#[derive(Serialize, Deserialize, Default)]
pub(in crate::native) struct PersistedSecurityEvent {
    pub(in crate::native) alias: String,
    pub(in crate::native) description: String,
    pub(in crate::native) timestamp_ms: u64,
}

#[derive(Serialize, Deserialize)]
pub(in crate::native) struct EncryptedSessionEnvelope {
    pub(in crate::native) version: u32,
    pub(in crate::native) alg: String,
    pub(in crate::native) key_source: String,
    pub(in crate::native) nonce_hex: String,
    pub(in crate::native) ciphertext_hex: String,
}

impl PersistedRoomIdentity {
    pub(in crate::native) fn from_runtime(identity: &RoomIdentity) -> Self {
        Self {
            version: ROOM_IDENTITY_VERSION,
            pop_public_hex: hex_encode(&identity.pop_public_key),
            pop_secret_hex: hex_encode(&identity.pop_secret_key),
        }
    }

    pub(in crate::native) fn into_runtime(self) -> Result<RoomIdentity> {
        if self.version != ROOM_IDENTITY_VERSION {
            return Err(anyhow!(
                "unsupported room identity file version {} (expected {})",
                self.version,
                ROOM_IDENTITY_VERSION
            ));
        }

        Ok(RoomIdentity {
            pop_public_key: decode_hex_vec("pop_public_hex", &self.pop_public_hex)?,
            pop_secret_key: decode_hex_vec("pop_secret_hex", &self.pop_secret_hex)?,
        })
    }
}
