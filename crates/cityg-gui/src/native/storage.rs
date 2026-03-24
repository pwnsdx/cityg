use super::*;
#[cfg(test)]
use std::cell::RefCell;
#[cfg(not(test))]
use std::sync::{LazyLock, Mutex};
use std::{fs, io::Write, path::PathBuf, time::Duration};

use blake3::hash as blake3_hash;
use dirs::config_dir;

pub(super) fn write_file_atomic(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("path has no parent directory: {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("session");

    for attempt in 0..32u8 {
        let mut suffix = [0u8; 8];
        rng().fill(&mut suffix);
        let suffix = u64::from_le_bytes(suffix);
        let temp_path = parent.join(format!(
            ".{file_name}.tmp-{}-{suffix}-{attempt}",
            std::process::id()
        ));

        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to create {}", temp_path.display()));
            }
        };

        if let Err(err) = file
            .write_all(data)
            .and_then(|_| file.sync_all())
            .with_context(|| format!("failed to write {}", temp_path.display()))
        {
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }
        drop(file);

        if let Err(err) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(err).with_context(|| {
                format!(
                    "failed to atomically replace {} with {}",
                    path.display(),
                    temp_path.display()
                )
            });
        }

        #[cfg(unix)]
        {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        return Ok(());
    }

    Err(anyhow!(
        "failed to allocate unique temporary file for {}",
        path.display()
    ))
}

pub(super) fn persist_session(session: &AppSession) -> Result<()> {
    let persisted = PersistedSession::from_session(session);
    let path = session_file_path(&session.server_url, &session.room_id)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let data = encrypt_persisted_session(&persisted, &path)?;
    write_file_atomic(&path, &data)?;

    let pointer = LastSessionPointer {
        server_url: session.server_url.clone(),
        room_id: session.room_id.clone(),
    };
    let pointer_path = last_session_pointer_path()?;
    if let Some(parent) = pointer_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let pointer_data = serde_json::to_vec(&pointer).context("failed to encode session pointer")?;
    write_file_atomic(&pointer_path, &pointer_data)?;

    Ok(())
}

pub(super) fn persist_room_identity(
    server_url: &str,
    room_id: &str,
    identity: &RoomIdentity,
) -> Result<()> {
    let persisted = PersistedRoomIdentity::from_runtime(identity);
    let path = room_identity_file_path(server_url, room_id)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let data = encrypt_persisted_room_identity(&persisted, &path)?;
    write_file_atomic(&path, &data)
}

pub(super) fn remove_persisted_session(server_url: &str, room_id: &str) -> Result<()> {
    let path = session_file_path(server_url, room_id)?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    }

    let pointer_path = last_session_pointer_path()?;
    if pointer_path.exists() {
        let should_remove = fs::read(&pointer_path)
            .ok()
            .and_then(|data| serde_json::from_slice::<LastSessionPointer>(&data).ok())
            .map(|pointer| pointer.server_url == server_url && pointer.room_id == room_id)
            .unwrap_or(false);

        if should_remove {
            fs::remove_file(&pointer_path)
                .with_context(|| format!("failed to remove {}", pointer_path.display()))?;
        }
    }

    Ok(())
}

pub(super) fn load_last_session() -> Result<Option<AppSession>> {
    let pointer_path = last_session_pointer_path()?;
    if !pointer_path.exists() {
        return Ok(None);
    }

    let data = fs::read(&pointer_path)
        .with_context(|| format!("failed to read {}", pointer_path.display()))?;
    let pointer: LastSessionPointer =
        serde_json::from_slice(&data).context("invalid session pointer JSON")?;
    let session = load_session_at(&pointer.server_url, &pointer.room_id)?;
    if session.is_none() {
        let _ = fs::remove_file(&pointer_path);
    }
    Ok(session)
}

pub(super) fn read_last_session_pointer() -> Result<Option<LastSessionPointer>> {
    let pointer_path = last_session_pointer_path()?;
    if !pointer_path.exists() {
        return Ok(None);
    }

    let data = fs::read(&pointer_path)
        .with_context(|| format!("failed to read {}", pointer_path.display()))?;
    let pointer: LastSessionPointer =
        serde_json::from_slice(&data).context("invalid session pointer JSON")?;
    Ok(Some(pointer))
}

pub(super) fn load_session_at(server_url: &str, room_id: &str) -> Result<Option<AppSession>> {
    let path = session_file_path(server_url, room_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let persisted = decode_persisted_session(&data, &path)?;
    persisted.into_app_session().map(Some)
}

pub(super) fn load_room_identity(server_url: &str, room_id: &str) -> Result<Option<RoomIdentity>> {
    let path = room_identity_file_path(server_url, room_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let persisted = decode_persisted_room_identity(&data, &path)?;
    persisted.into_runtime().map(Some)
}

pub(super) fn load_or_create_room_identity(
    server_url: &str,
    room_id: &str,
) -> Result<RoomIdentity> {
    if let Some(identity) = load_room_identity(server_url, room_id)? {
        return Ok(identity);
    }

    let (pop_pk, pop_sk) = dilithium5::keypair();
    let identity = RoomIdentity {
        pop_public_key: pop_pk.as_bytes().to_vec(),
        pop_secret_key: pop_sk.as_bytes().to_vec(),
    };
    persist_room_identity(server_url, room_id, &identity)?;
    Ok(identity)
}

pub(super) fn encrypt_persisted_payload<T: Serialize>(
    persisted: &T,
    path: &std::path::Path,
    payload_label: &str,
) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, AeadCore, KeyInit, OsRng},
    };

    let payload = serde_json::to_vec(persisted)
        .with_context(|| format!("failed to serialize {payload_label} JSON"))?;
    let (key, key_source) = session_encryption_key(path)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, payload.as_slice())
        .with_context(|| format!("failed to encrypt {payload_label}"))?;

    let envelope = EncryptedSessionEnvelope {
        version: ENCRYPTED_SESSION_ENVELOPE_VERSION,
        alg: ENCRYPTED_SESSION_ALG.to_string(),
        key_source: key_source.as_str().to_string(),
        nonce_hex: hex_encode(nonce),
        ciphertext_hex: hex_encode(ciphertext),
    };
    serde_json::to_vec_pretty(&envelope)
        .with_context(|| format!("failed to serialize encrypted {payload_label} envelope"))
}

pub(super) fn decode_persisted_payload<T: DeserializeOwned>(
    data: &[u8],
    path: &std::path::Path,
    payload_label: &str,
) -> Result<T> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit},
    };

    if let Ok(envelope) = serde_json::from_slice::<EncryptedSessionEnvelope>(data) {
        if envelope.version != ENCRYPTED_SESSION_ENVELOPE_VERSION {
            return Err(anyhow!(
                "unsupported encrypted session envelope version {} (expected {})",
                envelope.version,
                ENCRYPTED_SESSION_ENVELOPE_VERSION
            ));
        }
        if envelope.alg != ENCRYPTED_SESSION_ALG {
            return Err(anyhow!(
                "unsupported encrypted session algorithm '{}' (expected '{}')",
                envelope.alg,
                ENCRYPTED_SESSION_ALG
            ));
        }

        let nonce_bytes = hex_decode(&envelope.nonce_hex)
            .context("encrypted session envelope nonce is not valid hex")?;
        if nonce_bytes.len() != 12 {
            return Err(anyhow!(
                "encrypted session envelope nonce must be 12 bytes, got {}",
                nonce_bytes.len()
            ));
        }
        let ciphertext = hex_decode(&envelope.ciphertext_hex)
            .context("encrypted session envelope ciphertext is not valid hex")?;

        let (key, active_source) = session_encryption_key(path)?;
        if envelope.key_source != active_source.as_str() {
            warn!(
                "session key source mismatch (file='{}', active='{}')",
                envelope.key_source,
                active_source.as_str()
            );
        }

        let cipher = ChaCha20Poly1305::new((&key).into());
        let plaintext = cipher
            .decrypt(nonce_bytes.as_slice().into(), ciphertext.as_slice())
            .with_context(|| format!("failed to decrypt {payload_label}"))?;
        return serde_json::from_slice(&plaintext)
            .with_context(|| format!("invalid decrypted {payload_label} JSON"));
    }

    serde_json::from_slice(data).with_context(|| format!("invalid legacy {payload_label} JSON"))
}

pub(super) fn encrypt_persisted_session(
    persisted: &PersistedSession,
    session_path: &std::path::Path,
) -> Result<Vec<u8>> {
    encrypt_persisted_payload(persisted, session_path, "session payload")
}

pub(super) fn decode_persisted_session(
    data: &[u8],
    session_path: &std::path::Path,
) -> Result<PersistedSession> {
    decode_persisted_payload(data, session_path, "session payload")
}

pub(super) fn encrypt_persisted_room_identity(
    persisted: &PersistedRoomIdentity,
    path: &std::path::Path,
) -> Result<Vec<u8>> {
    encrypt_persisted_payload(persisted, path, "room identity payload")
}

pub(super) fn decode_persisted_room_identity(
    data: &[u8],
    path: &std::path::Path,
) -> Result<PersistedRoomIdentity> {
    decode_persisted_payload(data, path, "room identity payload")
}

pub(super) fn session_encryption_key(
    session_path: &std::path::Path,
) -> Result<([u8; 32], SessionKeySource)> {
    if let Ok(passphrase) = std::env::var(SESSION_PASSPHRASE_ENV)
        && !passphrase.trim().is_empty()
    {
        return Ok((
            blake3::derive_key(SESSION_KEY_DERIVE_CONTEXT, passphrase.as_bytes()),
            SessionKeySource::EnvPassphrase,
        ));
    }

    Ok((
        load_or_create_local_session_key(session_path)?,
        SessionKeySource::LocalKeyFile,
    ))
}

pub(super) fn load_or_create_local_session_key(session_path: &std::path::Path) -> Result<[u8; 32]> {
    use std::io::ErrorKind;

    let key_path = session_local_key_path(session_path)?;
    const READ_RETRIES: usize = 8;
    const READ_RETRY_DELAY_MS: u64 = 10;

    let read_key = |path: &std::path::Path| -> Result<[u8; 32]> {
        let raw = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        bytes32("session local key", &raw)
    };

    if key_path.exists() {
        return read_key(&key_path);
    }

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let mut key = [0u8; 32];
    rng().fill(&mut key);

    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&key_path)
    {
        Ok(mut file) => {
            file.write_all(&key)
                .with_context(|| format!("failed to write {}", key_path.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to sync {}", key_path.display()))?;
            drop(file);
            set_sensitive_file_permissions(&key_path)?;
            Ok(key)
        }
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            for attempt in 0..READ_RETRIES {
                match read_key(&key_path) {
                    Ok(existing) => return Ok(existing),
                    Err(read_err) if attempt + 1 < READ_RETRIES => {
                        warn!(
                            "session key file exists but is not readable yet (attempt {}/{READ_RETRIES}): {}",
                            attempt + 1,
                            read_err
                        );
                        std::thread::sleep(Duration::from_millis(READ_RETRY_DELAY_MS));
                    }
                    Err(read_err) => return Err(read_err),
                }
            }
            Err(anyhow!(
                "session local key read retry exhausted for {}",
                key_path.display()
            ))
        }
        Err(err) => Err(err).with_context(|| format!("failed to create {}", key_path.display())),
    }
}

pub(super) fn session_local_key_path(session_path: &std::path::Path) -> Result<PathBuf> {
    let base = session_path
        .parent()
        .ok_or_else(|| anyhow!("session path has no parent directory"))?;
    Ok(base.join(SESSION_LOCAL_KEY_FILE))
}

#[cfg(unix)]
pub(super) fn set_sensitive_file_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
pub(super) fn set_sensitive_file_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

pub(super) fn session_key_hash(server_url: &str, room_id: &str) -> Result<String> {
    let mut key = server_url.as_bytes().to_vec();
    key.push(0u8);
    key.extend_from_slice(room_id.as_bytes());
    let hash = blake3_hash(&key);
    Ok(hex_encode(hash.as_bytes()))
}

pub(super) fn session_file_path(server_url: &str, room_id: &str) -> Result<PathBuf> {
    let base = session_dir()?;
    let hash = session_key_hash(server_url, room_id)?;
    Ok(base.join(format!("session-{}.json", hash)))
}

pub(super) fn room_identity_file_path(server_url: &str, room_id: &str) -> Result<PathBuf> {
    let base = session_dir()?;
    let hash = session_key_hash(server_url, room_id)?;
    Ok(base.join(format!("room-identity-{}.json", hash)))
}

pub(super) fn roster_file_path(server_url: &str, room_id: &str) -> Result<PathBuf> {
    let base = session_dir()?;
    let hash = session_key_hash(server_url, room_id)?;
    Ok(base.join(format!("roster-{}.json", hash)))
}

pub(super) fn last_session_pointer_path() -> Result<PathBuf> {
    Ok(session_dir()?.join("last-session.json"))
}

pub(super) fn session_dir() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = CONFIG_DIR_OVERRIDE.with(|override_path| override_path.borrow().clone()) {
        return Ok(path);
    }

    #[cfg(not(test))]
    if let Some(path) = CONFIG_DIR_OVERRIDE
        .lock()
        .map_err(|_| anyhow!("Failed to acquire config dir lock"))?
        .clone()
    {
        return Ok(path);
    }

    if let Ok(override_path) = std::env::var("CITYG_GUI_CONFIG_DIR")
        && !override_path.is_empty()
    {
        let base = PathBuf::from(override_path).join("cityg").join("gui");
        return Ok(base);
    }

    let base = config_dir().ok_or_else(|| anyhow!("cannot determine config directory"))?;
    Ok(base.join("cityg").join("gui"))
}

pub(super) fn load_alias_bindings(
    server_url: &str,
    room_id: &str,
) -> Result<AHashMap<String, AliasBindingRecord>> {
    let path = roster_file_path(server_url, room_id)?;
    if !path.exists() {
        return Ok(AHashMap::new());
    }

    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let store: PersistedAliasStore = match serde_json::from_slice(&data) {
        Ok(store) => store,
        Err(_) => {
            let bindings: AHashMap<String, String> =
                serde_json::from_slice(&data).context("invalid alias store JSON")?;
            PersistedAliasStore {
                version: 0,
                bindings: bindings
                    .into_iter()
                    .map(|(alias, pop)| {
                        (
                            alias,
                            PersistedAliasBinding {
                                pop_public_key_hex: pop,
                                leaf_id_hex: String::new(),
                            },
                        )
                    })
                    .collect(),
            }
        }
    };

    let mut map = AHashMap::new();
    for (alias, entry) in store.bindings {
        if entry.pop_public_key_hex.is_empty() {
            continue;
        }
        let pop_key = match hex_decode(&entry.pop_public_key_hex) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(
                    "skipping alias binding '{}' due to invalid public key hex: {}",
                    alias, err
                );
                continue;
            }
        };

        let leaf_id = if entry.leaf_id_hex.is_empty() {
            [0u8; 32]
        } else {
            match decode_hex32("alias_leaf", &entry.leaf_id_hex) {
                Ok(arr) => arr,
                Err(err) => {
                    warn!(
                        "alias '{}' has invalid leaf id '{}': {err}",
                        alias, entry.leaf_id_hex
                    );
                    [0u8; 32]
                }
            }
        };

        map.insert(
            alias,
            AliasBindingRecord {
                pop_public_key: pop_key,
                leaf_id,
            },
        );
    }
    Ok(map)
}

pub(super) fn persist_alias_bindings(
    server_url: &str,
    room_id: &str,
    bindings: &AHashMap<String, AliasBindingRecord>,
) -> Result<()> {
    let path = roster_file_path(server_url, room_id)?;
    if bindings.is_empty() {
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let store = PersistedAliasStore {
        version: ALIAS_STORE_VERSION,
        bindings: bindings
            .iter()
            .map(|(alias, record)| {
                (
                    alias.clone(),
                    PersistedAliasBinding {
                        pop_public_key_hex: hex_encode(&record.pop_public_key),
                        leaf_id_hex: hex_encode(record.leaf_id),
                    },
                )
            })
            .collect(),
    };
    let data =
        serde_json::to_vec_pretty(&store).context("failed to serialize alias bindings to JSON")?;
    fs::write(&path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub(super) fn security_log_file_path(server_url: &str, room_id: &str) -> Result<PathBuf> {
    let base = session_dir()?;
    let hash = session_key_hash(server_url, room_id)?;
    Ok(base.join(format!("security-log-{}.json", hash)))
}

pub(super) fn load_security_log(server_url: &str, room_id: &str) -> Result<Vec<SecurityEvent>> {
    let path = security_log_file_path(server_url, room_id)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let log: PersistedSecurityLog =
        serde_json::from_slice(&data).context("invalid security log JSON")?;
    let mut events = Vec::with_capacity(log.events.len());
    for entry in log.events {
        events.push(SecurityEvent {
            alias: entry.alias,
            description: entry.description,
            timestamp_ms: entry.timestamp_ms,
        });
    }
    Ok(events)
}

pub(super) fn persist_security_log(
    server_url: &str,
    room_id: &str,
    events: &[SecurityEvent],
) -> Result<()> {
    let path = security_log_file_path(server_url, room_id)?;
    if events.is_empty() {
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let log = PersistedSecurityLog {
        version: SECURITY_LOG_VERSION,
        events: events
            .iter()
            .map(|event| PersistedSecurityEvent {
                alias: event.alias.clone(),
                description: event.description.clone(),
                timestamp_ms: event.timestamp_ms,
            })
            .collect(),
    };
    let data =
        serde_json::to_vec_pretty(&log).context("failed to serialize security log to JSON")?;
    fs::write(&path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub(super) fn remove_security_log(server_url: &str, room_id: &str) -> Result<()> {
    let path = security_log_file_path(server_url, room_id)?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

#[cfg(not(test))]
static CONFIG_DIR_OVERRIDE: LazyLock<Mutex<Option<PathBuf>>> = LazyLock::new(|| Mutex::new(None));

#[cfg(test)]
thread_local! {
    static CONFIG_DIR_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
pub(super) fn set_config_dir_override_for_tests(path: Option<PathBuf>) -> ConfigDirGuard {
    let previous = CONFIG_DIR_OVERRIDE.with(|override_path| {
        let mut slot = override_path.borrow_mut();
        let previous = slot.clone();
        *slot = path;
        previous
    });
    ConfigDirGuard { previous }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
pub(super) struct ConfigDirGuard {
    previous: Option<PathBuf>,
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
impl Drop for ConfigDirGuard {
    fn drop(&mut self) {
        CONFIG_DIR_OVERRIDE.with(|override_path| {
            *override_path.borrow_mut() = self.previous.clone();
        });
    }
}

pub(super) fn decode_hex32(name: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = hex_decode(value).with_context(|| format!("{name} is not valid hex"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{name} must decode to 32 bytes, got {}", bytes.len()))
}

pub(super) fn decode_hex32_or_zero(name: &str, value: &str) -> Result<[u8; 32]> {
    if value.is_empty() {
        Ok([0u8; 32])
    } else {
        decode_hex32(name, value)
    }
}

pub(super) fn decode_hex_vec(name: &str, value: &str) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    hex_decode(value).with_context(|| format!("{name} is not valid hex"))
}
