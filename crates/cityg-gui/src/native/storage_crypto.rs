use super::*;
use rand::{RngExt, rng};
use std::{fs, io::Write, path::PathBuf, time::Duration};

use blake3::hash as blake3_hash;

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

pub(super) fn encrypt_persisted_replay_progress(
    persisted: &PersistedReplayProgress,
    path: &std::path::Path,
) -> Result<Vec<u8>> {
    encrypt_persisted_payload(persisted, path, "replay progress payload")
}

pub(super) fn decode_persisted_replay_progress(
    data: &[u8],
    path: &std::path::Path,
) -> Result<PersistedReplayProgress> {
    decode_persisted_payload(data, path, "replay progress payload")
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
