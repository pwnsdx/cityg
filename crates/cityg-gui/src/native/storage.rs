use super::*;
use cityg_api_client::v2::cityg_core::identity::DeviceIdentity;
use cityg_api_client::v2::{DsClient, StateSink};
use rand::{RngExt, rng};
use std::{
    fs,
    io::Write,
    sync::atomic::{AtomicU64, Ordering},
};

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
        set_sensitive_file_permissions(&temp_path)?;

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

/// What the session file needs besides the member state.
#[derive(Clone)]
pub(super) struct SessionFileContext {
    pub(super) server_url: String,
    pub(super) room_id: String,
    pub(super) alias: String,
    pub(super) identity_secret_key: Arc<Zeroizing<Vec<u8>>>,
    pub(super) last_self_update_ms: Arc<AtomicU64>,
}

impl SessionFileContext {
    pub(super) fn for_member(server_url: &str, alias: &str, member: &Member) -> Self {
        Self {
            server_url: server_url.to_string(),
            room_id: hex_encode(member.gid()),
            alias: alias.to_string(),
            identity_secret_key: Arc::new(Zeroizing::new(
                member.identity().secret_key_bytes().to_vec(),
            )),
            last_self_update_ms: Arc::new(AtomicU64::new(engine::now_ms())),
        }
    }

    /// Encrypt and atomically write the session file for `member_state`.
    pub(super) fn write(&self, member_state: &[u8]) -> Result<()> {
        let persisted = PersistedSession {
            version: SESSION_FORMAT_VERSION,
            server_url: self.server_url.clone(),
            room_id: self.room_id.clone(),
            alias: self.alias.clone(),
            identity_secret_key_hex: hex_encode(self.identity_secret_key.as_slice()),
            member_state_hex: hex_encode(member_state),
            last_self_update_ms: self.last_self_update_ms.load(Ordering::SeqCst),
        };
        let path = session_file_path(&self.server_url, &self.room_id)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let data = encrypt_persisted_session(&persisted, &path)?;
        write_file_atomic(&path, &data)?;
        write_last_session_pointer(&self.server_url, &self.room_id)
    }

    /// Sink writing the session file whenever the member state must be
    /// durable (see `cityg_api_client::v2::StateSink`).
    pub(super) fn sink(&self) -> StateSink {
        let context = self.clone();
        Arc::new(move |member_state: &[u8]| {
            context
                .write(member_state)
                .map_err(|error| format!("{error:#}"))
        })
    }
}

/// Install the persistence sink on a new member, save it once and wrap it in
/// an [`AppSession`].
pub(super) fn open_session(
    server_url: &str,
    alias: &str,
    mut member: Member,
    last_self_update_ms: Option<u64>,
) -> Result<AppSession> {
    let context = SessionFileContext::for_member(server_url, alias, &member);
    if let Some(value) = last_self_update_ms {
        context.last_self_update_ms.store(value, Ordering::SeqCst);
    }
    member.set_state_sink(context.sink());
    member.save().context("failed to save the session")?;
    let mut session = AppSession::new(
        server_url.to_string(),
        alias.to_string(),
        member,
        context.last_self_update_ms.load(Ordering::SeqCst),
    );
    session.self_update_clock = context.last_self_update_ms;
    Ok(session)
}

fn write_last_session_pointer(server_url: &str, room_id: &str) -> Result<()> {
    let pointer = LastSessionPointer {
        server_url: server_url.to_string(),
        room_id: room_id.to_string(),
    };
    let path = last_session_pointer_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(&pointer).context("failed to encode session pointer")?;
    write_file_atomic(&path, &data)
}

/// Remove every file of the session `(server_url, room_id)`.
pub(super) fn remove_persisted_session(server_url: &str, room_id: &str) -> Result<()> {
    for path in [
        session_file_path(server_url, room_id)?,
        history_file_path(server_url, room_id)?,
        roster_file_path(server_url, room_id)?,
    ] {
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
    }
    if let Some(pointer) = read_last_session_pointer()?
        && pointer.server_url == server_url
        && pointer.room_id == room_id
    {
        let path = last_session_pointer_path()?;
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
    }
    Ok(())
}

/// The session the GUI used last, restored.
pub(super) fn load_last_session() -> Result<Option<AppSession>> {
    let Some(pointer) = read_last_session_pointer()? else {
        return Ok(None);
    };
    load_session_at(&pointer.server_url, &pointer.room_id)
}

pub(super) fn read_last_session_pointer() -> Result<Option<LastSessionPointer>> {
    let path = last_session_pointer_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let pointer = serde_json::from_slice(&data).context("invalid saved session pointer JSON")?;
    Ok(Some(pointer))
}

/// Restore the session `(server_url, room_id)` from disk.
pub(super) fn load_session_at(server_url: &str, room_id: &str) -> Result<Option<AppSession>> {
    let path = session_file_path(server_url, room_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let persisted = decode_persisted_session(&data, &path)?;
    persisted.check_version()?;
    let identity_secret = Zeroizing::new(decode_hex_vec(
        "identity_secret_key_hex",
        &persisted.identity_secret_key_hex,
    )?);
    let identity = DeviceIdentity::from_secret_key_bytes(&identity_secret)
        .map_err(|error| anyhow!("invalid saved identity: {error}"))?;
    let member_state = Zeroizing::new(decode_hex_vec(
        "member_state_hex",
        &persisted.member_state_hex,
    )?);
    let member = Member::restore(
        DsClient::new(&persisted.server_url)?,
        identity,
        &member_state,
    )
    .context("failed to restore the saved session")?;
    if hex_encode(member.gid()) != persisted.room_id {
        return Err(anyhow!("saved session does not match its room"));
    }
    let session = open_session(
        &persisted.server_url,
        &persisted.alias,
        member,
        Some(persisted.last_self_update_ms),
    )?;
    Ok(Some(session))
}

/// Persist the chat history of a room (the newest messages).
pub(super) fn persist_history(
    server_url: &str,
    room_id: &str,
    messages: &[ChatMessageEntry],
) -> Result<()> {
    let path = history_file_path(server_url, room_id)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let start = messages.len().saturating_sub(MAX_PERSISTED_MESSAGES);
    let history = PersistedHistory {
        version: HISTORY_VERSION,
        messages: messages[start..]
            .iter()
            .filter(|message| matches!(message.delivery, MessageDelivery::Sent))
            .map(PersistedChatMessage::from_entry)
            .collect(),
    };
    let data = encrypt_persisted_history(&history, &path)?;
    write_file_atomic(&path, &data)
}

/// Load the chat history of a room.
pub(super) fn load_history(server_url: &str, room_id: &str) -> Result<Vec<ChatMessageEntry>> {
    let path = history_file_path(server_url, room_id)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let history = decode_persisted_history(&data, &path)?;
    if history.version != HISTORY_VERSION {
        return Err(anyhow!(
            "unsupported chat history version {} (expected {HISTORY_VERSION})",
            history.version
        ));
    }
    Ok(history
        .messages
        .into_iter()
        .map(PersistedChatMessage::into_entry)
        .collect())
}

pub(super) fn decode_hex32(name: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = decode_hex_vec(name, value)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("{name} must be 32 bytes, got {}", bytes.len()))
}

pub(super) fn decode_hex_vec(name: &str, value: &str) -> Result<Vec<u8>> {
    hex_decode(value).with_context(|| format!("{name} is not valid hex"))
}
