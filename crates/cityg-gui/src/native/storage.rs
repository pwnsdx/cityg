#[cfg(test)]
use super::fault_injection::{FaultInjectionCutPoint, trigger_fault};
use super::*;
use rand::{RngExt, rng};
use std::{fs, io::Write};

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

        #[cfg(test)]
        trigger_fault(
            FaultInjectionCutPoint::AfterTempWriteFsync,
            Some(temp_path.as_path()),
        )?;

        drop(file);

        #[cfg(test)]
        trigger_fault(
            FaultInjectionCutPoint::BeforeAtomicRename,
            Some(temp_path.as_path()),
        )?;

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

    #[cfg(test)]
    trigger_fault(FaultInjectionCutPoint::BeforeSessionEncrypt, None)?;

    let data = encrypt_persisted_session(&persisted, &path)?;

    #[cfg(test)]
    trigger_fault(FaultInjectionCutPoint::AfterSessionEncrypt, None)?;

    write_file_atomic(&path, &data)?;

    #[cfg(test)]
    trigger_fault(
        FaultInjectionCutPoint::AfterSessionWrite,
        Some(path.as_path()),
    )?;

    persist_replay_progress(
        &session.server_url,
        &session.room_id,
        session.last_fetch_timestamp_ms,
        &session.msg_replay_state,
    )?;

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

    #[cfg(test)]
    trigger_fault(
        FaultInjectionCutPoint::BeforePointerWrite,
        Some(pointer_path.as_path()),
    )?;

    write_file_atomic(&pointer_path, &pointer_data)?;

    #[cfg(test)]
    trigger_fault(
        FaultInjectionCutPoint::AfterPointerWrite,
        Some(pointer_path.as_path()),
    )?;

    Ok(())
}

pub(super) fn persist_replay_progress(
    server_url: &str,
    room_id: &str,
    last_fetch_timestamp_ms: Option<u64>,
    msg_replay_state: &MsgReplayState,
) -> Result<()> {
    let persisted =
        PersistedReplayProgress::from_runtime(last_fetch_timestamp_ms, msg_replay_state);
    let path = replay_progress_file_path(server_url, room_id)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let data = encrypt_persisted_replay_progress(&persisted, &path)?;
    write_file_atomic(&path, &data)
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
    let replay_path = replay_progress_file_path(server_url, room_id)?;
    if replay_path.exists() {
        fs::remove_file(&replay_path)
            .with_context(|| format!("failed to remove {}", replay_path.display()))?;
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
    let mut session = persisted.into_app_session()?;
    if let Some((last_fetch_timestamp_ms, msg_replay_state)) =
        load_replay_progress(server_url, room_id)?
    {
        session.last_fetch_timestamp_ms = last_fetch_timestamp_ms;
        session.msg_replay_state = msg_replay_state;
    }
    Ok(Some(session))
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

    let identity = cityg_api_client::generate_room_admin_identity();
    persist_room_identity(server_url, room_id, &identity)?;
    Ok(identity)
}

fn load_replay_progress(
    server_url: &str,
    room_id: &str,
) -> Result<Option<(Option<u64>, MsgReplayState)>> {
    let path = replay_progress_file_path(server_url, room_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let persisted = decode_persisted_replay_progress(&data, &path)?;
    persisted.into_runtime().map(Some)
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
