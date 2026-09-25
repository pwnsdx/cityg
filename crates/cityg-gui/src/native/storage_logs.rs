use super::*;
use std::fs;

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
                                member: String::new(),
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

        let member = if entry.member.is_empty() {
            None
        } else {
            let parsed = parse_member_ref(&entry.member);
            if parsed.is_none() {
                warn!("alias '{}' has an invalid member '{}'", alias, entry.member);
            }
            parsed
        };

        map.insert(
            alias,
            AliasBindingRecord {
                pop_public_key: pop_key,
                member,
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
                        member: record.member.map(member_ref_text).unwrap_or_default(),
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
