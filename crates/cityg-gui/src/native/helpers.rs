use super::*;
pub(super) use cityg_client::barrier_crypto::generate_kbroad_keypair;
pub(super) use cityg_client::bundle_headers::{
    compute_fs_fingerprint_from_header, derive_fs_fingerprint_from_fields, recompute_proofs_commit,
    recompute_srx_commit,
};

pub(super) fn hex_encode_prefix(bytes: &[u8; 32], prefix_len: usize) -> String {
    let hex = hex_encode(bytes);
    if prefix_len >= hex.len() {
        hex
    } else {
        format!("{}…", &hex[..prefix_len])
    }
}

pub(super) fn room_admin_identity_preview(bytes: &[u8]) -> String {
    let hex = hex_encode(bytes);
    if hex.len() <= 24 {
        hex
    } else {
        let prefix = &hex[..12];
        let suffix = &hex[hex.len().saturating_sub(12)..];
        format!("{prefix}…{suffix}")
    }
}

pub(super) fn format_alias_display(alias: &str, leaf: &[u8; 32]) -> String {
    format!("{alias} ({})", hex_encode_prefix(leaf, 8))
}

pub(super) fn fingerprint_full_hex(bytes: &[u8; 32]) -> String {
    hex_encode(bytes)
}

pub(super) fn fingerprint_preview_hex(bytes: &[u8; 32]) -> String {
    let hex = fingerprint_full_hex(bytes);
    let first = &hex[..8];
    let second = &hex[8..16];
    format!(
        "{}-{} {}-{} …",
        &first[..4],
        &first[4..],
        &second[..4],
        &second[4..]
    )
}

pub(super) fn format_regular_fingerprint(value: Option<&[u8; 32]>) -> String {
    match value {
        Some(bytes) => fingerprint_preview_hex(bytes),
        None => "Not available".to_string(),
    }
}

pub(super) fn format_fs_fingerprint(value: Option<&[u8; 32]>, fs_ec: u64) -> String {
    match value {
        Some(bytes) => format!("{} · fs_ec {}", fingerprint_preview_hex(bytes), fs_ec),
        None => "Not available".to_string(),
    }
}

pub(super) fn header_policy_version(header: &BTreeMap<u64, Value>, key: u64) -> Option<String> {
    match header.get(&key)? {
        Value::Text(text) => Some(text.clone()),
        Value::Integer(value) => u64::try_from(*value).ok().map(|v| v.to_string()),
        _ => None,
    }
}

pub(super) fn header_text(header: &BTreeMap<u64, Value>, key: u64) -> Option<&str> {
    match header.get(&key)? {
        Value::Text(text) => Some(text.as_str()),
        _ => None,
    }
}

pub(super) fn header_u64(header: &BTreeMap<u64, Value>, key: u64) -> Option<u64> {
    match header.get(&key)? {
        Value::Integer(int) => (*int).try_into().ok(),
        _ => None,
    }
}

pub(super) fn header_bytes32(header: &BTreeMap<u64, Value>, key: u64) -> Option<[u8; 32]> {
    match header.get(&key)? {
        Value::Bytes(bytes) => bytes.as_slice().try_into().ok(),
        _ => None,
    }
}

pub(super) fn decode_hex_32(input: &str) -> Option<[u8; 32]> {
    let bytes = hex_decode(input).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Some(result)
}

pub(super) fn decode_room_admin_target_hex(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("room admin target identity must not be empty"));
    }
    let normalized = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex_decode(normalized).context("room admin target must be valid hex")?;
    let expected_len = dilithium5::public_key_bytes();
    if bytes.len() != expected_len {
        return Err(anyhow!(
            "room admin target must be {} bytes (got {})",
            expected_len,
            bytes.len()
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
pub(super) fn configured_hex_from_env(var_name: &str) -> Result<Option<Vec<u8>>> {
    let raw = match std::env::var(var_name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(err) => {
            return Err(anyhow!("failed reading {}: {}", var_name, err));
        }
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let normalized = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if normalized.is_empty() {
        return Ok(None);
    }

    let bytes =
        hex_decode(normalized).with_context(|| format!("{var_name} must contain hex bytes"))?;
    Ok(Some(bytes))
}

pub(super) fn build_identity_binding(
    alias: &str,
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<cityg_api_client::IdentityBinding> {
    use cityg_api_client::IdentityBinding;
    let binding = cityg_client::message_auth::build_signed_identity_binding(
        alias,
        pop_public_key,
        pop_secret_key,
    )?;

    Ok(IdentityBinding {
        alias: binding.alias,
        pop_public_key: binding.pop_public_key,
        signature: binding.signature,
    })
}

pub(super) fn format_member_label(member: &MemberEntry) -> String {
    if let Some(alias) = member.alias.as_ref().filter(|s| !s.is_empty()) {
        format_alias_display(alias, &member.leaf_id)
    } else {
        hex_encode(member.leaf_id)
    }
}

pub(super) fn format_timestamp(ts_ms: u64) -> String {
    let dt = UNIX_EPOCH + Duration::from_millis(ts_ms);
    format_rfc3339_seconds(dt).to_string()
}

pub(super) fn current_unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(super) fn short_leaf_display(leaf: &[u8; 32]) -> String {
    format!("{}…", hex_encode(&leaf[..4]))
}

#[cfg(test)]
pub(super) fn header_bytes(
    header: &BTreeMap<u64, Value>,
    key: u64,
    label: &'static str,
) -> Result<Vec<u8>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        Some(_) => Err(anyhow!("{label} must be bytes")),
        None => Err(anyhow!("{label} missing")),
    }
}

#[cfg(test)]
pub(super) fn header_bytes_opt(header: &BTreeMap<u64, Value>, key: u64) -> Result<Option<Vec<u8>>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(Some(bytes.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(anyhow!("header {key} must be bytes")),
    }
}

#[cfg(test)]
pub(super) fn header_bytes32_opt(
    header: &BTreeMap<u64, Value>,
    key: u64,
) -> Result<Option<[u8; 32]>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Ok(Some(arr))
        }
        Some(Value::Bytes(_)) => Err(anyhow!("header {key} must be 32 bytes")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(anyhow!("header {key} must be bytes")),
    }
}

pub(super) fn bytes32(name: &str, data: &[u8]) -> Result<[u8; 32]> {
    data.try_into()
        .map_err(|_| anyhow!("{name} must be 32 bytes, received {} bytes", data.len()))
}
