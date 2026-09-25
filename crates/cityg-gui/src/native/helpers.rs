use super::*;

pub(super) fn fingerprint_full_hex(bytes: &[u8; 32]) -> String {
    hex_encode(bytes)
}

/// Grouped preview of a 32-byte fingerprint, for display.
pub(super) fn fingerprint_preview_hex(bytes: &[u8; 32]) -> String {
    let hex = fingerprint_full_hex(bytes);
    format!(
        "{}-{} {}-{} …",
        &hex[..4],
        &hex[4..8],
        &hex[8..12],
        &hex[12..16]
    )
}

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

pub(super) fn format_regular_fingerprint(value: Option<&[u8; 32]>) -> String {
    match value {
        Some(bytes) => fingerprint_preview_hex(bytes),
        None => "Not available".to_string(),
    }
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
    let expected_len = cityg_pqc::ML_DSA_87_PUBLIC_KEY_BYTES;
    if bytes.len() != expected_len {
        return Err(anyhow!(
            "room admin target must be {} bytes (got {})",
            expected_len,
            bytes.len()
        ));
    }
    Ok(bytes)
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
