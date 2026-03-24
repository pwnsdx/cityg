use super::*;

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

#[derive(Serialize)]
pub(super) struct FsFingerprintInputs<'a> {
    pub(super) fs_policy_version: &'a str,
    pub(super) fs_ec: u64,
    #[serde(with = "serde_bytes")]
    pub(super) fs_epoch_commit: &'a [u8],
    pub(super) fs_epoch_base_ts: u64,
}

pub(super) fn derive_fs_fingerprint_from_fields(
    fs_policy_version: &str,
    fs_ec: u64,
    fs_epoch_commit: &[u8; 32],
    fs_epoch_base_ts: u64,
) -> Option<[u8; 32]> {
    let inputs = FsFingerprintInputs {
        fs_policy_version,
        fs_ec,
        fs_epoch_commit,
        fs_epoch_base_ts,
    };
    h_l("fs/fingerprint", &inputs).ok()
}

pub(super) fn compute_fs_fingerprint_from_header(
    header: &BTreeMap<u64, Value>,
) -> Option<[u8; 32]> {
    let policy = header_policy_version(header, hdr::HDR_FS_POLICY_VERSION)?;
    let fs_ec = header_u64(header, hdr::HDR_FS_EC)?;
    let fs_epoch_commit = header_bytes32(header, hdr::HDR_FS_EPOCH_COMMIT)?;
    let fs_epoch_base_ts = header_u64(header, hdr::HDR_FS_EPOCH_BASE_TS)?;
    derive_fs_fingerprint_from_fields(policy.as_str(), fs_ec, &fs_epoch_commit, fs_epoch_base_ts)
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

pub(super) fn generate_kbroad_keypair() -> (Vec<u8>, Vec<u8>) {
    let (public, secret) = kyber768::keypair();
    (
        KemPublicKey::as_bytes(&public).to_vec(),
        KemSecretKey::as_bytes(&secret).to_vec(),
    )
}

pub(super) fn build_identity_binding(
    alias: &str,
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<cityg_api_client::IdentityBinding> {
    use ciborium::ser::into_writer;
    use cityg_api_client::IdentityBinding;
    use pqcrypto_traits::sign::DetachedSignature as _;
    use serde_bytes::ByteBuf;

    let pop_secret = dilithium5::SecretKey::from_bytes(pop_secret_key)
        .context("invalid persisted room identity secret key")?;
    let message_data = (
        ByteBuf::from(alias.as_bytes().to_vec()),
        ByteBuf::from(pop_public_key.to_vec()),
    );
    let mut message = Vec::new();
    into_writer(&message_data, &mut message)
        .context("failed to encode identity binding message")?;
    let signature = dilithium5::detached_sign(&message, &pop_secret);

    Ok(IdentityBinding {
        alias: alias.to_string(),
        pop_public_key: pop_public_key.to_vec(),
        signature: signature.as_bytes().to_vec(),
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

pub(super) fn recompute_proofs_commit(header: &BTreeMap<u64, Value>) -> Result<[u8; 32]> {
    let vrf = header_bytes(header, hdr::HDR_VRF_PROOF, "vrf_proof")?;
    let fs = header_bytes(header, hdr::HDR_FS_CAPSS, "fs_capss")?;
    let srx_root = header_bytes32_opt(header, hdr::HDR_SRX_ROOT_SW)?;
    let srx_smallwood = header_bytes_opt(header, hdr::HDR_SRX_SMALLWOOD)?;
    compute_proofs_commit_bytes(
        &vrf,
        &fs,
        srx_root.as_ref().map(|arr| arr.as_slice()),
        srx_smallwood.as_deref(),
    )
    .map_err(|err| anyhow!("compute proofs commit: {err}"))
}

pub(super) fn recompute_srx_commit(header: &BTreeMap<u64, Value>) -> Result<Option<[u8; 32]>> {
    let payload = match header.get(&hdr::HDR_SRX_PAYLOAD) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        Some(Value::Null) | None => return Ok(None),
        Some(_) => return Err(anyhow!("srx_payload must be bytes")),
    };

    #[derive(Serialize)]
    struct SrxCommit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

    let commit = h_l(ds::MSPHF_SRX_COMMIT, &SrxCommit(payload))
        .map_err(|err| anyhow!("compute srx commit: {err}"))?;
    Ok(Some(commit))
}

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

pub(super) fn header_bytes_opt(header: &BTreeMap<u64, Value>, key: u64) -> Result<Option<Vec<u8>>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(Some(bytes.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(anyhow!("header {key} must be bytes")),
    }
}

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
